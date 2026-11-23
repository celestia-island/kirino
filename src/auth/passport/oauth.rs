//! The OAuth 2.0 relying-party protocol core: authorization-code flow with
//! PKCE, a one-time `state`, the token exchange and ID-token verification.
//!
//! # What lives here and what does not
//!
//! This module is the **protocol**, pure and testable: it builds the
//! authorization request, binds a login attempt to a one-time `state` and a
//! PKCE verifier, turns the callback into an [`ExternalIdentity`], and
//! verifies ID tokens. It opens **no socket** — the crate's threat model
//! forbids it — so every network call goes through the [`HttpFetcher`]
//! trait, which the host (or a platform adapter) implements. It also keeps
//! no provider-specific quirks: endpoints and the token body encoding are
//! data ([`ProviderMetadata`]), not `match` arms on a vendor name.
//!
//! # Trust boundary
//!
//! * **PKCE (RFC 7636, S256) is always on.** The verifier never leaves the
//!   server: it lives in the [`LoginAttempt`] until the callback spends it.
//!   A public client ([`ClientAuth::Public`]) has no secret and MUST NOT be
//!   given one; a confidential client's secret is zeroized and never placed
//!   in an authorization URL.
//! * **`state` is one-time and server-side.** [`LoginAttemptStore::take`]
//!   hands an attempt out exactly once and never an expired one, which is
//!   what turns a replayed callback into [`CallbackProblem::UnknownState`].
//! * **The subject is the identity.** Whatever else the provider says, the
//!   account is keyed by its stable subject — never by an email address.
//! * **Nothing is logged.** Codes, verifiers and tokens never reach a log
//!   line in this module; errors carry no secret material.
//!
//! # Flow
//!
//! ```text
//! begin()      → LoginAttempt { state, Pkce, return_to }  — store.put()
//! authorize_url() → the browser is sent to the provider
//! finish()     → take(state) once → exchange code + verifier → identity
//! ```

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use base64::Engine as _;
use chrono::{DateTime, Duration, Utc};
use rand::RngExt as _;
use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use subtle::ConstantTimeEq as _;
use tokio::sync::RwLock;
use url::Url;
use zeroize::Zeroizing;

use crate::auth::identity::external::ExternalIdentity;
use crate::error::KirinoError;

fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn is_unreserved(text: &str) -> bool {
    text.bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
}

/// PKCE proof for one authorization request (RFC 7636, method `S256`).
///
/// The verifier stays server-side; only the challenge travels in the
/// authorization URL. `plain` is not implemented on purpose.
#[derive(Clone, PartialEq, Eq)]
pub struct Pkce {
    challenge: String,
    verifier: Zeroizing<String>,
}

impl std::fmt::Debug for Pkce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The verifier is a secret for the lifetime of the attempt.
        f.debug_struct("Pkce")
            .field("challenge", &self.challenge)
            .field("verifier", &"[redacted]")
            .finish()
    }
}

impl Pkce {
    /// A fresh verifier (43 unreserved characters from the OS RNG).
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::rng().fill(&mut bytes);
        let mut proof = Self {
            challenge: String::new(),
            verifier: Zeroizing::new(b64url(&bytes)),
        };
        proof.challenge = proof.derive_challenge();
        proof
    }

    /// Wrap a verifier the caller already holds.
    ///
    /// # Errors
    ///
    /// [`KirinoError::Validation`] unless the verifier is 43–128 unreserved
    /// characters (RFC 7636 §4.1).
    pub fn from_verifier(verifier: impl Into<String>) -> Result<Self> {
        let verifier = verifier.into();
        if !(43..=128).contains(&verifier.len()) || !is_unreserved(&verifier) {
            return Err(KirinoError::Validation(
                "PKCE verifier must be 43..=128 unreserved characters".to_owned(),
            )
            .into());
        }
        let mut proof = Self {
            challenge: String::new(),
            verifier: Zeroizing::new(verifier),
        };
        proof.challenge = proof.derive_challenge();
        Ok(proof)
    }

    fn derive_challenge(&self) -> String {
        b64url(sha2::Sha256::digest(self.verifier.as_bytes()).as_slice())
    }

    /// `BASE64URL(SHA256(verifier))`, sent as `code_challenge`.
    #[must_use]
    pub fn challenge(&self) -> &str {
        &self.challenge
    }

    /// The verifier, sent only to the token endpoint.
    #[must_use]
    pub fn verifier(&self) -> &str {
        &self.verifier
    }

    /// Whether `verifier` is the one this challenge was derived from,
    /// compared in constant time.
    #[must_use]
    pub fn matches(&self, verifier: &str) -> bool {
        let candidate = b64url(sha2::Sha256::digest(verifier.as_bytes()).as_slice());
        candidate.as_bytes().ct_eq(self.challenge.as_bytes()).into()
    }
}

/// One in-flight authorization request, parked between the redirect and the
/// callback.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoginAttempt {
    /// Opaque, single-use, 32 unreserved characters; the only value that
    /// travels through the browser.
    pub state: String,
    /// The host's provider id this attempt was started for.
    pub provider: String,
    /// The PKCE proof the token exchange will spend.
    pub pkce: Pkce,
    /// Where the browser asked to land, validated by the host beforehand.
    pub return_to: Option<String>,
    /// OIDC `nonce` bound into the ID token when the host asked for one.
    pub nonce: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl LoginAttempt {
    /// `true` once `now` is at or past `expires_at`.
    #[must_use]
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        now >= self.expires_at
    }
}

fn random_token(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::rng().fill(&mut buf);
    b64url(&buf)
}

/// Server-side storage of in-flight login attempts.
///
/// `take` must be **one-time and atomic**: a second caller presenting the
/// same `state` gets `None`. That single rule is what makes a replayed
/// callback harmless.
#[async_trait]
pub trait LoginAttemptStore: Send + Sync {
    /// Park an attempt.
    ///
    /// # Errors
    ///
    /// Whatever the backing store reports.
    async fn put(&self, attempt: LoginAttempt) -> Result<()>;
    /// Hand an attempt out exactly once; `None` for an unknown or expired
    /// `state`.
    ///
    /// # Errors
    ///
    /// Whatever the backing store reports.
    async fn take(&self, state: &str) -> Result<Option<LoginAttempt>>;
}

/// In-memory [`LoginAttemptStore`]: the reference implementation and the
/// test double.
#[derive(Debug, Clone, Default)]
pub struct InMemoryLoginAttemptStore {
    attempts: Arc<RwLock<HashMap<String, LoginAttempt>>>,
}

impl InMemoryLoginAttemptStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl LoginAttemptStore for InMemoryLoginAttemptStore {
    async fn put(&self, attempt: LoginAttempt) -> Result<()> {
        self.attempts
            .write()
            .await
            .insert(attempt.state.clone(), attempt);
        Ok(())
    }

    async fn take(&self, state: &str) -> Result<Option<LoginAttempt>> {
        let mut attempts = self.attempts.write().await;
        // One write lock spans lookup, expiry check and removal.
        let taken = attempts.remove(state);
        match taken {
            Some(attempt) if !attempt.is_expired(Utc::now()) => Ok(Some(attempt)),
            _ => {
                // Expired attempts are dropped, never returned; a lazy sweep
                // keeps the map from holding them.
                attempts.retain(|_, kept| !kept.is_expired(Utc::now()));
                Ok(None)
            }
        }
    }
}

/// How the token endpoint wants its request body encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TokenBody {
    /// `application/x-www-form-urlencoded` (RFC 6749 §4.1.3) — the default.
    #[default]
    Form,
    /// JSON — an explicit override for legacy providers that never
    /// implemented the form encoding.
    Json,
}

/// Where a provider's endpoints are and how it speaks.
#[derive(Debug, Clone)]
pub struct ProviderMetadata {
    /// The provider's issuer, when it is URL-addressed; recorded on the
    /// identity when the provider's answer carries no `iss`.
    pub issuer: Option<String>,
    /// Authorization endpoint the browser is sent to.
    pub authorize_url: Url,
    /// Token endpoint the server calls.
    pub token_url: Url,
    /// UserInfo endpoint; `None` when identity comes from the ID token.
    pub userinfo_url: Option<Url>,
    /// Token-endpoint body encoding.
    pub token_body: TokenBody,
    /// Scopes requested, space-joined.
    pub scopes: Vec<String>,
}

/// How the client authenticates at the token endpoint.
#[derive(Debug, Clone)]
pub enum ClientAuth {
    /// A registered client with no secret (an installed or web client).
    /// PKCE is the only proof it can give.
    Public { client_id: String },
    /// A client secret held server-side, zeroized on drop.
    Confidential {
        client_id: String,
        client_secret: Zeroizing<String>,
    },
}

impl ClientAuth {
    /// The `client_id` sent in every request.
    #[must_use]
    pub fn client_id(&self) -> &str {
        match self {
            Self::Public { client_id } | Self::Confidential { client_id, .. } => client_id,
        }
    }

    /// The secret, for the token endpoint only; `None` for a public client.
    #[must_use]
    pub fn client_secret(&self) -> Option<&str> {
        match self {
            Self::Public { .. } => None,
            Self::Confidential { client_secret, .. } => Some(client_secret),
        }
    }
}

/// Build the authorization request: everything the browser carries, and
/// never the secret.
///
/// # Panics
///
/// Never in practice: the provider's URL is parsed when the metadata is
/// built, and `append_pair` does not fail on a valid `Url`.
#[must_use]
pub fn authorize_url(
    meta: &ProviderMetadata,
    client: &ClientAuth,
    redirect_uri: &Url,
    attempt: &LoginAttempt,
) -> Url {
    let mut url = meta.authorize_url.clone();
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("response_type", "code");
        query.append_pair("client_id", client.client_id());
        query.append_pair("redirect_uri", redirect_uri.as_str());
        if !meta.scopes.is_empty() {
            query.append_pair("scope", &meta.scopes.join(" "));
        }
        query.append_pair("state", &attempt.state);
        query.append_pair("code_challenge", attempt.pkce.challenge());
        query.append_pair("code_challenge_method", "S256");
        if let Some(nonce) = &attempt.nonce {
            query.append_pair("nonce", nonce);
        }
    }
    url
}

/// What the provider sent back on the redirect.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

/// Why a callback could not be turned into a login.
#[derive(Debug, thiserror::Error)]
pub enum CallbackProblem {
    /// The provider answered with an OAuth error instead of a code.
    #[error("provider refused the sign-in: {error}")]
    ProviderDenied {
        error: String,
        description: Option<String>,
    },
    /// The redirect carried no `state`.
    #[error("callback carries no state")]
    MissingState,
    /// The redirect carried neither a code nor an error.
    #[error("callback carries no code")]
    MissingCode,
    /// The state is unknown: never issued, already spent, or expired.
    #[error("unknown or already used state")]
    UnknownState,
    /// The token endpoint answered without an access token.
    #[error("token endpoint returned no access token")]
    TokenInvalid(String),
    /// The identity answer carried no usable subject.
    #[error("provider returned an empty identity")]
    IdentityEmpty,
    /// The ID token failed verification.
    #[error("ID token rejected: {0}")]
    IdTokenInvalid(String),
    /// The transport failed.
    #[error("identity provider unreachable: {0}")]
    Transport(String),
}

/// The token endpoint's answer.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    #[serde(default)]
    pub token_type: Option<String>,
    #[serde(default)]
    pub expires_in: Option<u64>,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub id_token: Option<String>,
}

/// The one network seam: kirino opens no sockets, the host implements this.
#[async_trait]
pub trait HttpFetcher: Send + Sync {
    /// `POST application/x-www-form-urlencoded`.
    ///
    /// # Errors
    ///
    /// Transport failures; a non-2xx answer is an error too.
    async fn post_form(&self, url: &Url, params: &[(&str, &str)]) -> Result<serde_json::Value>;
    /// `POST application/json`.
    ///
    /// # Errors
    ///
    /// Transport failures; a non-2xx answer is an error too.
    async fn post_json(&self, url: &Url, body: &serde_json::Value) -> Result<serde_json::Value>;
    /// `GET` with `Authorization: Bearer`.
    ///
    /// # Errors
    ///
    /// Transport failures; a non-2xx answer is an error too.
    async fn get_bearer(&self, url: &Url, access_token: &str) -> Result<serde_json::Value>;
}

/// Who the provider says the visitor is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderIdentity {
    /// The provider's stable subject (`sub`); the join key.
    pub subject: String,
    pub username: Option<String>,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub display_name: Option<String>,
    pub issuer: Option<String>,
    /// The raw claims, for host-specific needs.
    pub claims: serde_json::Value,
}

/// The provider's stable subject, trying the spellings the family meets:
/// `sub`, `id`, `open_id`, `openid_id`. Blank values do not count.
#[must_use]
pub fn subject_from_userinfo(claims: &serde_json::Value) -> Option<String> {
    ["sub", "id", "open_id", "openid_id"]
        .iter()
        .filter_map(|key| claims.get(key).and_then(serde_json::Value::as_str))
        .map(str::trim)
        .find(|subject| !subject.is_empty())
        .map(str::to_owned)
}

fn claim_str(claims: &serde_json::Value, key: &str) -> Option<String> {
    claims
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn identity_from_claims(
    claims: &serde_json::Value,
    fallback_issuer: Option<&str>,
) -> Result<ProviderIdentity, CallbackProblem> {
    let subject = subject_from_userinfo(claims).ok_or(CallbackProblem::IdentityEmpty)?;
    let issuer = claim_str(claims, "iss").or_else(|| fallback_issuer.map(str::to_owned));
    let display_name = claim_str(claims, "name")
        .or_else(|| claim_str(claims, "display_name"))
        .or_else(|| claim_str(claims, "nickname"));
    Ok(ProviderIdentity {
        subject,
        username: claim_str(claims, "preferred_username").or_else(|| claim_str(claims, "username")),
        email: claim_str(claims, "email"),
        email_verified: claims
            .get("email_verified")
            .and_then(serde_json::Value::as_bool),
        display_name,
        issuer,
        claims: claims.clone(),
    })
}

/// Verifies ID tokens against keys the caller supplies.
///
/// There is no JWKS fetch here (no sockets); a host that wants key rotation
/// resolves the keys itself and hands them in. `alg: none` and every
/// algorithm outside the allow-list are refused by construction.
#[derive(Clone)]
pub struct IdTokenVerifier {
    decoding_keys: Vec<jsonwebtoken::DecodingKey>,
    algorithms: Vec<jsonwebtoken::Algorithm>,
    issuer: Option<String>,
    audience: Option<String>,
}

impl std::fmt::Debug for IdTokenVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdTokenVerifier")
            .field("keys", &self.decoding_keys.len())
            .field("algorithms", &self.algorithms)
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .finish()
    }
}

impl IdTokenVerifier {
    /// Accept tokens signed by any of `keys` with RS256, ES256 or EdDSA.
    #[must_use]
    pub fn new(
        keys: Vec<jsonwebtoken::DecodingKey>,
        issuer: Option<String>,
        audience: Option<String>,
    ) -> Self {
        Self {
            decoding_keys: keys,
            algorithms: vec![
                jsonwebtoken::Algorithm::RS256,
                jsonwebtoken::Algorithm::ES256,
                jsonwebtoken::Algorithm::EdDSA,
            ],
            issuer,
            audience,
        }
    }

    /// Verify signature, expiry (60 s leeway), issuer, audience and nonce,
    /// returning the claims.
    ///
    /// # Errors
    ///
    /// [`CallbackProblem::IdTokenInvalid`] naming the failed check.
    pub fn verify(
        &self,
        id_token: &str,
        nonce: Option<&str>,
    ) -> Result<serde_json::Value, CallbackProblem> {
        let refuse = |why: &str| CallbackProblem::IdTokenInvalid(why.to_owned());
        let header =
            jsonwebtoken::decode_header(id_token).map_err(|_| refuse("unreadable header"))?;
        // The declared algorithm must be one we are willing to verify; a
        // token that names anything else (including `none`) is refused before
        // any key is tried.
        if !self.algorithms.contains(&header.alg) {
            return Err(refuse("algorithm not allowed"));
        }
        let mut last = "no key".to_owned();
        for key in &self.decoding_keys {
            for algorithm in &self.algorithms {
                let mut validation = jsonwebtoken::Validation::new(*algorithm);
                validation.validate_exp = true;
                validation.leeway = 60;
                if let Some(issuer) = &self.issuer {
                    validation.set_issuer(&[issuer]);
                } else {
                    validation.validate_aud = false;
                }
                if let Some(audience) = &self.audience {
                    validation.set_audience(&[audience]);
                } else {
                    validation.validate_aud = false;
                }
                match jsonwebtoken::decode::<serde_json::Value>(id_token, key, &validation) {
                    Ok(data) => {
                        if let (Some(expected), Some(claimed)) = (
                            nonce,
                            data.claims.get("nonce").and_then(serde_json::Value::as_str),
                        ) {
                            if expected != claimed {
                                return Err(refuse("nonce mismatch"));
                            }
                        }
                        return Ok(data.claims);
                    }
                    Err(error) => last = error.to_string(),
                }
            }
        }
        Err(refuse(&last))
    }
}

/// The result of a completed external sign-in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayLogin {
    /// The external identity, keyed by provider / issuer / subject.
    pub identity: ExternalIdentity,
    /// What the provider said about the visitor.
    pub profile: ProviderIdentity,
    /// Where the browser asked to land.
    pub return_to: Option<String>,
}

/// Start an authorization request: mint `state` + PKCE and park the attempt.
///
/// # Errors
///
/// Whatever the store reports.
pub async fn begin(
    store: &dyn LoginAttemptStore,
    provider: impl Into<String>,
    return_to: Option<String>,
    ttl: Duration,
) -> Result<LoginAttempt> {
    let now = Utc::now();
    let attempt = LoginAttempt {
        state: random_token(24),
        provider: provider.into(),
        pkce: Pkce::generate(),
        return_to,
        nonce: Some(random_token(16)),
        created_at: now,
        expires_at: now + ttl,
    };
    store.put(attempt.clone()).await?;
    Ok(attempt)
}

/// Turn the callback into a login: spend the `state`, exchange the code with
/// the PKCE verifier, and read the identity.
///
/// Identity comes from the UserInfo endpoint when the metadata has one,
/// else from a verified ID token (needs `id_token_keys`); with neither there
/// is no identity to be had and the callback is refused.
///
/// # Errors
///
/// [`CallbackProblem`] for every refusal; nothing here carries a secret.
pub async fn finish(
    http: &dyn HttpFetcher,
    store: &dyn LoginAttemptStore,
    meta: &ProviderMetadata,
    client: &ClientAuth,
    redirect_uri: &Url,
    query: &CallbackQuery,
    id_token_keys: &[jsonwebtoken::DecodingKey],
) -> Result<RelayLogin, CallbackProblem> {
    if let Some(error) = &query.error {
        return Err(CallbackProblem::ProviderDenied {
            error: error.clone(),
            description: query.error_description.clone(),
        });
    }
    let state = query
        .state
        .as_deref()
        .ok_or(CallbackProblem::MissingState)?;
    let code = query.code.as_deref().ok_or(CallbackProblem::MissingCode)?;
    let attempt = store
        .take(state)
        .await
        .map_err(|error| CallbackProblem::Transport(error.to_string()))?
        .ok_or(CallbackProblem::UnknownState)?;

    // The token request: the code, the redirect it was issued for, and the
    // PKCE verifier the authorization request promised. A public client has
    // no secret to add; a confidential one adds it here and only here.
    let mut fields: Vec<(String, String)> = vec![
        ("grant_type".to_owned(), "authorization_code".to_owned()),
        ("code".to_owned(), code.to_owned()),
        ("redirect_uri".to_owned(), redirect_uri.to_string()),
        ("client_id".to_owned(), client.client_id().to_owned()),
        (
            "code_verifier".to_owned(),
            attempt.pkce.verifier().to_owned(),
        ),
    ];
    if let Some(secret) = client.client_secret() {
        fields.push(("client_secret".to_owned(), secret.to_owned()));
    }
    let token_answer = match meta.token_body {
        TokenBody::Form => {
            let params: Vec<(&str, &str)> = fields
                .iter()
                .map(|(key, value)| (key.as_str(), value.as_str()))
                .collect();
            http.post_form(&meta.token_url, &params)
                .await
                .map_err(|error| CallbackProblem::Transport(error.to_string()))?
        }
        TokenBody::Json => {
            let body = serde_json::Map::from_iter(
                fields
                    .into_iter()
                    .map(|(key, value)| (key, serde_json::Value::String(value))),
            );
            http.post_json(&meta.token_url, &serde_json::Value::Object(body))
                .await
                .map_err(|error| CallbackProblem::Transport(error.to_string()))?
        }
    };
    let token: TokenResponse = serde_json::from_value(token_answer)
        .map_err(|error| CallbackProblem::TokenInvalid(error.to_string()))?;
    if token.access_token.trim().is_empty() {
        return Err(CallbackProblem::TokenInvalid(
            "empty access token".to_owned(),
        ));
    }

    // Identity: UserInfo when the provider has one, else a verified ID
    // token. With neither there is nothing to key an account on.
    let claims = if let Some(userinfo_url) = &meta.userinfo_url {
        http.get_bearer(userinfo_url, &token.access_token)
            .await
            .map_err(|error| CallbackProblem::Transport(error.to_string()))?
    } else {
        let Some(id_token) = token.id_token.as_deref() else {
            return Err(CallbackProblem::TokenInvalid(
                "no identity source: no userinfo endpoint and no ID token".to_owned(),
            ));
        };
        if id_token_keys.is_empty() {
            return Err(CallbackProblem::TokenInvalid(
                "no identity source: ID token present but no verification keys".to_owned(),
            ));
        }
        let audience = (!client.client_id().is_empty()).then(|| client.client_id().to_owned());
        IdTokenVerifier::new(id_token_keys.to_vec(), meta.issuer.clone(), audience)
            .verify(id_token, attempt.nonce.as_deref())?
    };
    let profile = identity_from_claims(&claims, meta.issuer.as_deref())?;
    let identity = ExternalIdentity {
        provider: attempt.provider.clone(),
        issuer: profile.issuer.clone(),
        subject: profile.subject.clone(),
    }
    .normalised();
    identity
        .validate()
        .map_err(|_| CallbackProblem::IdentityEmpty)?;
    Ok(RelayLogin {
        identity,
        profile,
        return_to: attempt.return_to,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    fn meta() -> ProviderMetadata {
        ProviderMetadata {
            issuer: Some("https://idp.example".to_owned()),
            authorize_url: Url::parse("https://idp.example/oauth/authorize").expect("url"),
            token_url: Url::parse("https://idp.example/oauth/token").expect("url"),
            userinfo_url: Some(Url::parse("https://idp.example/oauth/userinfo").expect("url")),
            token_body: TokenBody::Form,
            scopes: vec!["openid".to_owned(), "profile".to_owned()],
        }
    }

    fn redirect() -> Url {
        Url::parse("https://app.example/api/auth/relay/callback").expect("url")
    }

    /// One recorded `POST form` call: the URL and its parameters.
    type FormCall = (String, Vec<(String, String)>);

    #[derive(Default)]
    struct Scripted {
        form_calls: Mutex<Vec<FormCall>>,
        json_calls: Mutex<Vec<(String, serde_json::Value)>>,
        bearer_calls: Mutex<Vec<(String, String)>>,
    }

    impl Scripted {
        fn new() -> Self {
            Self {
                form_calls: Mutex::new(Vec::new()),
                json_calls: Mutex::new(Vec::new()),
                bearer_calls: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl HttpFetcher for Scripted {
        async fn post_form(&self, url: &Url, params: &[(&str, &str)]) -> Result<serde_json::Value> {
            self.form_calls.lock().expect("lock").push((
                url.to_string(),
                params
                    .iter()
                    .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                    .collect(),
            ));
            Ok(serde_json::json!({ "access_token": "at-1", "token_type": "Bearer" }))
        }

        async fn post_json(
            &self,
            url: &Url,
            body: &serde_json::Value,
        ) -> Result<serde_json::Value> {
            self.json_calls
                .lock()
                .expect("lock")
                .push((url.to_string(), body.clone()));
            Ok(serde_json::json!({ "access_token": "at-1", "token_type": "Bearer" }))
        }

        async fn get_bearer(&self, url: &Url, access_token: &str) -> Result<serde_json::Value> {
            self.bearer_calls
                .lock()
                .expect("lock")
                .push((url.to_string(), access_token.to_owned()));
            Ok(serde_json::json!({
                "sub": "sub-1", "name": "Ada", "email": "ada@example",
                "email_verified": true, "iss": "https://idp.example"
            }))
        }
    }

    #[test]
    fn pkce_matches_the_rfc_vector_and_refuses_bad_verifiers() {
        // RFC 7636 Appendix B.
        let proof = Pkce::from_verifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
            .expect("valid verifier");
        assert_eq!(
            proof.challenge(),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        assert!(proof.matches("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"));
        // MUT:pkce-verifier-bound — a different verifier must not match the challenge.
        assert!(!proof.matches("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXl"));
        for bad in [
            "",
            "too-short",
            "has*star*in*it*and*is*long*enough*for*the*length*rule",
            &"a".repeat(129),
        ] {
            assert!(Pkce::from_verifier(bad).is_err(), "{bad:?} must be refused");
        }
        let generated = Pkce::generate();
        assert_eq!(generated.verifier().len(), 43);
        assert!(generated.matches(generated.verifier()));
        assert!(
            !format!("{generated:?}").contains(generated.verifier()),
            "Debug hides the verifier"
        );
    }

    #[test]
    fn authorize_url_carries_the_request_and_never_the_secret() {
        let attempt = LoginAttempt {
            state: "st".to_owned(),
            provider: "example-idp".to_owned(),
            pkce: Pkce::generate(),
            return_to: Some("/inbox".to_owned()),
            nonce: Some("n-1".to_owned()),
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::minutes(5),
        };
        let client = ClientAuth::Confidential {
            client_id: "cid".to_owned(),
            client_secret: Zeroizing::new("s3cr3t-value".to_owned()),
        };
        let url = authorize_url(&meta(), &client, &redirect(), &attempt).to_string();
        // MUT:authorize-no-secret — the secret must never reach the browser.
        assert!(
            !url.contains("s3cr3t"),
            "secret leaked into the authorize URL: {url}"
        );
        for pair in [
            "response_type=code",
            "client_id=cid",
            "redirect_uri=https%3A%2F%2Fapp.example%2Fapi%2Fauth%2Frelay%2Fcallback",
            "scope=openid+profile",
            "state=st",
            &format!("code_challenge={}", attempt.pkce.challenge()),
            "code_challenge_method=S256",
            "nonce=n-1",
        ] {
            assert!(url.contains(pair), "authorize URL lacks {pair}: {url}");
        }
    }

    #[tokio::test]
    async fn state_is_one_time_and_expired_attempts_are_never_returned() {
        let store = InMemoryLoginAttemptStore::new();
        let attempt = begin(
            &store,
            "example-idp",
            Some("/inbox".to_owned()),
            Duration::minutes(5),
        )
        .await
        .expect("begin");
        assert_eq!(attempt.state.len(), 32);
        assert!(is_unreserved(&attempt.state));
        assert_eq!(attempt.pkce.verifier().len(), 43);
        assert!(attempt.nonce.is_some());

        let taken = store
            .take(&attempt.state)
            .await
            .expect("take")
            .expect("first take returns it");
        assert_eq!(taken.return_to.as_deref(), Some("/inbox"));
        // MUT:state-one-time — a replayed state must find nothing.
        assert_eq!(
            store.take(&attempt.state).await.expect("take"),
            None,
            "state is single-use"
        );

        let mut stale = begin(&store, "example-idp", None, Duration::minutes(5))
            .await
            .expect("begin");
        stale.expires_at = Utc::now() - Duration::seconds(1);
        store.put(stale.clone()).await.expect("put");
        assert_eq!(
            store.take(&stale.state).await.expect("take"),
            None,
            "expired is not returned"
        );
    }

    fn query(state: &str) -> CallbackQuery {
        CallbackQuery {
            code: Some("code-1".to_owned()),
            state: Some(state.to_owned()),
            error: None,
            error_description: None,
        }
    }

    #[tokio::test]
    async fn finish_spends_the_verifier_and_reads_the_identity() {
        let store = InMemoryLoginAttemptStore::new();
        let http = Scripted::new();
        let client = ClientAuth::Public {
            client_id: "cid".to_owned(),
        };
        let attempt = begin(
            &store,
            "example-idp",
            Some("/inbox".to_owned()),
            Duration::minutes(5),
        )
        .await
        .expect("begin");

        let login = finish(
            &http,
            &store,
            &meta(),
            &client,
            &redirect(),
            &query(&attempt.state),
            &[],
        )
        .await
        .expect("finish");
        assert_eq!(
            login.identity,
            ExternalIdentity {
                provider: "example-idp".to_owned(),
                issuer: Some("https://idp.example".to_owned()),
                subject: "sub-1".to_owned(),
            }
        );
        assert_eq!(login.profile.display_name.as_deref(), Some("Ada"));
        assert_eq!(login.return_to.as_deref(), Some("/inbox"));

        let calls = http.form_calls.lock().expect("lock");
        assert_eq!(calls.len(), 1, "one token call");
        let params: std::collections::HashMap<&str, &str> = calls[0]
            .1
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        assert_eq!(params.get("grant_type"), Some(&"authorization_code"));
        assert_eq!(params.get("code"), Some(&"code-1"));
        // MUT:verifier-sent — the token request must carry the attempt's own verifier.
        assert_eq!(params.get("code_verifier"), Some(&attempt.pkce.verifier()));
        assert_eq!(params.get("client_id"), Some(&"cid"));
        // MUT:public-no-secret — a public client never sends a secret.
        assert!(!params.contains_key("client_secret"));
        let bearer = http.bearer_calls.lock().expect("lock");
        assert_eq!(bearer[0].1, "at-1");
    }

    #[tokio::test]
    async fn a_confidential_client_sends_its_secret_only_to_the_token_endpoint() {
        let store = InMemoryLoginAttemptStore::new();
        let http = Scripted::new();
        let client = ClientAuth::Confidential {
            client_id: "cid".to_owned(),
            client_secret: Zeroizing::new("s3cr3t-value".to_owned()),
        };
        let attempt = begin(&store, "example-idp", None, Duration::minutes(5))
            .await
            .expect("begin");
        let mut json_meta = meta();
        json_meta.token_body = TokenBody::Json;
        finish(
            &http,
            &store,
            &json_meta,
            &client,
            &redirect(),
            &query(&attempt.state),
            &[],
        )
        .await
        .expect("finish");
        let calls = http.json_calls.lock().expect("lock");
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].1["client_secret"], "s3cr3t-value");
        assert_eq!(calls[0].1["client_id"], "cid");
        assert_eq!(calls[0].1["code_verifier"], attempt.pkce.verifier());
        assert!(http.form_calls.lock().expect("lock").is_empty());
    }

    #[tokio::test]
    async fn refusals_name_the_problem_and_spend_nothing_on_replays() {
        let store = InMemoryLoginAttemptStore::new();
        let http = Scripted::new();
        let client = ClientAuth::Public {
            client_id: "cid".to_owned(),
        };
        let attempt = begin(&store, "example-idp", None, Duration::minutes(5))
            .await
            .expect("begin");

        let denied = CallbackQuery {
            error: Some("access_denied".to_owned()),
            error_description: Some("the user said no".to_owned()),
            ..Default::default()
        };
        assert!(matches!(
            finish(&http, &store, &meta(), &client, &redirect(), &denied, &[]).await,
            Err(CallbackProblem::ProviderDenied { .. })
        ));
        let no_state = CallbackQuery {
            state: None,
            ..query(&attempt.state)
        };
        assert_eq!(
            finish(&http, &store, &meta(), &client, &redirect(), &no_state, &[])
                .await
                .unwrap_err()
                .to_string(),
            "callback carries no state"
        );
        let no_code = CallbackQuery {
            code: None,
            ..query(&attempt.state)
        };
        assert_eq!(
            finish(&http, &store, &meta(), &client, &redirect(), &no_code, &[])
                .await
                .unwrap_err()
                .to_string(),
            "callback carries no code"
        );
        assert!(
            http.form_calls.lock().expect("lock").is_empty(),
            "no exchange before the state is spent"
        );

        finish(
            &http,
            &store,
            &meta(),
            &client,
            &redirect(),
            &query(&attempt.state),
            &[],
        )
        .await
        .expect("first use");
        // MUT:replay-refused — the same callback again must not produce a login.
        assert_eq!(
            finish(
                &http,
                &store,
                &meta(),
                &client,
                &redirect(),
                &query(&attempt.state),
                &[]
            )
            .await
            .unwrap_err()
            .to_string(),
            "unknown or already used state"
        );
        assert_eq!(
            http.form_calls.lock().expect("lock").len(),
            1,
            "the replay never reached the token endpoint"
        );
    }

    #[test]
    fn subject_takes_the_first_non_blank_spelling() {
        // MUT:subject-order — `sub` wins over `id`; a blank `sub` is skipped.
        assert_eq!(
            subject_from_userinfo(&serde_json::json!({"sub": "a", "id": "b"})).as_deref(),
            Some("a")
        );
        assert_eq!(
            subject_from_userinfo(&serde_json::json!({"sub": " ", "id": "b"})).as_deref(),
            Some("b")
        );
        assert_eq!(
            subject_from_userinfo(&serde_json::json!({"open_id": "c"})).as_deref(),
            Some("c")
        );
        assert_eq!(
            subject_from_userinfo(&serde_json::json!({"email": "x@y"})),
            None
        );
    }

    /// Sign `claims` with the Ed25519 seed `key` (the JWT is assembled by
    /// hand so the test depends on no signer feature); the matching public
    /// key — what a verifier needs — comes from `public_of`.
    fn mint(key: &[u8; 32], claims: serde_json::Value) -> String {
        use ed25519_dalek::Signer as _;
        let signing = ed25519_dalek::SigningKey::from_bytes(key);
        let message = format!(
            "{}.{}",
            b64url(br#"{"alg":"EdDSA","typ":"JWT"}"#),
            b64url(claims.to_string().as_bytes())
        );
        let signature = signing.sign(message.as_bytes());
        format!("{message}.{}", b64url(&signature.to_bytes()))
    }

    fn public_of(seed: &[u8; 32]) -> jsonwebtoken::DecodingKey {
        let signing = ed25519_dalek::SigningKey::from_bytes(seed);
        jsonwebtoken::DecodingKey::from_ed_der(signing.verifying_key().as_bytes())
    }

    fn id_claims(exp: i64, aud: &str, nonce: &str) -> serde_json::Value {
        serde_json::json!({
            "iss": "https://idp.example", "aud": aud, "sub": "sub-9", "exp": exp,
            "iat": exp - 60, "nonce": nonce
        })
    }

    #[test]
    fn id_tokens_are_verified_on_every_axis() {
        let key = [7u8; 32];
        let verifier = IdTokenVerifier::new(
            vec![public_of(&key)],
            Some("https://idp.example".to_owned()),
            Some("cid".to_owned()),
        );
        let exp = (Utc::now() + Duration::hours(1)).timestamp();
        let good = mint(&key, id_claims(exp, "cid", "n-1"));
        let claims = verifier.verify(&good, Some("n-1")).expect("valid token");
        assert_eq!(claims["sub"], "sub-9");

        // MUT:id-token-axes — each axis refuses on its own.
        assert!(
            verifier
                .verify(&mint(&key, id_claims(exp, "cid", "n-1")), Some("other"))
                .is_err(),
            "nonce"
        );
        assert!(
            verifier
                .verify(&mint(&key, id_claims(exp, "other", "n-1")), Some("n-1"))
                .is_err(),
            "audience"
        );
        assert!(
            verifier
                .verify(
                    &mint(
                        &key,
                        id_claims((Utc::now() - Duration::hours(2)).timestamp(), "cid", "n-1")
                    ),
                    Some("n-1")
                )
                .is_err(),
            "expired"
        );
        let other_key = [9u8; 32];
        assert!(
            verifier
                .verify(&mint(&other_key, id_claims(exp, "cid", "n-1")), Some("n-1"))
                .is_err(),
            "wrong key"
        );
        let mut wrong_iss = id_claims(exp, "cid", "n-1");
        wrong_iss["iss"] = serde_json::json!("https://evil.example");
        assert!(
            verifier
                .verify(&mint(&key, wrong_iss), Some("n-1"))
                .is_err(),
            "issuer"
        );

        // `alg: none` (an unsigned token) is refused outright …
        let unsigned = format!(
            "{}.{}.",
            b64url(br#"{"alg":"none","typ":"JWT"}"#),
            b64url(id_claims(exp, "cid", "n-1").to_string().as_bytes())
        );
        assert!(verifier.verify(&unsigned, Some("n-1")).is_err(), "alg none");
        // … and so is any algorithm outside the allow-list, before a key is tried.
        // MUT:alg-allow-list — a symmetric-alg token must be refused by name even
        // though a key and a well-formed signature follow.
        let symmetric = format!(
            "{}.{}.{}",
            b64url(br#"{"alg":"HS256","typ":"JWT"}"#),
            b64url(id_claims(exp, "cid", "n-1").to_string().as_bytes()),
            b64url(&[0u8; 32])
        );
        assert_eq!(
            verifier
                .verify(&symmetric, Some("n-1"))
                .unwrap_err()
                .to_string(),
            "ID token rejected: algorithm not allowed"
        );
    }
}
