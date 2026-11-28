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
//! * **Login CSRF is the host's to close, with help from here.** A one-time
//!   `state` binds the callback to an *attempt*, not to a *browser*: an
//!   attacker who starts an attempt and lures the victim through it would
//!   log the victim into the attacker's account. The host must therefore
//!   bind the attempt to the browser — start with [`begin_with_binding`],
//!   store the binding in an httpOnly cookie, and present it to [`finish`];
//!   a mismatch is [`CallbackProblem::BindingMismatch`].
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

use anyhow::Result;
use base64::Engine as _;
use chrono::{DateTime, Duration, Utc};
use rand::RngExt as _;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;
use url::Url;

use async_trait::async_trait;
use sha2::Digest as _;
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use crate::{auth::identity::external::ExternalIdentity, error::KirinoError};

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
    /// A host-chosen value that must come back from the same browser at
    /// callback time (see the module docs on login CSRF); `None` = unbound.
    pub browser_binding: Option<String>,
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
    /// The host's provider id this metadata belongs to; an attempt started
    /// for another provider is refused (`CallbackProblem::ProviderMismatch`).
    pub provider: String,
    /// The provider's issuer, when it is URL-addressed; required when the
    /// identity comes from an ID token (it is the token's expected `iss`);
    /// recorded on the identity when the provider's answer carries no `iss`.
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
    /// Key under which a provider wraps its token answer in an envelope;
    /// `None` (the default) reads the token fields at the top level.
    ///
    /// An OAuth token answer is a flat object to RFC 6749, but some
    /// providers answer in their own transport envelope instead, carrying
    /// the token fields one level down next to a business result. Feishu's
    /// `…/authen/v2/oauth/token` is the reference case: it answers
    /// `{"code": 0, "msg": "ok", "data": {"access_token": …, "token_type":
    /// "Bearer", "expires_in": …, "refresh_token": …}}`, so its metadata
    /// sets `token_response_envelope: Some("data")`.
    ///
    /// The key is drilled into and the value inside is read as
    /// [`TokenResponse`]; nothing else changes. A missing key, or an envelope
    /// without `access_token` — which is how such a provider reports a
    /// business failure, e.g. a non-zero `code` with no `data` — is refused
    /// by the same missing-field path as a top-level answer without one.
    /// The envelope's own status fields are not interpreted: this module
    /// reads protocol shape only, never a vendor's business code.
    pub token_response_envelope: Option<&'static str>,
}

impl ProviderMetadata {
    /// A provider with the two endpoints every OAuth flow needs and RFC 6749's
    /// defaults everywhere else (form-encoded token body, identity from the
    /// UserInfo endpoint).
    ///
    /// This constructor — plus the `with_*` setters below — is the supported
    /// way to build a `ProviderMetadata` from outside this crate. A struct
    /// literal compiles only until the struct gains a field: `token_response_envelope`
    /// arrived in 0.9.9 and broke every external literal at once, because a
    /// new public field is a breaking change under the semver rules however
    /// minor the release. A constructor keeps its signature across additions
    /// (the new field gets its default here), so code that builds through it
    /// keeps compiling.
    #[must_use]
    pub fn new(provider: impl Into<String>, authorize_url: Url, token_url: Url) -> Self {
        Self {
            provider: provider.into(),
            issuer: None,
            authorize_url,
            token_url,
            userinfo_url: None,
            token_body: TokenBody::default(),
            scopes: Vec::new(),
            token_response_envelope: None,
        }
    }

    /// Records the provider's issuer (the ID token's expected `iss`).
    #[must_use]
    pub fn with_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    /// Sets the UserInfo endpoint the identity is read from.
    #[must_use]
    pub fn with_userinfo_url(mut self, userinfo_url: Url) -> Self {
        self.userinfo_url = Some(userinfo_url);
        self
    }

    /// Overrides the token-endpoint body encoding.
    #[must_use]
    pub fn with_token_body(mut self, token_body: TokenBody) -> Self {
        self.token_body = token_body;
        self
    }

    /// Sets the scopes requested, in the order they are joined.
    #[must_use]
    pub fn with_scopes(mut self, scopes: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.scopes = scopes.into_iter().map(Into::into).collect();
        self
    }

    /// Names the key a provider wraps its token answer in (Feishu's `data`,
    /// for one); `None` reads the token fields at the top level.
    #[must_use]
    pub fn with_token_response_envelope(mut self, key: &'static str) -> Self {
        self.token_response_envelope = Some(key);
        self
    }
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
    /// The browser that came back is not the one that started the attempt.
    #[error("the callback did not come from the browser that started the sign-in")]
    BindingMismatch,
    /// The attempt was started for a different provider than the one whose
    /// metadata was handed to `finish`.
    #[error("the attempt belongs to another provider")]
    ProviderMismatch,
    /// The token endpoint's answer was unusable; the string says why.
    #[error("token endpoint answer rejected: {0}")]
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
        .filter_map(|key| claims.get(key))
        .find_map(|value| match value {
            // Some providers number their subjects; the digits are the id.
            serde_json::Value::String(text) => {
                let text = text.trim();
                (!text.is_empty()).then(|| text.to_owned())
            }
            serde_json::Value::Number(number) => Some(number.to_string()),
            _ => None,
        })
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
    // A blank `iss` is no issuer at all: fall back to the metadata's.
    let issuer = claim_str(claims, "iss")
        .or_else(|| fallback_issuer.map(str::to_owned))
        .filter(|issuer| !issuer.trim().is_empty());
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
/// algorithm outside the allow-list are refused by construction. Issuer and
/// audience are **required**: an ID token is only meaningful for the party
/// it was issued to. A `nonce`, when one is expected, must be present in the
/// token as a string and equal — a token that omits it is refused.
#[derive(Clone)]
pub struct IdTokenVerifier {
    decoding_keys: Vec<jsonwebtoken::DecodingKey>,
    algorithms: Vec<jsonwebtoken::Algorithm>,
    issuer: String,
    audience: String,
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
    /// Accept tokens signed by any of `keys` with RS256, ES256 or EdDSA,
    /// issued by `issuer` for `audience`.
    #[must_use]
    pub fn new(
        keys: Vec<jsonwebtoken::DecodingKey>,
        issuer: impl Into<String>,
        audience: impl Into<String>,
    ) -> Self {
        Self {
            decoding_keys: keys,
            algorithms: vec![
                jsonwebtoken::Algorithm::RS256,
                jsonwebtoken::Algorithm::ES256,
                jsonwebtoken::Algorithm::EdDSA,
            ],
            issuer: issuer.into(),
            audience: audience.into(),
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
                validation.set_issuer(&[&self.issuer]);
                validation.set_audience(&[&self.audience]);
                match jsonwebtoken::decode::<serde_json::Value>(id_token, key, &validation) {
                    Ok(data) => {
                        // MUT:nonce-must-be-present — an expected nonce that the
                        // token omits (or carries as a non-string) is a refusal.
                        if let Some(expected) = nonce {
                            match data.claims.get("nonce").and_then(serde_json::Value::as_str) {
                                Some(claimed) if claimed == expected => {}
                                _ => return Err(refuse("nonce mismatch")),
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

/// What the callback handler presents: the provider's query, the browser
/// binding (when the host bound the attempt) and the ID-token keys.
#[derive(Debug, Clone, Copy)]
pub struct Callback<'a> {
    pub query: &'a CallbackQuery,
    pub browser_binding: Option<&'a str>,
    pub id_token_keys: &'a [jsonwebtoken::DecodingKey],
}

impl<'a> Callback<'a> {
    /// Bundle what [`finish`] needs from the callback request.
    #[must_use]
    pub fn new(
        query: &'a CallbackQuery,
        browser_binding: Option<&'a str>,
        id_token_keys: &'a [jsonwebtoken::DecodingKey],
    ) -> Self {
        Self {
            query,
            browser_binding,
            id_token_keys,
        }
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
/// Unbound — see the module docs for when a host must use
/// [`begin_with_binding`] instead.
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
    begin_with_binding(store, provider, return_to, None, ttl).await
}

/// [`begin`] with the attempt bound to the browser: `browser_binding` is a
/// value the host also stores in an httpOnly cookie and presents to
/// [`finish`] — the login-CSRF defence described in the module docs.
///
/// # Errors
///
/// Whatever the store reports.
pub async fn begin_with_binding(
    store: &dyn LoginAttemptStore,
    provider: impl Into<String>,
    return_to: Option<String>,
    browser_binding: Option<String>,
    ttl: Duration,
) -> Result<LoginAttempt> {
    let now = Utc::now();
    let attempt = LoginAttempt {
        state: random_token(24),
        provider: provider.into(),
        pkce: Pkce::generate(),
        return_to,
        nonce: Some(random_token(16)),
        browser_binding: browser_binding.filter(|binding| !binding.is_empty()),
        created_at: now,
        expires_at: now + ttl,
    };
    store.put(attempt.clone()).await?;
    Ok(attempt)
}

/// Read the token fields out of the token endpoint's answer, honouring
/// [`ProviderMetadata::token_response_envelope`].
///
/// A top-level answer parses as it is. An enveloped one is drilled into
/// `payload[key]` first; an absent key is a deserialization error like any
/// other missing field, so a provider that reports a business failure inside
/// its envelope (no `data` at all) is refused rather than read as a token.
fn token_answer_for(
    meta: &ProviderMetadata,
    answer: serde_json::Value,
) -> Result<TokenResponse, serde_json::Error> {
    let payload = match meta.token_response_envelope {
        None => answer,
        // MUT:token-envelope — an enveloped answer is read from inside the key, not the top level.
        Some(key) => match answer.get(key) {
            Some(payload) => payload.clone(),
            // An absent key is reported as the token field being absent:
            // serde's own wording for the only field a token must carry.
            None => {
                return Err(serde::de::Error::missing_field("access_token"));
            }
        },
    };
    serde_json::from_value(payload)
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
    callback: Callback<'_>,
) -> Result<RelayLogin, CallbackProblem> {
    let Callback {
        query,
        browser_binding,
        id_token_keys,
    } = callback;
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
    // The browser that comes back must be the one that started the attempt
    // (when the host bound it), and the metadata must belong to the provider
    // the attempt was started for — an attempt for one provider can never be
    // finished with another's endpoints.
    // MUT:browser-binding — a bound attempt presented from another browser is refused.
    if let Some(expected) = &attempt.browser_binding {
        if browser_binding != Some(expected.as_str()) {
            return Err(CallbackProblem::BindingMismatch);
        }
    }
    if attempt.provider != meta.provider {
        return Err(CallbackProblem::ProviderMismatch);
    }

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
    let token: TokenResponse = token_answer_for(meta, token_answer)
        .map_err(|error| CallbackProblem::TokenInvalid(format!("unreadable answer: {error}")))?;
    if token.access_token.trim().is_empty() {
        return Err(CallbackProblem::TokenInvalid("no access token".to_owned()));
    }
    // RFC 6749 §7.1: only bearer tokens are usable with `Authorization`.
    if let Some(token_type) = &token.token_type {
        if !token_type.eq_ignore_ascii_case("bearer") {
            return Err(CallbackProblem::TokenInvalid(format!(
                "unsupported token type {token_type:?}"
            )));
        }
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
        // An ID token is only meaningful for a known issuer and audience.
        let (Some(issuer), true) = (&meta.issuer, !client.client_id().is_empty()) else {
            return Err(CallbackProblem::TokenInvalid(
                "ID token needs the provider issuer and a client id to verify against".to_owned(),
            ));
        };
        IdTokenVerifier::new(id_token_keys.to_vec(), issuer.clone(), client.client_id())
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
        ProviderMetadata::new(
            "example-idp",
            Url::parse("https://idp.example/oauth/authorize").expect("url"),
            Url::parse("https://idp.example/oauth/token").expect("url"),
        )
        .with_issuer("https://idp.example")
        .with_userinfo_url(Url::parse("https://idp.example/oauth/userinfo").expect("url"))
        .with_scopes(["openid", "profile"])
    }

    /// The constructor seeds every optional field with its RFC 6749 default,
    /// and each setter changes exactly the field it names. This is the pin a
    /// future field addition has to extend: a new field that `new` leaves
    /// unset fails here first, before any consumer sees it.
    #[test]
    fn the_constructor_defaults_every_field_and_each_setter_moves_one() {
        let authorize = Url::parse("https://idp.example/a").expect("url");
        let token = Url::parse("https://idp.example/t").expect("url");
        let bare = ProviderMetadata::new("idp", authorize.clone(), token.clone());
        assert_eq!(bare.provider, "idp");
        assert_eq!(bare.issuer, None);
        assert_eq!(bare.authorize_url, authorize);
        assert_eq!(bare.token_url, token);
        assert_eq!(bare.userinfo_url, None);
        assert_eq!(bare.token_body, TokenBody::Form);
        assert!(bare.scopes.is_empty());
        assert_eq!(bare.token_response_envelope, None);

        let full = ProviderMetadata::new("idp", authorize.clone(), token.clone())
            .with_issuer("https://idp.example")
            .with_userinfo_url(Url::parse("https://idp.example/u").expect("url"))
            .with_token_body(TokenBody::Json)
            .with_scopes(["openid", "email"])
            .with_token_response_envelope("data");
        assert_eq!(full.issuer.as_deref(), Some("https://idp.example"));
        assert_eq!(
            full.userinfo_url.as_ref().map(Url::as_str),
            Some("https://idp.example/u")
        );
        assert_eq!(full.token_body, TokenBody::Json);
        assert_eq!(full.scopes, vec!["openid".to_owned(), "email".to_owned()]);
        assert_eq!(full.token_response_envelope, Some("data"));
        // The setters are builders: the required fields and the provider id
        // pass through untouched.
        assert_eq!(full.provider, "idp");
        assert_eq!(full.authorize_url, authorize);
        assert_eq!(full.token_url, token);
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

    #[tokio::test]
    async fn a_feishu_shaped_envelope_is_read_from_the_configured_key() {
        // The token endpoint of Feishu's `…/authen/v2/oauth/token`, as those
        // serving it answer on the wire: the token fields sit one level down
        // inside `data`, next to the business result. A provider of that
        // shape is metadata — `token_response_envelope: Some("data")`.
        const ANSWER: &str = r#"{
            "code": 0, "msg": "ok",
            "data": {
                "access_token": "at-env", "token_type": "Bearer",
                "expires_in": 7200, "refresh_token": "rt-env"
            }
        }"#;

        struct Enveloped {
            bearer_calls: Mutex<Vec<String>>,
        }
        #[async_trait]
        impl HttpFetcher for Enveloped {
            async fn post_form(&self, _: &Url, _: &[(&str, &str)]) -> Result<serde_json::Value> {
                Ok(serde_json::from_str(ANSWER).expect("fixture"))
            }
            async fn post_json(&self, _: &Url, _: &serde_json::Value) -> Result<serde_json::Value> {
                unreachable!()
            }
            async fn get_bearer(&self, _: &Url, access_token: &str) -> Result<serde_json::Value> {
                self.bearer_calls
                    .lock()
                    .expect("lock")
                    .push(access_token.to_owned());
                Ok(serde_json::json!({ "open_id": "ou-1", "name": "Ada" }))
            }
        }

        let http = Enveloped {
            bearer_calls: Mutex::new(Vec::new()),
        };
        let store = InMemoryLoginAttemptStore::new();
        let client = ClientAuth::Public {
            client_id: "cid".to_owned(),
        };
        let mut enveloped = meta();
        enveloped.token_response_envelope = Some("data");
        let attempt = begin(&store, "example-idp", None, Duration::minutes(5))
            .await
            .expect("begin");
        let login = finish(
            &http,
            &store,
            &enveloped,
            &client,
            &redirect(),
            Callback::new(&query(&attempt.state), None, &[]),
        )
        .await
        .expect("an enveloped answer is read from inside the key");
        assert_eq!(login.identity.subject, "ou-1");
        assert_eq!(login.profile.display_name.as_deref(), Some("Ada"));
        // The token came out of the envelope, not off the top level.
        assert_eq!(
            http.bearer_calls.lock().expect("lock").as_slice(),
            ["at-env"],
            "UserInfo is called with the enveloped access token"
        );

        // Every field of the answer survives the drill, not just the token.
        let token = token_answer_for(&enveloped, serde_json::from_str(ANSWER).expect("fixture"))
            .expect("envelope parses");
        assert_eq!(token.access_token, "at-env");
        assert_eq!(token.token_type.as_deref(), Some("Bearer"));
        assert_eq!(token.expires_in, Some(7200));
        assert_eq!(token.refresh_token.as_deref(), Some("rt-env"));
        assert_eq!(token.id_token, None);
    }

    #[tokio::test]
    async fn without_an_envelope_the_answer_is_read_at_the_top_level() {
        // The default is the RFC 6749 shape: no key configured, no drill.
        let http = Scripted::new();
        let store = InMemoryLoginAttemptStore::new();
        let client = ClientAuth::Public {
            client_id: "cid".to_owned(),
        };
        let plain = meta();
        assert_eq!(
            plain.token_response_envelope, None,
            "the default is a top-level answer"
        );
        let answer = serde_json::json!({
            "access_token": "at-top", "token_type": "Bearer",
            "expires_in": 3600, "refresh_token": "rt-top", "id_token": "idt-top"
        });
        let token = token_answer_for(&plain, answer.clone()).expect("top-level parses");
        assert_eq!(token.access_token, "at-top");
        assert_eq!(token.expires_in, Some(3600));
        assert_eq!(token.refresh_token.as_deref(), Some("rt-top"));
        assert_eq!(token.id_token.as_deref(), Some("idt-top"));

        // MUT:envelope-opt-in — with no envelope configured, a wrapped answer
        // is NOT unwrapped; the top level is what is read.
        let wrapped = serde_json::json!({ "data": { "access_token": "at-top" } });
        assert!(
            token_answer_for(&plain, wrapped).is_err(),
            "no envelope means no drill"
        );

        // … and a plain provider still signs in end to end.
        let attempt = begin(&store, "example-idp", None, Duration::minutes(5))
            .await
            .expect("begin");
        finish(
            &http,
            &store,
            &plain,
            &client,
            &redirect(),
            Callback::new(&query(&attempt.state), None, &[]),
        )
        .await
        .expect("finish");
        assert_eq!(
            http.bearer_calls.lock().expect("lock")[0].1,
            "at-1",
            "the top-level token is the one used"
        );
    }

    #[tokio::test]
    async fn an_envelope_without_the_key_or_without_a_token_is_refused() {
        let store = InMemoryLoginAttemptStore::new();
        let client = ClientAuth::Public {
            client_id: "cid".to_owned(),
        };
        let mut enveloped = meta();
        enveloped.token_response_envelope = Some("data");

        // The envelope key is absent altogether.
        let missing_key =
            token_answer_for(&enveloped, serde_json::json!({ "access_token": "at-1" }))
                .unwrap_err();
        assert!(
            missing_key
                .to_string()
                .contains("missing field `access_token`"),
            "absent envelope key keeps the missing-field error: {missing_key}"
        );

        // A business failure inside the envelope: a non-zero `code` and no
        // `data` at all. MUT:envelope-fail-closed — such an answer must not
        // yield a usable token.
        struct Refused {
            calls: Mutex<usize>,
        }
        #[async_trait]
        impl HttpFetcher for Refused {
            async fn post_form(&self, _: &Url, _: &[(&str, &str)]) -> Result<serde_json::Value> {
                *self.calls.lock().expect("lock") += 1;
                Ok(serde_json::json!({
                    "code": 20026, "msg": "invalid code",
                    "data": {},
                    "error": "invalid_grant"
                }))
            }
            async fn post_json(&self, _: &Url, _: &serde_json::Value) -> Result<serde_json::Value> {
                unreachable!()
            }
            async fn get_bearer(&self, _: &Url, _: &str) -> Result<serde_json::Value> {
                unreachable!("a refused token never reaches UserInfo")
            }
        }
        let http = Refused {
            calls: Mutex::new(0),
        };
        let attempt = begin(&store, "example-idp", None, Duration::minutes(5))
            .await
            .expect("begin");
        let err = finish(
            &http,
            &store,
            &enveloped,
            &client,
            &redirect(),
            Callback::new(&query(&attempt.state), None, &[]),
        )
        .await
        .unwrap_err();
        let message = err.to_string();
        assert!(
            message.starts_with("token endpoint answer rejected: unreadable answer:")
                && message.contains("missing field `access_token`"),
            "an envelope-level failure is refused as a missing field: {message}"
        );
        assert_eq!(*http.calls.lock().expect("lock"), 1, "one token call");
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
            browser_binding: None,
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
            Callback::new(&query(&attempt.state), None, &[]),
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
            Callback::new(&query(&attempt.state), None, &[]),
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
            finish(
                &http,
                &store,
                &meta(),
                &client,
                &redirect(),
                Callback::new(&denied, None, &[])
            )
            .await,
            Err(CallbackProblem::ProviderDenied { .. })
        ));
        let no_state = CallbackQuery {
            state: None,
            ..query(&attempt.state)
        };
        assert_eq!(
            finish(
                &http,
                &store,
                &meta(),
                &client,
                &redirect(),
                Callback::new(&no_state, None, &[])
            )
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
            finish(
                &http,
                &store,
                &meta(),
                &client,
                &redirect(),
                Callback::new(&no_code, None, &[])
            )
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
            Callback::new(&query(&attempt.state), None, &[]),
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
                Callback::new(&query(&attempt.state), None, &[]),
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
        let verifier = IdTokenVerifier::new(vec![public_of(&key)], "https://idp.example", "cid");
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
    #[tokio::test]
    async fn a_bound_attempt_must_come_back_from_the_same_browser() {
        let store = InMemoryLoginAttemptStore::new();
        let http = Scripted::new();
        let client = ClientAuth::Public {
            client_id: "cid".to_owned(),
        };
        let attempt = begin_with_binding(
            &store,
            "example-idp",
            None,
            Some("browser-1".to_owned()),
            Duration::minutes(5),
        )
        .await
        .expect("begin");
        assert_eq!(attempt.browser_binding.as_deref(), Some("browser-1"));
        // The attempt is spent by the first (foreign) presentation …
        let foreign = finish(
            &http,
            &store,
            &meta(),
            &client,
            &redirect(),
            Callback::new(&query(&attempt.state), Some("browser-2"), &[]),
        )
        .await
        .unwrap_err();
        assert_eq!(
            foreign.to_string(),
            "the callback did not come from the browser that started the sign-in"
        );
        assert!(
            http.form_calls.lock().expect("lock").is_empty(),
            "no exchange for a foreign browser"
        );
        // … so the genuine browser cannot replay it either.
        let replay = finish(
            &http,
            &store,
            &meta(),
            &client,
            &redirect(),
            Callback::new(&query(&attempt.state), Some("browser-1"), &[]),
        )
        .await
        .unwrap_err();
        assert_eq!(replay.to_string(), "unknown or already used state");

        let attempt = begin_with_binding(
            &store,
            "example-idp",
            None,
            Some("browser-1".to_owned()),
            Duration::minutes(5),
        )
        .await
        .expect("begin");
        finish(
            &http,
            &store,
            &meta(),
            &client,
            &redirect(),
            Callback::new(&query(&attempt.state), Some("browser-1"), &[]),
        )
        .await
        .expect("the same browser passes");
    }

    #[tokio::test]
    async fn an_attempt_cannot_be_finished_with_another_providers_metadata() {
        let store = InMemoryLoginAttemptStore::new();
        let http = Scripted::new();
        let client = ClientAuth::Public {
            client_id: "cid".to_owned(),
        };
        let attempt = begin(&store, "provider-a", None, Duration::minutes(5))
            .await
            .expect("begin");
        // MUT:provider-bound — metadata for another provider must not finish the attempt.
        let err = finish(
            &http,
            &store,
            &meta(),
            &client,
            &redirect(),
            Callback::new(&query(&attempt.state), None, &[]),
        )
        .await
        .unwrap_err();
        assert_eq!(err.to_string(), "the attempt belongs to another provider");
        assert!(http.form_calls.lock().expect("lock").is_empty());
    }

    #[tokio::test]
    async fn a_non_bearer_token_is_refused_and_numeric_subjects_are_accepted() {
        let store = InMemoryLoginAttemptStore::new();
        let client = ClientAuth::Public {
            client_id: "cid".to_owned(),
        };
        struct MacOs;
        #[async_trait]
        impl HttpFetcher for MacOs {
            async fn post_form(&self, _: &Url, _: &[(&str, &str)]) -> Result<serde_json::Value> {
                Ok(serde_json::json!({ "access_token": "at-1", "token_type": "mac" }))
            }
            async fn post_json(&self, _: &Url, _: &serde_json::Value) -> Result<serde_json::Value> {
                unreachable!()
            }
            async fn get_bearer(&self, _: &Url, _: &str) -> Result<serde_json::Value> {
                unreachable!()
            }
        }
        let attempt = begin(&store, "example-idp", None, Duration::minutes(5))
            .await
            .expect("begin");
        // MUT:bearer-only — only bearer tokens may be used with `Authorization`.
        let err = finish(
            &MacOs,
            &store,
            &meta(),
            &client,
            &redirect(),
            Callback::new(&query(&attempt.state), None, &[]),
        )
        .await
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "token endpoint answer rejected: unsupported token type \"mac\""
        );

        // MUT:numeric-subject — a numbered subject is an id, not an empty identity.
        assert_eq!(
            subject_from_userinfo(&serde_json::json!({"sub": 12345})).as_deref(),
            Some("12345")
        );
    }

    #[test]
    fn an_expected_nonce_must_be_present_and_issuer_and_audience_are_required() {
        let key = [7u8; 32];
        let verifier = IdTokenVerifier::new(vec![public_of(&key)], "https://idp.example", "cid");
        let exp = (Utc::now() + Duration::hours(1)).timestamp();
        // MUT:nonce-omitted — a token that omits the nonce is refused when one is expected.
        let mut no_nonce = id_claims(exp, "cid", "n-1");
        no_nonce.as_object_mut().expect("object").remove("nonce");
        assert!(
            verifier.verify(&mint(&key, no_nonce), Some("n-1")).is_err(),
            "omitted nonce"
        );
        let mut numeric_nonce = id_claims(exp, "cid", "n-1");
        numeric_nonce["nonce"] = serde_json::json!(42);
        assert!(
            verifier
                .verify(&mint(&key, numeric_nonce), Some("42"))
                .is_err(),
            "non-string nonce"
        );
        // A token minted for another audience is refused — there is no "unchecked" mode.
        assert!(verifier
            .verify(&mint(&key, id_claims(exp, "other", "n-1")), Some("n-1"))
            .is_err());
    }
}
