//! The token endpoint's orchestration: one call per grant, from the wire
//! request to the wire response, with every store interaction in between.
//!
//! The decision cores in the sibling modules are deliberately separate —
//! `client::authenticate_client`, `code::redeem`, `id_token` — so each can be
//! tested alone. This module is the **order** they run in, and the order is
//! the security property:
//!
//! ```text
//! authenticate the client        (unknown/wrong secret → InvalidClient, nothing else runs)
//!   ↓
//! claim the code in the store    (exactly one racer wins; a loser is InvalidGrant)
//!   ↓
//! redeem the claimed grant       (expiry, client, redirect, PKCE — same error for all)
//!   ↓
//! mint access + refresh + ID token
//! ```
//!
//! A losing racer never reaches `redeem`, so it never learns whether the
//! code was valid. A wrong client never reaches the store, so it cannot burn
//! somebody else's code by guessing. A storage failure is surfaced as
//! [`ProviderError::Storage`] — never as `InvalidGrant`, which would turn an
//! outage into a wave of users told their login is invalid.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{
    client::{authenticate_client, ClientAuthMethod, ClientRecord, ClientRegistry, GrantType},
    code::{self, CodeGrant, GrantKind},
    id_token::{IdTokenClaims, IdTokenSigner},
    ProviderError,
};
use crate::auth::store::{Claim, ConsumableStore};

/// A parsed token-endpoint request (the body of `POST /api/oauth/token`).
///
/// `Debug` is hand-written: every field except `grant_type`, `client_id`
/// and `redirect_uri` is a credential, and logging the request body on an
/// error path is the most natural thing for a host to do.
#[derive(Clone, Default, PartialEq, Eq, Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    #[serde(default)]
    pub code: Option<String>,
    pub client_id: String,
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default)]
    pub redirect_uri: Option<String>,
    #[serde(default)]
    pub code_verifier: Option<String>,
    #[serde(default)]
    pub refresh_token: Option<String>,
}

impl std::fmt::Debug for TokenRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let secret = |v: &Option<String>| v.as_ref().map(|_| "<redacted>");
        f.debug_struct("TokenRequest")
            .field("grant_type", &self.grant_type)
            .field("client_id", &self.client_id)
            .field("redirect_uri", &self.redirect_uri)
            .field("code", &secret(&self.code))
            .field("client_secret", &secret(&self.client_secret))
            .field("code_verifier", &secret(&self.code_verifier))
            .field("refresh_token", &secret(&self.refresh_token))
            .finish()
    }
}

/// What the token endpoint answers on success.
///
/// Every string field that is a credential is `Debug`-redacted: the struct
/// prints the shape, never the tokens.
#[derive(Clone, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    pub scope: String,
    /// Present exactly when the grant carried `openid`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
}

impl std::fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenResponse")
            .field("access_token", &"<redacted>")
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "<redacted>"),
            )
            .field("scope", &self.scope)
            .field("id_token", &self.id_token.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// Access-token lifetime. One hour: long enough that a client is not
/// refreshing constantly, short enough that a leaked token's damage window
/// is bounded without a revocation round trip.
pub const DEFAULT_ACCESS_TTL_SECS: i64 = 3600;

/// Everything the orchestration needs that is not the request.
pub struct TokenContext<'a, S: ConsumableStore<CodeGrant> + ?Sized> {
    pub registry: &'a dyn ClientRegistry,
    /// Where authorization codes are parked.
    pub codes: &'a S,
    /// Where refresh grants are parked (by the refresh token itself).
    pub refresh: &'a S,
    /// Signs the ID token. `None` means the provider has no signing key
    /// loaded and an `openid`-scope grant will fail loudly rather than
    /// mint an ID token nobody can verify.
    pub id_token_signer: Option<&'a IdTokenSigner>,
    /// The issuer URL, written into `iss`.
    pub issuer: String,
    /// Signs the access token. The access token is opaque to the client;
    /// it is a JWT so that `userinfo` can verify it without a store lookup.
    pub access_signer: &'a AccessTokenSigner,
    pub now: DateTime<Utc>,
}

/// Signs access tokens. Separate from [`IdTokenSigner`] on purpose: an
/// access token is **for the resource server**, an ID token is **for the
/// client**, and the two must not be interchangeable (OIDC Core §1.3.1 —
/// a resource server that accepts an ID token as a bearer is a confused-
/// deputy waiting to happen). Different `aud`, different `token_type`
/// claim, and the verifier below rejects a token whose type is not
/// `access`.
pub struct AccessTokenSigner {
    encoding: jsonwebtoken::EncodingKey,
    audience: String,
}

impl std::fmt::Debug for AccessTokenSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccessTokenSigner")
            .field("audience", &self.audience)
            .finish()
    }
}

impl AccessTokenSigner {
    /// An Ed25519 signer whose tokens carry `aud = audience`.
    ///
    /// # Errors
    ///
    /// [`ProviderError::SigningUnavailable`] when the PEM is not Ed25519.
    pub fn from_ed25519_pem(pem: &str, audience: impl Into<String>) -> Result<Self, ProviderError> {
        let encoding = jsonwebtoken::EncodingKey::from_ed_pem(pem.as_bytes())
            .map_err(|e| ProviderError::SigningUnavailable(format!("Ed25519 PEM rejected: {e}")))?;
        Ok(Self {
            encoding,
            audience: audience.into(),
        })
    }

    /// Sign an access token for `sub` with `scope`, bound to `aud`.
    ///
    /// # Errors
    ///
    /// [`ProviderError::SigningUnavailable`] when signing fails.
    pub fn sign(
        &self,
        issuer: &str,
        sub: &str,
        scope: &str,
        client_id: &str,
        now: DateTime<Utc>,
        ttl_secs: i64,
    ) -> Result<String, ProviderError> {
        let claims = serde_json::json!({
            "iss": issuer,
            "sub": sub,
            "aud": self.audience,
            "client_id": client_id,
            "scope": scope,
            "token_type": "access",
            "iat": now.timestamp(),
            "exp": now.timestamp() + ttl_secs,
            "jti": uuid::Uuid::now_v7().to_string(),
        });
        jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA),
            &claims,
            &self.encoding,
        )
        .map_err(|e| ProviderError::SigningUnavailable(format!("access sign failed: {e}")))
    }

    /// The audience access tokens are minted for.
    #[must_use]
    pub fn audience(&self) -> &str {
        &self.audience
    }
}

/// The parsed claims of a verified access token.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct AccessClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub client_id: String,
    pub scope: String,
    pub token_type: String,
    pub exp: i64,
    pub iat: i64,
}

/// Verify an access token at the resource server (UserInfo).
///
/// Refuses an ID token presented as a bearer (its `token_type` is absent or
/// wrong), a token for another audience, and an expired token.
///
/// # Errors
///
/// [`ProviderError::InvalidGrant`] for every refusal — the same error for
/// all, for the same reason as `code::redeem`.
pub fn verify_access_token(
    token: &str,
    public_pem: &str,
    expected_issuer: &str,
    expected_audience: &str,
    now: DateTime<Utc>,
) -> Result<AccessClaims, ProviderError> {
    let key = jsonwebtoken::DecodingKey::from_ed_pem(public_pem.as_bytes()).map_err(|e| {
        ProviderError::SigningUnavailable(format!("Ed25519 public PEM rejected: {e}"))
    })?;
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
    validation.validate_exp = true;
    validation.leeway = 0;
    validation.set_audience(&[expected_audience]);
    validation.set_issuer(&[expected_issuer]);
    let data = jsonwebtoken::decode::<AccessClaims>(token, &key, &validation)
        .map_err(|_| ProviderError::InvalidGrant)?;
    // alg is pinned by `Validation::new(EdDSA)`; this is the explicit
    // cross-check that a different `alg` header never slips through a
    // permissive verifier.
    let header = jsonwebtoken::decode_header(token).map_err(|_| ProviderError::InvalidGrant)?;
    if header.alg != jsonwebtoken::Algorithm::EdDSA {
        return Err(ProviderError::InvalidGrant);
    }
    if data.claims.token_type != "access" {
        // An ID token has no `token_type`; this is where the confused-deputy
        // case dies.
        return Err(ProviderError::InvalidGrant);
    }
    if data.claims.aud != expected_audience {
        return Err(ProviderError::InvalidGrant);
    }
    if data.claims.exp <= now.timestamp() {
        return Err(ProviderError::InvalidGrant);
    }
    Ok(data.claims)
}

/// The authorization_code grant, end to end.
///
/// # Errors
///
/// Every [`ProviderError`] variant is possible and each maps to exactly one
/// HTTP status at the host: `InvalidClient`/`InvalidTokenRequest`/
/// `InvalidGrant`/`PkceFailed` → 400 (401 for `InvalidClient` at the
/// host's discretion), `Storage`/`SigningUnavailable` → 5xx. `InvalidGrant`
/// is returned for a lost claim and for every redeem failure alike.
#[allow(clippy::too_many_arguments)]
pub async fn authorization_code_grant(
    req: &TokenRequest,
    ctx: &TokenContext<'_, impl ConsumableStore<CodeGrant> + ?Sized>,
) -> Result<TokenResponse, ProviderError> {
    let client =
        authenticate_client(ctx.registry, &req.client_id, req.client_secret.as_deref()).await?;
    if !client.allows_grant(GrantType::AuthorizationCode) {
        return Err(ProviderError::UnauthorizedClientForGrant);
    }
    let Some(code) = req.code.as_deref().filter(|c| !c.is_empty()) else {
        return Err(ProviderError::InvalidTokenRequest("code required".into()));
    };
    // The one atomic step. A loser is told "invalid code" and nothing else.
    let claim = ctx.codes.claim(code, ctx.now).await?;
    let grant = match claim {
        Claim::Won(grant) => grant,
        Claim::Lost => return Err(ProviderError::InvalidGrant),
    };
    let expires_at = grant.expires_at;
    code::redeem(
        &grant,
        ctx.now,
        &req.client_id,
        req.redirect_uri.as_deref(),
        req.code_verifier.as_deref(),
        // Defence in depth: a public client must have used PKCE regardless
        // of what the record says, because it has no other proof. A record
        // that somehow exempted a public client (a hand-built struct, a
        // stale row) is corrected here rather than trusted.
        client.require_pkce() || client.auth_method == ClientAuthMethod::None,
    )?;
    // Everything from here on is our own work, not the caller's request. If
    // minting fails for a reason that is ours and transient — the refresh
    // store is full (`Policy`), the database blinks (`Storage`) — the code
    // has already been consumed by the claim above and the caller would be
    // locked out of a login that was *valid*. Put it back so the same code
    // can be presented again. A `SigningUnavailable` (no key loaded) is
    // deliberately NOT restored: it is a deployment fault that will fail
    // the same way on retry, and leaving the code consumed keeps the
    // surface smaller. The put is best-effort because the alternative (a
    // consumed code and a 5xx) is strictly worse for the user — but note
    // it cannot help when the code's own store is what is down.
    match mint_tokens(&grant, &client, ctx).await {
        Ok(response) => Ok(response),
        Err(err @ (ProviderError::Policy(_) | ProviderError::Storage(_))) => {
            let _ = ctx.codes.put(code, grant, expires_at, ctx.now).await;
            Err(err)
        }
        Err(err) => Err(err),
    }
}

/// Mint the token set for a redeemed grant and park the refresh grant.
///
/// `pub(crate)` so the device grant and the client-credentials grant (K5)
/// mint through the same path as the authorization-code grant instead of
/// growing a second, subtly different one.
pub(crate) async fn mint_tokens(
    grant: &CodeGrant,
    client: &ClientRecord,
    ctx: &TokenContext<'_, impl ConsumableStore<CodeGrant> + ?Sized>,
) -> Result<TokenResponse, ProviderError> {
    let access = ctx.access_signer.sign(
        &ctx.issuer,
        &grant.sub,
        &grant.scope,
        &grant.client_id,
        ctx.now,
        DEFAULT_ACCESS_TTL_SECS,
    )?;
    let id_token = if super::scope_granted(&grant.scope, "openid") {
        let signer = ctx.id_token_signer.ok_or_else(|| {
            ProviderError::SigningUnavailable("openid granted but no ID-token signer".into())
        })?;
        let claims = IdTokenClaims::from_grant(&ctx.issuer, grant, ctx.now, None)?;
        Some(signer.sign(&claims)?)
    } else {
        None
    };
    // Park the refresh grant under a fresh random token if the client may
    // use it; the same grant rides along so a refresh can re-mint without
    // re-asking the user.
    let refresh_token = if client.allows_grant(GrantType::RefreshToken) {
        // Park a REFRESH grant. `mint_code` stamps kind=Code (a code is a
        // code), so the record is corrected to the refresh lane here; the
        // TTL it stamped is already the seven-day one.
        let minted = code::mint_code(grant.clone(), ctx.now, Some(REFRESH_TTL_SECS));
        let mut refresh_grant = minted.grant;
        refresh_grant.kind = GrantKind::Refresh;
        ctx.refresh
            .put(&minted.code, refresh_grant, minted.expires_at, ctx.now)
            .await?;
        Some(minted.code)
    } else {
        None
    };
    Ok(TokenResponse {
        access_token: access,
        token_type: "Bearer",
        expires_in: DEFAULT_ACCESS_TTL_SECS,
        refresh_token,
        scope: grant.scope.clone(),
        id_token,
    })
}

/// Refresh-grant lifetime: seven days, matching the RP core's expectation.
pub const REFRESH_TTL_SECS: i64 = 7 * 24 * 3600;

/// The refresh_token grant: rotate the presented token for a fresh set.
///
/// The presented refresh token is **claimed** (one-time, atomic) exactly
/// like a code: a replayed refresh token finds nothing and is refused. This
/// is the rotation the RP core and `kirino-session` already expect.
///
/// # Errors
///
/// As [`authorization_code_grant`], plus `InvalidGrant` for an unknown or
/// already-rotated refresh token.
pub async fn refresh_token_grant(
    req: &TokenRequest,
    ctx: &TokenContext<'_, impl ConsumableStore<CodeGrant> + ?Sized>,
) -> Result<TokenResponse, ProviderError> {
    let client =
        authenticate_client(ctx.registry, &req.client_id, req.client_secret.as_deref()).await?;
    if !client.allows_grant(GrantType::RefreshToken) {
        return Err(ProviderError::UnauthorizedClientForGrant);
    }
    let Some(presented) = req.refresh_token.as_deref().filter(|t| !t.is_empty()) else {
        return Err(ProviderError::InvalidTokenRequest(
            "refresh_token required".into(),
        ));
    };
    let claim = ctx.refresh.claim(presented, ctx.now).await?;
    let grant = match claim {
        Claim::Won(grant) => grant,
        Claim::Lost => return Err(ProviderError::InvalidGrant),
    };
    // A refresh token is bound to the client it was issued to…
    if grant.client_id != client.client_id {
        return Err(ProviderError::InvalidGrant);
    }
    // …and must actually BE a refresh grant. A code presented at this
    // grant would otherwise skip the redirect and PKCE checks the code
    // lane enforces (R3: with both lanes on one store, a code redeemed
    // here minted tokens without a verifier).
    if grant.kind != GrantKind::Refresh {
        return Err(ProviderError::InvalidGrant);
    }
    if ctx.now > grant.expires_at {
        return Err(ProviderError::InvalidGrant);
    }
    let expires_at = grant.expires_at;
    // Same restore-on-our-failure as the code lane: a refresh token is a
    // seven-day credential, and burning it over our own 5xx is worse.
    match mint_tokens(&grant, &client, ctx).await {
        Ok(response) => Ok(response),
        Err(err @ (ProviderError::Policy(_) | ProviderError::Storage(_))) => {
            let _ = ctx.refresh.put(presented, grant, expires_at, ctx.now).await;
            Err(err)
        }
        Err(err) => Err(err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::provider::client::InMemoryClientRegistry;
    use crate::auth::store::MemoryConsumableStore;

    /// Throwaway Ed25519 keypair for tests only (never a deployment key).
    const PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEID3zTmAP9MdPuN/YdS5wbUXgOWWRd4LYu6lNdo/eBgZn
-----END PRIVATE KEY-----";
    const PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAPH53IpxGc7yhGj/Hb6390oc/ij0hPzepMo9gsUIKRXU=
-----END PUBLIC KEY-----";

    type Store = MemoryConsumableStore<CodeGrant>;

    struct Fixture {
        registry: InMemoryClientRegistry,
        codes: Store,
        refresh: Store,
        signer: IdTokenSigner,
        access: AccessTokenSigner,
        code: String,
    }

    fn challenge_for(verifier: &str) -> String {
        use sha2::Digest;
        crate::utils::base64url::encode(&sha2::Sha256::digest(verifier.as_bytes()))
    }

    async fn fixture() -> Fixture {
        let registry = InMemoryClientRegistry::new();
        registry
            .register(ClientRecord::confidential(
                "erp-admin",
                vec!["https://admin.example/cb".into()],
                "s3cret",
            ))
            .await;
        let verifier = "v".repeat(43);
        let grant = CodeGrant {
            client_id: "erp-admin".into(),
            redirect_uri: "https://admin.example/cb".into(),
            scope: "openid profile".into(),
            sub: "user-1".into(),
            auth_time: Utc::now(),
            amr: vec!["pwd".into()],
            acr: None,
            nonce: Some("n-1".into()),
            code_challenge: Some(challenge_for(&verifier)),
            authenticated_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::seconds(code::DEFAULT_CODE_TTL_SECS),
            kind: GrantKind::Code,
        };
        let codes = Store::new();
        let minted = code::mint_code(grant, Utc::now(), None);
        codes
            .put(
                &minted.code,
                minted.grant.clone(),
                minted.expires_at,
                Utc::now(),
            )
            .await
            .unwrap();
        Fixture {
            refresh: Store::new(),
            signer: IdTokenSigner::from_ed25519_pem(PRIVATE_PEM, "k1").unwrap(),
            access: AccessTokenSigner::from_ed25519_pem(PRIVATE_PEM, "https://resource.example")
                .unwrap(),
            code: minted.code,
            registry,
            codes,
        }
    }

    fn ctx<'a>(f: &'a Fixture) -> TokenContext<'a, Store> {
        TokenContext {
            registry: &f.registry,
            codes: &f.codes,
            refresh: &f.refresh,
            id_token_signer: Some(&f.signer),
            issuer: "https://auth.example".into(),
            access_signer: &f.access,
            now: Utc::now(),
        }
    }

    fn good_req(code: &str) -> TokenRequest {
        TokenRequest {
            grant_type: "authorization_code".into(),
            code: Some(code.to_owned()),
            client_id: "erp-admin".into(),
            client_secret: Some("s3cret".into()),
            redirect_uri: Some("https://admin.example/cb".into()),
            code_verifier: Some("v".repeat(43)),
            refresh_token: None,
        }
    }

    #[tokio::test]
    async fn a_valid_exchange_mints_access_id_and_refresh() {
        let f = fixture().await;
        let resp = authorization_code_grant(&good_req(&f.code), &ctx(&f))
            .await
            .unwrap();
        assert_eq!(resp.token_type, "Bearer");
        assert_eq!(resp.scope, "openid profile");
        assert!(resp.refresh_token.is_some());
        let id_token = resp.id_token.as_ref().expect("openid granted → ID token");
        // The ID token is the one the RP core accepts.
        let key = jsonwebtoken::DecodingKey::from_ed_pem(PUBLIC_PEM.as_bytes()).unwrap();
        let v = crate::auth::passport::oauth::IdTokenVerifier::new(
            vec![key],
            "https://auth.example",
            "erp-admin",
        );
        let claims = v.verify(id_token, Some("n-1")).unwrap();
        assert_eq!(claims["sub"], "user-1");
        // The access token verifies at the resource with the right audience.
        let ac = verify_access_token(
            &resp.access_token,
            PUBLIC_PEM,
            "https://auth.example",
            "https://resource.example",
            Utc::now(),
        )
        .unwrap();
        assert_eq!(
            ac.iss, "https://auth.example",
            "the configured issuer, not a constant"
        );
        assert_eq!(ac.sub, "user-1");
        assert_eq!(ac.scope, "openid profile");
        // The Debug of the response leaks nothing.
        let rendered = format!("{resp:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains(&resp.access_token));
        // The code is consumed: a second exchange fails.
        let again = authorization_code_grant(&good_req(&f.code), &ctx(&f)).await;
        assert_eq!(again.unwrap_err(), ProviderError::InvalidGrant);
    }

    /// The defect class, end to end: 32 concurrent exchanges of one code,
    /// exactly one mints. A loser is told `InvalidGrant` and never reaches
    /// `redeem` — it cannot learn whether the code was valid.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_exchanges_of_one_code_mint_exactly_one_token_set() {
        for round in 0..4 {
            let f = std::sync::Arc::new(fixture().await);
            let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(32));
            let mut handles = Vec::new();
            for _ in 0..32 {
                let f = std::sync::Arc::clone(&f);
                let barrier = std::sync::Arc::clone(&barrier);
                let code = f.code.clone();
                handles.push(tokio::spawn(async move {
                    barrier.wait().await;
                    let ctx = TokenContext {
                        registry: &f.registry,
                        codes: &f.codes,
                        refresh: &f.refresh,
                        id_token_signer: Some(&f.signer),
                        issuer: "https://auth.example".into(),
                        access_signer: &f.access,
                        now: Utc::now(),
                    };
                    authorization_code_grant(&good_req(&code), &ctx).await
                }));
            }
            let mut ok = 0usize;
            let mut invalid_grant = 0usize;
            for handle in handles {
                match handle.await.unwrap() {
                    Ok(_) => ok += 1,
                    Err(ProviderError::InvalidGrant) => invalid_grant += 1,
                    Err(other) => panic!("round {round}: unexpected error {other}"),
                }
            }
            assert_eq!(ok, 1, "round {round}: exactly one exchange mints");
            assert_eq!(
                invalid_grant, 31,
                "round {round}: every loser is InvalidGrant"
            );
        }
    }

    #[tokio::test]
    async fn every_failure_class_maps_to_its_own_error() {
        let f = fixture().await;
        // Unknown client.
        let mut r = good_req(&f.code);
        r.client_id = "ghost".into();
        assert_eq!(
            authorization_code_grant(&r, &ctx(&f)).await.unwrap_err(),
            ProviderError::InvalidClient
        );
        // Wrong secret.
        let mut r = good_req(&f.code);
        r.client_secret = Some("nope".into());
        assert_eq!(
            authorization_code_grant(&r, &ctx(&f)).await.unwrap_err(),
            ProviderError::InvalidClient
        );
        // Missing code.
        let mut r = good_req(&f.code);
        r.code = None;
        assert!(matches!(
            authorization_code_grant(&r, &ctx(&f)).await.unwrap_err(),
            ProviderError::InvalidTokenRequest(_)
        ));
        // Unknown code.
        let r = good_req("never-issued");
        assert_eq!(
            authorization_code_grant(&r, &ctx(&f)).await.unwrap_err(),
            ProviderError::InvalidGrant
        );
        // Wrong verifier: the code is still consumed (the claim happened).
        let mut r = good_req(&f.code);
        r.code_verifier = Some("w".repeat(43));
        assert_eq!(
            authorization_code_grant(&r, &ctx(&f)).await.unwrap_err(),
            ProviderError::PkceFailed
        );
        let r = good_req(&f.code);
        assert_eq!(
            authorization_code_grant(&r, &ctx(&f)).await.unwrap_err(),
            ProviderError::InvalidGrant
        );
    }

    /// The order of checks, stated honestly. A client that presents a
    /// **valid** code it does not own (wrong `client_id` at redeem) burns
    /// that code: the claim happens before the grant's client is known. This
    /// is deliberate and not a DoS surface — burning a code requires
    /// knowing it, and a code is 256 bits of entropy that never appears in
    /// any log or URL the attacker can read. What the order *does* buy is
    /// the property the concurrency case proves: a losing racer never
    /// reaches `redeem`, so it learns nothing about the code's validity.
    /// Moving the client check before the claim would require reading the
    /// grant before consuming it — the read-then-delete shape this module
    /// exists to make impossible.
    #[tokio::test]
    async fn a_code_presented_by_the_wrong_client_is_consumed_and_refused() {
        let f = fixture().await;
        f.registry
            .register(ClientRecord::confidential(
                "other",
                vec!["https://other.example/cb".into()],
                "x",
            ))
            .await;
        let mut r = good_req(&f.code);
        r.client_id = "other".into();
        r.client_secret = Some("x".into());
        assert_eq!(
            authorization_code_grant(&r, &ctx(&f)).await.unwrap_err(),
            ProviderError::InvalidGrant
        );
        // The code is gone: consumed by the claim, refused by redeem.
        let real = authorization_code_grant(&good_req(&f.code), &ctx(&f)).await;
        assert_eq!(real.unwrap_err(), ProviderError::InvalidGrant);
    }

    /// A client that fails **authentication** (unknown id, wrong secret)
    /// never reaches the store at all — so a code cannot be burned by a
    /// client that cannot even prove who it is.
    #[tokio::test]
    async fn an_unauthenticated_client_cannot_touch_the_store() {
        let f = fixture().await;
        let mut r = good_req(&f.code);
        r.client_secret = Some("wrong".into());
        assert_eq!(
            authorization_code_grant(&r, &ctx(&f)).await.unwrap_err(),
            ProviderError::InvalidClient
        );
        // The real holder still succeeds afterwards.
        assert!(authorization_code_grant(&good_req(&f.code), &ctx(&f))
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn refresh_rotates_and_a_replay_is_refused() {
        let f = fixture().await;
        let first = authorization_code_grant(&good_req(&f.code), &ctx(&f))
            .await
            .unwrap();
        let refresh = first.refresh_token.expect("refresh granted");
        let req = TokenRequest {
            grant_type: "refresh_token".into(),
            refresh_token: Some(refresh.clone()),
            client_id: "erp-admin".into(),
            client_secret: Some("s3cret".into()),
            ..Default::default()
        };
        let second = refresh_token_grant(&req, &ctx(&f)).await.unwrap();
        assert!(second.refresh_token.is_some());
        assert_ne!(
            second.refresh_token.as_deref(),
            Some(refresh.as_str()),
            "rotation"
        );
        // Replay of the first refresh token is refused.
        assert_eq!(
            refresh_token_grant(&req, &ctx(&f)).await.unwrap_err(),
            ProviderError::InvalidGrant
        );
        // A refresh token is bound to its client.
        f.registry
            .register(ClientRecord::confidential(
                "other",
                vec!["https://other.example/cb".into()],
                "x",
            ))
            .await;
        let mut stolen = TokenRequest {
            grant_type: "refresh_token".into(),
            refresh_token: second.refresh_token.clone(),
            client_id: "other".into(),
            client_secret: Some("x".into()),
            ..Default::default()
        };
        stolen.refresh_token = second.refresh_token.clone();
        assert_eq!(
            refresh_token_grant(&stolen, &ctx(&f)).await.unwrap_err(),
            ProviderError::InvalidGrant
        );
    }

    /// The `token_type` defence, exercised for real (R2: deleting the check
    /// left 51/51 green — the old case only fed a genuine ID token, which
    /// `aud` and serde shape reject before this branch). Forged here: signed
    /// with the real key, correct `aud`/`iss`, every field present — and
    /// `token_type: "id"`. Only this branch can refuse it.
    #[tokio::test]
    async fn a_forged_token_with_the_wrong_type_is_refused_by_the_type_check() {
        let f = fixture().await;
        let key = jsonwebtoken::EncodingKey::from_ed_pem(PRIVATE_PEM.as_bytes()).unwrap();
        let now = Utc::now();
        let forged = jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA),
            &serde_json::json!({
                "iss": "https://auth.example",
                "sub": "user-1",
                "aud": "https://resource.example",
                "client_id": "erp-admin",
                "scope": "openid profile",
                "token_type": "id",
                "iat": now.timestamp(),
                "exp": now.timestamp() + 3600,
            }),
            &key,
        )
        .unwrap();
        let err = verify_access_token(
            &forged,
            PUBLIC_PEM,
            "https://auth.example",
            "https://resource.example",
            now,
        )
        .unwrap_err();
        assert_eq!(
            err,
            ProviderError::InvalidGrant,
            "only the token_type check can refuse this"
        );
        // And a genuine ID token is refused too (several reasons; this one
        // is the belt to the braces above).
        let resp = authorization_code_grant(&good_req(&f.code), &ctx(&f))
            .await
            .unwrap();
        let id_token = resp.id_token.unwrap();
        assert!(verify_access_token(
            &id_token,
            PUBLIC_PEM,
            "https://auth.example",
            "https://resource.example",
            now
        )
        .is_err());
        // Audience and issuer mismatches.
        assert!(verify_access_token(
            &resp.access_token,
            PUBLIC_PEM,
            "https://auth.example",
            "https://elsewhere.example",
            now
        )
        .is_err());
        assert!(verify_access_token(
            &resp.access_token,
            PUBLIC_PEM,
            "https://other-issuer.example",
            "https://resource.example",
            now
        )
        .is_err());
        // Expired (now is a parameter).
        let later = now + chrono::Duration::seconds(DEFAULT_ACCESS_TTL_SECS + 1);
        assert!(verify_access_token(
            &resp.access_token,
            PUBLIC_PEM,
            "https://auth.example",
            "https://resource.example",
            later
        )
        .is_err());
    }

    /// A mint failure after the claim puts the code back (R2 S1): the
    /// refresh store is full, so the first exchange answers `Policy` — and
    /// the *same code* can be presented again once there is room, instead
    /// of having been burned by our own 5xx.
    #[tokio::test]
    async fn a_mint_failure_after_the_claim_restores_the_code() {
        let f = fixture().await;
        let full = MemoryConsumableStore::<CodeGrant>::with_capacity(1);
        // Occupy the only slot with an unrelated grant.
        let junk = code::mint_code(
            CodeGrant {
                kind: GrantKind::Code,
                client_id: "x".into(),
                redirect_uri: String::new(),
                scope: "profile".into(),
                sub: "x".into(),
                auth_time: Utc::now(),
                amr: vec![],
                acr: None,
                nonce: None,
                code_challenge: None,
                authenticated_at: Utc::now(),
                expires_at: Utc::now(),
            },
            Utc::now(),
            None,
        );
        full.put(&junk.code, junk.grant, junk.expires_at, Utc::now())
            .await
            .unwrap();
        let ctx_full = TokenContext {
            registry: &f.registry,
            codes: &f.codes,
            refresh: &full,
            id_token_signer: Some(&f.signer),
            issuer: "https://auth.example".into(),
            access_signer: &f.access,
            now: Utc::now(),
        };
        let first = authorization_code_grant(&good_req(&f.code), &ctx_full).await;
        assert!(
            matches!(first, Err(ProviderError::Policy(_))),
            "a full refresh store is a policy refusal: {first:?}"
        );
        // The code is back in the store, so a retry against a roomy store succeeds.
        let retry = authorization_code_grant(&good_req(&f.code), &ctx(&f)).await;
        assert!(
            retry.is_ok(),
            "the code must survive our own mint failure: {retry:?}"
        );
    }

    /// R3 S1: with both lanes on ONE store (the `TokenContext` shape permits
    /// it), a code presented at the refresh grant skipped PKCE and the
    /// redirect check and minted tokens. The grant's kind closes that.
    #[tokio::test]
    async fn a_code_cannot_be_redeemed_through_the_refresh_grant() {
        let f = fixture().await;
        let shared = Store::new();
        let now = Utc::now();
        let verifier = "v".repeat(43);
        let grant = CodeGrant {
            kind: GrantKind::Code,
            client_id: "erp-admin".into(),
            redirect_uri: "https://admin.example/cb".into(),
            scope: "openid profile".into(),
            sub: "user-1".into(),
            auth_time: now,
            amr: vec!["pwd".into()],
            acr: None,
            nonce: Some("n-1".into()),
            code_challenge: Some(challenge_for(&verifier)),
            authenticated_at: now,
            expires_at: now + chrono::Duration::seconds(60),
        };
        let minted = code::mint_code(grant, now, None);
        let code_value = minted.code.clone();
        shared
            .put(&minted.code, minted.grant.clone(), minted.expires_at, now)
            .await
            .unwrap();
        let ctx = TokenContext {
            registry: &f.registry,
            codes: &shared,
            refresh: &shared,
            id_token_signer: Some(&f.signer),
            issuer: "https://auth.example".into(),
            access_signer: &f.access,
            now,
        };
        // The code, presented as a refresh token, with no verifier at all.
        let as_refresh = TokenRequest {
            grant_type: "refresh_token".into(),
            refresh_token: Some(code_value),
            client_id: "erp-admin".into(),
            client_secret: Some("s3cret".into()),
            ..Default::default()
        };
        assert_eq!(
            refresh_token_grant(&as_refresh, &ctx).await.unwrap_err(),
            ProviderError::InvalidGrant,
            "a code must not mint without its verifier"
        );
        assert!(
            shared.is_empty().await,
            "and nothing was parked as a refresh grant"
        );
    }

    /// The mirror: a genuine refresh grant presented at the code lane is
    /// refused by the KIND check — not by a missing row. The grant is parked
    /// in the code store too (one shared store is the shape a host can
    /// write), so the claim succeeds and only `redeem` can refuse it.
    #[tokio::test]
    async fn a_refresh_grant_cannot_be_redeemed_through_the_code_grant() {
        let f = fixture().await;
        let now = Utc::now();
        let refresh_grant = CodeGrant {
            kind: GrantKind::Refresh,
            client_id: "erp-admin".into(),
            redirect_uri: "https://admin.example/cb".into(),
            scope: "openid profile".into(),
            sub: "user-1".into(),
            auth_time: now,
            amr: vec!["pwd".into()],
            acr: None,
            nonce: Some("n-1".into()),
            // A challenge IS present, so the PKCE check passes and only the
            // kind check can refuse.
            code_challenge: Some(challenge_for(&"v".repeat(43))),
            authenticated_at: now,
            expires_at: now + chrono::Duration::seconds(REFRESH_TTL_SECS),
        };
        let parked = code::mint_code(refresh_grant, now, Some(REFRESH_TTL_SECS));
        let mut g = parked.grant;
        g.kind = GrantKind::Refresh;
        f.codes
            .put(&parked.code, g, parked.expires_at, now)
            .await
            .unwrap();
        let as_code = TokenRequest {
            grant_type: "authorization_code".into(),
            code: Some(parked.code.clone()),
            client_id: "erp-admin".into(),
            client_secret: Some("s3cret".into()),
            redirect_uri: Some("https://admin.example/cb".into()),
            code_verifier: Some("v".repeat(43)),
            ..Default::default()
        };
        assert_eq!(
            authorization_code_grant(&as_code, &ctx(&f))
                .await
                .unwrap_err(),
            ProviderError::InvalidGrant,
            "a refresh grant must not mint through the code lane"
        );
    }

    /// The parked refresh grant is a Refresh with a seven-day life, not a
    /// Code with the code's TTL (R3 S3: it carried `now+60`).
    #[tokio::test]
    async fn a_parked_refresh_grant_is_a_seven_day_refresh() {
        let f = fixture().await;
        let first = authorization_code_grant(&good_req(&f.code), &ctx(&f))
            .await
            .unwrap();
        let refresh = first.refresh_token.expect("refresh granted");
        // Peek at what was parked by claiming it directly.
        let parked = f.refresh.claim(&refresh, Utc::now()).await.unwrap();
        let Claim::Won(g) = parked else {
            panic!("parked")
        };
        assert_eq!(g.kind, GrantKind::Refresh);
        assert!(g.expires_at > Utc::now() + chrono::Duration::seconds(REFRESH_TTL_SECS - 5));
    }

    /// R3 S2: the defence-in-depth line in `redeem` is the only thing
    /// standing between a public client that somehow got exempted and a
    /// bare-code mint. Pinned on its own.
    #[tokio::test]
    async fn a_public_client_cannot_redeem_without_pkce_whatever_the_record_says() {
        let f = fixture().await;
        // The shape a stale row would produce: a public client with
        // `require_pkce` false. `exempt_from_pkce` refuses this today, so
        // the record is built the way the row would look, not through the API.
        let mut stale = ClientRecord::public("cli", vec!["https://admin.example/cb".into()]);
        stale.require_pkce = false;
        f.registry.register(stale).await;
        let now = Utc::now();
        let grant = CodeGrant {
            kind: GrantKind::Code,
            client_id: "cli".into(),
            redirect_uri: "https://admin.example/cb".into(),
            scope: "profile".into(),
            sub: "user-1".into(),
            auth_time: now,
            amr: vec![],
            acr: None,
            nonce: None,
            code_challenge: None,
            authenticated_at: now,
            expires_at: now + chrono::Duration::seconds(60),
        };
        let minted = code::mint_code(grant, now, None);
        f.codes
            .put(&minted.code, minted.grant, minted.expires_at, now)
            .await
            .unwrap();
        let req = TokenRequest {
            grant_type: "authorization_code".into(),
            code: Some(minted.code.clone()),
            client_id: "cli".into(),
            client_secret: None,
            redirect_uri: Some("https://admin.example/cb".into()),
            code_verifier: None,
            ..Default::default()
        };
        let err = authorization_code_grant(&req, &ctx(&f)).await.unwrap_err();
        assert_eq!(
            err,
            ProviderError::PkceFailed,
            "no PKCE on a public client is an open mint"
        );
    }

    /// R3 S2: `TokenRequest`'s `Debug` redaction had no pin.
    #[test]
    fn a_token_request_never_prints_its_credentials() {
        let req = TokenRequest {
            grant_type: "authorization_code".into(),
            code: Some("CODE-SECRET-VALUE".into()),
            client_id: "erp-admin".into(),
            client_secret: Some("CLIENT-SECRET-VALUE".into()),
            redirect_uri: Some("https://admin.example/cb".into()),
            code_verifier: Some("VERIFIER-SECRET-VALUE".into()),
            refresh_token: Some("REFRESH-SECRET-VALUE".into()),
        };
        let rendered = format!("{req:?}");
        for secret in [
            "CODE-SECRET-VALUE",
            "CLIENT-SECRET-VALUE",
            "VERIFIER-SECRET-VALUE",
            "REFRESH-SECRET-VALUE",
        ] {
            assert!(!rendered.contains(secret), "{rendered}");
        }
        assert!(rendered.contains("<redacted>"));
        assert!(
            rendered.contains("erp-admin"),
            "the client id is not a secret"
        );
    }

    /// R3 S3: the issuer written into the access token is the CONFIGURED
    /// one — pinned with a value that is not the fixture's.
    #[tokio::test]
    async fn the_access_token_iss_is_the_configured_issuer() {
        let f = fixture().await;
        let mut c = ctx(&f);
        c.issuer = "https://other-issuer.example".into();
        let resp = authorization_code_grant(&good_req(&f.code), &c)
            .await
            .unwrap();
        assert!(verify_access_token(
            &resp.access_token,
            PUBLIC_PEM,
            "https://other-issuer.example",
            "https://resource.example",
            Utc::now()
        )
        .is_ok());
        assert!(verify_access_token(
            &resp.access_token,
            PUBLIC_PEM,
            "https://auth.example",
            "https://resource.example",
            Utc::now()
        )
        .is_err());
        // The ID token carries the configured issuer too (R4: only the
        // access token was pinned; a hard-coded `https://auth.example` in
        // id_token.rs survived).
        let id_token = resp.id_token.expect("openid granted");
        let key = jsonwebtoken::DecodingKey::from_ed_pem(PUBLIC_PEM.as_bytes()).unwrap();
        let under_configured = crate::auth::passport::oauth::IdTokenVerifier::new(
            vec![key.clone()],
            "https://other-issuer.example",
            "erp-admin",
        );
        assert!(
            under_configured.verify(&id_token, Some("n-1")).is_ok(),
            "the ID token's iss is the configured issuer"
        );
        let under_fixture = crate::auth::passport::oauth::IdTokenVerifier::new(
            vec![key],
            "https://auth.example",
            "erp-admin",
        );
        assert!(
            under_fixture.verify(&id_token, Some("n-1")).is_err(),
            "and not the fixture's"
        );
    }

    /// A lane whose `put` refuses exactly once when armed: the claim
    /// succeeds, the rotation's park fails, and the token must come back —
    /// so the seven-day credential survives our own 5xx (R3 S1). A
    /// hand-written store rather than a capacity trick: rotation consumes
    /// one slot and takes one, so a real store never runs out mid-rotation.
    struct RefusingPark {
        inner: Store,
        /// 0 = pass-through, 1 = refuse the next put once, then 2.
        armed: std::sync::atomic::AtomicUsize,
    }

    #[async_trait::async_trait]
    impl ConsumableStore<CodeGrant> for RefusingPark {
        async fn put(
            &self,
            token: &str,
            payload: CodeGrant,
            expires_at: DateTime<Utc>,
            now: DateTime<Utc>,
        ) -> anyhow::Result<()> {
            if self
                .armed
                .compare_exchange(
                    1,
                    2,
                    std::sync::atomic::Ordering::SeqCst,
                    std::sync::atomic::Ordering::SeqCst,
                )
                .is_ok()
            {
                return Err(
                    crate::error::KirinoError::Validation("rotation park refused".into()).into(),
                );
            }
            self.inner.put(token, payload, expires_at, now).await
        }
        async fn claim(&self, token: &str, now: DateTime<Utc>) -> anyhow::Result<Claim<CodeGrant>> {
            self.inner.claim(token, now).await
        }
        async fn sweep(&self, now: DateTime<Utc>) -> anyhow::Result<u64> {
            self.inner.sweep(now).await
        }
    }

    #[tokio::test]
    async fn a_mint_failure_after_the_refresh_claim_restores_the_token() {
        let f = fixture().await;
        let now = Utc::now();
        let grant = CodeGrant {
            kind: GrantKind::Refresh,
            client_id: "erp-admin".into(),
            redirect_uri: "https://admin.example/cb".into(),
            scope: "openid profile".into(),
            sub: "user-1".into(),
            auth_time: now,
            amr: vec!["pwd".into()],
            acr: None,
            nonce: Some("n-1".into()),
            code_challenge: None,
            authenticated_at: now,
            expires_at: now + chrono::Duration::seconds(REFRESH_TTL_SECS),
        };
        let parked = code::mint_code(grant, now, Some(REFRESH_TTL_SECS));
        let mut g = parked.grant;
        g.kind = GrantKind::Refresh;
        let lane = RefusingPark {
            inner: Store::new(),
            armed: std::sync::atomic::AtomicUsize::new(0),
        };
        let g_for_retry = g.clone();
        lane.inner
            .put(&parked.code, g, parked.expires_at, now)
            .await
            .unwrap();
        // Arm: the next put is the rotation's park and must be refused.
        lane.armed.store(1, std::sync::atomic::Ordering::SeqCst);
        let ctx = TokenContext {
            registry: &f.registry,
            codes: &lane,
            refresh: &lane,
            id_token_signer: Some(&f.signer),
            issuer: "https://auth.example".into(),
            access_signer: &f.access,
            now,
        };
        let req = TokenRequest {
            grant_type: "refresh_token".into(),
            refresh_token: Some(parked.code.clone()),
            client_id: "erp-admin".into(),
            client_secret: Some("s3cret".into()),
            ..Default::default()
        };
        let refused = refresh_token_grant(&req, &ctx).await;
        assert!(
            matches!(refused, Err(ProviderError::Policy(_))),
            "the refused park is a policy refusal: {refused:?}"
        );
        // The restore went through the real store. (Both lanes are the same
        // object in this fixture, so the lane by itself is not what is
        // pinned here — the code-lane case uses two distinct stores.)
        assert!(
            lane.inner.claim(&parked.code, now).await.unwrap().is_won(),
            "the refused park was followed by a restore into the refresh lane"
        );
        // Put it back for the retry (the probe above consumed it).
        let g2 = g_for_retry;
        lane.inner
            .put(&parked.code, g2, parked.expires_at, now)
            .await
            .unwrap();
        let retry = refresh_token_grant(&req, &ctx).await;
        assert!(
            retry.is_ok(),
            "the refresh token must survive our own mint failure: {retry:?}"
        );
    }

    /// The host shape a downstream service actually uses: a store behind a
    /// trait object. R6 found `TokenContext<S>`'s implicit `Sized` made
    /// `Arc<dyn ConsumableStore<CodeGrant>>` unrepresentable — the doc on
    /// `ConsumableStore` promises that shape, and the first host (ERP P2)
    /// would have hit it.
    #[tokio::test]
    async fn a_store_behind_a_trait_object_works() {
        let f = fixture().await;
        let codes: std::sync::Arc<dyn ConsumableStore<CodeGrant>> =
            std::sync::Arc::new(Store::new());
        let refresh: std::sync::Arc<dyn ConsumableStore<CodeGrant>> =
            std::sync::Arc::new(Store::new());
        let now = Utc::now();
        let grant = CodeGrant {
            kind: GrantKind::Code,
            client_id: "erp-admin".into(),
            redirect_uri: "https://admin.example/cb".into(),
            scope: "profile".into(),
            sub: "user-1".into(),
            auth_time: now,
            amr: vec![],
            acr: None,
            nonce: None,
            code_challenge: Some(challenge_for(&"v".repeat(43))),
            authenticated_at: now,
            expires_at: now + chrono::Duration::seconds(60),
        };
        let minted = code::mint_code(grant, now, None);
        codes
            .put(&minted.code, minted.grant, minted.expires_at, now)
            .await
            .unwrap();
        let ctx = TokenContext {
            registry: &f.registry,
            codes: codes.as_ref(),
            refresh: refresh.as_ref(),
            id_token_signer: Some(&f.signer),
            issuer: "https://auth.example".into(),
            access_signer: &f.access,
            now,
        };
        let resp = authorization_code_grant(&good_req(&minted.code), &ctx)
            .await
            .expect("a dyn store is a valid host shape");
        assert!(resp.refresh_token.is_some());
    }

    #[tokio::test]
    async fn openid_without_a_signer_fails_loudly() {
        let f = fixture().await;
        let mut c = ctx(&f);
        c.id_token_signer = None;
        let err = authorization_code_grant(&good_req(&f.code), &c)
            .await
            .unwrap_err();
        assert!(
            matches!(err, ProviderError::SigningUnavailable(_)),
            "never a silent ID-token-less success: {err}"
        );
    }
}
