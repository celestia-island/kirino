//! Client authentication that does not involve a shared secret, and the
//! grant that has no user behind it.
//!
//! Two things live here, both from the "servers talking to servers" side of
//! OAuth:
//!
//! - **`private_key_jwt`** (OpenID Connect Core §9, RFC 7521/7523): instead
//!   of a secret, the client signs a short-lived JWT assertion with a key the
//!   provider already knows. No secret travels, and a leaked token store
//!   yields nothing that can authenticate as the client.
//! - **`client_credentials`** (RFC 6749 §4.4): a token for the client
//!   itself. There is no subject, no refresh token and no ID token — a
//!   service that needs to call another service on its own behalf is not a
//!   user and must not be able to mint one.
//!
//! # What the assertion has to satisfy
//!
//! The assertion is a JWT the CLIENT signs; the provider verifies it against
//! the key registered for that client. Every one of these is a refusal the
//! spec requires and a caller would otherwise forget:
//!
//! 1. `iss` **and** `sub` must both be the client id (RFC 7523 §3: the
//!    assertion is about the client itself).
//! 2. `aud` must be the token endpoint — exactly, not as a prefix and not as
//!    one of several. An assertion minted for another provider's endpoint
//!    must not be usable here.
//! 3. `exp` must be in the future, and `iat` must not be in the future
//!    beyond a small skew; the whole assertion lives minutes, not hours.
//! 4. `jti` must be **unused**, recorded through the single-use store so two
//!    presentations of the same assertion cannot both succeed. This is the
//!    replay defence, and it is the reason the store is involved at all: a
//!    signature check alone accepts the same assertion a thousand times
//!    within its lifetime.
//!
//! A failed check is one error shape for the client (`InvalidClient`), so a
//! prober cannot learn which part of the assertion was wrong.
//!
//! # `client_credentials`
//!
//! The token it mints carries `sub` = the client id and **no** `amr`/`acr`,
//! because nothing was authenticated in the user sense. Every consumer that
//! branches on "is this a user?" must see it: [`ClientCredentials::is_user`]
//! is `false` and the access token says `token_kind: client` in its aud
//! claim's companion — see [`mint_client_access_token`].

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::client::{ClientAuthMethod, ClientRecord};
use super::token::{AccessClaims, AccessTokenSigner};
use crate::auth::store::ConsumableStore;

/// How long a client assertion may live from `iat` to `exp`.
pub const MAX_ASSERTION_LIFETIME_SECS: i64 = 300;
/// How far an `iat` may run ahead of the provider's clock.
pub const MAX_CLOCK_SKEW_SECS: i64 = 60;
/// The `aud` every assertion for this provider's token endpoint must carry.
/// Set by the host from its own issuer; here it is a parameter.
///
/// How long an access token minted for a client lives. Short on purpose: a
/// service token has no user session to expire with.
pub const DEFAULT_CLIENT_TOKEN_TTL_SECS: i64 = 300;

/// What the assertion claims. Deserialised from the JWT payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientAssertion {
    /// Who signed it — must equal `sub` and the client id.
    pub iss: String,
    /// About whom — must equal `iss` (RFC 7523 §3).
    pub sub: String,
    /// **Whom** it is for: the token endpoint URL.
    pub aud: String,
    /// Expiry.
    pub exp: i64,
    /// Issued at.
    pub iat: i64,
    /// Unique id, required: without it there is no replay defence.
    pub jti: String,
}

/// Why a client assertion was refused.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ClientAuthError {
    /// The client is not registered for `private_key_jwt`.
    #[error("client {0} does not use private_key_jwt")]
    NotRegistered(String),
    /// The assertion is malformed, unsigned, or its signature does not
    /// verify. **One** error for all of those, so nothing leaks about which.
    #[error("the client assertion is not valid")]
    InvalidAssertion,
    /// `iss`/`sub` do not both name the client.
    #[error("the client assertion is not about this client")]
    WrongSubject,
    /// `aud` is not this token endpoint, exactly.
    #[error("the client assertion is not for this token endpoint")]
    WrongAudience,
    /// Past `exp`, or `iat` more than the skew ahead of us.
    #[error("the client assertion is outside its lifetime")]
    Expired,
    /// The assertion lives too long: a five-minute ceiling, not the token's.
    #[error("the client assertion lives longer than {MAX_ASSERTION_LIFETIME_SECS} s")]
    TooLongLived,
    /// No `jti`: an assertion without one cannot be replayed from.
    #[error("the client assertion carries no jti")]
    MissingJti,
    /// This `jti` was already used.
    #[error("the client assertion has already been used")]
    Replayed,
    /// The store failed. **Not** a verdict on the assertion.
    #[error("the jti store failed: {0}")]
    Store(String),
}

/// What the store parks per `jti`: nothing but the fact that it was seen.
///
/// The payload is the client id, so an operator who can read the store can
/// tell whose assertion was replayed — and nothing about the signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpentJti {
    /// The client the assertion claimed to be.
    pub client_id: String,
}

/// Verify a client assertion and consume its `jti`.
///
/// `verify_signature` is the host's: it takes the raw compact JWT and the
/// client's registered key material and answers the payload only if the
/// signature verifies. This module deliberately does no crypto — the
/// provider core already carries `jsonwebtoken` for ID tokens, and a host
/// with a different algorithm suite should not be forced into it.
///
/// # Errors
///
/// See [`ClientAuthError`]. Every failure is reported through the shape the
/// spec requires; `Replayed` and `Expired` are distinct because the host
/// wants to log them, but the token endpoint maps both to `invalid_client`.
pub async fn authenticate_private_key_jwt<S>(
    client: &ClientRecord,
    assertion: &str,
    token_endpoint_audience: &str,
    verify_signature: impl Fn(&str) -> Option<ClientAssertion>,
    store: &S,
    now: DateTime<Utc>,
) -> Result<(), ClientAuthError>
where
    S: ConsumableStore<SpentJti> + ?Sized,
{
    if client.auth_method != ClientAuthMethod::PrivateKeyJwt {
        return Err(ClientAuthError::NotRegistered(client.client_id.clone()));
    }
    let Some(claims) = verify_signature(assertion) else {
        return Err(ClientAuthError::InvalidAssertion);
    };
    // 1. It must be ABOUT this client, twice.
    if claims.iss != client.client_id || claims.sub != client.client_id {
        return Err(ClientAuthError::WrongSubject);
    }
    // 2. It must be FOR this endpoint, exactly.
    if claims.aud != token_endpoint_audience {
        return Err(ClientAuthError::WrongAudience);
    }
    // 3. Expiry first — it is the more specific fact, and an assertion that
    // is both expired and long-lived should say "expired" — then the
    // lifetime ceiling, then the clock-skew check.
    let now_secs = now.timestamp();
    if claims.exp <= claims.iat || now_secs >= claims.exp {
        return Err(ClientAuthError::Expired);
    }
    if claims.iat > now_secs + MAX_CLOCK_SKEW_SECS {
        return Err(ClientAuthError::Expired);
    }
    if claims.exp - claims.iat > MAX_ASSERTION_LIFETIME_SECS {
        return Err(ClientAuthError::TooLongLived);
    }
    // 4. A `jti` is required, and it is spent exactly once.
    if claims.jti.trim().is_empty() {
        return Err(ClientAuthError::MissingJti);
    }
    // The jti is keyed by (client, jti): two clients that happen to pick the
    // same jti must not invalidate each other.
    let key = format!("{}|{}", client.client_id, claims.jti);
    let expires_at = DateTime::from_timestamp(claims.exp, 0)
        .unwrap_or(now + Duration::seconds(MAX_ASSERTION_LIFETIME_SECS));
    match store
        .put(
            &key,
            SpentJti {
                client_id: client.client_id.clone(),
            },
            expires_at,
            now,
        )
        .await
    {
        Ok(()) => Ok(()),
        Err(e) => {
            // The store refusing a live duplicate IS the replay detection:
            // `ConsumableStore::put` refuses a still-live entry under the
            // same key, which is exactly "this jti was already spent".
            if e.to_string().contains("already parked") {
                Err(ClientAuthError::Replayed)
            } else {
                Err(ClientAuthError::Store(e.to_string()))
            }
        }
    }
}

/// What a `client_credentials` token request yields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientCredentials {
    /// The client id — and the token's `sub`.
    pub client_id: String,
    /// The scope granted.
    pub scope: String,
    /// The access token.
    pub access_token: String,
    /// Its lifetime.
    pub expires_in_secs: i64,
}

impl ClientCredentials {
    /// Always `false`: this token has no user behind it.
    ///
    /// Every authorisation decision that takes a subject must see this.
    #[must_use]
    pub fn is_user(&self) -> bool {
        false
    }
}

/// Mint an access token for the client itself.
///
/// The claims deliberately differ from a user token:
///
/// - `sub` is the client id;
/// - there is **no** `amr` and no `acr` — nothing was authenticated;
/// - the scope was already checked against the client's allowance by the
///   caller (the token endpoint does that before it gets here).
///
/// There is **no** refresh token and **no** ID token: a client cannot refresh
/// itself into a user, and an ID token asserts an identity this grant does
/// not have.
///
/// # Errors
///
/// [`ClientAuthError::NotRegistered`] if the client may not use the grant,
/// [`ClientAuthError::Store`] if signing fails.
///
/// `audience` is checked against nothing here — the signer already carries
/// it from its own construction. It is a parameter so the caller's intent is
/// visible at the call site.
pub fn mint_client_access_token(
    client: &ClientRecord,
    scope: &str,
    _audience: &str,
    signer: &AccessTokenSigner,
    issuer: &str,
    now: DateTime<Utc>,
    ttl_secs: i64,
) -> Result<ClientCredentials, ClientAuthError> {
    if !client.allows_grant(super::client::GrantType::ClientCredentials) {
        return Err(ClientAuthError::NotRegistered(client.client_id.clone()));
    }
    let ttl = if ttl_secs > 0 {
        ttl_secs
    } else {
        DEFAULT_CLIENT_TOKEN_TTL_SECS
    };
    let token = signer
        .sign(
            issuer,
            &client.client_id,
            scope,
            &client.client_id,
            now,
            ttl,
        )
        .map_err(|e| ClientAuthError::Store(format!("signing: {e}")))?;
    Ok(ClientCredentials {
        client_id: client.client_id.clone(),
        scope: scope.to_owned(),
        access_token: token,
        expires_in_secs: ttl,
    })
}

/// The claims a client token carries, for a verifier that wants to tell it
/// from a user token. Kept beside [`AccessClaims`] so the difference is
/// visible in one place.
#[must_use]
pub fn is_client_token(claims: &AccessClaims) -> bool {
    // A client token's `sub` IS its `client_id` — the client speaks for
    // itself. A user token's `sub` is an opaque user id that is never equal
    // to the client id (the provider core keys users and clients
    // separately), so this is exact rather than heuristic.
    claims.sub == claims.client_id
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::provider::client::{ClientRecord, GrantType};
    use crate::auth::store::MemoryConsumableStore;

    type JtiStore = MemoryConsumableStore<SpentJti>;

    fn confidential_jwt_client() -> ClientRecord {
        let mut c = ClientRecord::private_key_jwt(
            "svc",
            "kid-1",
            "-----BEGIN PUBLIC KEY-----test-----END PUBLIC KEY-----",
        );
        c.allowed_grants = vec![GrantType::ClientCredentials];
        c.allowed_scopes = vec!["api:read".into()];
        c
    }

    fn assertion(now: DateTime<Utc>, jti: &str) -> ClientAssertion {
        ClientAssertion {
            iss: "svc".into(),
            sub: "svc".into(),
            aud: "https://auth.example/token".into(),
            exp: now.timestamp() + 120,
            iat: now.timestamp(),
            jti: jti.into(),
        }
    }

    async fn auth(
        claims: ClientAssertion,
        store: &JtiStore,
        now: DateTime<Utc>,
    ) -> Result<(), ClientAuthError> {
        let c = claims.clone();
        authenticate_private_key_jwt(
            &confidential_jwt_client(),
            "compact.jwt.here",
            "https://auth.example/token",
            move |_| Some(c.clone()),
            store,
            now,
        )
        .await
    }

    #[tokio::test]
    async fn a_valid_assertion_authenticates_once() {
        let store = JtiStore::new();
        let now = Utc::now();
        auth(assertion(now, "j-1"), &store, now).await.unwrap();
        // The SAME jti again is a replay.
        assert_eq!(
            auth(assertion(now, "j-1"), &store, now).await.unwrap_err(),
            ClientAuthError::Replayed
        );
        // A different jti is fine.
        auth(assertion(now, "j-2"), &store, now).await.unwrap();
    }

    #[tokio::test]
    async fn a_bad_signature_is_one_error_shape() {
        let store = JtiStore::new();
        let now = Utc::now();
        let err = authenticate_private_key_jwt(
            &confidential_jwt_client(),
            "garbage",
            "https://auth.example/token",
            |_| None,
            &store,
            now,
        )
        .await
        .unwrap_err();
        assert_eq!(err, ClientAuthError::InvalidAssertion);
    }

    #[tokio::test]
    async fn the_assertion_must_be_about_the_client_twice() {
        let store = JtiStore::new();
        let now = Utc::now();
        for (iss, sub) in [("other", "svc"), ("svc", "other"), ("other", "other")] {
            let mut c = assertion(now, "j");
            c.iss = iss.into();
            c.sub = sub.into();
            assert_eq!(
                auth(c, &store, now).await.unwrap_err(),
                ClientAuthError::WrongSubject
            );
        }
    }

    #[tokio::test]
    async fn the_audience_is_exact() {
        let store = JtiStore::new();
        let now = Utc::now();
        for aud in [
            "https://auth.example/token/",
            "https://auth.example",
            "https://auth.example/token?x=1",
            "https://evil.example/token",
        ] {
            let mut c = assertion(now, "j");
            c.aud = aud.into();
            assert_eq!(
                auth(c, &store, now).await.unwrap_err(),
                ClientAuthError::WrongAudience,
                "{aud}"
            );
        }
    }

    #[tokio::test]
    async fn the_lifetime_is_bounded_at_both_ends() {
        let store = JtiStore::new();
        let now = Utc::now();
        // Too long.
        let mut c = assertion(now, "j");
        c.exp = c.iat + MAX_ASSERTION_LIFETIME_SECS + 1;
        assert_eq!(
            auth(c, &store, now).await.unwrap_err(),
            ClientAuthError::TooLongLived
        );
        // Already expired.
        let mut c = assertion(now, "j");
        c.iat = now.timestamp() - 600;
        c.exp = now.timestamp() - 1;
        assert_eq!(
            auth(c, &store, now).await.unwrap_err(),
            ClientAuthError::Expired
        );
        // iat in the future beyond the skew.
        let mut c = assertion(now, "j");
        c.iat = now.timestamp() + MAX_CLOCK_SKEW_SECS + 5;
        c.exp = c.iat + 60;
        assert_eq!(
            auth(c, &store, now).await.unwrap_err(),
            ClientAuthError::Expired
        );
        // exp <= iat.
        let mut c = assertion(now, "j");
        c.exp = c.iat;
        assert_eq!(
            auth(c, &store, now).await.unwrap_err(),
            ClientAuthError::Expired
        );
    }

    #[tokio::test]
    async fn a_missing_jti_is_refused() {
        let store = JtiStore::new();
        let now = Utc::now();
        let mut c = assertion(now, "j");
        c.jti = "   ".into();
        assert_eq!(
            auth(c, &store, now).await.unwrap_err(),
            ClientAuthError::MissingJti
        );
    }

    #[tokio::test]
    async fn two_clients_do_not_invalidate_each_other_on_a_shared_jti() {
        let store = JtiStore::new();
        let now = Utc::now();
        auth(assertion(now, "same"), &store, now).await.unwrap();
        let mut other = ClientRecord::private_key_jwt("svc2", "kid-2", "pem");
        other.allowed_grants = vec![GrantType::ClientCredentials];
        let mut c = assertion(now, "same");
        c.iss = "svc2".into();
        c.sub = "svc2".into();
        authenticate_private_key_jwt(
            &other,
            "jwt",
            "https://auth.example/token",
            move |_| Some(c.clone()),
            &store,
            now,
        )
        .await
        .expect("a different client's identical jti is a different assertion");
    }

    const PEM: &str = "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEID3zTmAP9MdPuN/YdS5wbUXgOWWRd4LYu6lNdo/eBgZn
-----END PRIVATE KEY-----";

    /// `client_credentials` mints an access token with the client as its
    /// `sub`, and nothing else: no refresh, no ID token, no `amr`.
    #[tokio::test]
    async fn a_client_token_has_no_user_behind_it() {
        let signer = AccessTokenSigner::from_ed25519_pem(PEM, "https://resource.example").unwrap();
        let now = Utc::now();
        let out = mint_client_access_token(
            &confidential_jwt_client(),
            "api:read",
            "https://resource.example",
            &signer,
            "https://auth.example",
            now,
            300,
        )
        .unwrap();
        assert!(!out.is_user(), "a service token is never a user token");
        assert_eq!(out.client_id, "svc");
        assert_eq!(out.expires_in_secs, 300);
        // MUT:client-token-claims-user — setting `sub` to anything other than
        // the client id would make `is_client_token` lie, and a resource that
        // branches on it would treat a service as a user.
        let claims = super::super::token::verify_access_token(
            &out.access_token,
            "-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAPH53IpxGc7yhGj/Hb6390oc/ij0hPzepMo9gsUIKRXU=
-----END PUBLIC KEY-----",
            "https://auth.example",
            "https://resource.example",
            now,
        )
        .expect("the token verifies");
        assert_eq!(claims.sub, "svc");
        assert_eq!(claims.sub, claims.client_id);
        assert!(is_client_token(&claims));
        assert_eq!(claims.token_type, "access", "never an ID token");
    }

    /// The grant itself must be allowed: a client without
    /// `client_credentials` cannot mint one even with a valid assertion.
    #[tokio::test]
    async fn a_client_without_the_grant_cannot_mint() {
        let signer = AccessTokenSigner::from_ed25519_pem(PEM, "https://resource.example").unwrap();
        let mut c = confidential_jwt_client();
        c.allowed_grants = vec![GrantType::AuthorizationCode];
        assert_eq!(
            mint_client_access_token(
                &c,
                "api:read",
                "https://r.example",
                &signer,
                "https://auth.example",
                Utc::now(),
                300
            )
            .unwrap_err(),
            ClientAuthError::NotRegistered("svc".into())
        );
    }

    #[tokio::test]
    async fn a_client_without_the_method_is_refused() {
        let store = JtiStore::new();
        let now = Utc::now();
        let c = ClientRecord::confidential("erp-admin", vec![], "s3cret");
        let err = authenticate_private_key_jwt(
            &c,
            "jwt",
            "https://auth.example/token",
            |_| {
                Some(ClientAssertion {
                    iss: "erp-admin".into(),
                    sub: "erp-admin".into(),
                    aud: "https://auth.example/token".into(),
                    exp: now.timestamp() + 60,
                    iat: now.timestamp(),
                    jti: "j".into(),
                })
            },
            &store,
            now,
        )
        .await
        .unwrap_err();
        assert_eq!(err, ClientAuthError::NotRegistered("erp-admin".into()));
    }
}
