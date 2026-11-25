//! The OAuth 2.0 / OIDC **provider** (OP) core — pure logic, no HTTP.
//!
//! The relying-party half already lives in [`super::passport::oauth`] (PKCE,
//! state, the token exchange, ID-token *verification*). This module is the
//! other side: the server that *issues* the codes and signs the tokens. It
//! is the piece every downstream service has been hand-writing — one of them
//! with a concurrency hole in its code exchange — and it is deliberately
//! protocol-only: validation, decision and claim construction are pure
//! functions over host-supplied storage, so a host wires them to axum or
//! anything else and never re-derives the rules.
//!
//! # Shape
//!
//! ```text
//! client      — who may ask: registered clients, their redirect URIs, auth methods, grants
//! authorize   — may this browser be sent back with a code: validate the request, mint the grant
//! code        — the parked grant a code resolves to, and the one-time claim of it
//! token       — the token endpoint, end to end: authenticate, claim, redeem, mint
//! id_token    — the OIDC ID token: claims, signing, kid
//! userinfo    — the standard profile claims, trimmed to the granted scope
//! discovery   — `/.well-known/openid-configuration` and the JWKS document
//! ```
//!
//! # What this module will not do
//!
//! - **No HTTP.** Every function takes its inputs and returns a value or a
//!   typed [`ProviderError`]; the host owns routing, cookies and status codes.
//! - **No storage.** Codes are parked through the host's
//!   [`ConsumableStore`](crate::auth::store::ConsumableStore); clients and
//!   consents through [`ClientRegistry`] and [`ConsentStore`], which the host
//!   implements over whatever it runs.
//! - **No secrets in logs.** The code, the client secret and every signed
//!   token are [`Zeroizing`](zeroize::Zeroize) or passed by reference and
//!   never formatted with `{:?}`.
//!
//! # Defaults that are deliberately strict
//!
//! - **PKCE S256 is required** for every client unless the registry entry
//!   says the client predates it ([`ClientRecord::require_pkce`]). `plain`
//!   is refused unconditionally (RFC 7636 §4.2: the raw verifier must never
//!   cross this server).
//! - **`response_type` is `code` only.** There is no implicit flow and no
//!   hybrid; tokens never ride a URL fragment.
//! - **The `nonce` is bound to the code** and replayed into the ID token,
//!   so an ID token is useless to a different authorization request.
//! - **The redirect URI is an exact match** against the registered value.
//!   No prefix, no wildcard, no normalisation (RFC 6749 §3.1.2.3 forbids it).

pub mod authorize;
pub mod client;
pub mod client_auth;
pub mod code;
pub mod device;
pub mod discovery;
#[cfg(feature = "auth-dpop")]
pub mod dpop;
pub mod id_token;
#[cfg(feature = "auth-mtls")]
pub mod mtls;
pub mod token;
pub mod userinfo;

pub use authorize::{authorize, AuthorizeDecision, AuthorizeRequest};
pub use client::{ClientAuthMethod, ClientRecord, ClientRegistry, GrantType, RedirectMatch};
pub use client_auth::{
    authenticate_private_key_jwt, is_client_token, mint_client_access_token, ClientAssertion,
    ClientAuthError, ClientCredentials, SpentJti, DEFAULT_CLIENT_TOKEN_TTL_SECS,
    MAX_ASSERTION_LIFETIME_SECS, MAX_CLOCK_SKEW_SECS,
};
pub use code::{mint_code, CodeGrant, GrantKind};
pub use device::{
    Decision, DeviceAuthorization, DeviceError, DevicePoll, PendingDevice, DEVICE_CODE_GRANT,
};
pub use discovery::{DiscoveryDocument, JwksDocument};
#[cfg(feature = "auth-dpop")]
pub use dpop::{
    access_token_hash, check_binding as check_dpop_binding, strip_query_and_fragment, verify_proof,
    Confirmation, DpopError, ProofClaims, SpentProof, VerifiedProof, DPOP_PROOF_TYPE,
    MAX_PROOF_AGE_SECS, MAX_PROOF_SKEW_SECS,
};
pub use id_token::{IdTokenClaims, IdTokenSigner};
#[cfg(feature = "auth-mtls")]
pub use mtls::{
    CertificateBinding, CertificateConfirmation, MtlsError, PresentedCertificate, X5T_S256,
};
pub use token::{
    authorization_code_grant, refresh_token_grant, verify_access_token, AccessClaims,
    AccessTokenSigner, TokenContext, TokenRequest, TokenResponse,
};
pub use userinfo::{userinfo, UserInfoClaims};

/// A refusal at the provider, in the vocabulary the host maps onto the wire.
///
/// The distinction that matters: [`Redirectable`](Self::Redirectable) is a
/// client error the browser may be **sent back with** (the request named a
/// valid client and redirect, so the reply is safe to deliver), while every
/// other variant must be shown on the provider's own page — reflecting an
/// error to an unvalidated redirect is an open redirect (RFC 6749 §4.2.2.1).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ProviderError {
    /// The request is well-formed enough to be answered at the client's
    /// redirect URI with `error=` / `error_description=`.
    #[error("{error}: {description}")]
    Redirectable {
        error: ProtocolError,
        description: String,
    },
    /// `client_id` is unknown, or the redirect is not registered for it.
    /// Never reflected: there is no verified place to send it.
    #[error("unknown client or unregistered redirect")]
    UnauthorizedClient,
    /// The client authenticated, but is not allowed this grant/response type.
    #[error("client is not allowed this request")]
    UnauthorizedClientForGrant,
    /// The client secret presented at the token endpoint did not match.
    #[error("invalid client credentials")]
    InvalidClient,
    /// A token-endpoint request that is malformed or missing a field.
    #[error("invalid token request: {0}")]
    InvalidTokenRequest(String),
    /// The code was unknown, expired, already consumed, or issued elsewhere.
    #[error("the authorization code is invalid")]
    InvalidGrant,
    /// PKCE: the verifier is missing or does not hash to the challenge.
    #[error("PKCE verification failed")]
    PkceFailed,
    /// Storage is unreachable. **Not** a verdict on the request — the host
    /// must answer 5xx, never fold this into an `invalid_grant`.
    #[error("provider storage failed: {0}")]
    Storage(String),
    /// The signing key cannot do what was asked (unset, unloaded, wrong alg).
    #[error("token signing is unavailable: {0}")]
    SigningUnavailable(String),
    /// The request exceeded what the provider will do (scope, TTL, count).
    #[error("request exceeds policy: {0}")]
    Policy(String),
}

impl From<anyhow::Error> for ProviderError {
    /// The boundary with the host's stores. A `ConsumableStore` reports a
    /// contract violation (a reused token, a full store) as
    /// `KirinoError::Validation` and everything else as its own error; the
    /// former is the caller's bug and becomes [`Policy`](Self::Policy), the
    /// latter is an outage and becomes [`Storage`](Self::Storage) — **never**
    /// `InvalidGrant`, which would tell a user their login is invalid
    /// because a database was down.
    fn from(err: anyhow::Error) -> Self {
        match err.downcast_ref::<crate::error::KirinoError>() {
            Some(crate::error::KirinoError::Validation(message)) => Self::Policy(message.clone()),
            _ => Self::Storage(err.to_string()),
        }
    }
}

#[cfg(test)]
mod from_anyhow_tests {
    use super::*;
    use crate::error::KirinoError;

    /// The module's headline claim — an outage must never tell a user their
    /// login is invalid — as a test. R6 found folding the non-`Validation`
    /// arm into `InvalidGrant` (the doc's own named anti-pattern) survived
    /// the whole suite.
    #[test]
    fn an_outage_is_never_reported_as_an_invalid_grant() {
        // A contract violation is the caller's bug → Policy.
        let contract = anyhow::Error::from(KirinoError::Validation("dup".into()));
        assert!(matches!(ProviderError::from(contract), ProviderError::Policy(m) if m == "dup"));
        // Anything else is an outage → Storage.
        for message in [
            "error returned from database: connection refused",
            "connection pool timed out",
            "attempt store is down",
        ] {
            let outage = anyhow::Error::msg(message);
            let mapped = ProviderError::from(outage);
            assert!(
                matches!(mapped, ProviderError::Storage(ref m) if m.contains(message)),
                "an outage must be Storage, not {mapped:?}: {message}"
            );
            assert_ne!(mapped, ProviderError::InvalidGrant);
            // MUT:outage-is-invalid — folding the outage arm into
            // `InvalidGrant` reddens this loop.
        }
        // A Validation nested under `.context()` still downcasts.
        let wrapped =
            anyhow::Error::from(KirinoError::Validation("dup".into())).context("while claiming");
        assert!(matches!(ProviderError::from(wrapped), ProviderError::Policy(m) if m == "dup"));
    }
}

/// The OAuth 2.0 error codes this provider emits (RFC 6749 §5.2, §4.2.2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ProtocolError {
    #[error("invalid_request")]
    InvalidRequest,
    #[error("unauthorized_client")]
    UnauthorizedClient,
    #[error("access_denied")]
    AccessDenied,
    #[error("unsupported_response_type")]
    UnsupportedResponseType,
    #[error("invalid_scope")]
    InvalidScope,
    #[error("server_error")]
    ServerError,
    #[error("unsupported_grant_type")]
    UnsupportedGrantType,
}

impl ProviderError {
    /// The protocol error to put on the wire when this refusal is
    /// [`Redirectable`](Self::Redirectable); `None` otherwise.
    #[must_use]
    pub fn redirectable(&self) -> Option<ProtocolError> {
        match self {
            Self::Redirectable { error, .. } => Some(*error),
            _ => None,
        }
    }
}

/// Scope tokens this provider understands — the same three the relying-party
/// core accepts, so a client configured against either side agrees.
pub const KNOWN_SCOPES: &[&str] = &["openid", "profile", "email"];

/// Validate a space-separated scope string: every token known, returned
/// sorted and de-duplicated. An empty string defaults to `openid profile`,
/// matching what the relying-party core requests by default.
///
/// # Errors
///
/// [`ProviderError::Redirectable`] with `invalid_scope` naming the first
/// unknown token — but **only** when the caller has already established the
/// client and redirect, which is why this returns the structured error and
/// the host decides whether reflecting it is safe.
pub fn validate_scope(raw: &str) -> Result<String, ProviderError> {
    let mut tokens: Vec<&str> = raw.split_whitespace().collect();
    if tokens.is_empty() {
        tokens = vec!["openid", "profile"];
    }
    for token in &tokens {
        if !KNOWN_SCOPES.contains(token) {
            return Err(ProviderError::Redirectable {
                error: ProtocolError::InvalidScope,
                description: format!("unknown scope: {token}"),
            });
        }
    }
    tokens.sort_unstable();
    tokens.dedup();
    Ok(tokens.join(" "))
}

/// Does a scope string grant `scope`?
#[must_use]
pub fn scope_granted(granted: &str, scope: &str) -> bool {
    granted.split_whitespace().any(|t| t == scope)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_validation_sorts_dedups_and_defaults() {
        assert_eq!(
            validate_scope("email openid profile").unwrap(),
            "email openid profile"
        );
        assert_eq!(validate_scope("openid openid").unwrap(), "openid");
        assert_eq!(validate_scope("").unwrap(), "openid profile");
        assert_eq!(validate_scope("   ").unwrap(), "openid profile");
    }

    #[test]
    fn an_unknown_scope_is_redirectable_invalid_scope() {
        let err = validate_scope("openid admin:everything").unwrap_err();
        assert_eq!(err.redirectable(), Some(ProtocolError::InvalidScope));
        assert!(err.to_string().contains("admin:everything"));
    }

    /// Only the redirectable class may ever be reflected to the browser.
    /// Everything else must render on the provider's own page — sending
    /// `UnauthorizedClient` back to an unvalidated redirect is an open
    /// redirect, and folding `Storage` into a redirect would turn an outage
    /// into a visible "your request was invalid".
    #[test]
    fn only_the_redirectable_variant_has_a_wire_error() {
        assert!(ProviderError::Redirectable {
            error: ProtocolError::AccessDenied,
            description: String::new(),
        }
        .redirectable()
        .is_some());
        for err in [
            ProviderError::UnauthorizedClient,
            ProviderError::InvalidClient,
            ProviderError::InvalidGrant,
            ProviderError::PkceFailed,
            ProviderError::Storage("db down".into()),
            ProviderError::SigningUnavailable("no key".into()),
        ] {
            assert_eq!(err.redirectable(), None, "{err}");
        }
    }

    #[test]
    fn scope_granted_is_token_exact() {
        assert!(scope_granted("openid profile", "profile"));
        assert!(!scope_granted("openid profile", "email"));
        // Not a substring match: `profile` is not granted by `profiles`.
        assert!(!scope_granted("openid profiles", "profile"));
    }
}
