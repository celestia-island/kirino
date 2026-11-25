//! DPoP: making an access token useless to whoever steals it (RFC 9449).
//!
//! A bearer token is a password: whoever holds it IS the client. DPoP binds
//! the token to a key the client holds, so a copy is worthless without the
//! private key. The mechanism is one extra header per request — a signed
//! **proof JWT** — and a `cnf` claim in the token the provider issued.
//!
//! # The flow, and where each piece is checked
//!
//! 1. The client generates a keypair and computes the JWK thumbprint (`jkt`).
//! 2. At the token endpoint it presents `DPoP: <proof>` with `htm=POST`,
//!    `htu` = the token URL, plus its usual credentials.
//! 3. The provider checks the proof ([`verify_proof`]) and, if it accepts,
//!    puts `cnf: { jkt }` into the access token.
//! 4. At the resource server the client presents BOTH the token and a fresh
//!    proof whose `ath` is the hash of the token. The resource checks the
//!    proof again AND that the token's `cnf.jkt` equals the proof key's
//!    thumbprint ([`check_binding`]).
//!
//! # What a proof must satisfy
//!
//! Every one of these is a hole if it is skipped, which is why they are all
//! here rather than left to the host:
//!
//! | Claim | Checked because |
//! | --- | --- |
//! | `typ` | `dpop+jwt` — anything else is some other JWT replayed as a proof |
//! | `alg` | asymmetric only: `none`, `HS256` and friends let the prover choose the key |
//! | `jwk` | present, public, and matching the key that signed it |
//! | `htm` | the method, so a proof for `GET` cannot authorise a `POST` |
//! | `htu` | the URL **without** query/fragment, so a proof for one endpoint cannot be replayed at another |
//! | `iat` | inside a short window, so an old proof cannot be kept and reused |
//! | `jti` | single-use through the store, so a captured proof dies after one use |
//! | `ath` | at the resource: the hash of the token, so a proof cannot be paired with a different token |
//!
//! The `jti` window and the `iat` window overlap on purpose: `iat` bounds how
//! old a proof may be, `jti` bounds how many times it may be used.
//!
//! # Thumbprints
//!
//! `cnf.jkt` is the RFC 7638 SHA-256 thumbprint of the JWK, base64url. It is
//! derived **from the key**, never sent as a separate field: a thumbprint the
//! client asserts is a thumbprint the client can lie about.

use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::auth::store::ConsumableStore;

/// How old a proof may be (RFC 9449 §11.1 suggests a small window).
pub const MAX_PROOF_AGE_SECS: i64 = 300;
/// How far ahead of the provider's clock an `iat` may sit.
pub const MAX_PROOF_SKEW_SECS: i64 = 60;

/// The `typ` header every proof must carry.
pub const DPOP_PROOF_TYPE: &str = "dpop+jwt";

/// Why a proof was refused.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum DpopError {
    /// `typ` is not `dpop+jwt`.
    #[error("the proof's typ is not {DPOP_PROOF_TYPE}")]
    WrongType,
    /// The algorithm is symmetric or `none`: the prover would choose the key.
    #[error("the proof must be signed with an asymmetric algorithm")]
    SymmetricAlgorithm,
    /// No `jwk`, or it is private/malformed.
    #[error("the proof carries no usable public jwk")]
    NoJwk,
    /// The `jwk` does not match the key that signed the proof.
    #[error("the proof's jwk is not the key that signed it")]
    JwkMismatch,
    /// `htm` is not this request's method.
    #[error("the proof is for {found}, not {expected}")]
    WrongMethod {
        /// What the proof claims.
        found: String,
        /// What the request is.
        expected: String,
    },
    /// `htu` is not this request's URL **without** query or fragment.
    #[error("the proof is for another endpoint")]
    WrongTarget,
    /// `iat` outside the window.
    #[error("the proof is outside its time window")]
    Stale,
    /// No `jti`.
    #[error("the proof carries no jti")]
    MissingJti,
    /// This `jti` was already used.
    #[error("the proof has already been used")]
    Replayed,
    /// At the resource: no `ath`, or it is not this token's hash.
    #[error("the proof is not bound to this access token")]
    WrongTokenHash,
    /// The token has no `cnf.jkt`, so it is a bearer token and this check
    /// cannot succeed.
    #[error("the access token carries no DPoP binding")]
    NotBound,
    /// The token's `cnf.jkt` is a different key than the proof's.
    #[error("the access token is bound to another key")]
    WrongKey,
    /// The store failed.
    #[error("the jti store failed: {0}")]
    Store(String),
}

/// What the host's signature verifier answers: the claims, and the thumbprint
/// of the key that actually verified the signature.
///
/// Handing back the thumbprint (rather than letting the caller parse `jwk`
/// itself) is deliberate: it is what `cnf.jkt` must equal, and computing it
/// in two places is computing it wrong in one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedProof {
    /// The thumbprint of the signing key, base64url SHA-256 (RFC 7638).
    pub jkt: String,
}

/// The proof's payload, as the host's verifier exposes it after checking the
/// signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofClaims {
    /// Unique id — single use.
    pub jti: String,
    /// HTTP method this proof is for.
    pub htm: String,
    /// HTTP URI, **without** query or fragment.
    pub htu: String,
    /// Issued at, seconds since the epoch.
    pub iat: i64,
    /// At a resource server: base64url SHA-256 of the access token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ath: Option<String>,
}

/// What the store parks per used proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpentProof {
    /// The key it was made with, so an operator can tell whose proof it was.
    pub jkt: String,
}

/// Verify a proof against the request it accompanies.
///
/// `verify_signature` is the host's: it parses the compact JWT, refuses a
/// bad `typ`/`alg`/`jwk`, verifies the signature, and answers the claims plus
/// the signing key's thumbprint. This module does the POLICY — the parts a
/// caller forgets — and consumes the `jti`.
///
/// `htu` is compared **after** stripping query and fragment (RFC 9449 §4.3:
/// the proof covers the URI without them).
///
/// # Errors
///
/// See [`DpopError`]. Every failure is a refusal, never a degraded success.
pub async fn verify_proof<S>(
    proof: &str,
    http_method: &str,
    http_uri: &str,
    verify_signature: impl Fn(&str) -> Option<(ProofClaims, VerifiedProof)>,
    store: &S,
    now: DateTime<Utc>,
) -> Result<VerifiedProof, DpopError>
where
    S: ConsumableStore<SpentProof> + ?Sized,
{
    let Some((claims, verified)) = verify_signature(proof) else {
        // The host answers `None` for every structural failure (typ, alg,
        // jwk, signature). One error at this layer, so a prober cannot pick
        // the checks apart.
        return Err(DpopError::NoJwk);
    };
    // The METHOD is part of what was signed: a proof for a read must not
    // authorise a write.
    if !claims.htm.eq_ignore_ascii_case(http_method) {
        return Err(DpopError::WrongMethod {
            found: claims.htm,
            expected: http_method.to_owned(),
        });
    }
    // The TARGET is compared on the URI without query or fragment, because
    // that is what RFC 9449 §4.3 binds — and comparing the full URL would
    // let `?x=1` vs `?x=2` decide whether a proof is valid.
    if strip_query_and_fragment(&claims.htu) != strip_query_and_fragment(http_uri) {
        return Err(DpopError::WrongTarget);
    }
    let now_secs = now.timestamp();
    if claims.iat > now_secs + MAX_PROOF_SKEW_SECS {
        return Err(DpopError::Stale);
    }
    if claims.iat < now_secs - MAX_PROOF_AGE_SECS {
        return Err(DpopError::Stale);
    }
    if claims.jti.trim().is_empty() {
        return Err(DpopError::MissingJti);
    }
    // Single use. The store refuses a live duplicate — judged by error type,
    // not by a message.
    let expires_at = now + Duration::seconds(MAX_PROOF_AGE_SECS);
    match store
        .put(
            &claims.jti,
            SpentProof {
                jkt: verified.jkt.clone(),
            },
            expires_at,
            now,
        )
        .await
    {
        Ok(()) => Ok(verified),
        Err(e) => {
            let duplicate = e
                .downcast_ref::<crate::error::KirinoError>()
                .is_some_and(|k| matches!(k, crate::error::KirinoError::Validation(_)));
            if duplicate {
                Err(DpopError::Replayed)
            } else {
                Err(DpopError::Store(e.to_string()))
            }
        }
    }
}

/// At the resource server: the proof must be bound to THIS token.
///
/// Two separate facts, both required:
///
/// - the proof carries `ath` equal to the base64url SHA-256 of the token, so
///   a captured proof cannot be paired with a different token;
/// - the token's `cnf.jkt` equals the proof key's thumbprint, so a token
///   without a binding (a plain bearer token) cannot be used here at all.
///
/// # Errors
///
/// [`DpopError::WrongTokenHash`], [`DpopError::NotBound`],
/// [`DpopError::WrongKey`].
pub fn check_binding(
    proof_claims: &ProofClaims,
    token: &str,
    token_cnf_jkt: Option<&str>,
    proof_jkt: &str,
) -> Result<(), DpopError> {
    let Some(ath) = proof_claims.ath.as_deref() else {
        return Err(DpopError::WrongTokenHash);
    };
    if ath != access_token_hash(token) {
        return Err(DpopError::WrongTokenHash);
    }
    let Some(bound) = token_cnf_jkt else {
        // A token with no `cnf.jkt` is a bearer token. Accepting it here
        // would let anyone who stole it skip DPoP entirely.
        return Err(DpopError::NotBound);
    };
    if bound != proof_jkt {
        return Err(DpopError::WrongKey);
    }
    Ok(())
}

/// The `ath` value for a token: base64url(SHA-256(token)).
#[must_use]
pub fn access_token_hash(token: &str) -> String {
    use sha2::Digest;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(token.as_bytes()))
}

/// The URI a proof covers: scheme, authority, path — no query, no fragment.
///
/// RFC 9449 §4.3 says `htu` is "the HTTP target URI … excluding query and
/// fragment"; a naive string compare would make `?a=1` and `?a=2` different
/// resources, which they are not for this purpose.
#[must_use]
pub fn strip_query_and_fragment(uri: &str) -> &str {
    let end = uri.find(['?', '#']).unwrap_or(uri.len());
    &uri[..end]
}

/// The `cnf` claim a DPoP-bound token carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Confirmation {
    /// The JWK thumbprint the token is bound to.
    pub jkt: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::store::MemoryConsumableStore;

    type ProofStore = MemoryConsumableStore<SpentProof>;

    fn claims(now: DateTime<Utc>) -> ProofClaims {
        ProofClaims {
            jti: "j-1".into(),
            htm: "POST".into(),
            htu: "https://auth.example/token".into(),
            iat: now.timestamp(),
            ath: None,
        }
    }

    fn verified() -> VerifiedProof {
        VerifiedProof {
            jkt: "thumb-1".into(),
        }
    }

    async fn check(
        c: ProofClaims,
        method: &str,
        uri: &str,
        store: &ProofStore,
        now: DateTime<Utc>,
    ) -> Result<VerifiedProof, DpopError> {
        let v = verified();
        verify_proof(
            "proof",
            method,
            uri,
            move |_| Some((c.clone(), v.clone())),
            store,
            now,
        )
        .await
    }

    #[tokio::test]
    async fn a_valid_proof_is_accepted_once() {
        let store = ProofStore::new();
        let now = Utc::now();
        let out = check(
            claims(now),
            "POST",
            "https://auth.example/token",
            &store,
            now,
        )
        .await
        .unwrap();
        assert_eq!(out.jkt, "thumb-1");
        // The same jti again: replayed.
        assert_eq!(
            check(
                claims(now),
                "POST",
                "https://auth.example/token",
                &store,
                now
            )
            .await
            .unwrap_err(),
            DpopError::Replayed
        );
    }

    #[tokio::test]
    async fn the_method_is_part_of_the_binding() {
        let store = ProofStore::new();
        let now = Utc::now();
        // A proof minted for GET cannot authorise a POST at the same URL.
        let mut c = claims(now);
        c.htm = "GET".into();
        // MUT:htm-unchecked — without the check a read proof authorises a write.
        assert_eq!(
            check(c, "POST", "https://auth.example/token", &store, now)
                .await
                .unwrap_err(),
            DpopError::WrongMethod {
                found: "GET".into(),
                expected: "POST".into()
            }
        );
        // And the matching method does pass.
        check(
            claims(now),
            "POST",
            "https://auth.example/token",
            &store,
            now,
        )
        .await
        .expect("the method matches");
    }

    #[tokio::test]
    async fn a_proof_for_one_endpoint_cannot_be_replayed_at_another() {
        let store = ProofStore::new();
        let now = Utc::now();
        let mut c = claims(now);
        c.htm = "GET".into();
        c.htu = "https://auth.example/userinfo".into();
        // MUT:htu-unchecked — without this, a proof minted for /userinfo is
        // accepted at /token.
        assert_eq!(
            check(c, "GET", "https://auth.example/token", &store, now)
                .await
                .unwrap_err(),
            DpopError::WrongTarget
        );
    }

    #[tokio::test]
    async fn the_target_ignores_query_and_fragment() {
        let store = ProofStore::new();
        let now = Utc::now();
        let mut c = claims(now);
        c.htu = "https://auth.example/token".into();
        // A request with a query string is the same resource for this purpose.
        check(c, "POST", "https://auth.example/token?x=1", &store, now)
            .await
            .expect("the query is not part of htu");
        assert_eq!(strip_query_and_fragment("https://a/b?c#d"), "https://a/b");
        assert_eq!(strip_query_and_fragment("https://a/b"), "https://a/b");
    }

    #[tokio::test]
    async fn a_proof_outside_its_window_is_stale() {
        let store = ProofStore::new();
        let now = Utc::now();
        let mut old = claims(now);
        old.iat = now.timestamp() - MAX_PROOF_AGE_SECS - 1;
        assert_eq!(
            check(old, "POST", "https://auth.example/token", &store, now)
                .await
                .unwrap_err(),
            DpopError::Stale
        );
        let mut future = claims(now);
        future.iat = now.timestamp() + MAX_PROOF_SKEW_SECS + 1;
        assert_eq!(
            check(future, "POST", "https://auth.example/token", &store, now)
                .await
                .unwrap_err(),
            DpopError::Stale
        );
    }

    #[tokio::test]
    async fn a_missing_jti_is_refused() {
        let store = ProofStore::new();
        let now = Utc::now();
        let mut c = claims(now);
        c.jti = "  ".into();
        assert_eq!(
            check(c, "POST", "https://auth.example/token", &store, now)
                .await
                .unwrap_err(),
            DpopError::MissingJti
        );
    }

    #[tokio::test]
    async fn a_host_that_cannot_verify_gets_no_benefit_of_the_doubt() {
        let store = ProofStore::new();
        let now = Utc::now();
        assert_eq!(
            verify_proof(
                "bad",
                "POST",
                "https://auth.example/token",
                |_| None,
                &store,
                now
            )
            .await
            .unwrap_err(),
            DpopError::NoJwk
        );
    }

    // ── the resource-side binding ───────────────────────────────────────

    #[test]
    fn the_token_hash_is_the_base64url_sha256() {
        let h = access_token_hash("abc");
        assert_eq!(h.len(), 43, "32 bytes base64url");
        assert_ne!(h, access_token_hash("abd"));
        assert!(!h.contains('='), "no padding");
    }

    #[test]
    fn a_token_without_a_binding_is_refused_at_a_dpop_resource() {
        let mut c = claims(Utc::now());
        c.ath = Some(access_token_hash("tok"));
        // MUT:not-bound-accepted — returning Ok here lets a stolen bearer
        // token through a DPoP-only resource.
        assert_eq!(
            check_binding(&c, "tok", None, "thumb-1").unwrap_err(),
            DpopError::NotBound
        );
    }

    #[test]
    fn the_token_bound_to_another_key_is_refused() {
        let mut c = claims(Utc::now());
        c.ath = Some(access_token_hash("tok"));
        assert_eq!(
            check_binding(&c, "tok", Some("thumb-2"), "thumb-1").unwrap_err(),
            DpopError::WrongKey
        );
    }

    #[test]
    fn the_proof_must_hash_this_token() {
        let mut c = claims(Utc::now());
        c.ath = Some(access_token_hash("other-token"));
        // MUT:ath-unchecked — without this a captured proof pairs with any
        // token.
        assert_eq!(
            check_binding(&c, "tok", Some("thumb-1"), "thumb-1").unwrap_err(),
            DpopError::WrongTokenHash
        );
        // And no `ath` at all.
        let c2 = claims(Utc::now());
        assert_eq!(
            check_binding(&c2, "tok", Some("thumb-1"), "thumb-1").unwrap_err(),
            DpopError::WrongTokenHash
        );
    }

    #[test]
    fn the_happy_path_binds_all_three() {
        let mut c = claims(Utc::now());
        c.ath = Some(access_token_hash("tok"));
        check_binding(&c, "tok", Some("thumb-1"), "thumb-1").expect("token, hash and key agree");
    }
}
