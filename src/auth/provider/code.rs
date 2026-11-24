//! The authorization code: what is parked under it, and how it is minted.
//!
//! The code is a random string; the grant it names is parked in the host's
//! [`ConsumableStore`](crate::auth::store::ConsumableStore) under the
//! code's fingerprint. Redemption is that store's `claim` — one atomic
//! `Won`/`Lost`, never a lookup followed by a delete. This is exactly the
//! seam where a downstream service shipped a double-spend: it `SELECT`ed
//! the code, validated it, `DELETE`d it and only checked that the delete
//! did not *error*.

use chrono::{DateTime, Utc};
use rand::RngExt;
use serde::{Deserialize, Serialize};

use super::ProviderError;

/// Default code lifetime. RFC 6749 §4.1.2 recommends ≤10 minutes; a minute
/// is plenty for a browser redirect and bounds the replay window.
pub const DEFAULT_CODE_TTL_SECS: i64 = 60;

/// Entropy of the code: 32 random bytes, base64url, ≈ 256 bits. Not
/// guessable, and long enough that an index keyed on its fingerprint has no
/// collision story.
const CODE_BYTES: usize = 32;

/// Which credential a parked grant answers to.
///
/// Both the authorization code and the refresh token park a grant in the
/// host's store. Without this marker the two are indistinguishable once
/// claimed, and a code presented at the refresh grant would skip the PKCE
/// and redirect checks the code path enforces (R3 found exactly that when
/// a host wired both lanes to one store). The kind is set at mint, checked
/// at redeem, and never taken from the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GrantKind {
    /// Redeemable by `grant_type=authorization_code` only, with the
    /// redirect and PKCE checks.
    Code,
    /// Redeemable by `grant_type=refresh_token` only.
    Refresh,
}

/// Everything the token endpoint needs to know about one authorization,
/// parked under a code or a refresh token. Serialisable so the host's store
/// can persist it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeGrant {
    /// Which lane this grant may be redeemed through. See [`GrantKind`].
    pub kind: GrantKind,
    pub client_id: String,
    /// The exact `redirect_uri` the code was issued for; the token request
    /// must present the same one (RFC 6749 §4.1.3).
    pub redirect_uri: String,
    /// Normalised (sorted, de-duplicated) scope string.
    pub scope: String,
    pub sub: String,
    pub auth_time: DateTime<Utc>,
    pub amr: Vec<String>,
    pub acr: Option<String>,
    /// Bound into the ID token later; the token endpoint does not see it.
    pub nonce: Option<String>,
    /// The S256 challenge the code was issued under, if any.
    pub code_challenge: Option<String>,
    pub authenticated_at: DateTime<Utc>,
    /// When the code stops being redeemable. Set by [`mint_code`] from its
    /// `ttl`; the token endpoint reads **this** and nothing else, so a host
    /// that mints a ten-minute code gets a ten-minute code (R2: a second,
    /// divergent TTL was derived from `authenticated_at` and made every
    /// host-chosen TTL a lie).
    pub expires_at: DateTime<Utc>,
}

/// A freshly minted code plus the grant to park and its expiry.
#[derive(Clone)]
#[must_use]
pub struct MintedCode {
    /// The code to send on the redirect. Not `Debug`-printed by the host
    /// (this struct's `Debug` shows only the grant, never the code).
    pub code: String,
    pub grant: CodeGrant,
    pub expires_at: DateTime<Utc>,
}

impl std::fmt::Debug for MintedCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The grant is safe to log (it names a subject and a client); the
        // code is a bearer credential and must never reach a log.
        f.debug_struct("MintedCode")
            .field("code", &"<redacted>")
            .field("grant", &self.grant)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Generate a fresh code and the grant it will name.
///
/// The OS RNG cannot fail here, so there is no `Result` to thread through
/// the host's authorize handler; the returned struct is `#[must_use]` so a
/// minted code cannot be dropped on the floor by accident.
pub fn mint_code(grant: CodeGrant, now: DateTime<Utc>, ttl_secs: Option<i64>) -> MintedCode {
    let raw: [u8; CODE_BYTES] = rand::rng().random();
    let code = crate::utils::base64url::encode(&raw);
    let expires_at = now + chrono::Duration::seconds(ttl_secs.unwrap_or(DEFAULT_CODE_TTL_SECS));
    let mut grant = grant;
    grant.expires_at = expires_at;
    grant.kind = GrantKind::Code;
    MintedCode {
        code,
        grant,
        expires_at,
    }
}

/// Verify a PKCE S256 verifier against the challenge the code carries.
///
/// Constant-time over the encoded comparison; the verifier's shape is
/// checked first (RFC 7636 §4.1: 43–128 unreserved characters).
#[must_use]
pub fn pkce_matches(challenge: &str, verifier: &str) -> bool {
    use sha2::Digest;
    use subtle::ConstantTimeEq;
    if !(43..=128).contains(&verifier.len())
        || !verifier
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~'))
    {
        return false;
    }
    let digest = sha2::Sha256::digest(verifier.as_bytes());
    let encoded = crate::utils::base64url::encode(&digest);
    encoded.as_bytes().ct_eq(challenge.as_bytes()).into()
}

/// What the token endpoint must check about a claimed grant, in order.
///
/// Every check after the claim is a plain comparison — the claim itself is
/// the only atomic step, and it already happened. Splitting the checks out
/// keeps the endpoint host code free of policy.
///
/// # Errors
///
/// [`ProviderError::InvalidGrant`] for every grant mismatch — expiry,
/// client, redirect, kind — with the same error for all of them: once the
/// code has been consumed there is nothing left to protect by telling a
/// prober which check failed. PKCE is the one exception and answers
/// [`ProviderError::PkceFailed`]: a client that lost its verifier benefits
/// from being told so, and the code is burned either way.
#[allow(clippy::too_many_arguments)]
pub fn redeem(
    grant: &CodeGrant,
    now: DateTime<Utc>,
    client_id: &str,
    redirect_uri: Option<&str>,
    code_verifier: Option<&str>,
    client_requires_pkce: bool,
) -> Result<(), ProviderError> {
    if grant.kind != GrantKind::Code {
        // A refresh grant presented as a code: the same refusal as any
        // other mismatch, so the two lanes cannot be used interchangeably.
        return Err(ProviderError::InvalidGrant);
    }
    if now > grant.expires_at {
        return Err(ProviderError::InvalidGrant);
    }
    if grant.client_id != client_id {
        return Err(ProviderError::InvalidGrant);
    }
    // The redirect is required when it was part of the authorization
    // request (RFC 6749 §4.1.3), and must then be identical.
    if let Some(presented) = redirect_uri {
        if presented != grant.redirect_uri {
            return Err(ProviderError::InvalidGrant);
        }
    } else if !grant.redirect_uri.is_empty() {
        return Err(ProviderError::InvalidGrant);
    }
    match (&grant.code_challenge, code_verifier) {
        (Some(challenge), Some(verifier)) => {
            if !pkce_matches(challenge, verifier) {
                return Err(ProviderError::PkceFailed);
            }
        }
        (Some(_), None) => return Err(ProviderError::PkceFailed),
        (None, Some(_)) => {
            // A verifier for a code that has no challenge: harmless on its
            // own, but a client that *must* use PKCE issuing one without it
            // means the authorize step was bypassed. Refuse.
            if client_requires_pkce {
                return Err(ProviderError::PkceFailed);
            }
        }
        (None, None) => {
            if client_requires_pkce {
                return Err(ProviderError::PkceFailed);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant() -> CodeGrant {
        CodeGrant {
            kind: GrantKind::Code,
            client_id: "erp-admin".into(),
            redirect_uri: "https://admin.example/cb".into(),
            scope: "openid profile".into(),
            sub: "user-1".into(),
            auth_time: Utc::now(),
            amr: vec!["pwd".into()],
            acr: None,
            nonce: Some("n-1".into()),
            code_challenge: None,
            authenticated_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::seconds(DEFAULT_CODE_TTL_SECS),
        }
    }

    #[test]
    fn minted_codes_are_unique_and_opaque() {
        let now = Utc::now();
        let a = mint_code(grant(), now, None);
        let b = mint_code(grant(), now, None);
        assert_ne!(a.code, b.code);
        assert_eq!(a.code.len(), 43, "32 bytes base64url without padding");
        assert!(a
            .code
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_')));
        assert_eq!(
            a.expires_at,
            now + chrono::Duration::seconds(DEFAULT_CODE_TTL_SECS)
        );
        // The Debug of a minted code never shows the code.
        let rendered = format!("{a:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains(&a.code));
    }

    /// A code is a Code: `mint_code` stamps the kind whatever the caller's
    /// grant said (R4: removing the stamp survived every other case).
    #[test]
    fn mint_code_always_stamps_the_code_kind() {
        let mut g = grant();
        g.kind = GrantKind::Refresh;
        assert_eq!(mint_code(g, Utc::now(), None).grant.kind, GrantKind::Code);
    }

    #[test]
    fn pkce_is_s256_only_and_shape_checked() {
        let verifier = "a".repeat(43);
        let challenge = {
            use sha2::Digest;
            crate::utils::base64url::encode(&sha2::Sha256::digest(verifier.as_bytes()))
        };
        assert!(pkce_matches(&challenge, &verifier));
        // MUT:pkce-verifier — a wrong verifier must not match.
        let mut wrong = "a".repeat(43);
        wrong.replace_range(0..1, "b");
        assert!(!pkce_matches(&challenge, &wrong));
        assert!(!pkce_matches(&challenge, &"a".repeat(42)));
        assert!(!pkce_matches(&challenge, &"a".repeat(129)));
        assert!(!pkce_matches(&challenge, &format!("{}*", "a".repeat(42))));
        // The challenge is compared as the encoded digest, so a `plain`
        // challenge (the raw verifier) never matches.
        assert!(!pkce_matches(&verifier, &verifier));
    }

    #[test]
    fn redeem_enforces_every_dimension() {
        let now = Utc::now();
        let mut g = grant();
        g.code_challenge = Some({
            use sha2::Digest;
            crate::utils::base64url::encode(&sha2::Sha256::digest("v".repeat(43).as_bytes()))
        });
        let v = "v".repeat(43);
        let cb = "https://admin.example/cb";
        assert_eq!(
            redeem(&g, now, "erp-admin", Some(cb), Some(&v), true),
            Ok(())
        );
        // Expired: the grant's own `expires_at` is the only clock.
        assert_eq!(
            redeem(
                &g,
                g.expires_at + chrono::Duration::seconds(1),
                "erp-admin",
                Some(cb),
                Some(&v),
                true
            ),
            Err(ProviderError::InvalidGrant)
        );
        // Wrong client.
        assert_eq!(
            redeem(&g, now, "other", Some(cb), Some(&v), true),
            Err(ProviderError::InvalidGrant)
        );
        // Wrong redirect.
        assert_eq!(
            redeem(
                &g,
                now,
                "erp-admin",
                Some("https://evil.example/cb"),
                Some(&v),
                true
            ),
            Err(ProviderError::InvalidGrant)
        );
        // Redirect omitted though it was bound.
        assert_eq!(
            redeem(&g, now, "erp-admin", None, Some(&v), true),
            Err(ProviderError::InvalidGrant)
        );
        // Missing verifier, wrong verifier.
        assert_eq!(
            redeem(&g, now, "erp-admin", Some(cb), None, true),
            Err(ProviderError::PkceFailed)
        );
        assert_eq!(
            redeem(&g, now, "erp-admin", Some(cb), Some(&"w".repeat(43)), true),
            Err(ProviderError::PkceFailed)
        );
    }

    /// A host-chosen TTL is honoured end to end: `mint_code(.., Some(600))`
    /// parks a code that is redeemable at +120 s (R2: a second, divergent
    /// TTL derived from `authenticated_at` refused it).
    #[test]
    fn a_host_chosen_ttl_is_the_ttl() {
        let now = Utc::now();
        let minted = mint_code(grant(), now, Some(600));
        assert_eq!(
            minted.grant.expires_at,
            now + chrono::Duration::seconds(600)
        );
        assert_eq!(
            redeem(
                &minted.grant,
                now + chrono::Duration::seconds(120),
                "erp-admin",
                Some("https://admin.example/cb"),
                None,
                false
            ),
            Ok(())
        );
        // …and the default is sixty seconds.
        let minted = mint_code(grant(), now, None);
        assert_eq!(
            redeem(
                &minted.grant,
                now + chrono::Duration::seconds(61),
                "erp-admin",
                Some("https://admin.example/cb"),
                None,
                false
            ),
            Err(ProviderError::InvalidGrant)
        );
    }

    /// A code issued without a challenge cannot be redeemed by a client that
    /// must use PKCE: that combination means the authorize step was skipped
    /// or tampered, and the token endpoint is the last place to catch it.
    #[test]
    fn a_pkce_client_cannot_redeem_a_challenge_less_code() {
        let now = Utc::now();
        let g = grant();
        let cb = "https://admin.example/cb";
        assert_eq!(
            redeem(&g, now, "erp-admin", Some(cb), None, true),
            Err(ProviderError::PkceFailed)
        );
        // An exempt client may.
        assert_eq!(redeem(&g, now, "erp-admin", Some(cb), None, false), Ok(()));
    }

    /// Every failure is the *same* error: once the code is consumed there is
    /// nothing left to protect by telling a prober which check they failed.
    #[test]
    fn every_redeem_failure_is_indistinguishable() {
        let now = Utc::now();
        let g = grant();
        let a = redeem(&g, now, "other", None, None, false)
            .unwrap_err()
            .to_string();
        let b = redeem(
            &g,
            now,
            "erp-admin",
            Some("https://evil.example/cb"),
            None,
            false,
        )
        .unwrap_err()
        .to_string();
        assert_eq!(a, b);
    }
}
