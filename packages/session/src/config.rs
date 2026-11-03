use zeroize::Zeroizing;

use crate::SessionError;

/// Minimum accepted shared-secret length for [`SessionConfig::try_new`].
///
/// HS256 security rests entirely on this secret's entropy; the OWASP
/// guidance for symmetric signing keys starts at 256 bits (32 bytes).
pub const MIN_SECRET_BYTES: usize = 32;

/// Configuration for JWT session management.
///
/// Three key profiles exist. The historical one is a **shared secret**
/// (HS256): every service holding the secret can both mint and verify
/// tokens, so a leak in any one of them forges credentials for all of
/// them. The asymmetric profiles are **Ed25519** and, behind the
/// default-off `mldsa` feature, **ML-DSA-65** (FIPS 204 / RFC 9964):
/// the issuer service holds the private key and every verifier
/// distributes only public keys, so a verifier compromise cannot mint
/// anything. Configure an asymmetric profile by adding at least one of
/// its public verifying keys; the shared secret is then ignored (remove
/// it — see [`SessionConfig::add_ed25519_verifying_key`] and
/// [`SessionConfig::add_mldsa65_verifying_key`]). The two asymmetric
/// profiles are mutually exclusive: configuring key material for both
/// leaves the manager unusable (a
/// [`SessionError::Keys`](crate::SessionError::Keys) on every sign and
/// verify) rather than guessing which trust path was meant.
#[derive(Clone, Default)]
pub(crate) struct Ed25519Keys {
    /// Private key PEM (issuer side). `None` on verify-only services such
    /// as a gateway that must never mint tokens.
    pub signing_pem: Option<Zeroizing<String>>,
    /// Public key PEMs accepted for verification, in try-order. More than
    /// one entry enables key rotation: tokens signed by any listed public
    /// key verify, so a new key can be rolled out before the old one
    /// retires.
    pub verifying_pems: Vec<Zeroizing<String>>,
}

/// ML-DSA-65 (FIPS 204 / RFC 9964) key material.
///
/// Structurally the same role as [`Ed25519Keys`] but byte-oriented:
/// ML-DSA has no PEM wrapping here — the 32-byte seed **is** the private
/// key, and the 1952-byte encoded public key (FIPS 204 `pkEncode`
/// output) is the trust anchor. Holding plain bytes keeps this struct
/// usable without the `mldsa` feature: a config that declares ML-DSA
/// keys on a build without the feature resolves to a `Broken` keyset
/// (see [`TokenManager`](crate::TokenManager)) instead of silently
/// falling back to the HS256 shared secret.
#[derive(Clone, Default)]
pub(crate) struct MlDsa65Keys {
    /// 32-byte signing seed (issuer side). `None` on verify-only
    /// services.
    pub signing_seed: Option<Zeroizing<[u8; 32]>>,
    /// Encoded public keys (1952 bytes each, FIPS 204 `pkEncode`
    /// output) accepted for verification, in try-order — the same
    /// rotation semantics as [`Ed25519Keys::verifying_pems`]. Any
    /// 1952-byte array is structurally admissible (FIPS 204 has no cheap
    /// pk syntax check); a junk key simply fails every signature it is
    /// tried against.
    pub verifying: Vec<[u8; 1952]>,
}

#[derive(Clone)]
pub struct SessionConfig {
    /// Shared secret for JWT signing (HS256). Only used when no Ed25519
    /// or ML-DSA-65 verifying key is configured.
    pub(crate) secret: Zeroizing<String>,
    /// Ed25519 key material; `verifying_pems` non-empty selects the
    /// Ed25519 profile.
    pub(crate) ed25519: Ed25519Keys,
    /// ML-DSA-65 key material; `verifying` non-empty selects the
    /// ML-DSA-65 profile (requires the `mldsa` feature at build time).
    pub(crate) mldsa65: MlDsa65Keys,
    /// Access token lifetime in seconds (default: 900 = 15 min).
    pub access_ttl_secs: u64,
    /// Refresh token lifetime in seconds (default: 604800 = 7 days).
    pub refresh_ttl_secs: u64,
    /// Token issuer claim.
    pub issuer: String,
    /// Optional audience validation. If set, tokens must have this audience.
    pub audience: Option<String>,
    /// Optional key id (`kid`): stamped into the JOSE header on mint and
    /// published by [`TokenManager::jwks`](crate::TokenManager::jwks) on
    /// the Ed25519 and ML-DSA-65 profiles. The legacy HS256 profile does
    /// not stamp `kid` — its byte format stays frozen.
    pub(crate) kid: Option<String>,
}

impl SessionConfig {
    /// Build a configuration around a shared secret (HS256 profile).
    ///
    /// Infallible on purpose: existing deployments and tests construct
    /// here. A secret that is empty or shorter than [`MIN_SECRET_BYTES`]
    /// leaves a `tracing` warning behind (audit R1-SESS-7 — a weak HS256
    /// key is a standing, logged risk, not a silent one); the strict
    /// constructor is [`SessionConfig::try_new`].
    pub fn new(secret: impl Into<String>) -> Self {
        Self::from_secret(secret.into())
    }

    /// Strict constructor: refuses an empty shared secret outright and
    /// any secret shorter than [`MIN_SECRET_BYTES`] — exactly the keys an
    /// HS256 brute forcer hopes for.
    ///
    /// # Errors
    ///
    /// [`SessionError::Other`] describing the rejected secret.
    pub fn try_new(secret: impl Into<String>) -> Result<Self, SessionError> {
        let secret = secret.into();
        if secret.is_empty() {
            return Err(SessionError::Other(
                "shared secret is empty; refusing to configure HS256 without a key".into(),
            ));
        }
        if secret.len() < MIN_SECRET_BYTES {
            return Err(SessionError::Other(format!(
                "shared secret is {len} bytes; HS256 needs at least {MIN_SECRET_BYTES}",
                len = secret.len()
            )));
        }
        Ok(Self::from_secret(secret))
    }

    fn from_secret(secret: String) -> Self {
        if secret.len() < MIN_SECRET_BYTES {
            tracing::warn!(
                target: "kirino_session::config",
                len = secret.len(),
                "weak HS256 shared secret (empty or under 32 bytes); \
                 SessionConfig::try_new refuses it at construction"
            );
        }
        Self {
            secret: Zeroizing::new(secret),
            ed25519: Ed25519Keys::default(),
            mldsa65: MlDsa65Keys::default(),
            access_ttl_secs: 900,
            refresh_ttl_secs: 604_800,
            issuer: "kirino".into(),
            audience: None,
            kid: None,
        }
    }

    pub fn with_ttl(mut self, access_secs: u64, refresh_secs: u64) -> Self {
        self.access_ttl_secs = access_secs;
        self.refresh_ttl_secs = refresh_secs;
        self
    }

    pub fn with_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = issuer.into();
        self
    }

    pub fn with_audience(mut self, aud: impl Into<String>) -> Self {
        self.audience = Some(aud.into());
        self
    }

    /// Configure the Ed25519 **signing** (private) key. The manager becomes
    /// able to mint tokens; verification still needs at least one public
    /// key via [`Self::add_ed25519_verifying_key`].
    ///
    /// Issuer services (the ones users log into) set this; verify-only
    /// services (gateways, sibling APIs) must not — a missing signing key
    /// makes every minting call fail with
    /// [`SessionError::SigningUnavailable`](crate::SessionError::SigningUnavailable)
    /// instead of silently working.
    pub fn with_ed25519_signing_key(mut self, pem: impl Into<String>) -> Self {
        self.ed25519.signing_pem = Some(Zeroizing::new(pem.into()));
        self
    }

    /// Add an Ed25519 **verifying** (public) key. Adding the first one
    /// switches the profile from HS256 to Ed25519; the shared secret is
    /// then ignored entirely — an HS256 token is rejected because the
    /// accepted algorithm set no longer contains it, so a leftover secret
    /// cannot quietly keep the old trust path alive.
    pub fn add_ed25519_verifying_key(mut self, pem: impl Into<String>) -> Self {
        self.ed25519.verifying_pems.push(Zeroizing::new(pem.into()));
        self
    }

    /// Set the key id (`kid`) for the asymmetric profiles.
    ///
    /// On mint the `kid` is written into the JOSE header of Ed25519 and
    /// ML-DSA-65 tokens; on verify (ML-DSA-65 profile) a token whose
    /// header `kid` differs from the configured one is rejected outright,
    /// while a token without a `kid` falls back to trying every verifying
    /// key in order. The same `kid` is published in
    /// [`TokenManager::jwks`](crate::TokenManager::jwks). The legacy
    /// HS256 profile ignores it to keep its token bytes frozen.
    pub fn with_kid(mut self, kid: impl Into<String>) -> Self {
        self.kid = Some(kid.into());
        self
    }

    /// Configure the ML-DSA-65 **signing seed** (32 bytes, FIPS 204
    /// `xi`). The manager becomes able to mint tokens; verification
    /// still needs at least one public key via
    /// [`Self::add_mldsa65_verifying_key`] — a seed without any
    /// verifying key leaves the manager unusable (loudly, mirroring the
    /// Ed25519 wrong-direction guard) because it would otherwise be a
    /// silent invitation to fall back to the shared secret.
    ///
    /// Issuer services set this; verify-only services must not — a
    /// missing seed makes every minting call fail with
    /// [`SessionError::SigningUnavailable`](crate::SessionError::SigningUnavailable)
    /// instead of silently working. Enabling ML-DSA-65 requires the
    /// `mldsa` feature at build time (toolchain ≥ 1.87 per the ml-dsa
    /// MSRV).
    pub fn with_mldsa65_signing_seed(mut self, seed: &[u8; 32]) -> Self {
        self.mldsa65.signing_seed = Some(Zeroizing::new(*seed));
        self
    }

    /// Add an ML-DSA-65 **verifying** (public) key — the 1952-byte FIPS
    /// 204 `pkEncode` output, exactly as
    /// [`TokenManager::jwks`](crate::TokenManager::jwks) publishes it in
    /// the `pub` field (base64url of the same bytes). Adding the first
    /// one switches the profile from HS256 to ML-DSA-65; the shared
    /// secret is then ignored entirely, and Ed25519 key material must
    /// not be configured on the same config (the two asymmetric profiles
    /// are mutually exclusive — mixing them leaves the manager unusable
    /// rather than ambiguous).
    pub fn add_mldsa65_verifying_key(mut self, key: &[u8; 1952]) -> Self {
        self.mldsa65.verifying.push(*key);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_new_refuses_empty_and_short_secrets() {
        assert!(SessionConfig::try_new("").is_err());
        assert!(SessionConfig::try_new("short").is_err());
        assert!(SessionConfig::try_new("a".repeat(MIN_SECRET_BYTES - 1)).is_err());
    }

    #[test]
    fn try_new_accepts_a_full_length_secret() {
        let secret = "a".repeat(MIN_SECRET_BYTES);
        assert!(SessionConfig::try_new(secret).is_ok());
    }

    #[test]
    fn new_stays_infallible_for_legacy_callers() {
        // The historical constructor must keep working (scepter/arona
        // construct through it) — weakness is logged, not refused.
        let _ = SessionConfig::new("test-secret");
    }
}
