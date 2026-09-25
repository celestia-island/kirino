use zeroize::Zeroizing;

/// Configuration for JWT session management.
///
/// Two key profiles exist. The historical one is a **shared secret**
/// (HS256): every service holding the secret can both mint and verify
/// tokens, so a leak in any one of them forges credentials for all of
/// them. The asymmetric profile is **Ed25519**: the issuer service holds
/// the private key and every verifier distributes only public keys, so a
/// verifier compromise cannot mint anything. Configure it by adding at
/// least one Ed25519 public verifying key; the shared secret is then
/// ignored (remove it — see [`SessionConfig::add_ed25519_verifying_key`]).
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

#[derive(Clone)]
pub struct SessionConfig {
    /// Shared secret for JWT signing (HS256). Only used when no Ed25519
    /// verifying key is configured.
    pub(crate) secret: Zeroizing<String>,
    /// Ed25519 key material; `verifying_pems` non-empty selects the
    /// asymmetric profile.
    pub(crate) ed25519: Ed25519Keys,
    /// Access token lifetime in seconds (default: 900 = 15 min).
    pub access_ttl_secs: u64,
    /// Refresh token lifetime in seconds (default: 604800 = 7 days).
    pub refresh_ttl_secs: u64,
    /// Token issuer claim.
    pub issuer: String,
    /// Optional audience validation. If set, tokens must have this audience.
    pub audience: Option<String>,
}

impl SessionConfig {
    pub fn new(secret: impl Into<String>) -> Self {
        Self {
            secret: Zeroizing::new(secret.into()),
            ed25519: Ed25519Keys::default(),
            access_ttl_secs: 900,
            refresh_ttl_secs: 604_800,
            issuer: "kirino".into(),
            audience: None,
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
}
