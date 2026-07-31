use zeroize::Zeroizing;

/// Configuration for JWT session management.
#[derive(Clone)]
pub struct SessionConfig {
    /// Shared secret for JWT signing (HS256).
    pub(crate) secret: Zeroizing<String>,
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
}
