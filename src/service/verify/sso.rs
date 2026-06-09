#![allow(missing_docs)]
#![allow(clippy::missing_errors_doc)]

use anyhow::Result;

pub struct SsoVerifier {
    #[allow(dead_code)]
    provider: String,
}

impl SsoVerifier {
    #[must_use]
    pub fn new(provider: String) -> Self {
        Self { provider }
    }

    pub fn verify(&self, _token: &str) -> Result<SsoClaims> {
        unimplemented!(
            "implement SSO token verification for provider {}",
            self.provider
        )
    }
}

pub struct SsoClaims {
    pub user_id: String,
    pub email: Option<String>,
    pub provider: String,
}
