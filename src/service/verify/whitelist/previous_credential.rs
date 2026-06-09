#![allow(missing_docs)]
#![allow(clippy::missing_errors_doc)]

use anyhow::Result;

pub struct PreviousCredentialVerifier;

impl PreviousCredentialVerifier {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    pub fn verify(&self, _user_id: &str, _credential_hash: &str) -> Result<bool> {
        unimplemented!("previous credential whitelist verification")
    }
}

impl Default for PreviousCredentialVerifier {
    fn default() -> Self {
        Self::new()
    }
}
