#![allow(missing_docs)]
#![allow(clippy::missing_errors_doc)]

use anyhow::Result;

pub struct WebAuthnVerifier;

impl WebAuthnVerifier {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    pub fn verify_assertion(
        &self,
        _credential_id: &[u8],
        _authenticator_data: &[u8],
        _client_data_json: &[u8],
        _signature: &[u8],
    ) -> Result<bool> {
        unimplemented!("WebAuthn assertion verification")
    }

    pub fn start_registration(&self, _user_id: &str) -> Result<RegistrationChallenge> {
        unimplemented!("WebAuthn registration challenge generation")
    }
}

impl Default for WebAuthnVerifier {
    fn default() -> Self {
        Self::new()
    }
}

pub struct RegistrationChallenge {
    pub challenge: Vec<u8>,
    pub rp_id: String,
}
