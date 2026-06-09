#![allow(missing_docs)]
#![allow(clippy::missing_errors_doc)]

use anyhow::Result;

pub struct KeyPairVerifier;

impl KeyPairVerifier {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    pub fn verify_signature(
        &self,
        _public_key: &[u8],
        _message: &[u8],
        _signature: &[u8],
    ) -> Result<bool> {
        unimplemented!("key-pair signature verification")
    }

    pub fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        unimplemented!("key-pair generation")
    }
}

impl Default for KeyPairVerifier {
    fn default() -> Self {
        Self::new()
    }
}
