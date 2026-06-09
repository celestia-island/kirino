#![allow(missing_docs)]
#![allow(clippy::missing_errors_doc)]

use anyhow::Result;

use super::Credential;

pub struct ServiceCredential {
    #[allow(dead_code)]
    token_hash: String,
}

impl ServiceCredential {
    #[must_use]
    pub fn new(token_hash: String) -> Self {
        Self { token_hash }
    }

    pub fn from_plain_token(_token: &str) -> Self {
        unimplemented!("service token hashing")
    }
}

impl Credential for ServiceCredential {
    fn verify(&self, token: &str) -> Result<bool> {
        let _ = (token, &self.token_hash);
        unimplemented!("service token verification")
    }
}
