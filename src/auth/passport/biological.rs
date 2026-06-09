#![allow(missing_docs)]
#![allow(clippy::missing_errors_doc)]

use anyhow::Result;

pub struct BiologicalVerifier;

impl BiologicalVerifier {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    pub fn verify(&self, _sample: &[u8], _template: &[u8]) -> Result<bool> {
        unimplemented!("biological verification (fingerprint, face, etc.)")
    }
}

impl Default for BiologicalVerifier {
    fn default() -> Self {
        Self::new()
    }
}
