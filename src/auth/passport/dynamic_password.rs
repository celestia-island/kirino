#![allow(missing_docs)]
#![allow(clippy::missing_errors_doc)]

use anyhow::Result;

pub struct TotpVerifier {
    #[allow(dead_code)]
    secret: Vec<u8>,
    #[allow(dead_code)]
    digits: u32,
    #[allow(dead_code)]
    period_secs: u32,
}

impl TotpVerifier {
    #[must_use]
    pub fn new(secret: Vec<u8>) -> Self {
        Self {
            secret,
            digits: 6,
            period_secs: 30,
        }
    }

    pub fn verify(&self, _code: &str) -> Result<bool> {
        unimplemented!("TOTP verification (RFC 6238)")
    }

    pub fn generate(&self) -> Result<String> {
        unimplemented!("TOTP code generation")
    }
}

pub struct HotpVerifier {
    #[allow(dead_code)]
    secret: Vec<u8>,
    #[allow(dead_code)]
    counter: u64,
}

impl HotpVerifier {
    #[must_use]
    pub fn new(secret: Vec<u8>, counter: u64) -> Self {
        Self { secret, counter }
    }

    pub fn verify(&self, _code: &str) -> Result<bool> {
        unimplemented!("HOTP verification (RFC 4226)")
    }
}
