#![allow(missing_docs)]
#![allow(clippy::missing_errors_doc)]

use anyhow::Result;

pub struct CaptchaVerifier;

impl CaptchaVerifier {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    pub fn verify(&self, _challenge_id: &str, _user_response: &str) -> Result<bool> {
        unimplemented!("CAPTCHA verification")
    }

    pub fn generate_challenge(&self) -> Result<CaptchaChallenge> {
        unimplemented!("CAPTCHA challenge generation")
    }
}

impl Default for CaptchaVerifier {
    fn default() -> Self {
        Self::new()
    }
}

pub struct CaptchaChallenge {
    pub id: String,
    pub challenge_data: Vec<u8>,
}
