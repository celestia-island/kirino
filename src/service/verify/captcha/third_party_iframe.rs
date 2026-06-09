#![allow(missing_docs)]
#![allow(clippy::missing_errors_doc)]

use anyhow::Result;

pub struct ThirdPartyIframeVerifier {
    #[allow(dead_code)]
    provider: String,
}

impl ThirdPartyIframeVerifier {
    #[must_use]
    pub fn new(provider: String) -> Self {
        Self { provider }
    }

    pub fn verify(&self, _response_token: &str) -> Result<bool> {
        unimplemented!(
            "implement third-party CAPTCHA iframe verification for {}",
            self.provider
        )
    }

    pub fn render_url(&self, _site_key: &str) -> String {
        unimplemented!("third-party CAPTCHA render URL generation")
    }
}
