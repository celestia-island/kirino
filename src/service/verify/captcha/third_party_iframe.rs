use anyhow::{anyhow, Result};

/// Reference stub for third-party CAPTCHA iframe verification.
///
/// **Security warning:** This implementation does NOT perform actual verification
/// against any external CAPTCHA service. It only checks token format (length >= 10).
/// For production use, you MUST implement server-side verification by calling the
/// CAPTCHA provider's API (e.g., Google reCAPTCHA, hCaptcha, Cloudflare Turnstile).
#[deprecated(
    since = "0.5.1",
    note = "This implementation does NOT perform server-side CAPTCHA verification. Use a proper CAPTCHA provider integration instead."
)]
pub struct ThirdPartyIframeVerifier {
    provider: String,
}

#[allow(deprecated)]
impl ThirdPartyIframeVerifier {
    #[must_use]
    pub const fn new(provider: String) -> Self {
        Self { provider }
    }

    /// Verifies a CAPTCHA response token.
    ///
    /// **Note:** This is a reference stub. It only checks that the token is
    /// non-empty and at least 10 characters. In production, replace this with
    /// actual server-side verification against the CAPTCHA provider's API.
    pub fn verify(&self, response_token: &str) -> Result<bool> {
        if response_token.is_empty() {
            return Err(anyhow!("empty CAPTCHA response token"));
        }
        if response_token.len() < 10 {
            return Err(anyhow!(
                "CAPTCHA response token too short (minimum 10 characters)"
            ));
        }
        // Reference stub: accepts any token >= 10 chars.
        // Production must call the provider's siteverify endpoint.
        Ok(true)
    }

    #[must_use]
    pub fn render_url(&self, site_key: &str) -> String {
        match self.provider.as_str() {
            "recaptcha" => format!("https://www.google.com/recaptcha/api.js?render={site_key}"),
            "hcaptcha" => format!("https://js.hcaptcha.com/1/api.js?sitekey={site_key}"),
            "turnstile" => {
                format!("https://challenges.cloudflare.com/turnstile/v0/api.js?sitekey={site_key}")
            }
            _ => format!("https://{}/captcha.js?sitekey={site_key}", self.provider),
        }
    }

    #[must_use]
    pub fn provider(&self) -> &str {
        &self.provider
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_valid_token() {
        let v = ThirdPartyIframeVerifier::new("recaptcha".to_string());
        assert!(v.verify("a-valid-response-token").unwrap());
    }

    #[test]
    fn test_verify_empty_token() {
        let v = ThirdPartyIframeVerifier::new("recaptcha".to_string());
        assert!(v.verify("").is_err());
    }

    #[test]
    fn test_verify_short_token() {
        let v = ThirdPartyIframeVerifier::new("recaptcha".to_string());
        assert!(v.verify("short").is_err());
    }

    #[test]
    fn test_verify_exactly_10_chars() {
        let v = ThirdPartyIframeVerifier::new("recaptcha".to_string());
        assert!(v.verify("1234567890").unwrap());
    }

    #[test]
    fn test_verify_9_chars() {
        let v = ThirdPartyIframeVerifier::new("recaptcha".to_string());
        assert!(v.verify("123456789").is_err());
    }

    #[test]
    fn test_render_url_recaptcha() {
        let v = ThirdPartyIframeVerifier::new("recaptcha".to_string());
        let url = v.render_url("my-site-key");
        assert!(url.contains("google.com/recaptcha"));
        assert!(url.contains("my-site-key"));
    }

    #[test]
    fn test_render_url_hcaptcha() {
        let v = ThirdPartyIframeVerifier::new("hcaptcha".to_string());
        let url = v.render_url("key");
        assert!(url.contains("hcaptcha.com"));
    }

    #[test]
    fn test_render_url_turnstile() {
        let v = ThirdPartyIframeVerifier::new("turnstile".to_string());
        let url = v.render_url("key");
        assert!(url.contains("cloudflare.com/turnstile"));
    }

    #[test]
    fn test_render_url_generic() {
        let v = ThirdPartyIframeVerifier::new("captcha.example.com".to_string());
        let url = v.render_url("key");
        assert!(url.contains("captcha.example.com"));
    }

    #[test]
    fn test_provider_accessor() {
        let v = ThirdPartyIframeVerifier::new("recaptcha".to_string());
        assert_eq!(v.provider(), "recaptcha");
    }
}
