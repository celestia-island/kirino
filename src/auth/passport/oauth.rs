use anyhow::{anyhow, Result};

use crate::utils::base64;

/// Reference OAuth verifier that extracts claims from JWT-format access tokens.
///
/// # Security Warning
///
/// This implementation does **not** verify the JWT signature. Any token with a
/// valid base64-encoded JSON payload containing a `"sub"` field will be accepted.
/// **Do not use in production.** Replace with a verifier that validates the
/// signature against the authorization server's public key (e.g. via the
/// `jsonwebtoken` crate) or performs an opaque token introspection call.
#[deprecated(
    since = "0.5.0",
    note = "This implementation does NOT verify JWT signatures. Use a proper OAuth verifier with jwks_uri signature validation instead."
)]
pub struct OAuthVerifier {
    provider: String,
    client_id: String,
}

#[allow(deprecated)]
impl OAuthVerifier {
    #[must_use]
    pub fn new(provider: String, client_id: String) -> Self {
        Self {
            provider,
            client_id,
        }
    }

        pub fn verify_token(&self, access_token: &str) -> Result<OAuthClaims> {
        if access_token.is_empty() {
            return Err(anyhow!("empty access token"));
        }
        let parts: Vec<&str> = access_token.split('.').collect();
        if parts.len() == 3 {
            return self.verify_jwt_token(access_token);
        }
        self.verify_opaque_token(access_token)
    }

    fn verify_jwt_token(&self, token: &str) -> Result<OAuthClaims> {
        let parts: Vec<&str> = token.split('.').collect();
        let payload_b64 = parts.get(1).ok_or_else(|| anyhow!("malformed JWT"))?;
        let payload_bytes = base64::decode_url_safe(payload_b64)?;
        let payload_str =
            String::from_utf8(payload_bytes).map_err(|_| anyhow!("invalid UTF-8 in payload"))?;
        let payload: serde_json::Value =
            serde_json::from_str(&payload_str).map_err(|e| anyhow!("JSON parse failed: {e}"))?;

        let sub = payload["sub"]
            .as_str()
            .ok_or_else(|| anyhow!("missing 'sub' claim"))?
            .to_string();
        let email = payload["email"].as_str().map(String::from);
        let name = payload["name"].as_str().map(String::from);

        Ok(OAuthClaims { sub, email, name })
    }

    fn verify_opaque_token(&self, _token: &str) -> Result<OAuthClaims> {
        Err(anyhow!(
            "opaque token verification requires an external provider call for '{}'; use an OAuthProvider implementation",
            self.provider
        ))
    }

    #[must_use]
    pub fn authorization_url(&self, redirect_uri: &str, state: &str) -> String {
        let encoded_redirect = crate::utils::url_encode(redirect_uri);
        let encoded_state = crate::utils::url_encode(state);
        match self.provider.as_str() {
            "google" => format!(
                "https://accounts.google.com/o/oauth2/v2/auth?client_id={}&redirect_uri={}&response_type=code&scope=openid+email+profile&state={}",
                self.client_id, encoded_redirect, encoded_state
            ),
            "github" => format!(
                "https://github.com/login/oauth/authorize?client_id={}&redirect_uri={}&state={}",
                self.client_id, encoded_redirect, encoded_state
            ),
            _ => format!(
                "https://{}/oauth/authorize?client_id={}&redirect_uri={}&response_type=code&state={}",
                self.provider, self.client_id, encoded_redirect, encoded_state
            ),
        }
    }
}

#[derive(Debug)]
pub struct OAuthClaims {
    pub sub: String,
    pub email: Option<String>,
    pub name: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(deprecated)]
    #[test]
    fn test_authorization_url_google() {
        let v = OAuthVerifier::new("google".to_string(), "my-client".to_string());
        let url = v.authorization_url("http://localhost/cb", "state123");
        assert!(url.contains("accounts.google.com"));
        assert!(url.contains("my-client"));
        assert!(url.contains("redirect_uri=http%3A%2F%2Flocalhost%2Fcb"));
        assert!(url.contains("state=state123"));
    }

    #[allow(deprecated)]
    #[test]
    fn test_authorization_url_github() {
        let v = OAuthVerifier::new("github".to_string(), "gh-client".to_string());
        let url = v.authorization_url("/callback", "xyz");
        assert!(url.contains("github.com"));
        assert!(url.contains("gh-client"));
        assert!(url.contains("redirect_uri=%2Fcallback"));
    }

    #[allow(deprecated)]
    #[test]
    fn test_authorization_url_generic() {
        let v = OAuthVerifier::new("sso.example.com".to_string(), "cid".to_string());
        let url = v.authorization_url("/callback", "xyz");
        assert!(url.contains("sso.example.com"));
    }

    #[allow(deprecated)]
    #[test]
    fn test_authorization_url_encodes_special_chars() {
        let v = OAuthVerifier::new("google".to_string(), "id".to_string());
        let url = v.authorization_url("http://example.com/cb?foo=bar&baz=1", "state with spaces");
        assert!(url.contains("redirect_uri=http%3A%2F%2Fexample.com%2Fcb%3Ffoo%3Dbar%26baz%3D1"));
        assert!(url.contains("state=state%20with%20spaces"));
    }

    #[allow(deprecated)]
    #[test]
    fn test_verify_empty_token() {
        let v = OAuthVerifier::new("test".to_string(), "cid".to_string());
        assert!(v.verify_token("").is_err());
    }

    #[allow(deprecated)]
    #[test]
    fn test_verify_opaque_token() {
        let v = OAuthVerifier::new("test".to_string(), "cid".to_string());
        let result = v.verify_token("opaque-token-value");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("opaque"));
    }

    #[allow(deprecated)]
    #[test]
    fn test_verify_jwt_extracts_claims() {
        let v = OAuthVerifier::new("test".to_string(), "cid".to_string());
        let payload = r#"{"sub":"user-1","email":"user@example.com","name":"User One"}"#;
        let payload_b64 = base64::encode(payload.as_bytes());
        let token = format!("header.{payload_b64}.signature");
        let claims = v.verify_token(&token).unwrap();
        assert_eq!(claims.sub, "user-1");
        assert_eq!(claims.email, Some("user@example.com".to_string()));
        assert_eq!(claims.name, Some("User One".to_string()));
    }

    #[allow(deprecated)]
    #[test]
    fn test_verify_jwt_missing_sub() {
        let v = OAuthVerifier::new("test".to_string(), "cid".to_string());
        let payload = r#"{"email":"user@example.com"}"#;
        let payload_b64 = base64::encode(payload.as_bytes());
        let token = format!("header.{payload_b64}.signature");
        assert!(v.verify_token(&token).is_err());
    }

    #[allow(deprecated)]
    #[test]
    fn test_verify_jwt_invalid_utf8() {
        let v = OAuthVerifier::new("test".to_string(), "cid".to_string());
        let payload_b64 = base64::encode(&[0xFF, 0xFE, 0xFD]);
        let token = format!("header.{payload_b64}.signature");
        assert!(v.verify_token(&token).is_err());
    }

    #[allow(deprecated)]
    #[test]
    fn test_verify_jwt_invalid_json() {
        let v = OAuthVerifier::new("test".to_string(), "cid".to_string());
        let payload_b64 = base64::encode(b"not json");
        let token = format!("header.{payload_b64}.signature");
        assert!(v.verify_token(&token).is_err());
    }
}
