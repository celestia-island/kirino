use anyhow::{anyhow, Result};

use crate::utils::base64;

/// Reference SSO verifier that extracts claims from JWT-format tokens.
///
/// # Security Warning
///
/// This implementation does **not** verify the JWT signature. Any token with a
/// valid base64-encoded JSON payload containing a `"sub"` field will be accepted.
/// **Do not use in production.** Replace with a verifier that validates the
/// signature against the `IdP`'s public key (e.g. via the `jsonwebtoken` crate).
pub struct SsoVerifier {
    provider: String,
}

impl SsoVerifier {
    #[must_use]
    pub const fn new(provider: String) -> Self {
        Self { provider }
    }

    pub fn verify(&self, token: &str) -> Result<SsoClaims> {
        if token.is_empty() {
            return Err(anyhow!("empty SSO token"));
        }
        if token.split('.').count() == 3 {
            return self.verify_jwt_sso(token);
        }
        Err(anyhow!(
            "opaque SSO token for '{}' requires external validation; implement a custom SsoProvider",
            self.provider
        ))
    }

    fn verify_jwt_sso(&self, token: &str) -> Result<SsoClaims> {
        let parts: Vec<&str> = token.split('.').collect();
        let payload_b64 = parts.get(1).ok_or_else(|| anyhow!("malformed JWT"))?;

        let decoded = base64::decode_url_safe(payload_b64)?;
        let payload_str =
            String::from_utf8(decoded).map_err(|_| anyhow!("invalid UTF-8 in SSO payload"))?;
        let payload: serde_json::Value =
            serde_json::from_str(&payload_str).map_err(|e| anyhow!("JSON parse: {e}"))?;

        let user_id = payload["sub"]
            .as_str()
            .ok_or_else(|| anyhow!("missing 'sub' in SSO token"))?
            .to_string();
        let email = payload["email"].as_str().map(String::from);

        Ok(SsoClaims {
            user_id,
            email,
            provider: self.provider.clone(),
        })
    }
}

pub struct SsoClaims {
    pub user_id: String,
    pub email: Option<String>,
    pub provider: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_token() {
        let v = SsoVerifier::new("test".to_string());
        assert!(v.verify("").is_err());
    }

    #[test]
    fn test_opaque_token_not_supported() {
        let v = SsoVerifier::new("test".to_string());
        assert!(v.verify("opaque-token").is_err());
    }

    fn make_jwt_payload(sub: &str, email: Option<&str>) -> String {
        use std::fmt::Write;
        let mut json = format!(r#"{{"sub":"{sub}""#);
        if let Some(e) = email {
            let _ = write!(json, r#","email":"{e}""#);
        }
        json.push('}');
        let b64 = crate::utils::base64::url_safe_encode(json.as_bytes());
        format!("header.{b64}.signature")
    }

    #[test]
    fn test_jwt_sso_extracts_claims() {
        let v = SsoVerifier::new("test".to_string());
        let token = make_jwt_payload("user-1", Some("user@example.com"));
        let claims = v.verify(&token).unwrap();
        assert_eq!(claims.user_id, "user-1");
        assert_eq!(claims.email, Some("user@example.com".to_string()));
    }

    #[test]
    fn test_jwt_sso_missing_sub() {
        let payload = crate::utils::base64::url_safe_encode(b"{\"email\":\"a@b.com\"}");
        let token = format!("header.{payload}.sig");
        let v = SsoVerifier::new("test".to_string());
        assert!(v.verify(&token).is_err());
    }
}
