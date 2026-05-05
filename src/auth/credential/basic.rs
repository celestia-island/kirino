use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};

use anyhow::{anyhow, Result};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub user_id: String,
    pub roles: Vec<String>,
    pub iat: i64,
    pub exp: i64,
}

#[derive(Clone)]
pub struct JwtManager {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    expiration_hours: i64,
}

impl JwtManager {
    pub fn new(secret: &str, expiration_hours: i64) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(secret.as_bytes()),
            decoding_key: DecodingKey::from_secret(secret.as_bytes()),
            expiration_hours,
        }
    }

    pub fn issue(&self, user_id: &str, username: &str, roles: Vec<String>) -> Result<String> {
        let now = Utc::now();
        let claims = Claims {
            sub: username.to_string(),
            user_id: user_id.to_string(),
            roles,
            iat: now.timestamp(),
            exp: (now + Duration::hours(self.expiration_hours)).timestamp(),
        };
        encode(&Header::default(), &claims, &self.encoding_key)
            .map_err(|e| anyhow!("JWT encode failed: {}", e))
    }

    pub fn verify(&self, token: &str) -> Result<Claims> {
        let data = decode::<Claims>(
            token,
            &self.decoding_key,
            &Validation::new(Algorithm::HS256),
        )
        .map_err(|e| anyhow!("JWT verify failed: {}", e))?;
        Ok(data.claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_issue_and_verify() {
        let mgr = JwtManager::new("test-secret", 24);
        let token = mgr.issue("user-1", "alice", vec!["admin".into()]).unwrap();
        let claims = mgr.verify(&token).unwrap();
        assert_eq!(claims.sub, "alice");
        assert_eq!(claims.user_id, "user-1");
        assert_eq!(claims.roles, vec!["admin".to_string()]);
    }

    #[test]
    fn test_invalid_token() {
        let mgr = JwtManager::new("test-secret", 24);
        assert!(mgr.verify("garbage.token.here").is_err());
    }
}
