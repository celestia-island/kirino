use anyhow::{anyhow, Result};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;

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
    revocation: Arc<RwLock<HashMap<String, i64>>>,
}

impl JwtManager {
    #[must_use]
    pub fn new(secret: &str, expiration_hours: i64) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(secret.as_bytes()),
            decoding_key: DecodingKey::from_secret(secret.as_bytes()),
            expiration_hours: expiration_hours.max(1),
            revocation: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    #[allow(clippy::missing_errors_doc)]
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
            .map_err(|e| anyhow!("JWT encode failed: {e}"))
    }

    #[allow(clippy::missing_errors_doc)]
    pub fn verify(&self, token: &str) -> Result<Claims> {
        let data = decode::<Claims>(
            token,
            &self.decoding_key,
            &Validation::new(Algorithm::HS256),
        )
        .map_err(|e| anyhow!("JWT verify failed: {e}"))?;
        Ok(data.claims)
    }

    #[allow(clippy::missing_errors_doc)]
    pub async fn verify_with_revocation(&self, token: &str) -> Result<Claims> {
        let claims = self.verify(token)?;
        let revocation = self.revocation.read().await;
        if let Some(&not_before) = revocation.get(&claims.user_id) {
            if claims.iat <= not_before {
                return Err(anyhow!("token has been revoked"));
            }
        }
        Ok(claims)
    }

    pub async fn revoke_all_for_user(&self, user_id: &str) {
        let now = Utc::now().timestamp();
        let mut revocation = self.revocation.write().await;
        revocation.insert(user_id.to_string(), now);
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

    #[tokio::test]
    async fn test_revoke_all_for_user() {
        let mgr = JwtManager::new("test-secret", 24);
        let token = mgr.issue("user-1", "alice", vec!["admin".into()]).unwrap();
        let claims = mgr.verify_with_revocation(&token).await.unwrap();
        assert_eq!(claims.sub, "alice");

        mgr.revoke_all_for_user("user-1").await;
        assert!(mgr.verify_with_revocation(&token).await.is_err());
    }

    #[tokio::test]
    async fn test_new_token_after_revocation() {
        let mgr = JwtManager::new("test-secret", 24);
        let old_token = mgr.issue("user-1", "alice", vec!["admin".into()]).unwrap();
        mgr.revoke_all_for_user("user-1").await;
        assert!(mgr.verify_with_revocation(&old_token).await.is_err());

        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let new_token = mgr.issue("user-1", "alice", vec!["admin".into()]).unwrap();
        assert!(mgr.verify_with_revocation(&new_token).await.is_ok());
    }

    #[tokio::test]
    async fn test_revocation_does_not_affect_other_users() {
        let mgr = JwtManager::new("test-secret", 24);
        let token_a = mgr.issue("user-a", "alice", vec!["admin".into()]).unwrap();
        let token_b = mgr.issue("user-b", "bob", vec!["viewer".into()]).unwrap();

        mgr.revoke_all_for_user("user-a").await;
        assert!(mgr.verify_with_revocation(&token_a).await.is_err());
        assert!(mgr.verify_with_revocation(&token_b).await.is_ok());
    }
}
