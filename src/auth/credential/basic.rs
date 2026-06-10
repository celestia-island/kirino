use anyhow::{anyhow, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;

use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub user_id: String,
    pub roles: Vec<String>,
    #[serde(default)]
    pub permissions: Vec<String>,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub jti: Option<String>,
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

const MIN_JWT_SECRET_LENGTH: usize = 32;
const MAX_JWT_EXPIRATION_HOURS: i64 = 87600;
const REVOCATION_MAX_ENTRIES: usize = 50_000;
const REVOCATION_AUTO_CLEANUP_WINDOW_SECS: i64 = 86400 * 7;

impl JwtManager {
    pub fn new(secret: &str, expiration_hours: i64) -> Result<Self> {
        if secret.len() < MIN_JWT_SECRET_LENGTH {
            return Err(anyhow!(
                "JWT secret must be at least {MIN_JWT_SECRET_LENGTH} bytes for HS256 security"
            ));
        }
        Ok(Self {
            encoding_key: EncodingKey::from_secret(secret.as_bytes()),
            decoding_key: DecodingKey::from_secret(secret.as_bytes()),
            expiration_hours: expiration_hours.clamp(1, MAX_JWT_EXPIRATION_HOURS),
            revocation: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Issues a JWT for the given user.
    ///
    /// # Errors
    ///
    /// Returns an error if JWT encoding fails.
    pub fn issue(&self, user_id: &str, username: &str, roles: Vec<String>) -> Result<String> {
        self.issue_with_options(user_id, username, roles, vec![], None)
    }

    /// Issues a JWT with optional permissions and session ID.
    ///
    /// # Errors
    ///
    /// Returns an error if JWT encoding fails.
    pub fn issue_with_options(
        &self,
        user_id: &str,
        username: &str,
        roles: Vec<String>,
        permissions: Vec<String>,
        session_id: Option<String>,
    ) -> Result<String> {
        let now = Utc::now();
        let claims = Claims {
            sub: username.to_string(),
            user_id: user_id.to_string(),
            roles,
            permissions,
            session_id,
            jti: Some(uuid::Uuid::now_v7().to_string()),
            iat: now.timestamp(),
            exp: (now + chrono::Duration::hours(self.expiration_hours)).timestamp(),
        };
        encode(&Header::default(), &claims, &self.encoding_key)
            .map_err(|e| anyhow!("JWT encode failed: {e}"))
    }

    /// Verifies a JWT and returns the decoded claims.
    ///
    /// # Errors
    ///
    /// Returns an error if the token is invalid, expired, or has an invalid signature.
    pub fn verify(&self, token: &str) -> Result<Claims> {
        let data = decode::<Claims>(
            token,
            &self.decoding_key,
            &Validation::new(Algorithm::HS256),
        )
        .map_err(|e| anyhow!("JWT verify failed: {e}"))?;
        Ok(data.claims)
    }

    /// Verifies a JWT and checks it against the revocation list.
    ///
    /// # Errors
    ///
    /// Returns an error if the token is invalid, expired, or has been revoked.
    pub async fn verify_with_revocation(&self, token: &str) -> Result<Claims> {
        let claims = self.verify(token)?;
        let revocation = self.revocation.read().await;
        if let Some(&not_before) = revocation.get(&claims.user_id) {
            if claims.iat <= not_before {
                return Err(anyhow!("token has been revoked"));
            }
        }
        if let Some(ref jti) = claims.jti {
            if let Some(&not_before) = revocation.get(jti) {
                if claims.iat <= not_before {
                    return Err(anyhow!("token has been revoked"));
                }
            }
        }
        if let Some(ref sid) = claims.session_id {
            let key = format!("session:{sid}");
            if let Some(&not_before) = revocation.get(&key) {
                if claims.iat <= not_before {
                    return Err(anyhow!("token has been revoked"));
                }
            }
        }
        Ok(claims)
    }

    pub async fn revoke_token(&self, jti: &str) {
        let not_before = Utc::now().timestamp();
        let mut revocation = self.revocation.write().await;
        revocation.insert(jti.to_string(), not_before);
    }

    pub async fn revoke_all_for_user(&self, user_id: &str) {
        let not_before = Utc::now().timestamp() + 1;
        let mut revocation = self.revocation.write().await;
        revocation.insert(user_id.to_string(), not_before);
        if revocation.len() > REVOCATION_MAX_ENTRIES {
            let cutoff = not_before - REVOCATION_AUTO_CLEANUP_WINDOW_SECS;
            revocation.retain(|_, &mut nb| nb >= cutoff);
        }
    }

    pub async fn revoke_session(&self, session_id: &str) {
        let not_before = Utc::now().timestamp();
        let mut revocation = self.revocation.write().await;
        revocation.insert(format!("session:{session_id}"), not_before);
        if revocation.len() > REVOCATION_MAX_ENTRIES {
            let cutoff = not_before - REVOCATION_AUTO_CLEANUP_WINDOW_SECS;
            revocation.retain(|_, &mut nb| nb >= cutoff);
        }
    }

    pub async fn cleanup_revocation(&self, max_token_lifetime_secs: i64) {
        let cutoff = Utc::now().timestamp() - max_token_lifetime_secs;
        let mut revocation = self.revocation.write().await;
        revocation.retain(|_, &mut not_before| not_before >= cutoff);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_mgr() -> JwtManager {
        JwtManager::new("test-secret-that-is-at-least-32-bytes-long", 24).unwrap()
    }

    #[test]
    fn test_issue_and_verify() {
        let mgr = make_mgr();
        let token = mgr.issue("user-1", "alice", vec!["admin".into()]).unwrap();
        let claims = mgr.verify(&token).unwrap();
        assert_eq!(claims.sub, "alice");
        assert_eq!(claims.user_id, "user-1");
        assert_eq!(claims.roles, vec!["admin".to_string()]);
    }

    #[test]
    fn test_invalid_token() {
        let mgr = make_mgr();
        assert!(mgr.verify("garbage.token.here").is_err());
    }

    #[test]
    fn test_tampered_token() {
        let mgr = make_mgr();
        let token = mgr.issue("user-1", "alice", vec!["admin".into()]).unwrap();
        let tampered = format!("{}.TAMPERED.{}", &token[..20], &token[token.len() - 20..]);
        assert!(mgr.verify(&tampered).is_err());
    }

    #[test]
    fn test_secret_too_short_returns_error() {
        assert!(JwtManager::new("short", 24).is_err());
    }

    #[test]
    fn test_expiration_hours_minimum_one() {
        let mgr = JwtManager::new("test-secret-that-is-at-least-32-bytes-long", 0).unwrap();
        let token = mgr.issue("u1", "user", vec![]).unwrap();
        let claims = mgr.verify(&token).unwrap();
        assert!(claims.exp > claims.iat);
    }

    #[tokio::test]
    async fn test_revoke_all_for_user() {
        let mgr = make_mgr();
        let token = mgr.issue("user-1", "alice", vec!["admin".into()]).unwrap();
        let claims = mgr.verify_with_revocation(&token).await.unwrap();
        assert_eq!(claims.sub, "alice");

        mgr.revoke_all_for_user("user-1").await;
        assert!(mgr.verify_with_revocation(&token).await.is_err());
    }

    #[tokio::test]
    async fn test_new_token_after_revocation() {
        let mgr = make_mgr();
        let old_token = mgr.issue("user-1", "alice", vec!["admin".into()]).unwrap();
        mgr.revoke_all_for_user("user-1").await;
        assert!(mgr.verify_with_revocation(&old_token).await.is_err());

        // Wait for the not_before window (now + 1) to pass
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let new_token = mgr.issue("user-1", "alice", vec!["admin".into()]).unwrap();
        assert!(mgr.verify_with_revocation(&new_token).await.is_ok());
    }

    #[tokio::test]
    async fn test_revocation_does_not_affect_other_users() {
        let mgr = make_mgr();
        let token_a = mgr.issue("user-a", "alice", vec!["admin".into()]).unwrap();
        let token_b = mgr.issue("user-b", "bob", vec!["viewer".into()]).unwrap();

        mgr.revoke_all_for_user("user-a").await;
        assert!(mgr.verify_with_revocation(&token_a).await.is_err());
        assert!(mgr.verify_with_revocation(&token_b).await.is_ok());
    }

    #[tokio::test]
    async fn test_cleanup_revocation() {
        let mgr = make_mgr();
        mgr.revoke_all_for_user("user-1").await;
        mgr.revoke_all_for_user("user-2").await;

        // Use a small positive lifetime to ensure entries are cleaned up
        // while accounting for the +1 second offset in revoke_all_for_user.
        const CLEANUP_WINDOW: i64 = 3;
        tokio::time::sleep(std::time::Duration::from_secs(CLEANUP_WINDOW as u64)).await;
        mgr.cleanup_revocation(CLEANUP_WINDOW).await;

        let token = mgr.issue("user-1", "alice", vec![]).unwrap();
        assert!(mgr.verify_with_revocation(&token).await.is_ok());
    }

    #[test]
    fn test_issue_with_permissions_and_session() {
        let mgr = make_mgr();
        let token = mgr
            .issue_with_options(
                "user-1",
                "alice",
                vec!["admin".into()],
                vec!["read".into(), "write".into()],
                Some("sess-123".into()),
            )
            .unwrap();
        let claims = mgr.verify(&token).unwrap();
        assert_eq!(claims.permissions, vec!["read", "write"]);
        assert_eq!(claims.session_id, Some("sess-123".to_string()));
    }

    #[test]
    fn test_backward_compat_old_token_deserialize() {
        let mgr = make_mgr();
        let token = mgr.issue("user-1", "alice", vec!["admin".into()]).unwrap();
        let claims = mgr.verify(&token).unwrap();
        assert!(claims.permissions.is_empty());
        assert!(claims.session_id.is_none());
    }

    #[test]
    fn test_claims_serializable() {
        let mgr = make_mgr();
        let token = mgr
            .issue_with_options("u1", "user", vec!["role".into()], vec!["perm".into()], None)
            .unwrap();
        let claims = mgr.verify(&token).unwrap();
        let json = serde_json::to_string(&claims).unwrap();
        assert!(json.contains("\"sub\":\"user\""));
        assert!(json.contains("\"permissions\":[\"perm\"]"));
    }
}
