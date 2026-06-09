use anyhow::Result;
use rand::Rng;
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::RwLock;

use async_trait::async_trait;

use crate::utils::constant_time_eq;

pub struct OneTimeCredential {
    token: String,
    used: bool,
}

impl OneTimeCredential {
    #[must_use]
    pub fn new(token: &str) -> Self {
        Self {
            token: token.to_string(),
            used: false,
        }
    }

    #[must_use]
    pub fn generate() -> Self {
        let token = Self::generate_token(32);
        Self { token, used: false }
    }

    #[must_use]
    pub fn token(&self) -> &str {
        &self.token
    }

    #[must_use]
    pub fn is_used(&self) -> bool {
        self.used
    }

    fn generate_token(len: usize) -> String {
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        let mut rng = rand::thread_rng();
        (0..len)
            .map(|_| {
                let idx = rng.gen_range(0..CHARSET.len());
                char::from(CHARSET[idx])
            })
            .collect()
    }
}

impl super::Credential for OneTimeCredential {
    fn verify(&self, token: &str) -> Result<bool> {
        if self.used {
            return Ok(false);
        }
        Ok(constant_time_eq(self.token.as_bytes(), token.as_bytes()))
    }
}

struct PendingToken {
    expires_at: Instant,
}

pub struct InMemoryOneTimeStore {
    tokens: Arc<RwLock<HashMap<String, PendingToken>>>,
}

impl InMemoryOneTimeStore {
    #[must_use]
    pub fn new() -> Self {
        Self {
            tokens: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl Default for InMemoryOneTimeStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
pub trait OneTimeStore: Send + Sync {
    async fn claim(&self, token: &str) -> Result<bool>;
    async fn issue(&self, ttl_secs: u64) -> Result<String>;
}

fn hash_token(token: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    format!("{:x}", hasher.finalize())
}

#[async_trait]
impl OneTimeStore for InMemoryOneTimeStore {
    async fn claim(&self, token: &str) -> Result<bool> {
        let hash = hash_token(token);
        let mut tokens = self.tokens.write().await;
        if let Some(pending) = tokens.remove(&hash) {
            if Instant::now() < pending.expires_at {
                return Ok(true);
            }
        }
        Ok(false)
    }

    async fn issue(&self, ttl_secs: u64) -> Result<String> {
        let cred = OneTimeCredential::generate();
        let token = cred.token().to_string();
        let hash = hash_token(&token);
        let mut tokens = self.tokens.write().await;
        tokens.insert(
            hash,
            PendingToken {
                expires_at: Instant::now() + Duration::from_secs(ttl_secs),
            },
        );
        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::credential::Credential;

    #[test]
    fn test_generate_and_verify() {
        let cred = OneTimeCredential::generate();
        let token = cred.token().to_string();
        assert!(!cred.is_used());
        assert!(cred.verify(&token).unwrap());
    }

    #[test]
    fn test_wrong_token() {
        let cred = OneTimeCredential::generate();
        assert!(!cred.verify("wrong-token").unwrap());
    }

    #[test]
    fn test_credential_is_one_time() {
        let cred = OneTimeCredential::generate();
        let token = cred.token().to_string();

        let mut cred = cred;
        assert!(cred.verify(&token).unwrap());

        cred.used = true;
        assert!(!cred.verify(&token).unwrap());
    }

    #[test]
    fn test_new_credential() {
        let cred = OneTimeCredential::new("my-token-12345678901234567890");
        assert_eq!(cred.token(), "my-token-12345678901234567890");
        assert!(!cred.is_used());
        assert!(cred.verify("my-token-12345678901234567890").unwrap());
    }

    #[test]
    fn test_generate_unique_tokens() {
        let a = OneTimeCredential::generate();
        let b = OneTimeCredential::generate();
        assert_ne!(a.token(), b.token());
    }

    #[tokio::test]
    async fn test_store_issue_and_claim() {
        let store = InMemoryOneTimeStore::new();
        let token = store.issue(300).await.unwrap();
        assert!(!token.is_empty());
        assert!(store.claim(&token).await.unwrap());
        assert!(!store.claim(&token).await.unwrap());
    }

    #[tokio::test]
    async fn test_store_claim_unknown_token() {
        let store = InMemoryOneTimeStore::new();
        assert!(!store.claim("nonexistent").await.unwrap());
    }

    #[tokio::test]
    async fn test_store_tokens_are_hashed() {
        let store = InMemoryOneTimeStore::new();
        let token = store.issue(300).await.unwrap();
        let tokens = store.tokens.read().await;
        assert!(!tokens.contains_key(&token));
        let hash = hash_token(&token);
        assert!(tokens.contains_key(&hash));
    }

    #[tokio::test]
    async fn test_store_issue_multiple() {
        let store = InMemoryOneTimeStore::new();
        let t1 = store.issue(300).await.unwrap();
        let t2 = store.issue(300).await.unwrap();
        assert_ne!(t1, t2);
        assert!(store.claim(&t1).await.unwrap());
        assert!(store.claim(&t2).await.unwrap());
    }
}
