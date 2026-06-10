use anyhow::Result;
use rand::Rng;
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::sync::RwLock;

use async_trait::async_trait;

use crate::utils::constant_time_eq;

pub struct OneTimeCredential {
    token: String,
    used: AtomicBool,
}

const TOKEN_LENGTH: usize = 32;

impl OneTimeCredential {
    #[must_use]
    pub fn new(token: &str) -> Self {
        Self {
            token: token.to_string(),
            used: AtomicBool::new(false),
        }
    }

    #[must_use]
    pub fn generate() -> Self {
        let token = Self::generate_token(TOKEN_LENGTH);
        Self {
            token,
            used: AtomicBool::new(false),
        }
    }

    #[must_use]
    pub fn token(&self) -> &str {
        &self.token
    }

    #[must_use]
    pub fn is_used(&self) -> bool {
        self.used.load(Ordering::SeqCst)
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
        if self.used.load(Ordering::SeqCst) {
            return Ok(false);
        }
        if constant_time_eq(self.token.as_bytes(), token.as_bytes()) {
            self.used.store(true, Ordering::SeqCst);
            return Ok(true);
        }
        Ok(false)
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

    #[must_use]
    pub async fn cleanup_expired(&self) -> usize {
        let mut tokens = self.tokens.write().await;
        let before = tokens.len();
        tokens.retain(|_, v| Instant::now() < v.expires_at);
        before - tokens.len()
    }
}

impl Default for InMemoryOneTimeStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
pub trait OneTimeStore: Send + Sync {
    #[must_use]
    async fn claim(&self, token: &str) -> Result<bool>;
    #[must_use]
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
        assert!(cred.verify(&token).unwrap());
        assert!(cred.is_used());
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

    #[tokio::test]
    async fn test_store_expired_token_rejected() {
        let store = InMemoryOneTimeStore::new();
        let token = store.issue(0).await.unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(!store.claim(&token).await.unwrap());
    }

    #[tokio::test]
    async fn test_cleanup_expired() {
        let store = InMemoryOneTimeStore::new();
        let t1 = store.issue(0).await.unwrap();
        let t2 = store.issue(300).await.unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
        let removed = store.cleanup_expired().await;
        assert_eq!(removed, 1);
        assert!(!store.claim(&t1).await.unwrap());
        assert!(store.claim(&t2).await.unwrap());
    }

    #[tokio::test]
    async fn test_cleanup_nothing_when_all_valid() {
        let store = InMemoryOneTimeStore::new();
        store.issue(300).await.unwrap();
        store.issue(300).await.unwrap();
        assert_eq!(store.cleanup_expired().await, 0);
    }
}
