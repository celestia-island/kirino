use anyhow::Result;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;

use crate::utils::constant_time_eq;

pub struct PreviousCredentialVerifier {
    store: Arc<RwLock<HashMap<String, String>>>,
}

impl PreviousCredentialVerifier {
    #[must_use]
    pub fn new() -> Self {
        Self {
            store: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn register(&self, user_id: &str, credential_hash: &str) {
        self.store
            .write()
            .await
            .insert(user_id.to_string(), credential_hash.to_string());
    }

    pub async fn verify(&self, user_id: &str, credential_hash: &str) -> Result<bool> {
        let store = self.store.read().await;
        let stored = store.get(user_id).map(|s| s.as_bytes()).unwrap_or(b"");
        let result = constant_time_eq(stored, credential_hash.as_bytes());
        Ok(result && !stored.is_empty())
    }

    pub async fn unregister(&self, user_id: &str) {
        self.store.write().await.remove(user_id);
    }
}

impl Default for PreviousCredentialVerifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_register_and_verify() {
        let v = PreviousCredentialVerifier::new();
        v.register("user-1", "hash-of-old-password").await;
        assert!(v.verify("user-1", "hash-of-old-password").await.unwrap());
    }

    #[tokio::test]
    async fn test_wrong_hash() {
        let v = PreviousCredentialVerifier::new();
        v.register("user-1", "hash-of-old-password").await;
        assert!(!v.verify("user-1", "wrong-hash").await.unwrap());
    }

    #[tokio::test]
    async fn test_unknown_user() {
        let v = PreviousCredentialVerifier::new();
        assert!(!v.verify("unknown", "any-hash").await.unwrap());
    }

    #[tokio::test]
    async fn test_unregister() {
        let v = PreviousCredentialVerifier::new();
        v.register("user-1", "hash").await;
        assert!(v.verify("user-1", "hash").await.unwrap());
        v.unregister("user-1").await;
        assert!(!v.verify("user-1", "hash").await.unwrap());
    }

    #[tokio::test]
    async fn test_overwrite_credential() {
        let v = PreviousCredentialVerifier::new();
        v.register("user-1", "old-hash").await;
        v.register("user-1", "new-hash").await;
        assert!(!v.verify("user-1", "old-hash").await.unwrap());
        assert!(v.verify("user-1", "new-hash").await.unwrap());
    }

    #[tokio::test]
    async fn test_multiple_users() {
        let v = PreviousCredentialVerifier::new();
        v.register("user-a", "hash-a").await;
        v.register("user-b", "hash-b").await;
        assert!(v.verify("user-a", "hash-a").await.unwrap());
        assert!(v.verify("user-b", "hash-b").await.unwrap());
        assert!(!v.verify("user-a", "hash-b").await.unwrap());
    }
}
