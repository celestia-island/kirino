use chrono::{DateTime, Utc};
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use async_trait::async_trait;

use crate::{
    error::{KirinoError, KirinoResult},
    models::identity::Identity,
};

fn identity_id(identity: &Identity) -> Uuid {
    match identity {
        Identity::Basic { id } => *id,
        Identity::Anonymous { id, .. } => *id,
        Identity::Temporary { id, .. } => *id,
        Identity::Service { id, .. } => *id,
    }
}

#[async_trait]
pub trait IdentityProvider: Send + Sync {
    async fn create(&self, record: IdentityRecord) -> KirinoResult<()>;
    async fn get(&self, id: Uuid) -> KirinoResult<Option<IdentityRecord>>;
    async fn find_by_username(&self, username: &str) -> KirinoResult<Option<IdentityRecord>>;
    async fn delete(&self, id: Uuid) -> KirinoResult<bool>;
    async fn list(&self) -> KirinoResult<Vec<IdentityRecord>>;
}

#[derive(Debug, Clone)]
pub struct IdentityRecord {
    pub identity: Identity,
    pub username: String,
    pub password_hash: String,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub struct InMemoryIdentityProvider {
    records: Arc<RwLock<Vec<IdentityRecord>>>,
}

impl InMemoryIdentityProvider {
    #[must_use]
    pub fn new() -> Self {
        Self {
            records: Arc::new(RwLock::new(Vec::new())),
        }
    }
}

impl Default for InMemoryIdentityProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl IdentityProvider for InMemoryIdentityProvider {
    async fn create(&self, record: IdentityRecord) -> KirinoResult<()> {
        let mut records = self.records.write().await;
        if records.iter().any(|r| r.username == record.username) {
            return Err(KirinoError::Validation(
                "username already exists".to_string(),
            ));
        }
        if records
            .iter()
            .any(|r| identity_id(&r.identity) == identity_id(&record.identity))
        {
            return Err(KirinoError::Validation(
                "identity already exists".to_string(),
            ));
        }
        records.push(record);
        Ok(())
    }

    async fn get(&self, id: Uuid) -> KirinoResult<Option<IdentityRecord>> {
        let records = self.records.read().await;
        Ok(records
            .iter()
            .find(|r| identity_id(&r.identity) == id)
            .cloned())
    }

    async fn find_by_username(&self, username: &str) -> KirinoResult<Option<IdentityRecord>> {
        let records = self.records.read().await;
        Ok(records.iter().find(|r| r.username == username).cloned())
    }

    async fn delete(&self, id: Uuid) -> KirinoResult<bool> {
        let mut records = self.records.write().await;
        let before = records.len();
        records.retain(|r| identity_id(&r.identity) != id);
        Ok(records.len() < before)
    }

    async fn list(&self) -> KirinoResult<Vec<IdentityRecord>> {
        let records = self.records.read().await;
        Ok(records.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_record(username: &str) -> IdentityRecord {
        let id = Uuid::now_v7();
        let now = Utc::now();
        IdentityRecord {
            identity: Identity::Basic { id },
            username: username.to_string(),
            password_hash: "hashed".to_string(),
            is_active: true,
            created_at: now,
            updated_at: now,
        }
    }

    #[tokio::test]
    async fn test_create_and_get() {
        let provider = InMemoryIdentityProvider::new();
        let record = make_record("alice");
        let id = identity_id(&record.identity);

        provider.create(record).await.unwrap();
        let found = provider.get(id).await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().username, "alice");
    }

    #[tokio::test]
    async fn test_get_nonexistent() {
        let provider = InMemoryIdentityProvider::new();
        let found = provider.get(Uuid::now_v7()).await.unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn test_find_by_username() {
        let provider = InMemoryIdentityProvider::new();
        provider.create(make_record("bob")).await.unwrap();
        provider.create(make_record("charlie")).await.unwrap();

        let found = provider.find_by_username("bob").await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().username, "bob");

        let not_found = provider.find_by_username("dave").await.unwrap();
        assert!(not_found.is_none());
    }

    #[tokio::test]
    async fn test_delete() {
        let provider = InMemoryIdentityProvider::new();
        let record = make_record("eve");
        let id = identity_id(&record.identity);

        provider.create(record).await.unwrap();
        assert!(provider.delete(id).await.unwrap());
        assert!(provider.get(id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_delete_nonexistent() {
        let provider = InMemoryIdentityProvider::new();
        assert!(!provider.delete(Uuid::now_v7()).await.unwrap());
    }

    #[tokio::test]
    async fn test_list() {
        let provider = InMemoryIdentityProvider::new();
        provider.create(make_record("u1")).await.unwrap();
        provider.create(make_record("u2")).await.unwrap();
        provider.create(make_record("u3")).await.unwrap();

        let list = provider.list().await.unwrap();
        assert_eq!(list.len(), 3);
    }

    #[tokio::test]
    async fn test_list_empty() {
        let provider = InMemoryIdentityProvider::new();
        let list = provider.list().await.unwrap();
        assert!(list.is_empty());
    }

    #[tokio::test]
    async fn test_create_duplicate_username_rejected() {
        let provider = InMemoryIdentityProvider::new();
        provider.create(make_record("alice")).await.unwrap();
        let err = provider.create(make_record("alice")).await.unwrap_err();
        assert!(matches!(err, KirinoError::Validation(_)));
    }
}
