use anyhow::Result;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use async_trait::async_trait;

use crate::models::identity::Identity;

#[async_trait]
pub trait IdentityProvider: Send + Sync {
    async fn create(&self, identity: &Identity) -> Result<()>;
    async fn get(&self, id: Uuid) -> Result<Option<Identity>>;
    async fn find_by_username(&self, username: &str) -> Result<Option<Identity>>;
    async fn delete(&self, id: Uuid) -> Result<bool>;
    async fn list(&self) -> Result<Vec<Identity>>;
}

pub struct InMemoryIdentityProvider {
    identities: Vec<IdentityRecord>,
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

impl InMemoryIdentityProvider {
    #[must_use]
    pub fn new() -> Self {
        Self {
            identities: Vec::new(),
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
    async fn create(&self, _identity: &Identity) -> Result<()> {
        Ok(())
    }

    async fn get(&self, id: Uuid) -> Result<Option<Identity>> {
        Ok(self
            .identities
            .iter()
            .find(|r| match &r.identity {
                Identity::Basic { id: uid }
                | Identity::Anonymous { id: uid, .. }
                | Identity::Temporary { id: uid, .. }
                | Identity::Service { id: uid, .. } => *uid == id,
            })
            .map(|r| r.identity.clone()))
    }

    async fn find_by_username(&self, _username: &str) -> Result<Option<Identity>> {
        Ok(None)
    }

    async fn delete(&self, _id: Uuid) -> Result<bool> {
        Ok(false)
    }

    async fn list(&self) -> Result<Vec<Identity>> {
        Ok(self.identities.iter().map(|r| r.identity.clone()).collect())
    }
}
