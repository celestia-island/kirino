use anyhow::Result;
use uuid::Uuid;

use async_trait::async_trait;

use crate::models::identity::Identity;

#[async_trait]
pub trait AnonymousIdentityProvider: Send + Sync {
    async fn create_anonymous(&self) -> Result<Identity>;
    async fn get_anonymous(&self, id: Uuid) -> Result<Option<Identity>>;
}
