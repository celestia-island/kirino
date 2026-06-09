use anyhow::Result;
use uuid::Uuid;

use async_trait::async_trait;

use crate::models::identity::Identity;

#[async_trait]
pub trait ServiceIdentityProvider: Send + Sync {
    async fn create_service(&self, caller: Uuid) -> Result<Identity>;
    async fn get_service(&self, id: Uuid) -> Result<Option<Identity>>;
}
