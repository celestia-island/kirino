use anyhow::Result;
use uuid::Uuid;

use async_trait::async_trait;

use crate::models::identity::Identity;

/// SPI for service identity persistence.
///
/// Implement this trait to provide a storage backend for service identities.
/// The crate ships [`InMemoryIdentityProvider`](crate::auth::identity::basic::InMemoryIdentityProvider)
/// for `Basic` identities only; anonymous, temporary, and service identity stores
/// are left to downstream consumers.
#[async_trait]
pub trait ServiceIdentityProvider: Send + Sync {
    async fn create_service(&self, caller: Uuid) -> Result<Identity>;
    async fn get_service(&self, id: Uuid) -> Result<Option<Identity>>;
}
