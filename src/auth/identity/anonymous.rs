use anyhow::Result;
use uuid::Uuid;

use async_trait::async_trait;

use crate::models::identity::Identity;

/// SPI for anonymous identity persistence.
///
/// Implement this trait to provide a storage backend for anonymous identities.
/// The crate ships [`InMemoryIdentityProvider`](crate::auth::identity::basic::InMemoryIdentityProvider)
/// for `Basic` identities only; anonymous, temporary, and service identity stores
/// are left to downstream consumers.
#[async_trait]
pub trait AnonymousIdentityProvider: Send + Sync {
    async fn create_anonymous(&self) -> Result<Identity>;
    async fn get_anonymous(&self, id: Uuid) -> Result<Option<Identity>>;
}
