use anyhow::Result;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use async_trait::async_trait;

use crate::models::identity::Identity;

#[async_trait]
pub trait TemporaryIdentityProvider: Send + Sync {
    async fn create_temporary(&self, expires_at: DateTime<Utc>) -> Result<Identity>;
    async fn get_temporary(&self, id: Uuid) -> Result<Option<Identity>>;
    async fn is_expired(&self, id: Uuid) -> Result<bool>;
}
