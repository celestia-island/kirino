use anyhow::Result;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use async_trait::async_trait;

use crate::models::identity::Identity;

/// SPI for temporary identity persistence.
///
/// Implement this trait to provide a storage backend for temporary (time-limited) identities.
/// The crate ships [`InMemoryIdentityProvider`](crate::auth::identity::basic::InMemoryIdentityProvider)
/// for `Basic` identities only; temporary identity stores are left to downstream consumers.
#[async_trait]
pub trait TemporaryIdentityProvider: Send + Sync {
    async fn create_temporary(&self, expires_at: DateTime<Utc>) -> Result<Identity>;
    async fn get_temporary(&self, id: Uuid) -> Result<Option<Identity>>;
    async fn is_expired(&self, id: Uuid) -> Result<bool>;

    /// Marks the temporary identity identified by `id` as revoked.
    ///
    /// Revocation is idempotent: revoking an already-revoked id returns `Ok(())`.
    /// It is also permanent: the same id is never un-revoked, so later calls to
    /// [`Self::is_revoked`] keep reporting `true`. Revoking an id that was
    /// never issued is not an error either: the flag is recorded and
    /// [`Self::is_revoked`] reports `true` for it, which keeps the whole
    /// surface answerable without an existence lookup.
    async fn revoke_temporary(&self, id: Uuid) -> Result<()>;

    /// Returns whether `id` carries the revocation flag.
    ///
    /// This answers the revocation bit only and stays orthogonal to expiry: an
    /// expired identity that was never revoked reports `false`. Any id that
    /// has not been revoked reports `false`. Callers compose `is_expired` and
    /// `is_revoked` themselves when they need the broader "unusable" verdict —
    /// and must confirm existence via [`Self::get_temporary`] first: a
    /// never-issued id reports `false` on both checks and would otherwise be
    /// mistaken for a usable one.
    async fn is_revoked(&self, id: Uuid) -> Result<bool>;
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use chrono::Duration;
    use tokio::sync::RwLock;

    use super::*;

    /// Minimal in-memory implementation used to pin the SPI contract.
    struct InMemoryTemporaryProvider {
        identities: RwLock<Vec<Identity>>,
        revoked: RwLock<HashSet<Uuid>>,
    }

    impl InMemoryTemporaryProvider {
        fn new() -> Self {
            Self {
                identities: RwLock::new(Vec::new()),
                revoked: RwLock::new(HashSet::new()),
            }
        }
    }

    fn temporary_id(identity: &Identity) -> Uuid {
        let Identity::Temporary { id, .. } = identity else {
            panic!("expected a temporary identity");
        };
        *id
    }

    #[async_trait]
    impl TemporaryIdentityProvider for InMemoryTemporaryProvider {
        async fn create_temporary(&self, expires_at: DateTime<Utc>) -> Result<Identity> {
            let identity = Identity::Temporary {
                id: Uuid::now_v7(),
                expires_at,
            };
            self.identities.write().await.push(identity.clone());
            Ok(identity)
        }

        async fn get_temporary(&self, id: Uuid) -> Result<Option<Identity>> {
            Ok(self
                .identities
                .read()
                .await
                .iter()
                .find(|i| temporary_id(i) == id)
                .cloned())
        }

        async fn is_expired(&self, id: Uuid) -> Result<bool> {
            Ok(self
                .get_temporary(id)
                .await?
                .is_some_and(|identity| match identity {
                    Identity::Temporary { expires_at, .. } => expires_at < Utc::now(),
                    _ => false,
                }))
        }

        async fn revoke_temporary(&self, id: Uuid) -> Result<()> {
            self.revoked.write().await.insert(id);
            Ok(())
        }

        async fn is_revoked(&self, id: Uuid) -> Result<bool> {
            Ok(self.revoked.read().await.contains(&id))
        }
    }

    #[tokio::test]
    async fn revoke_is_idempotent_and_permanent() {
        let provider = InMemoryTemporaryProvider::new();
        let identity = provider
            .create_temporary(Utc::now() + Duration::hours(1))
            .await
            .unwrap();
        let id = temporary_id(&identity);

        assert!(!provider.is_expired(id).await.unwrap());
        assert!(!provider.is_revoked(id).await.unwrap());

        provider.revoke_temporary(id).await.unwrap();
        assert!(provider.is_revoked(id).await.unwrap());

        // Revoking again still succeeds and the id stays revoked.
        provider.revoke_temporary(id).await.unwrap();
        assert!(provider.is_revoked(id).await.unwrap());

        // Revoking a never-issued id is not an error and records the flag.
        let unknown = Uuid::now_v7();
        provider.revoke_temporary(unknown).await.unwrap();
        assert!(provider.is_revoked(unknown).await.unwrap());
    }

    #[tokio::test]
    async fn is_revoked_stays_orthogonal_to_expiry() {
        let provider = InMemoryTemporaryProvider::new();
        let identity = provider
            .create_temporary(Utc::now() - Duration::hours(1))
            .await
            .unwrap();
        let id = temporary_id(&identity);

        assert!(provider.is_expired(id).await.unwrap());
        // Expired is not revoked: is_revoked answers the revocation bit only.
        assert!(!provider.is_revoked(id).await.unwrap());
    }
}
