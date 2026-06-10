use anyhow::Result;
use std::collections::HashMap;
use uuid::Uuid;

use async_trait::async_trait;

use crate::{
    error::KirinoError,
    service::login::{UserDatabase, UserRecord},
};

/// In-memory implementation of [`UserDatabase`].
///
/// Stores all user records in a `HashMap<String, UserRecord>` keyed by username,
/// alongside an id-to-username index, both protected by a single
/// [`tokio::sync::RwLock`]. Suitable for testing and single-node deployments.
/// For production, replace with a persistent backend.
#[derive(Clone, Default)]
pub struct InMemoryUserDatabase {
    inner: std::sync::Arc<tokio::sync::RwLock<InMemoryUserDatabaseInner>>,
}

#[derive(Default)]
struct InMemoryUserDatabaseInner {
    users: HashMap<String, UserRecord>,
    id_to_username: HashMap<Uuid, String>,
}

impl InMemoryUserDatabase {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl UserDatabase for InMemoryUserDatabase {
    async fn create_user(&self, user: &UserRecord) -> Result<()> {
        let mut inner = self.inner.write().await;
        if inner.users.contains_key(&user.username) {
            return Err(KirinoError::Validation("username already exists".to_string()).into());
        }
        if inner.id_to_username.contains_key(&user.id) {
            return Err(KirinoError::Validation("user ID already exists".to_string()).into());
        }
        let id = user.id;
        let username = user.username.clone();
        inner.users.insert(username.clone(), user.clone());
        inner.id_to_username.insert(id, username);
        Ok(())
    }

    async fn find_by_username(&self, username: &str) -> Result<Option<UserRecord>> {
        let inner = self.inner.read().await;
        Ok(inner.users.get(username).cloned())
    }

    async fn find_by_id(&self, id: &Uuid) -> Result<Option<UserRecord>> {
        let inner = self.inner.read().await;
        if let Some(username) = inner.id_to_username.get(id) {
            Ok(inner.users.get(username).cloned())
        } else {
            Ok(None)
        }
    }

    async fn update_password(&self, id: &Uuid, new_hash: &str) -> Result<()> {
        let mut inner = self.inner.write().await;
        let username = inner
            .id_to_username
            .get(id)
            .cloned()
            .ok_or_else(|| KirinoError::NotFound("user not found".to_string()))?;
        let user = inner
            .users
            .get_mut(&username)
            .ok_or_else(|| KirinoError::NotFound("user not found".to_string()))?;
        user.password_hash = new_hash.to_string();
        user.updated_at = chrono::Utc::now();
        Ok(())
    }

    async fn delete_user(&self, id: &Uuid) -> Result<bool> {
        let mut inner = self.inner.write().await;
        let username = inner.id_to_username.remove(id);
        match username {
            Some(name) => {
                let removed = inner.users.remove(&name).is_some();
                if !removed {
                    tracing::warn!(
                        target: "kirino::database::memory",
                        "inconsistent state: id mapped to '{}' but user not found in store",
                        name
                    );
                }
                Ok(removed)
            }
            None => Ok(false),
        }
    }

    async fn list_users(&self) -> Result<Vec<UserRecord>> {
        let inner = self.inner.read().await;
        Ok(inner.users.values().cloned().collect())
    }

    async fn count_users(&self) -> Result<u64> {
        let inner = self.inner.read().await;
        Ok(inner.users.len() as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::identity::Identity;

    fn make_user(username: &str) -> UserRecord {
        let id = Uuid::now_v7();
        let now = chrono::Utc::now();
        UserRecord {
            id,
            username: username.to_string(),
            password_hash: "hash".to_string(),
            display_name: None,
            is_active: true,
            identity: Identity::Basic {
                id,
                created_at: now,
            },
            created_at: now,
            updated_at: now,
        }
    }

    #[tokio::test]
    async fn test_crud() {
        let db = InMemoryUserDatabase::new();
        let user = make_user("alice");
        db.create_user(&user).await.unwrap();

        let found = db.find_by_username("alice").await.unwrap().unwrap();
        assert_eq!(found.username, "alice");

        let listed = db.list_users().await.unwrap();
        assert_eq!(listed.len(), 1);

        let count = db.count_users().await.unwrap();
        assert_eq!(count, 1);

        assert!(db.delete_user(&user.id).await.unwrap());
        assert!(db.find_by_username("alice").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_find_by_id_existing() {
        let db = InMemoryUserDatabase::new();
        let user = make_user("alice");
        db.create_user(&user).await.unwrap();

        let found = db.find_by_id(&user.id).await.unwrap().unwrap();
        assert_eq!(found.username, "alice");
    }

    #[tokio::test]
    async fn test_find_by_id_nonexistent() {
        let db = InMemoryUserDatabase::new();
        assert!(db.find_by_id(&Uuid::now_v7()).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_find_by_username_nonexistent() {
        let db = InMemoryUserDatabase::new();
        assert!(db.find_by_username("ghost").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_update_password() {
        let db = InMemoryUserDatabase::new();
        let user = make_user("alice");
        db.create_user(&user).await.unwrap();

        db.update_password(&user.id, "new-hash").await.unwrap();
        let updated = db.find_by_username("alice").await.unwrap().unwrap();
        assert_eq!(updated.password_hash, "new-hash");
    }

    #[tokio::test]
    async fn test_update_password_nonexistent_user() {
        let db = InMemoryUserDatabase::new();
        assert!(db
            .update_password(&Uuid::now_v7(), "new-hash")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_delete_nonexistent_user() {
        let db = InMemoryUserDatabase::new();
        assert!(!db.delete_user(&Uuid::now_v7()).await.unwrap());
    }

    #[tokio::test]
    async fn test_duplicate_username_rejected() {
        let db = InMemoryUserDatabase::new();
        let u1 = make_user("alice");
        db.create_user(&u1).await.unwrap();

        let u2 = UserRecord {
            username: "alice".to_string(),
            ..make_user("alice")
        };
        let err = db.create_user(&u2).await.unwrap_err();
        assert!(err
            .downcast_ref::<KirinoError>()
            .is_some_and(|e| matches!(e, KirinoError::Validation(_))));
    }

    #[tokio::test]
    async fn test_count_users_initial() {
        let db = InMemoryUserDatabase::new();
        assert_eq!(db.count_users().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn test_list_users_empty() {
        let db = InMemoryUserDatabase::new();
        assert!(db.list_users().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_duplicate_id_rejected() {
        let db = InMemoryUserDatabase::new();
        let id = Uuid::now_v7();
        let now = chrono::Utc::now();
        let u1 = UserRecord {
            id,
            username: "alice".to_string(),
            password_hash: "hash".to_string(),
            display_name: None,
            is_active: true,
            identity: Identity::Basic {
                id,
                created_at: now,
            },
            created_at: now,
            updated_at: now,
        };
        db.create_user(&u1).await.unwrap();

        let id2 = Uuid::now_v7();
        let u2 = UserRecord {
            id,
            username: "bob".to_string(),
            password_hash: "hash".to_string(),
            display_name: None,
            is_active: true,
            identity: Identity::Basic {
                id: id2,
                created_at: now,
            },
            created_at: now,
            updated_at: now,
        };
        let err = db.create_user(&u2).await.unwrap_err();
        assert!(err
            .downcast_ref::<KirinoError>()
            .is_some_and(|e| matches!(e, KirinoError::Validation(_))));
    }
}
