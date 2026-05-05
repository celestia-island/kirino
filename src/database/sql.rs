use anyhow::{anyhow, Result};
use async_trait::async_trait;
use std::collections::HashMap;
use uuid::Uuid;

use crate::service::login::{UserDatabase, UserRecord};

#[derive(Clone, Default)]
pub struct InMemoryUserDatabase {
    users: std::sync::Arc<tokio::sync::RwLock<HashMap<String, UserRecord>>>,
}

impl InMemoryUserDatabase {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl UserDatabase for InMemoryUserDatabase {
    async fn create_user(&self, user: &UserRecord) -> Result<()> {
        let mut users = self.users.write().await;
        users.insert(user.username.clone(), user.clone());
        Ok(())
    }

    async fn find_by_username(&self, username: &str) -> Result<Option<UserRecord>> {
        let users = self.users.read().await;
        Ok(users.get(username).cloned())
    }

    async fn find_by_id(&self, id: &Uuid) -> Result<Option<UserRecord>> {
        let users = self.users.read().await;
        Ok(users.values().find(|u| &u.id == id).cloned())
    }

    async fn update_password(&self, id: &Uuid, new_hash: &str) -> Result<()> {
        let mut users = self.users.write().await;
        let user = users
            .values_mut()
            .find(|u| &u.id == id)
            .ok_or_else(|| anyhow!("user not found"))?;
        user.password_hash = new_hash.to_string();
        user.updated_at = chrono::Utc::now();
        Ok(())
    }

    async fn delete_user(&self, id: &Uuid) -> Result<bool> {
        let mut users = self.users.write().await;
        let username = users
            .values()
            .find(|u| &u.id == id)
            .map(|u| u.username.clone());
        match username {
            Some(name) => Ok(users.remove(&name).is_some()),
            None => Ok(false),
        }
    }

    async fn list_users(&self) -> Result<Vec<UserRecord>> {
        let users = self.users.read().await;
        Ok(users.values().cloned().collect())
    }

    async fn count_users(&self) -> Result<u64> {
        let users = self.users.read().await;
        Ok(users.len() as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::identity::Identity;

    fn make_user(username: &str) -> UserRecord {
        UserRecord {
            id: Uuid::now_v7(),
            username: username.to_string(),
            password_hash: "hash".to_string(),
            display_name: None,
            is_active: true,
            identity: Identity::Basic { id: Uuid::now_v7() },
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
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
}
