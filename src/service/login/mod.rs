use anyhow::{anyhow, Result};
use chrono::Utc;
use uuid::Uuid;

use crate::auth::credential::basic::JwtManager;
use crate::auth::passport::static_password::{hash_password, verify_password};
use crate::rbac::{RbacStore, Role};
use crate::models::identity::Identity;

#[derive(Debug, Clone)]
pub struct UserRecord {
    pub id: Uuid,
    pub username: String,
    pub password_hash: String,
    pub display_name: Option<String>,
    pub is_active: bool,
    pub identity: Identity,
    pub created_at: chrono::DateTime<Utc>,
    pub updated_at: chrono::DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct LoginResult {
    pub token: String,
    pub user_id: String,
    pub username: String,
    pub display_name: Option<String>,
    pub roles: Vec<String>,
}

pub struct AuthService<DB> {
    db: DB,
    jwt: JwtManager,
    rbac: std::sync::Arc<tokio::sync::RwLock<RbacStore>>,
}

impl<DB: UserDatabase> AuthService<DB> {
    pub fn new(db: DB, jwt_secret: &str, jwt_expiration_hours: i64) -> Self {
        Self {
            db,
            jwt: JwtManager::new(jwt_secret, jwt_expiration_hours),
            rbac: std::sync::Arc::new(tokio::sync::RwLock::new(RbacStore::new())),
        }
    }

    pub fn with_rbac(mut self, rbac: std::sync::Arc<tokio::sync::RwLock<RbacStore>>) -> Self {
        self.rbac = rbac;
        self
    }

    pub fn rbac(&self) -> std::sync::Arc<tokio::sync::RwLock<RbacStore>> {
        self.rbac.clone()
    }

    pub fn jwt_manager(&self) -> &JwtManager {
        &self.jwt
    }

    pub async fn register(
        &self,
        username: &str,
        password: &str,
        display_name: Option<&str>,
    ) -> Result<UserRecord> {
        if username.trim().is_empty() {
            return Err(anyhow!("username must not be empty"));
        }
        if password.len() < 6 {
            return Err(anyhow!("password must be at least 6 characters"));
        }

        if self.db.find_by_username(username).await?.is_some() {
            return Err(anyhow!("username already exists"));
        }

        let password_hash = hash_password(password)?;
        let user_id = Uuid::now_v7();
        let now = Utc::now();
        let identity = Identity::Basic { id: user_id };

        let user = UserRecord {
            id: user_id,
            username: username.to_string(),
            password_hash,
            display_name: display_name.map(|s| s.to_string()),
            is_active: true,
            identity,
            created_at: now,
            updated_at: now,
        };

        self.db.create_user(&user).await?;

        let is_first = self.db.count_users().await? <= 1;
        let default_role = if is_first {
            Role::Admin
        } else {
            Role::Viewer
        };

        {
            let mut rbac = self.rbac.write().await;
            rbac.assign_role(&user_id.to_string(), default_role);
        }

        Ok(user)
    }

    pub async fn login(&self, username: &str, password: &str) -> Result<LoginResult> {
        let user = self
            .db
            .find_by_username(username)
            .await?
            .ok_or_else(|| anyhow!("invalid credentials"))?;

        if !user.is_active {
            return Err(anyhow!("account disabled"));
        }

        if !verify_password(password, &user.password_hash)? {
            return Err(anyhow!("invalid credentials"));
        }

        let user_id = user.id.to_string();
        let rbac = self.rbac.read().await;
        let roles: Vec<String> = rbac
            .get_user(&user_id)
            .map(|ur| ur.roles.iter().map(|r| format!("{:?}", r)).collect())
            .unwrap_or_default();
        drop(rbac);

        let token = self.jwt.issue(&user_id, &user.username, roles.clone())?;

        Ok(LoginResult {
            token,
            user_id,
            username: user.username.clone(),
            display_name: user.display_name.clone(),
            roles,
        })
    }

    pub async fn verify_token(&self, token: &str) -> Result<crate::auth::credential::basic::Claims> {
        self.jwt.verify(token)
    }

    pub async fn check_permission(
        &self,
        user_id: &str,
        permission: crate::rbac::Permission,
    ) -> bool {
        let rbac = self.rbac.read().await;
        rbac.check_permission(user_id, permission)
    }

    pub async fn change_password(
        &self,
        user_id: &str,
        old_password: &str,
        new_password: &str,
    ) -> Result<()> {
        let uid = Uuid::parse_str(user_id)
            .map_err(|_| anyhow!("invalid user_id"))?;

        let user = self
            .db
            .find_by_id(&uid)
            .await?
            .ok_or_else(|| anyhow!("user not found"))?;

        if !verify_password(old_password, &user.password_hash)? {
            return Err(anyhow!("old password is incorrect"));
        }

        if new_password.len() < 6 {
            return Err(anyhow!("new password must be at least 6 characters"));
        }

        let new_hash = hash_password(new_password)?;
        self.db.update_password(&uid, &new_hash).await
    }

    pub async fn list_users(&self) -> Result<Vec<UserRecord>> {
        self.db.list_users().await
    }

    pub async fn delete_user(&self, user_id: &str) -> Result<bool> {
        let uid = Uuid::parse_str(user_id)
            .map_err(|_| anyhow!("invalid user_id"))?;
        self.db.delete_user(&uid).await
    }
}

#[async_trait::async_trait]
pub trait UserDatabase: Send + Sync + Clone + 'static {
    async fn create_user(&self, user: &UserRecord) -> Result<()>;
    async fn find_by_username(&self, username: &str) -> Result<Option<UserRecord>>;
    async fn find_by_id(&self, id: &Uuid) -> Result<Option<UserRecord>>;
    async fn update_password(&self, id: &Uuid, new_hash: &str) -> Result<()>;
    async fn delete_user(&self, id: &Uuid) -> Result<bool>;
    async fn list_users(&self) -> Result<Vec<UserRecord>>;
    async fn count_users(&self) -> Result<u64>;
}
