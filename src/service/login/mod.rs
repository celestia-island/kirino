use anyhow::{anyhow, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Instant,
};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::{
    auth::{
        credential::basic::JwtManager,
        passport::static_password::{hash_password, verify_password},
    },
    models::identity::Identity,
    rbac::{
        dynamic::arbiter::AuthorizationArbiter,
        engine::RbacEngine,
        shared::Shared,
        store::{
            memory::InMemoryAssignmentStore,
            registry::{SimpleRole, StaticPermissionRegistry, StaticRoleRegistry},
        },
        subject::StringSubject,
        traits::{AssignmentStore, Permission, Role},
    },
};

#[derive(Debug, Clone)]
struct RateLimitEntry {
    attempts: u32,
    window_start: Instant,
}

pub struct LoginRateLimiter {
    max_attempts: u32,
    window_secs: u64,
    lockout_secs: u64,
    entries: Arc<RwLock<HashMap<String, RateLimitEntry>>>,
}

const MIN_PASSWORD_LEN: usize = 8;
const MAX_PASSWORD_LEN: usize = 128;
const MIN_USERNAME_LEN: usize = 2;
const MAX_USERNAME_LEN: usize = 64;

/// # Errors
/// Returns an error if the username is too short, too long, or contains invalid characters.
pub fn validate_username(username: &str) -> Result<()> {
    let trimmed = username.trim();
    if trimmed.is_empty() || trimmed.len() < MIN_USERNAME_LEN {
        return Err(anyhow!(
            "username must be at least {MIN_USERNAME_LEN} characters"
        ));
    }
    if trimmed.len() > MAX_USERNAME_LEN {
        return Err(anyhow!(
            "username must be at most {MAX_USERNAME_LEN} characters"
        ));
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
    {
        return Err(anyhow!(
            "username may only contain alphanumeric characters, underscores, hyphens, and dots"
        ));
    }
    Ok(())
}

/// # Errors
/// Returns an error if the password is too short, too long, or does not meet complexity requirements.
pub fn validate_password(password: &str) -> Result<()> {
    if password.len() < MIN_PASSWORD_LEN {
        return Err(anyhow!(
            "password must be at least {MIN_PASSWORD_LEN} characters"
        ));
    }
    if password.len() > MAX_PASSWORD_LEN {
        return Err(anyhow!(
            "password must be at most {MAX_PASSWORD_LEN} characters"
        ));
    }

    let has_uppercase = password.chars().any(|c| c.is_ascii_uppercase());
    let has_lowercase = password.chars().any(|c| c.is_ascii_lowercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_special = password.chars().any(|c| !c.is_ascii_alphanumeric());

    let categories = [has_uppercase, has_lowercase, has_digit, has_special]
        .iter()
        .filter(|&&x| x)
        .count();

    if categories < 3 {
        return Err(anyhow!(
            "password must contain at least 3 of: uppercase, lowercase, digit, special character"
        ));
    }

    Ok(())
}

impl LoginRateLimiter {
    #[must_use]
    pub fn new(max_attempts: u32, window_secs: u64, lockout_secs: u64) -> Self {
        Self {
            max_attempts,
            window_secs,
            lockout_secs,
            entries: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// # Errors
    /// Returns an error if too many login attempts have been made within the rate limit window.
    ///
    /// # Panics
    /// Panics if `window_secs + lockout_secs` overflows or is less than elapsed time (should never happen with valid config).
    pub async fn check(&self, key: &str) -> Result<()> {
        let mut entries = self.entries.write().await;
        let now = Instant::now();

        if let Some(entry) = entries.get_mut(key) {
            let elapsed = now.duration_since(entry.window_start);
            let total_window = std::time::Duration::from_secs(self.window_secs + self.lockout_secs);
            let window_duration = std::time::Duration::from_secs(self.window_secs);

            let should_reset = elapsed > total_window
                || (elapsed > window_duration && entry.attempts < self.max_attempts);

            if should_reset {
                entry.attempts = 0;
                entry.window_start = now;
            }

            if entry.attempts >= self.max_attempts {
                let remaining =
                    std::time::Duration::from_secs(self.window_secs + self.lockout_secs)
                        .checked_sub(elapsed)
                        .expect("total_window > elapsed should hold");
                if remaining > std::time::Duration::ZERO {
                    return Err(anyhow!(
                        "too many login attempts, try again in {} seconds",
                        remaining.as_secs()
                    ));
                }
                entry.attempts = 0;
                entry.window_start = now;
            }
        }

        Ok(())
    }

    pub async fn record_failure(&self, key: &str) {
        let mut entries = self.entries.write().await;
        let now = Instant::now();
        let entry = entries.entry(key.to_string()).or_insert(RateLimitEntry {
            attempts: 0,
            window_start: now,
        });
        entry.attempts += 1;
    }

    pub async fn reset(&self, key: &str) {
        let mut entries = self.entries.write().await;
        entries.remove(key);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KirinoPermission {
    AgentRead,
    AgentWrite,
    AgentExecute,
    ConfigRead,
    ConfigWrite,
    KnowledgeRead,
    KnowledgeWrite,
    ContainerRead,
    ContainerWrite,
    SystemRead,
    SystemWrite,
    DeployRead,
    DeployExecute,
}

impl KirinoPermission {
    #[must_use]
    pub fn all() -> HashSet<Self> {
        use KirinoPermission::{
            AgentExecute, AgentRead, AgentWrite, ConfigRead, ConfigWrite, ContainerRead,
            ContainerWrite, DeployExecute, DeployRead, KnowledgeRead, KnowledgeWrite, SystemRead,
            SystemWrite,
        };
        [
            AgentRead,
            AgentWrite,
            AgentExecute,
            ConfigRead,
            ConfigWrite,
            KnowledgeRead,
            KnowledgeWrite,
            ContainerRead,
            ContainerWrite,
            SystemRead,
            SystemWrite,
            DeployRead,
            DeployExecute,
        ]
        .into_iter()
        .collect()
    }
}

impl Permission for KirinoPermission {
    fn name(&self) -> &str {
        match self {
            KirinoPermission::AgentRead => "agent_read",
            KirinoPermission::AgentWrite => "agent_write",
            KirinoPermission::AgentExecute => "agent_execute",
            KirinoPermission::ConfigRead => "config_read",
            KirinoPermission::ConfigWrite => "config_write",
            KirinoPermission::KnowledgeRead => "knowledge_read",
            KirinoPermission::KnowledgeWrite => "knowledge_write",
            KirinoPermission::ContainerRead => "container_read",
            KirinoPermission::ContainerWrite => "container_write",
            KirinoPermission::SystemRead => "system_read",
            KirinoPermission::SystemWrite => "system_write",
            KirinoPermission::DeployRead => "deploy_read",
            KirinoPermission::DeployExecute => "deploy_execute",
        }
    }

    fn domain(&self) -> &'static str {
        match self {
            KirinoPermission::AgentRead
            | KirinoPermission::AgentWrite
            | KirinoPermission::AgentExecute => "agent",
            KirinoPermission::ConfigRead | KirinoPermission::ConfigWrite => "config",
            KirinoPermission::KnowledgeRead | KirinoPermission::KnowledgeWrite => "knowledge",
            KirinoPermission::ContainerRead | KirinoPermission::ContainerWrite => "container",
            KirinoPermission::SystemRead | KirinoPermission::SystemWrite => "system",
            KirinoPermission::DeployRead | KirinoPermission::DeployExecute => "deploy",
        }
    }
}

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

impl UserRecord {
    #[must_use]
    pub fn to_public(&self) -> UserInfo {
        UserInfo {
            id: self.id,
            username: self.username.clone(),
            display_name: self.display_name.clone(),
            is_active: self.is_active,
            identity: self.identity.clone(),
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

#[derive(Debug, Clone)]
pub struct UserInfo {
    pub id: Uuid,
    pub username: String,
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

pub struct AuthService<DB, P, R, A>
where
    P: Permission,
    R: Role<P>,
    A: AssignmentStore<StringSubject, P>,
{
    db: DB,
    jwt: JwtManager,
    engine: Shared<RbacEngine<StringSubject, P, R, A>>,
    arbiter: Option<Shared<AuthorizationArbiter>>,
    rate_limiter: LoginRateLimiter,
    first_user_role: String,
    default_role: String,
    auto_admin_first_user: bool,
}

impl<DB, P, R, A> AuthService<DB, P, R, A>
where
    DB: UserDatabase,
    P: Permission,
    R: Role<P>,
    A: AssignmentStore<StringSubject, P>,
{
    pub fn new(
        db: DB,
        jwt_secret: &str,
        jwt_expiration_hours: i64,
        engine: Shared<RbacEngine<StringSubject, P, R, A>>,
        first_user_role: &str,
        default_role: &str,
    ) -> Self {
        Self {
            db,
            jwt: JwtManager::new(jwt_secret, jwt_expiration_hours),
            engine,
            arbiter: None,
            rate_limiter: LoginRateLimiter::new(5, 300, 900),
            first_user_role: first_user_role.to_string(),
            default_role: default_role.to_string(),
            auto_admin_first_user: false,
        }
    }

    #[must_use]
    pub fn with_rate_limiter(mut self, limiter: LoginRateLimiter) -> Self {
        self.rate_limiter = limiter;
        self
    }

    #[must_use]
    pub fn with_auto_admin_first_user(mut self, enabled: bool) -> Self {
        self.auto_admin_first_user = enabled;
        self
    }

    #[must_use]
    pub fn with_arbiter(mut self, arbiter: AuthorizationArbiter) -> Self {
        self.arbiter = Some(Shared::new(arbiter));
        self
    }

    pub fn arbiter(&self) -> Option<Shared<AuthorizationArbiter>> {
        self.arbiter.clone()
    }

    pub fn jwt_manager(&self) -> &JwtManager {
        &self.jwt
    }

    pub fn engine(&self) -> Shared<RbacEngine<StringSubject, P, R, A>> {
        self.engine.clone()
    }

    /// # Errors
    /// Returns an error if the username or password is invalid, or if the username already exists.
    pub async fn register(
        &self,
        username: &str,
        password: &str,
        display_name: Option<&str>,
    ) -> Result<UserInfo> {
        validate_username(username)?;
        validate_password(password)?;

        if self.db.find_by_username(username).await?.is_some() {
            return Err(anyhow!("registration failed"));
        }

        let password_hash = hash_password(password)?;
        let user_id = Uuid::now_v7();
        let now = Utc::now();
        let identity = Identity::Basic { id: user_id };

        let user = UserRecord {
            id: user_id,
            username: username.to_string(),
            password_hash,
            display_name: display_name.map(ToString::to_string),
            is_active: true,
            identity,
            created_at: now,
            updated_at: now,
        };

        self.db.create_user(&user).await?;

        let is_first = self.auto_admin_first_user && self.db.count_users().await? <= 1;
        let role_name = if is_first {
            &self.first_user_role
        } else {
            &self.default_role
        };

        let subject = StringSubject::new(user_id.to_string());
        self.engine
            .assignment_store()
            .assign_role(&subject, role_name)
            .await?;

        Ok(user.to_public())
    }

    /// # Errors
    /// Returns an error if rate limited, credentials are invalid, or token issuance fails.
    pub async fn login(&self, username: &str, password: &str) -> Result<LoginResult> {
        self.rate_limiter.check(username).await?;

        let user = self
            .db
            .find_by_username(username)
            .await?
            .ok_or_else(|| anyhow!("invalid credentials"))?;

        if !user.is_active {
            self.rate_limiter.record_failure(username).await;
            return Err(anyhow!("invalid credentials"));
        }

        if !verify_password(password, &user.password_hash)? {
            self.rate_limiter.record_failure(username).await;
            return Err(anyhow!("invalid credentials"));
        }

        self.rate_limiter.reset(username).await;

        let user_id = user.id.to_string();
        let subject = StringSubject::new(&user_id);
        let roles = self
            .engine
            .assignment_store()
            .roles_of(&subject)
            .await
            .unwrap_or_default();

        let token = self.jwt.issue(&user_id, &user.username, roles.clone())?;

        Ok(LoginResult {
            token,
            user_id,
            username: user.username.clone(),
            display_name: user.display_name.clone(),
            roles,
        })
    }

    /// # Errors
    /// Returns an error if the token is invalid, expired, or has been revoked.
    pub async fn verify_token(
        &self,
        token: &str,
    ) -> Result<crate::auth::credential::basic::Claims> {
        self.jwt.verify_with_revocation(token).await
    }

    pub async fn check_permission(&self, user_id: &str, permission: &P) -> bool {
        let subject = StringSubject::new(user_id);
        self.engine.check(&subject, permission).await
    }

    pub async fn check_static_and_dynamic(
        &self,
        user_id: &str,
        permission: &P,
        action_request: &crate::rbac::dynamic::metrics::ActionRequest,
    ) -> bool {
        let subject = StringSubject::new(user_id);
        if !self.engine.check(&subject, permission).await {
            return false;
        }
        if let Some(ref arbiter) = self.arbiter {
            let verdict = arbiter.authorize(action_request).await;
            return verdict.allowed;
        }
        true
    }

    /// # Errors
    /// Returns an error if the user ID is invalid, user is not found, old password is incorrect, or the new password is invalid.
    pub async fn change_password(
        &self,
        user_id: &str,
        old_password: &str,
        new_password: &str,
    ) -> Result<()> {
        let uid = Uuid::parse_str(user_id).map_err(|_| anyhow!("invalid user_id"))?;

        let user = self
            .db
            .find_by_id(&uid)
            .await?
            .ok_or_else(|| anyhow!("user not found"))?;

        if !verify_password(old_password, &user.password_hash)? {
            return Err(anyhow!("old password is incorrect"));
        }

        validate_password(new_password)?;

        let new_hash = hash_password(new_password)?;
        self.jwt.revoke_all_for_user(user_id).await;
        self.db.update_password(&uid, &new_hash).await
    }

    /// # Errors
    /// Returns an error if the underlying database operation fails.
    pub async fn list_users(&self) -> Result<Vec<UserInfo>> {
        let users = self.db.list_users().await?;
        Ok(users.iter().map(UserRecord::to_public).collect())
    }

    /// # Errors
    /// Returns an error if the user ID is invalid or the underlying database operation fails.
    pub async fn delete_user(&self, user_id: &str) -> Result<bool> {
        let uid = Uuid::parse_str(user_id).map_err(|_| anyhow!("invalid user_id"))?;
        self.jwt.revoke_all_for_user(user_id).await;
        self.db.delete_user(&uid).await
    }
}

type DefaultEngine = RbacEngine<
    StringSubject,
    KirinoPermission,
    SimpleRole<KirinoPermission>,
    InMemoryAssignmentStore<StringSubject, KirinoPermission>,
>;

#[must_use]
pub fn build_default_engine() -> Shared<DefaultEngine> {
    let mut role_reg = StaticRoleRegistry::new();
    role_reg.register(SimpleRole::new("admin", KirinoPermission::all()));
    role_reg.register(SimpleRole::new(
        "operator",
        [
            KirinoPermission::AgentRead,
            KirinoPermission::AgentWrite,
            KirinoPermission::AgentExecute,
            KirinoPermission::ConfigRead,
            KirinoPermission::ConfigWrite,
            KirinoPermission::KnowledgeRead,
            KirinoPermission::KnowledgeWrite,
            KirinoPermission::ContainerRead,
            KirinoPermission::ContainerWrite,
            KirinoPermission::DeployRead,
            KirinoPermission::DeployExecute,
            KirinoPermission::SystemRead,
        ]
        .into_iter()
        .collect(),
    ));
    role_reg.register(SimpleRole::new(
        "viewer",
        [
            KirinoPermission::AgentRead,
            KirinoPermission::ConfigRead,
            KirinoPermission::KnowledgeRead,
            KirinoPermission::ContainerRead,
            KirinoPermission::SystemRead,
            KirinoPermission::DeployRead,
        ]
        .into_iter()
        .collect(),
    ));
    role_reg.register(SimpleRole::new(
        "agent",
        [
            KirinoPermission::AgentRead,
            KirinoPermission::AgentExecute,
            KirinoPermission::KnowledgeRead,
        ]
        .into_iter()
        .collect(),
    ));

    let perm_reg = StaticPermissionRegistry::new(KirinoPermission::all());
    let store = InMemoryAssignmentStore::new();

    Shared::new(RbacEngine::new(role_reg, perm_reg, store))
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
