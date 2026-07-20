use anyhow::Result;
use std::collections::HashSet;

use async_trait::async_trait;

pub trait Permission: Eq + std::hash::Hash + Clone + Send + Sync + 'static {
    fn name(&self) -> &str;

    fn domain(&self) -> &'static str {
        ""
    }

    fn path_segments(&self) -> &[&str] {
        &[]
    }

    fn ancestry_names(&self) -> Vec<&str> {
        vec![self.name()]
    }

    fn matches_pattern(&self, pattern: &str) -> bool {
        pattern == self.name()
    }

    fn is_leaf(&self) -> bool {
        true
    }

    fn is_branch(&self) -> bool {
        false
    }

    fn all() -> Vec<Self>
    where
        Self: Sized,
    {
        Vec::new()
    }

    fn all_domains() -> Vec<&'static str> {
        Vec::new()
    }

    fn from_path(_path: &str) -> Option<Self>
    where
        Self: Sized,
    {
        None
    }

    fn expand_domain(_domain_str: &str) -> Vec<Self>
    where
        Self: Sized,
    {
        Vec::new()
    }
}

pub trait Subject: Eq + std::hash::Hash + Clone + Send + Sync + 'static {
    #[must_use]
    fn subject_id(&self) -> &str;

    #[must_use]
    fn subject_type(&self) -> &'static str {
        "user"
    }

    #[must_use]
    fn from_subject_id(id: &str) -> Self;

    fn try_from_subject_id(id: &str) -> Result<Self> {
        Ok(Self::from_subject_id(id))
    }
}

impl Subject for String {
    fn subject_id(&self) -> &str {
        self
    }

    fn from_subject_id(id: &str) -> Self {
        id.to_string()
    }

    fn try_from_subject_id(id: &str) -> Result<Self> {
        Ok(id.to_string())
    }
}

pub trait Role<P: Permission>: Clone + Send + Sync + 'static {
    #[must_use]
    fn role_name(&self) -> &str;
    #[must_use]
    fn permissions(&self) -> &HashSet<P>;
}

pub trait PermissionRegistry<P: Permission>: Send + Sync {
    #[must_use]
    fn all_permissions(&self) -> HashSet<P>;
    #[must_use]
    fn get_permission(&self, name: &str) -> Option<P>;
}

pub trait RoleRegistry<P: Permission>: Send + Sync {
    #[must_use]
    fn get_role_permissions(&self, role_name: &str) -> Option<HashSet<P>>;
    #[must_use]
    fn role_parents(&self, _role_name: &str) -> Vec<String> {
        Vec::new()
    }
    #[must_use]
    fn list_role_names(&self) -> Vec<String>;
}

#[async_trait]
pub trait AssignmentStore<S, P>: Send + Sync
where
    S: Subject,
    P: Permission,
{
    async fn assign_role(&self, subject: &S, role_name: &str) -> Result<()>;
    async fn revoke_role(&self, subject: &S, role_name: &str) -> Result<()>;
    #[must_use]
    async fn roles_of(&self, subject: &S) -> Result<Vec<String>>;
    #[must_use]
    async fn subjects_with_role(&self, role_name: &str) -> Result<Vec<String>>;
    #[must_use]
    async fn extra_permissions(&self, subject: &S) -> Result<HashSet<P>>;
    async fn set_extra_permissions(&self, subject: &S, perms: HashSet<P>) -> Result<()>;
    #[must_use]
    async fn denied_permissions(&self, subject: &S) -> Result<HashSet<P>>;
    async fn set_denied_permissions(&self, subject: &S, perms: HashSet<P>) -> Result<()>;
}

#[async_trait]
pub trait RoleStore<P: Permission>: Send + Sync {
    async fn create_role(&self, role_name: &str, permissions: HashSet<P>) -> Result<()>;
    #[must_use]
    async fn delete_role(&self, role_name: &str) -> Result<bool>;
    #[must_use]
    async fn get_role_permissions(&self, role_name: &str) -> Result<Option<HashSet<P>>>;
    #[must_use]
    async fn list_roles(&self) -> Result<Vec<String>>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SystemRole {
    Admin,
    Operator,
    Member,
    Viewer,
}

impl SystemRole {
    pub fn from_str_lossy(s: &str) -> Option<Self> {
        match s {
            "admin" => Some(Self::Admin),
            "operator" => Some(Self::Operator),
            "member" => Some(Self::Member),
            "viewer" => Some(Self::Viewer),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Operator => "operator",
            Self::Member => "member",
            Self::Viewer => "viewer",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceRole {
    Viewer,
    Operator,
    Owner,
}

impl WorkspaceRole {
    pub fn from_str_lossy(s: &str) -> Option<Self> {
        match s {
            "viewer" => Some(Self::Viewer),
            "operator" => Some(Self::Operator),
            "owner" => Some(Self::Owner),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Viewer => "viewer",
            Self::Operator => "operator",
            Self::Owner => "owner",
        }
    }
}

#[derive(Debug, Clone)]
pub struct PermissionContext {
    pub user_id: uuid::Uuid,
    pub system_role: SystemRole,
    pub group_ids: Vec<uuid::Uuid>,
    pub workspace_id: Option<uuid::Uuid>,
    pub workspace_role: Option<WorkspaceRole>,
    pub session_version: u64,
    pub current_user_version: u64,
}

impl PermissionContext {
    pub fn is_session_stale(&self) -> bool {
        self.session_version < self.current_user_version
    }
}

#[derive(Debug, Clone)]
pub enum PermissionDecision {
    Granted {
        reason: String,
        source: GrantSource,
    },
    Denied {
        reason: String,
        source: Option<GrantSource>,
    },
}

#[derive(Debug, Clone)]
pub enum GrantSource {
    RoleDefault,
    GlobalGrant,
    GroupGrant,
    UserGrant,
    WorkspaceRole,
    AdminBypass,
}

#[async_trait]
pub trait GrantResolver<P: Permission>: Send + Sync {
    #[must_use]
    async fn resolve(
        &self,
        ctx: &PermissionContext,
        permission: &P,
        resource_id: Option<&str>,
    ) -> Result<PermissionDecision>;
}
