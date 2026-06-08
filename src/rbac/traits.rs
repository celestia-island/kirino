use std::collections::HashSet;

use async_trait::async_trait;

pub trait Permission: Eq + std::hash::Hash + Clone + Send + Sync + 'static {
    fn name(&self) -> &str;

    fn domain(&self) -> &'static str {
        ""
    }
}

pub trait Subject: Eq + std::hash::Hash + Clone + Send + Sync + 'static {
    fn subject_id(&self) -> &str;

    fn subject_type(&self) -> &'static str {
        "user"
    }
}

impl Subject for String {
    fn subject_id(&self) -> &str {
        self
    }
}

pub trait Role<P: Permission>: Clone + Send + Sync + 'static {
    fn role_name(&self) -> &str;
    fn permissions(&self) -> &HashSet<P>;
}

pub trait PermissionRegistry<P: Permission>: Send + Sync {
    fn all_permissions(&self) -> HashSet<P>;
    fn get_permission(&self, name: &str) -> Option<P>;
}

pub trait RoleRegistry<R, P: Permission>: Send + Sync
where
    R: Role<P>,
{
    fn get_role(&self, role_name: &str) -> Option<R>;
    fn list_role_names(&self) -> Vec<String>;
}

#[async_trait]
pub trait AssignmentStore<S, P>: Send + Sync
where
    S: Subject,
    P: Permission,
{
    async fn assign_role(&self, subject: &S, role_name: &str) -> anyhow::Result<()>;
    async fn revoke_role(&self, subject: &S, role_name: &str) -> anyhow::Result<()>;
    async fn roles_of(&self, subject: &S) -> anyhow::Result<Vec<String>>;
    async fn subjects_with_role(&self, role_name: &str) -> anyhow::Result<Vec<String>>;
    async fn extra_permissions(&self, subject: &S) -> anyhow::Result<HashSet<P>>;
    async fn set_extra_permissions(&self, subject: &S, perms: HashSet<P>) -> anyhow::Result<()>;
    async fn denied_permissions(&self, subject: &S) -> anyhow::Result<HashSet<P>>;
    async fn set_denied_permissions(&self, subject: &S, perms: HashSet<P>) -> anyhow::Result<()>;
}

#[async_trait]
pub trait RoleStore<P: Permission>: Send + Sync {
    async fn create_role(&self, role_name: &str, permissions: HashSet<P>) -> anyhow::Result<()>;
    async fn delete_role(&self, role_name: &str) -> anyhow::Result<bool>;
    async fn get_role_permissions(&self, role_name: &str) -> anyhow::Result<Option<HashSet<P>>>;
    async fn list_roles(&self) -> anyhow::Result<Vec<String>>;
}
