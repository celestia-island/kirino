use anyhow::Result;
use std::collections::HashMap;
use std::fmt::Debug;
use std::hash::Hash;

/// Workspace-scoped role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WorkspaceRole {
    Viewer,
    Operator,
    Owner,
}

impl WorkspaceRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Viewer => "viewer",
            Self::Operator => "operator",
            Self::Owner => "owner",
        }
    }

    pub fn from_str_lossy(s: &str) -> Option<Self> {
        match s {
            "owner" => Some(Self::Owner),
            "operator" => Some(Self::Operator),
            "viewer" => Some(Self::Viewer),
            _ => None,
        }
    }
}

/// Scoped permission with an optional workspace constraint.
///
/// Permissions like `agent.list` operate globally; permissions like
/// `workspace.manage` must be scoped to a specific workspace.
pub trait ScopedPermission: Debug + Clone + Send + Sync + 'static {
    /// Permission identifier (e.g. `"agent.list"`).
    fn name(&self) -> &str;
    /// Whether this permission requires a workspace scope to be meaningful.
    fn requires_workspace(&self) -> bool {
        false
    }
}

/// Three-dimensional access control: Subject → Group → Workspace.
///
/// Resolution order (first match wins):
/// 1. Direct user → workspace membership → workspace role
/// 2. User group → workspace grant → workspace role
/// 3. None (denied)
///
/// The effective permission set is the intersection of:
/// - Global role permissions (from `Subject::roles()`)
/// - Workspace role permissions (from the resolution above)
pub trait WorkspaceStore<S, W>
where
    S: Debug + Send + Sync,
    W: Debug + Clone + PartialEq + Eq + Hash + Send + Sync,
{
    /// Direct user → workspace member check.  Returns the workspace role
    /// if the user is a direct member, or `None`.
    async fn direct_membership(
        &self,
        subject: &S,
        workspace: &W,
    ) -> Result<Option<WorkspaceRole>>;

    /// Group → workspace grant check.  Returns the workspace role if any
    /// of the subject's groups has a grant on this workspace.
    async fn group_grants(
        &self,
        subject: &S,
        workspace: &W,
    ) -> Result<Option<WorkspaceRole>>;

    /// List all workspace IDs the subject has access to (via direct
    /// membership OR group grants).
    async fn accessible_workspaces(&self, subject: &S) -> Result<Vec<W>>;
}

/// Three-dimensional access guard.
///
/// Combines a `WorkspaceStore` with a global permission resolver to
/// answer: "does subject S have permission P on workspace W?"
pub struct WorkspaceGuard<S, W, Store> {
    store: Store,
    _phantom: std::marker::PhantomData<(S, W)>,
}

impl<S, W, Store> WorkspaceGuard<S, W, Store>
where
    S: Debug + Clone + Send + Sync,
    W: Debug + Clone + PartialEq + Eq + Hash + Send + Sync,
    Store: WorkspaceStore<S, W>,
{
    pub fn new(store: Store) -> Self {
        Self {
            store,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Check whether `subject` has `permission` on `workspace`.
    ///
    /// `global_permissions` is the set of global permission strings
    /// the subject holds.  These are intersected with workspace-scoped
    /// capabilities derived from the subject's workspace role.
    pub async fn check<P: ScopedPermission>(
        &self,
        subject: &S,
        permission: &P,
        workspace: &W,
        global_permissions: &[String],
    ) -> Result<bool> {
        let global_perm = global_permissions.iter().any(|p| p == permission.name());
        if !global_perm {
            return Ok(false);
        }

        match self.resolve_workspace_role(subject, workspace).await? {
            Some(role) => Ok(role_can(role, permission)),
            None => Ok(false),
        }
    }

    /// Resolve the effective workspace role for `subject` on `workspace`.
    pub async fn resolve_workspace_role(
        &self,
        subject: &S,
        workspace: &W,
    ) -> Result<Option<WorkspaceRole>> {
        if let Some(role) = self.store.direct_membership(subject, workspace).await? {
            return Ok(Some(role));
        }
        if let Some(role) = self.store.group_grants(subject, workspace).await? {
            return Ok(Some(role));
        }
        Ok(None)
    }

    /// List all workspace IDs accessible to `subject`.
    pub async fn accessible_workspaces(&self, subject: &S) -> Result<Vec<W>> {
        self.store.accessible_workspaces(subject).await
    }
}

/// Permission capabilities by workspace role.
fn role_can<P: ScopedPermission>(role: WorkspaceRole, perm: &P) -> bool {
    match role {
        WorkspaceRole::Owner => true,
        WorkspaceRole::Operator => {
            let name = perm.name();
            !name.starts_with("workspace.manage") && !name.starts_with("rbac.")
        },
        WorkspaceRole::Viewer => {
            let name = perm.name();
            name.ends_with(".list") || name.ends_with(".read") || name.starts_with("device.list")
        },
    }
}

/// In-memory workspace store for testing and simple deployments.
///
/// ```ignore
/// use kirino::rbac::workspace_guard::{WorkspaceGuard, InMemoryWorkspaceStore};
/// let mut store = InMemoryWorkspaceStore::new();
/// store.add_member("alice", "ws-1", WorkspaceRole::Owner);
/// let guard = WorkspaceGuard::new(store);
/// ```
#[derive(Clone)]
pub struct InMemoryWorkspaceStore<S, W> {
    members: HashMap<(S, W), WorkspaceRole>,
    group_grants: HashMap<(S, W), WorkspaceRole>,
}

impl<S, W> InMemoryWorkspaceStore<S, W>
where
    S: Debug + Clone + PartialEq + Eq + Hash + Send + Sync,
    W: Debug + Clone + PartialEq + Eq + Hash + Send + Sync,
{
    pub fn new() -> Self {
        Self {
            members: HashMap::new(),
            group_grants: HashMap::new(),
        }
    }

    pub fn add_member(&mut self, subject: S, workspace: W, role: WorkspaceRole) {
        self.members.insert((subject, workspace), role);
    }

    pub fn add_group_grant(&mut self, group_id: S, workspace: W, role: WorkspaceRole) {
        self.group_grants.insert((group_id, workspace), role);
    }
}

impl<S, W> WorkspaceStore<S, W> for InMemoryWorkspaceStore<S, W>
where
    S: Debug + Clone + PartialEq + Eq + Hash + Send + Sync,
    W: Debug + Clone + PartialEq + Eq + Hash + Send + Sync,
{
    async fn direct_membership(
        &self,
        subject: &S,
        workspace: &W,
    ) -> Result<Option<WorkspaceRole>> {
        Ok(self
            .members
            .get(&(subject.clone(), workspace.clone()))
            .copied())
    }

    async fn group_grants(
        &self,
        subject: &S,
        workspace: &W,
    ) -> Result<Option<WorkspaceRole>> {
        Ok(self
            .group_grants
            .get(&(subject.clone(), workspace.clone()))
            .copied())
    }

    async fn accessible_workspaces(&self, subject: &S) -> Result<Vec<W>> {
        let mut workspaces = Vec::new();
        for ((s, w), _) in &self.members {
            if s == subject {
                workspaces.push(w.clone());
            }
        }
        Ok(workspaces)
    }
}

impl<S, W> Default for InMemoryWorkspaceStore<S, W>
where
    S: Debug + Clone + PartialEq + Eq + Hash + Send + Sync,
    W: Debug + Clone + PartialEq + Eq + Hash + Send + Sync,
{
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    enum TestPerm {
        AgentList,
        AgentCreate,
        WorkspaceManage,
    }

    impl ScopedPermission for TestPerm {
        fn name(&self) -> &str {
            match self {
                TestPerm::AgentList => "agent.list",
                TestPerm::AgentCreate => "agent.create",
                TestPerm::WorkspaceManage => "workspace.manage",
            }
        }
    }

    #[test]
    fn workspace_role_ordering() {
        assert!(WorkspaceRole::Owner > WorkspaceRole::Operator);
        assert!(WorkspaceRole::Operator > WorkspaceRole::Viewer);
    }

    #[test]
    fn owner_can_manage() {
        assert!(role_can(WorkspaceRole::Owner, &TestPerm::WorkspaceManage));
    }

    #[test]
    fn operator_cannot_manage() {
        assert!(!role_can(WorkspaceRole::Operator, &TestPerm::WorkspaceManage));
    }

    #[test]
    fn viewer_can_list() {
        assert!(role_can(WorkspaceRole::Viewer, &TestPerm::AgentList));
    }

    #[test]
    fn viewer_cannot_create() {
        assert!(!role_can(WorkspaceRole::Viewer, &TestPerm::AgentCreate));
    }

    #[tokio::test]
    async fn direct_membership_grants_access() {
        let mut store = InMemoryWorkspaceStore::new();
        store.add_member("alice", "ws-1", WorkspaceRole::Owner);

        let guard = WorkspaceGuard::new(store);
        let has_access = guard
            .check(&"alice", &TestPerm::AgentCreate, &"ws-1", &["agent.create".into()])
            .await
            .unwrap();
        assert!(has_access);
    }

    #[tokio::test]
    async fn no_membership_denies() {
        let store = InMemoryWorkspaceStore::<&str, &str>::new();
        let guard = WorkspaceGuard::new(store);
        let has_access = guard
            .check(&"bob", &TestPerm::AgentList, &"ws-1", &["agent.list".into()])
            .await
            .unwrap();
        assert!(!has_access);
    }

    #[tokio::test]
    async fn missing_global_perm_denies_even_as_owner() {
        let mut store = InMemoryWorkspaceStore::new();
        store.add_member("alice", "ws-1", WorkspaceRole::Owner);

        let guard = WorkspaceGuard::new(store);
        let has_access = guard
            .check(&"alice", &TestPerm::AgentCreate, &"ws-1", &[]) // no global perms
            .await
            .unwrap();
        assert!(!has_access);
    }

    #[tokio::test]
    async fn group_grant_grants_access() {
        let mut store = InMemoryWorkspaceStore::<&str, &str>::new();
        store.add_group_grant("admin-group", "ws-1", WorkspaceRole::Owner);

        let guard = WorkspaceGuard::new(store);
        let has_access = guard
            .check(
                &"admin-group",
                &TestPerm::AgentCreate,
                &"ws-1",
                &["agent.create".into()],
            )
            .await
            .unwrap();
        assert!(has_access);
    }

    #[tokio::test]
    async fn direct_membership_overrides_group_grant() {
        let mut store = InMemoryWorkspaceStore::<&str, &str>::new();
        store.add_member("alice", "ws-1", WorkspaceRole::Owner);
        store.add_group_grant("group-x", "ws-1", WorkspaceRole::Viewer);

        let guard = WorkspaceGuard::new(store);
        let role = guard
            .resolve_workspace_role(&"alice", &"ws-1")
            .await
            .unwrap();
        assert_eq!(role, Some(WorkspaceRole::Owner));
    }

    #[tokio::test]
    async fn accessible_workspaces_filters_correctly() {
        let mut store = InMemoryWorkspaceStore::<&str, &str>::new();
        store.add_member("alice", "ws-1", WorkspaceRole::Owner);
        store.add_member("bob", "ws-2", WorkspaceRole::Viewer);

        let guard = WorkspaceGuard::new(store);
        let ws = guard.accessible_workspaces(&"alice").await.unwrap();
        assert_eq!(ws, vec!["ws-1"]);
        let ws = guard.accessible_workspaces(&"bob").await.unwrap();
        assert_eq!(ws, vec!["ws-2"]);
    }

    #[tokio::test]
    async fn viewer_denied_create_even_with_global_perm() {
        let mut store = InMemoryWorkspaceStore::new();
        store.add_member("bob", "ws-1", WorkspaceRole::Viewer);

        let guard = WorkspaceGuard::new(store);
        let has_access = guard
            .check(
                &"bob",
                &TestPerm::AgentCreate,
                &"ws-1",
                &["agent.create".into()],
            )
            .await
            .unwrap();
        assert!(!has_access);
    }
}
