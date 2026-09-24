//! Workspace membership guard: subject -> group -> workspace role.
//!
//! This module answers one coarse question -- which workspace role does a
//! subject hold on one workspace, and does that role allow a named
//! permission there. It is deliberately separate from
//! [`crate::rbac::scope`], the fine-grained per-permission scope axis:
//! the guard never consults scoped grants, and the scoped resolver never
//! consults workspace roles.
//!
//! Threat model and invariants:
//!
//! * Fail closed. A missing membership and a missing group grant both
//!   resolve to `None`, and `None` is always a denial. There is no
//!   implicit membership, no "public workspace" and no default role.
//! * A global permission is required IN ADDITION to the workspace role.
//!   [`WorkspaceGuard::check`] first requires `permission.name()` to
//!   appear in the caller-supplied global permission list; a workspace
//!   role alone never satisfies a check, however privileged the role is.
//! * Direct membership beats a group grant.
//!   [`WorkspaceGuard::resolve_workspace_role`] asks for direct
//!   membership first and returns it immediately, so a group grant is
//!   only a weaker fallback for subjects with no direct row -- it can
//!   neither raise nor lower a direct role.
//! * Store failures are not swallowed. Every store call is propagated
//!   with `?`, so an unreachable or failing store surfaces as `Err` and
//!   the caller must deny; the guard never turns a store failure into a
//!   grant, and it also never flattens one into `Ok(false)`.
//!
//! Staleness: the guard holds no cache and re-reads the store on every
//! call, so membership and grant changes take effect on the next call.
//! Any caching placed in front of it belongs to the caller.
//!
//! Trust boundary: the global permission list passed to `check` is
//! trusted as given. The guard does not verify where it came from, so
//! the caller must derive it from the authenticated subject (for example
//! from the RBAC engine) and must not let request data influence it.

use anyhow::Result;
use async_trait::async_trait;
use std::collections::HashMap;
use std::fmt::Debug;
use std::hash::Hash;

/// Workspace-scoped role.
///
/// Declaration order is also the privilege order (`Viewer < Operator <
/// Owner`), and the derived `Ord` relies on that order, so the variants
/// must not be reshuffled: any code comparing roles for "at least this
/// role" would silently invert otherwise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WorkspaceRole {
    /// Read-only access. Permitted permission names are only those ending
    /// in `.list` or `.read`, plus names starting with `device.list`.
    Viewer,
    /// Day-to-day operation. Everything is permitted except names
    /// starting with `workspace.manage` or `rbac.`, which stay
    /// Owner-only.
    Operator,
    /// Full control of the workspace, including `workspace.manage*` and
    /// `rbac.*`.
    Owner,
}

impl WorkspaceRole {
    /// Canonical lowercase name (`"viewer"` / `"operator"` / `"owner"`).
    ///
    /// This string is a wire/persistence contract: rows and API payloads
    /// store it, so it must stay stable and must round-trip through
    /// [`WorkspaceRole::from_str_lossy`].
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Viewer => "viewer",
            Self::Operator => "operator",
            Self::Owner => "owner",
        }
    }

    /// Parse a stored/transmitted role name, exact and case-sensitive.
    ///
    /// Anything unrecognized (including a differently-cased or unknown
    /// role, or an empty string) yields `None`. Despite the name this is
    /// not a lossy fallback: callers must treat `None` as "no role" and
    /// deny, not as a default role.
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
    ///
    /// Advisory only: nothing in this module reads this flag.
    /// `WorkspaceGuard::check` requires a workspace argument regardless,
    /// and `role_can` decides by permission name alone, so returning
    /// `true` here adds no guard-side enforcement.
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
///
/// Error contract: implementations must propagate store failures as
/// `Err` instead of flattening them into `Ok(None)`. Both deny at the
/// guard, but only `Err` lets the caller tell an outage apart from a
/// genuine "not a member".
#[async_trait]
pub trait WorkspaceStore<S, W>
where
    S: Debug + Send + Sync,
    W: Debug + Clone + PartialEq + Eq + Hash + Send + Sync,
{
    /// Direct user → workspace member check.  Returns the workspace role
    /// if the user is a direct member, or `None`.
    async fn direct_membership(&self, subject: &S, workspace: &W) -> Result<Option<WorkspaceRole>>;

    /// Group → workspace grant check.  Returns the workspace role if any
    /// of the subject's groups has a grant on this workspace.
    async fn group_grants(&self, subject: &S, workspace: &W) -> Result<Option<WorkspaceRole>>;

    /// List all workspace IDs the subject has access to (via direct
    /// membership OR group grants).
    async fn accessible_workspaces(&self, subject: &S) -> Result<Vec<W>>;
}

/// Three-dimensional access guard.
///
/// Combines a `WorkspaceStore` with a global permission resolver to
/// answer: "does subject S have permission P on workspace W?"
///
/// In this implementation the guard holds only the store: `check` takes
/// the subject's global permission strings as an argument, so the caller
/// owns that lookup, its freshness and its provenance. A guard built
/// with `new` is therefore inert on its own -- it can only deny or defer
/// to the store and the caller-supplied list.
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
    /// Build a guard over a store.
    ///
    /// Nothing is validated or pre-fetched here: the guard keeps no
    /// cached role, so every later call re-reads the store and reflects
    /// membership changes immediately.
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
    ///
    /// Both conditions are required, and either failure denies:
    ///
    /// 1. `permission.name()` must be present in `global_permissions` --
    ///    a workspace role never adds a capability the subject lacks
    ///    globally, and an empty global list denies even an Owner;
    /// 2. the subject must hold a workspace role on `workspace` and
    ///    `role_can` must allow the permission name for that role.
    ///
    /// The global list is trusted as given (see the module header): the
    /// guard does not verify its provenance.
    ///
    /// Result semantics: `Ok(false)` is a denial, including the "no
    /// membership" and "missing global permission" cases. A store error
    /// is returned as `Err`, not as `Ok(false)`, so callers must treat
    /// `Err` as a denial (fail closed) rather than propagating an
    /// allow.
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
    ///
    /// Ordering invariant: direct membership is asked first and returned
    /// as-is, so a group grant is only a fallback for subjects with no
    /// direct row on this workspace. A group grant therefore can neither
    /// upgrade nor downgrade a direct role, and it is the weaker of the
    /// two evidence shapes.
    ///
    /// `None` means "no direct membership and no group grant", which the
    /// guard reads as denial. Store errors propagate as `Err` (fail
    /// closed at the caller); nothing is cached, so each call re-reads
    /// the store.
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
    ///
    /// Delegates to the store and applies no filtering of its own, so
    /// the result is exactly what the store reports (no cache here, so
    /// it is as fresh as the store). This is a discovery/listing helper,
    /// not an authorization decision: a caller that needs to know
    /// whether an action is allowed on a workspace must call `check`
    /// with that workspace, because a store may under-report (the
    /// in-memory reference store omits group-granted workspaces).
    pub async fn accessible_workspaces(&self, subject: &S) -> Result<Vec<W>> {
        self.store.accessible_workspaces(subject).await
    }
}

/// Permission capabilities by workspace role.
///
/// This is the whole workspace capability matrix. The rules are name
/// conventions on the permission string, not lookups in a capability
/// registry: Viewer is an allow-list (only `.list` / `.read` suffixes
/// and the `device.list` prefix), while Operator and Owner are
/// deny-lists (Owner allows everything; Operator allows everything that
/// does not start with `workspace.manage` or `rbac.`). The asymmetry is
/// fail-open for Operator/Owner: a newly introduced permission name is
/// allowed to those two roles unless it happens to match an excluded
/// prefix, and it is allowed to Viewer only if it happens to match an
/// included suffix.
///
/// The exact name lists above and their basis are to be confirmed with
/// security review -- they are the deciding factor for every workspace
/// check, and they are not derived from any registry the crate ships.
fn role_can<P: ScopedPermission>(role: WorkspaceRole, perm: &P) -> bool {
    match role {
        WorkspaceRole::Owner => true,
        WorkspaceRole::Operator => {
            let name = perm.name();
            !name.starts_with("workspace.manage") && !name.starts_with("rbac.")
        }
        WorkspaceRole::Viewer => {
            let name = perm.name();
            name.ends_with(".list") || name.ends_with(".read") || name.starts_with("device.list")
        }
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
///
/// Semantics: two independent maps. `members` holds direct
/// `(subject, workspace)` rows, `group_grants` holds
/// `(group id, workspace)` rows. Both are plain map inserts with no
/// authorization check, so this type is a test/embedding seam and its
/// mutators must be reachable only from trusted administrative code.
/// An empty (or never populated) store denies every check, because a
/// missing row resolves to `None` rather than to a default role.
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
    /// Create an empty store: no members, no group grants.
    ///
    /// An empty store denies every check (no row resolves to `None`), so
    /// a store that was never populated fails closed rather than
    /// granting anything by default.
    pub fn new() -> Self {
        Self {
            members: HashMap::new(),
            group_grants: HashMap::new(),
        }
    }

    /// Grant `role` to `subject` on `workspace` directly. Adding the same
    /// `(subject, workspace)` pair again overwrites the previous role, so
    /// the last write wins.
    ///
    /// This bypasses all guard logic: no permission check, no audit and
    /// no notification. Treat it as an administrative/test seam and only
    /// call it from trusted code.
    pub fn add_member(&mut self, subject: S, workspace: W, role: WorkspaceRole) {
        self.members.insert((subject, workspace), role);
    }

    /// Grant `role` to a group key on `workspace`. Like `add_member`,
    /// this overwrites any previous role for the same key.
    ///
    /// The key must be the group identifier, not the user id:
    /// `WorkspaceStore::group_grants` looks up exactly this key, and
    /// `WorkspaceGuard::resolve_workspace_role` passes the caller's
    /// subject/group argument straight through. Because the key type is
    /// the same `S` as direct memberships, a user id stored here is not
    /// rejected -- it just never matches anything, which denies.
    pub fn add_group_grant(&mut self, group_id: S, workspace: W, role: WorkspaceRole) {
        self.group_grants.insert((group_id, workspace), role);
    }
}

#[async_trait]
impl<S, W> WorkspaceStore<S, W> for InMemoryWorkspaceStore<S, W>
where
    S: Debug + Clone + PartialEq + Eq + Hash + Send + Sync,
    W: Debug + Clone + PartialEq + Eq + Hash + Send + Sync,
{
    /// Exact `(subject, workspace)` lookup in the membership map. An
    /// absent row returns `None` (no membership), never a default role,
    /// and this lookup performs no expiry or revocation check of its
    /// own. It cannot fail, so it never returns `Err`.
    async fn direct_membership(&self, subject: &S, workspace: &W) -> Result<Option<WorkspaceRole>> {
        Ok(self
            .members
            .get(&(subject.clone(), workspace.clone()))
            .copied())
    }

    /// Exact `(group key, workspace)` lookup in the group-grant map. The
    /// `subject` parameter is used directly as the map key, so callers
    /// must pass the group identifier here; passing a user id simply
    /// finds no row and denies. An absent row returns `None` (and
    /// therefore denies) rather than erroring.
    async fn group_grants(&self, subject: &S, workspace: &W) -> Result<Option<WorkspaceRole>> {
        Ok(self
            .group_grants
            .get(&(subject.clone(), workspace.clone()))
            .copied())
    }

    /// Collects direct membership rows only. Group grants are NOT
    /// included, even though the trait contract mentions them, so the
    /// result can be shorter than the set of workspaces the guard would
    /// actually allow. Use it for listing only, never as an
    /// authorization decision.
    async fn accessible_workspaces(&self, subject: &S) -> Result<Vec<W>> {
        let mut workspaces = Vec::new();
        for (s, w) in self.members.keys() {
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
    /// Equivalent to [`InMemoryWorkspaceStore::new`]: an empty store that
    /// denies everything until rows are added.
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
        assert!(!role_can(
            WorkspaceRole::Operator,
            &TestPerm::WorkspaceManage
        ));
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
            .check(
                &"alice",
                &TestPerm::AgentCreate,
                &"ws-1",
                &["agent.create".into()],
            )
            .await
            .unwrap();
        assert!(has_access);
    }

    #[tokio::test]
    async fn no_membership_denies() {
        let store = InMemoryWorkspaceStore::<&str, &str>::new();
        let guard = WorkspaceGuard::new(store);
        let has_access = guard
            .check(
                &"bob",
                &TestPerm::AgentList,
                &"ws-1",
                &["agent.list".into()],
            )
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
