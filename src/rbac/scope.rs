//! Scoped grants — one permission string, three stacked scopes.
//!
//! The workspace RBAC partitioning model (2026-09-23 architecture round):
//! a grant is no longer only "user X holds permission P" — it carries a
//! [`GrantScope`] answering WHERE it applies:
//!
//! * [`GrantScope::Global`] — the whole system (the legacy grant shape:
//!   every existing grant table row is a global grant);
//! * [`GrantScope::Group`] — applies to members of one user group while
//!   resolving that group's subjects (high-privilege operators mint
//!   dedicated groups and grant at this level);
//! * [`GrantScope::Workspace`] — applies inside one workspace only.
//!
//! Resolution semantics ([`ScopedGrantResolver`]):
//!
//! 1. a stale session denies;
//! 2. the subject's deny set wins over every grant (except admin bypass);
//! 3. `SystemRole::Admin` bypasses with
//!    [`GrantSource::AdminBypass`](super::traits::GrantSource::AdminBypass);
//! 4. role defaults from the [`RoleRegistry`]
//!    grant with
//!    [`GrantSource::RoleDefault`](super::traits::GrantSource::RoleDefault);
//! 5. scoped grants apply when their scope matches the context — a group
//!    grant for a group the subject is in, a workspace grant when the
//!    context resolves inside that workspace; the most specific match
//!    labels the decision (a workspace qualifier →
//!    [`GrantSource::WorkspaceGrant`](super::traits::GrantSource::WorkspaceGrant);
//!    otherwise the attachment names the source —
//!    [`GrantSource::GroupGrant`](super::traits::GrantSource::GroupGrant) for
//!    group-attached,
//!    [`GrantSource::UserGrant`](super::traits::GrantSource::UserGrant) for
//!    user-attached global grants).
//!
//! Grants UNION: a workspace grant adds to (never subtracts from) global
//! and group grants — revocation is expressed by not granting, or by the
//! deny set. This is deliberately the same shape the unscoped engine
//! uses, so consumers can adopt the resolver without re-authoring their
//! decision logic.
//!
//! `PermissionContext` already carries the full scope context
//! (`system_role`, `group_ids`, `workspace_id`) — the resolver reads it,
//! never re-derives it.
//!
//! Two neighbouring mechanisms, deliberately distinct: this module is the
//! fine-grained per-permission scope axis; [`crate::rbac::workspace_guard`]
//! is the coarse Viewer/Operator/Owner workspace-role axis (which this
//! resolver does not consult). Error contract: a store `Err` propagates
//! from `resolve` as an uncertain outcome — callers MUST fail closed on
//! it (the engine's `resolve_effective_permissions` already denies on
//! error).

use std::collections::HashSet;

use async_trait::async_trait;
use uuid::Uuid;

use crate::rbac::traits::{
    GrantResolver, Permission, PermissionContext, PermissionDecision, RoleRegistry,
};

/// Where a grant applies.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantScope {
    /// The whole system. Legacy grants are globals.
    Global,
    /// Members of this user group (resolved when the subject's context
    /// includes the group).
    Group(Uuid),
    /// Inside this workspace only.
    Workspace(Uuid),
}

impl GrantScope {
    /// Specificity for decision labelling — a wider scope never outranks a
    /// narrower one when both match. `Global(0) < Group(1) < Workspace(2)`.
    ///
    /// Only this ordering is load-bearing (the resolver compares ranks
    /// with `>`); the numeric values themselves are arbitrary ordinals,
    /// and the choice of these particular values is basis to be
    /// confirmed with security review.
    #[must_use]
    pub fn specificity(&self) -> u8 {
        match self {
            Self::Global => 0,
            Self::Group(_) => 1,
            Self::Workspace(_) => 2,
        }
    }

    /// Whether the scope applies to the given resolution context.
    ///
    /// `Global` applies everywhere; `Group` only when the context lists
    /// that group id; `Workspace` only when the context's
    /// `workspace_id` is exactly that workspace. A context with no
    /// workspace id therefore matches no workspace grant -- the failure
    /// mode is a silent no-match (deny), never a fallback to global.
    #[must_use]
    pub fn applies_to(&self, ctx: &PermissionContext) -> bool {
        match self {
            Self::Global => true,
            Self::Group(g) => ctx.group_ids.contains(g),
            Self::Workspace(w) => ctx.workspace_id == Some(*w),
        }
    }
}

/// One permission held at one scope (a grant). Named `ScopedGrant` to
/// stay distinct from `workspace_guard::ScopedPermission`, the trait for
/// permissions that MAY require a workspace qualifier.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ScopedGrant<P> {
    /// The permission this grant confers: either the exact name, or a
    /// branch name that also satisfies every permission descending from
    /// it (see `grant_matches` in this module).
    pub permission: P,
    /// Where the grant applies. A scope that does not apply to the
    /// resolution context makes the grant invisible, never wildcard: a
    /// workspace grant outside its workspace cannot match.
    pub scope: GrantScope,
}

impl<P> ScopedGrant<P> {
    /// Pair a permission with the scope it applies at.
    ///
    /// No validation happens here: a grant is data, and its effect is
    /// decided only at resolution time, where a non-applicable scope
    /// makes it a silent no-match (never an implicit global grant).
    #[must_use]
    pub fn new(permission: P, scope: GrantScope) -> Self {
        Self { permission, scope }
    }
}

/// Does `grant` satisfy `requested`? Exact name, or the grant is a branch
/// the requested permission descends from (wildcard grants).
fn grant_matches<P: Permission>(grant: &P, requested: &P) -> bool {
    grant.name() == requested.name()
        || (grant.is_branch() && requested.ancestry_names().contains(&grant.name()))
}

/// Storage surface for scoped grants. Implement over your grant tables;
/// rows without a scope column are [`GrantScope::Global`].
#[async_trait]
pub trait ScopedGrantStore<P: Permission>: Send + Sync {
    /// Grants attached directly to the resolving user (any scope).
    async fn user_grants(&self, user_id: Uuid) -> anyhow::Result<Vec<ScopedGrant<P>>>;

    /// Grants attached to a group (any scope). The resolver asks once per
    /// group in the context.
    async fn group_grants(&self, group_id: Uuid) -> anyhow::Result<Vec<ScopedGrant<P>>>;

    /// The subject's deny set — denies win over every grant except admin
    /// bypass.
    async fn denied(&self, user_id: Uuid) -> anyhow::Result<HashSet<P>>;
}

/// In-memory [`ScopedGrantStore`] — the reference semantics and the test
/// double.
#[derive(Clone)]
pub struct MemoryScopedGrantStore<P: Permission> {
    user: std::collections::HashMap<Uuid, Vec<ScopedGrant<P>>>,
    group: std::collections::HashMap<Uuid, Vec<ScopedGrant<P>>>,
    denies: std::collections::HashMap<Uuid, HashSet<P>>,
}

impl<P: Permission> Default for MemoryScopedGrantStore<P> {
    /// Equivalent to [`MemoryScopedGrantStore::new`]: an empty store
    /// that grants nothing and denies nothing until rows are added.
    fn default() -> Self {
        Self {
            user: std::collections::HashMap::new(),
            group: std::collections::HashMap::new(),
            denies: std::collections::HashMap::new(),
        }
    }
}

impl<P: Permission> MemoryScopedGrantStore<P> {
    /// Create an empty store (identical to `Default::default()`).
    ///
    /// An empty store grants nothing: resolution then falls through to
    /// role defaults and finally to a deny, so a store that was never
    /// populated fails closed.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a grant attached to one user. Later rows are appended, and a
    /// duplicate is harmless -- resolution is a union, and the first
    /// matching row at the winning specificity only affects the label
    /// (`GrantSource`), never the outcome.
    pub fn grant_user(&mut self, user: Uuid, grant: ScopedGrant<P>) -> &mut Self {
        self.user.entry(user).or_default().push(grant);
        self
    }

    /// Add a grant attached to one group. It becomes effective only for
    /// contexts that list this group id; for everyone else the row is
    /// invisible (deny by absence, not an error).
    pub fn grant_group(&mut self, group: Uuid, grant: ScopedGrant<P>) -> &mut Self {
        self.group.entry(group).or_default().push(grant);
        self
    }

    /// Add one permission to the user's explicit deny set. Denies are
    /// additive and win over every grant shape except admin bypass, and
    /// they match branches too (a deny on a branch denies its
    /// descendants). There is no API here to remove a deny.
    pub fn deny(&mut self, user: Uuid, permission: P) -> &mut Self {
        self.denies.entry(user).or_default().insert(permission);
        self
    }
}

#[async_trait]
impl<P: Permission + Send + Sync> ScopedGrantStore<P> for MemoryScopedGrantStore<P> {
    /// In-memory lookup for one user. An unknown user id yields an empty
    /// list instead of an error, so the absence of rows denies by
    /// default; this implementation cannot fail.
    async fn user_grants(&self, user_id: Uuid) -> anyhow::Result<Vec<ScopedGrant<P>>> {
        Ok(self.user.get(&user_id).cloned().unwrap_or_default())
    }

    /// In-memory lookup for one group. A group with no rows (or a group
    /// id that was never granted) yields an empty list, which the
    /// resolver reads as "no group grant" -- not as an error.
    async fn group_grants(&self, group_id: Uuid) -> anyhow::Result<Vec<ScopedGrant<P>>> {
        Ok(self.group.get(&group_id).cloned().unwrap_or_default())
    }

    /// In-memory deny set for one user; empty when nothing was denied.
    /// Consequence for the fail-closed contract: a user id that was
    /// never populated here has an empty deny set, which only ever
    /// weakens restriction, so the empty result must not be read as
    /// "store unavailable".
    async fn denied(&self, user_id: Uuid) -> anyhow::Result<HashSet<P>> {
        Ok(self.denies.get(&user_id).cloned().unwrap_or_default())
    }
}

/// The scoped [`GrantResolver`]: deny-wins + admin bypass + role defaults +
/// union of matching scoped grants, most-specific match labels the source.
pub struct ScopedGrantResolver<P: Permission> {
    store: std::sync::Arc<dyn ScopedGrantStore<P>>,
    roles: std::sync::Arc<dyn RoleRegistry<P>>,
}

impl<P: Permission> ScopedGrantResolver<P> {
    /// Wire a grant store and a role registry into a resolver.
    ///
    /// Both are held as shared handles for the resolver's lifetime. The
    /// resolver keeps no decision cache of its own: every `resolve` call
    /// re-reads the deny set, the user grants and the group grants, so
    /// revocation (and group removal) takes effect on the next call.
    /// Any caching in front of this is the caller's, and it is the
    /// caller's job to decide how stale a cached grant may be.
    #[must_use]
    pub fn new(
        store: std::sync::Arc<dyn ScopedGrantStore<P>>,
        roles: std::sync::Arc<dyn RoleRegistry<P>>,
    ) -> Self {
        Self { store, roles }
    }
}

/// Decision-source labelling: a workspace qualifier is the narrowest
/// applicability and labels first; otherwise the attachment names the
/// source (group-attached → `GroupGrant`, user-attached global →
/// `UserGrant`).
fn grant_source(attachment: Attachment, scope: &GrantScope) -> crate::rbac::traits::GrantSource {
    use crate::rbac::traits::GrantSource;
    if matches!(scope, GrantScope::Workspace(_)) {
        return GrantSource::WorkspaceGrant;
    }
    match attachment {
        Attachment::User => GrantSource::UserGrant,
        Attachment::Group => GrantSource::GroupGrant,
    }
}

/// Where a candidate grant is attached.
#[derive(Clone, Copy)]
enum Attachment {
    User,
    Group,
}

#[async_trait]
impl<P: Permission + Send + Sync> GrantResolver<P> for ScopedGrantResolver<P> {
    /// Decide one permission for one subject context (the
    /// [`GrantResolver`] entry point for scoped grants).
    ///
    /// Evaluation order, exactly as implemented:
    ///
    /// 1. a stale session denies first (`session_version` below
    ///    `current_user_version`) -- this check runs before the admin
    ///    check, so a stale session denies administrators too;
    /// 2. `SystemRole::Admin` is granted with `AdminBypass` before the
    ///    deny set is even read: the deny set is delegated control and
    ///    must never be able to lock the administrator out;
    /// 3. an explicit deny matching the request (by name, or as a branch
    ///    the request descends from) denies, whatever grants exist;
    /// 4. a role default for the system role grants (`RoleDefault`,
    ///    global by definition);
    /// 5. otherwise the union of matching scoped grants is searched.
    ///
    /// Grant selection invariant: a grant matches only when its
    /// permission matches (exact name, or the grant is a branch the
    /// request descends from) AND its scope applies to the context. The
    /// matching grant with the highest scope specificity labels the
    /// decision (`Workspace` > `Group` > `Global`); on equal specificity
    /// the first candidate seen wins, and user-attached candidates are
    /// collected before group-attached ones, so a user global grant
    /// outranks a group global grant, and among groups the earliest
    /// entry in `ctx.group_ids` wins. Grants only ever union across
    /// scopes -- a workspace grant adds to a global one and never
    /// subtracts. No applicable match at all denies ("no matching grant
    /// at any applicable scope").
    ///
    /// Failure mode: a store error from `denied`, `user_grants` or
    /// `group_grants` propagates via `?` as `Err` and is never converted
    /// into a decision. Callers MUST treat that `Err` as a denial (fail
    /// closed): the engine's `resolve_effective_permissions` already
    /// denies on error, and swallowing it into `Ok(Denied { .. })` would
    /// also lose the distinction between a real denial and an outage.
    async fn resolve(
        &self,
        ctx: &PermissionContext,
        permission: &P,
        _resource_id: Option<&str>,
    ) -> anyhow::Result<PermissionDecision> {
        if ctx.is_session_stale() {
            return Ok(PermissionDecision::Denied {
                reason: "session version is stale — re-authentication required".into(),
                source: None,
            });
        }

        // Admin bypass first: the deny set is a delegated-control tool and
        // must not be able to lock the administrator out of the system.
        if ctx.system_role == crate::rbac::traits::SystemRole::Admin {
            return Ok(PermissionDecision::Granted {
                reason: "system administrator".into(),
                source: crate::rbac::traits::GrantSource::AdminBypass,
            });
        }

        // Deny wins over every grant shape.
        let denied = self.store.denied(ctx.user_id).await?;
        if denied.iter().any(|d| grant_matches(d, permission)) {
            return Ok(PermissionDecision::Denied {
                reason: "denied by explicit deny set".into(),
                source: None,
            });
        }

        // Role defaults (global by definition).
        if let Some(perms) = self.roles.get_role_permissions(ctx.system_role.as_str()) {
            if perms.iter().any(|p| grant_matches(p, permission)) {
                return Ok(PermissionDecision::Granted {
                    reason: format!("role default for {}", ctx.system_role.as_str()),
                    source: crate::rbac::traits::GrantSource::RoleDefault,
                });
            }
        }

        // Scoped grants — union; the most specific applicability labels
        // the decision (workspace > group attachment > user global).
        let mut candidates: Vec<(Attachment, ScopedGrant<P>)> = self
            .store
            .user_grants(ctx.user_id)
            .await?
            .into_iter()
            .map(|g| (Attachment::User, g))
            .collect();
        for group in &ctx.group_ids {
            candidates.extend(
                self.store
                    .group_grants(*group)
                    .await?
                    .into_iter()
                    .map(|g| (Attachment::Group, g)),
            );
        }
        let mut best: Option<(Attachment, &ScopedGrant<P>)> = None;
        for (attachment, grant) in &candidates {
            if grant.scope.applies_to(ctx) && grant_matches(&grant.permission, permission) {
                let more_specific = best.map_or(true, |(_, b)| {
                    grant.scope.specificity() > b.scope.specificity()
                });
                if more_specific {
                    best = Some((*attachment, grant));
                }
            }
        }
        if let Some((attachment, grant)) = best {
            return Ok(PermissionDecision::Granted {
                reason: format!("scoped grant ({:?})", grant.scope),
                source: grant_source(attachment, &grant.scope),
            });
        }
        Ok(PermissionDecision::Denied {
            reason: "no matching grant at any applicable scope".into(),
            source: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rbac::permission::Permission;

    /// The typed catalog's public constructor: leaf names are
    /// `"<domain>.<action>"` (e.g. "config.read").
    fn perm(path: &str) -> Permission {
        Permission::from_path(path).expect("valid catalog path")
    }

    fn ctx(user: Uuid, role: crate::rbac::traits::SystemRole) -> PermissionContext {
        PermissionContext {
            user_id: user,
            system_role: role,
            group_ids: vec![],
            workspace_id: None,
            workspace_role: None,
            session_version: 1,
            current_user_version: 1,
        }
    }

    struct StaticRegistry;

    impl RoleRegistry<Permission> for StaticRegistry {
        fn get_role_permissions(&self, _role_name: &str) -> Option<HashSet<Permission>> {
            None
        }
        fn list_role_names(&self) -> Vec<String> {
            vec![]
        }
    }

    fn registry() -> std::sync::Arc<dyn RoleRegistry<Permission>> {
        std::sync::Arc::new(StaticRegistry)
    }

    async fn decide(
        store: MemoryScopedGrantStore<Permission>,
        ctx: &PermissionContext,
        permission: &Permission,
    ) -> PermissionDecision {
        let resolver = ScopedGrantResolver::new(std::sync::Arc::new(store), registry());
        resolver.resolve(ctx, permission, None).await.unwrap()
    }

    use crate::rbac::traits::GrantSource;

    async fn granted(d: PermissionDecision) -> Option<GrantSource> {
        match d {
            PermissionDecision::Granted { source, .. } => Some(source),
            PermissionDecision::Denied { .. } => None,
        }
    }

    #[tokio::test]
    async fn empty_store_denies_member() {
        let d = decide(
            MemoryScopedGrantStore::new(),
            &ctx(Uuid::new_v4(), crate::rbac::traits::SystemRole::Member),
            &perm("config.read"),
        )
        .await;
        assert!(matches!(d, PermissionDecision::Denied { .. }));
    }

    #[tokio::test]
    async fn admin_bypasses_without_grants() {
        let d = decide(
            MemoryScopedGrantStore::new(),
            &ctx(Uuid::new_v4(), crate::rbac::traits::SystemRole::Admin),
            &perm("system.write"),
        )
        .await;
        assert!(matches!(granted(d).await, Some(GrantSource::AdminBypass)));
    }

    #[tokio::test]
    async fn deny_beats_grant_but_not_admin() {
        let u = Uuid::new_v4();
        let p = perm("config.read");
        let mut store = MemoryScopedGrantStore::new();
        store
            .grant_user(u, ScopedGrant::new(p, GrantScope::Global))
            .deny(u, p);
        let d = decide(
            store.clone(),
            &ctx(u, crate::rbac::traits::SystemRole::Member),
            &p,
        )
        .await;
        assert!(matches!(d, PermissionDecision::Denied { .. }));

        // The same subject as admin: bypass wins over the deny — the deny
        // set is delegated control and must never lock out the admin.
        let d = decide(store, &ctx(u, crate::rbac::traits::SystemRole::Admin), &p).await;
        assert!(matches!(granted(d).await, Some(GrantSource::AdminBypass)));
    }

    #[tokio::test]
    async fn workspace_grant_applies_only_inside_its_workspace() {
        let u = Uuid::new_v4();
        let ws_a = Uuid::new_v4();
        let ws_b = Uuid::new_v4();
        let p = perm("device.connect");
        let mut store = MemoryScopedGrantStore::new();
        store.grant_user(u, ScopedGrant::new(p, GrantScope::Workspace(ws_a)));

        let mut in_a = ctx(u, crate::rbac::traits::SystemRole::Member);
        in_a.workspace_id = Some(ws_a);
        let mut in_b = ctx(u, crate::rbac::traits::SystemRole::Member);
        in_b.workspace_id = Some(ws_b);

        assert!(matches!(
            decide(store.clone(), &in_a, &p).await,
            PermissionDecision::Granted {
                source: GrantSource::WorkspaceGrant,
                ..
            }
        ));
        assert!(matches!(
            decide(store.clone(), &in_b, &p).await,
            PermissionDecision::Denied { .. }
        ));
    }

    #[tokio::test]
    async fn group_grant_requires_membership_and_labels_source() {
        let u = Uuid::new_v4();
        let g = Uuid::new_v4();
        let p = perm("deploy.execute");
        let mut store = MemoryScopedGrantStore::new();
        store.grant_group(g, ScopedGrant::new(p, GrantScope::Global));

        let outsider = ctx(u, crate::rbac::traits::SystemRole::Member);
        let mut member = ctx(u, crate::rbac::traits::SystemRole::Member);
        member.group_ids = vec![g];

        assert!(matches!(
            decide(store.clone(), &outsider, &p).await,
            PermissionDecision::Denied { .. }
        ));
        assert!(matches!(
            granted(decide(store.clone(), &member, &p).await).await,
            Some(GrantSource::GroupGrant)
        ));
    }

    #[tokio::test]
    async fn most_specific_match_labels_the_decision() {
        let u = Uuid::new_v4();
        let g = Uuid::new_v4();
        let ws = Uuid::new_v4();
        let p = perm("channel.use");
        let mut store = MemoryScopedGrantStore::new();
        store
            .grant_user(u, ScopedGrant::new(p, GrantScope::Global))
            .grant_user(u, ScopedGrant::new(p, GrantScope::Workspace(ws)));
        let mut c = ctx(u, crate::rbac::traits::SystemRole::Member);
        c.group_ids = vec![g];
        c.workspace_id = Some(ws);
        // Both the global and the workspace grant apply; the more specific
        // workspace one must label the decision.
        assert!(matches!(
            granted(decide(store, &c, &p).await).await,
            Some(GrantSource::WorkspaceGrant)
        ));
    }

    #[tokio::test]
    async fn role_default_grants_without_any_store_rows() {
        let u = Uuid::new_v4();
        let p = perm("knowledge.read");
        struct WithDefault;
        impl RoleRegistry<Permission> for WithDefault {
            fn get_role_permissions(&self, _role: &str) -> Option<HashSet<Permission>> {
                let mut set = HashSet::new();
                set.insert(perm("knowledge.read"));
                Some(set)
            }
            fn list_role_names(&self) -> Vec<String> {
                vec!["member".into()]
            }
        }
        let resolver = ScopedGrantResolver::new(
            std::sync::Arc::new(MemoryScopedGrantStore::new()),
            std::sync::Arc::new(WithDefault),
        );
        let d = resolver
            .resolve(&ctx(u, crate::rbac::traits::SystemRole::Member), &p, None)
            .await
            .unwrap();
        assert!(matches!(granted(d).await, Some(GrantSource::RoleDefault)));
    }

    #[tokio::test]
    async fn stale_session_denies_even_admin() {
        let mut c = ctx(Uuid::new_v4(), crate::rbac::traits::SystemRole::Admin);
        c.session_version = 0;
        c.current_user_version = 2;
        let d = decide(MemoryScopedGrantStore::new(), &c, &perm("system.read")).await;
        assert!(matches!(d, PermissionDecision::Denied { .. }));
    }

    #[tokio::test]
    async fn equal_specificity_tie_labels_user_before_group() {
        // Same permission granted globally by both the user attachment
        // and a group attachment: equal scope specificity, and the
        // user-attached grant labels the decision (first-seen wins —
        // user candidates are collected before group candidates).
        let u = Uuid::new_v4();
        let g = Uuid::new_v4();
        let p = perm("yolo.use");
        let mut store = MemoryScopedGrantStore::new();
        store
            .grant_user(u, ScopedGrant::new(p, GrantScope::Global))
            .grant_group(g, ScopedGrant::new(p, GrantScope::Global));
        let mut c = ctx(u, crate::rbac::traits::SystemRole::Member);
        c.group_ids = vec![g];
        assert!(matches!(
            granted(decide(store, &c, &p).await).await,
            Some(GrantSource::UserGrant)
        ));
    }

    #[test]
    fn scope_specificity_and_serde_round_trip() {
        let w = GrantScope::Workspace(Uuid::new_v4()).specificity();
        let g = GrantScope::Group(Uuid::new_v4()).specificity();
        let global = GrantScope::Global.specificity();
        assert!(w > g && g > global);
        let s = serde_json::to_string(&GrantScope::Workspace(Uuid::nil())).unwrap();
        assert!(
            s.starts_with("{\"workspace\""),
            "externally tagged serde: {s}"
        );
        let back: GrantScope = serde_json::from_str(&s).unwrap();
        assert_eq!(back, GrantScope::Workspace(Uuid::nil()));
    }
}
