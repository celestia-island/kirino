use anyhow::Result;
use std::{
    collections::{HashMap, HashSet},
    marker::PhantomData,
    sync::Arc,
    time::Duration,
};

#[cfg(feature = "rbac-hierarchy")]
use crate::rbac::hierarchy::resolve_role_chain;
use crate::rbac::{
    cache::{PermissionCache, TtlPermissionCache},
    shared::Shared,
    traits::{
        AssignmentStore, GrantResolver, Permission, PermissionContext, PermissionDecision,
        PermissionRegistry, RoleRegistry, Subject,
    },
};

/// Role-based access-control decision engine over pluggable registries and stores.
///
/// Composes a role registry, a permission registry, an assignment store and a
/// permission cache. Security invariants it upholds:
///
/// - Deny wins. An explicitly denied permission is checked before extra grants and
///   cannot be re-granted by a role.
/// - Fail closed. A store error during a check is reported as a denial (never as a
///   grant) and is deliberately not cached, so a transient store outage cannot pin
///   an allow or a deny.
/// - Decisions may be served from cache. Role or assignment writes performed
///   outside this type must be followed by [`RbacEngine::invalidate_subject_cache`]
///   (or [`RbacEngine::invalidate_all_cache`]), otherwise a revoked grant stays
///   usable until the cache entry expires.
pub struct RbacEngine<S, P, A>
where
    S: Subject,
    P: Permission,
    A: AssignmentStore<S, P>,
{
    role_registry: Shared<dyn RoleRegistry<P>>,
    permission_registry: Shared<dyn PermissionRegistry<P>>,
    assignment_store: Shared<A>,
    cache: Shared<dyn PermissionCache<S, P>>,
    _phantom: PhantomData<S>,
}

impl<S, P, A> Clone for RbacEngine<S, P, A>
where
    S: Subject,
    P: Permission,
    A: AssignmentStore<S, P>,
{
    fn clone(&self) -> Self {
        Self {
            role_registry: self.role_registry.clone(),
            permission_registry: self.permission_registry.clone(),
            assignment_store: self.assignment_store.clone(),
            cache: self.cache.clone(),
            _phantom: PhantomData,
        }
    }
}

impl<S, P, A> RbacEngine<S, P, A>
where
    S: Subject,
    P: Permission,
    A: AssignmentStore<S, P>,
{
    /// Build an engine with the default TTL permission cache (300 s).
    ///
    /// The TTL is the revocation window: revoking a role through the assignment store
    /// does not take effect for checks served from this cache until it expires or is
    /// invalidated. Use [`RbacEngine::with_cache`] to supply a different policy.
    #[must_use]
    pub fn new(
        role_registry: impl RoleRegistry<P> + 'static,
        permission_registry: impl PermissionRegistry<P> + 'static,
        assignment_store: A,
    ) -> Self {
        Self {
            role_registry: Shared::from_arc_unsized(Arc::new(role_registry)),
            permission_registry: Shared::from_arc_unsized(Arc::new(permission_registry)),
            assignment_store: Shared::new(assignment_store),
            cache: Shared::from_arc_unsized(Arc::new(TtlPermissionCache::new(
                Duration::from_secs(300),
            ))),
            _phantom: PhantomData,
        }
    }

    /// Replace the default cache.
    ///
    /// The engine calls `invalidate_subject`/`invalidate_all` on the supplied cache,
    /// so it must honour them; a cache with a longer TTL (or none) widens the window
    /// in which a revoked permission is still reported as granted.
    #[must_use]
    pub fn with_cache(mut self, cache: impl PermissionCache<S, P> + 'static) -> Self {
        self.cache = Shared::from_arc_unsized(Arc::new(cache));
        self
    }

    /// Shared handle to the role registry.
    ///
    /// It is the live object, not a snapshot: mutating role definitions through this
    /// handle bypasses the engine's cache, so follow a write with
    /// [`RbacEngine::invalidate_all_cache`] or revocations may not take effect.
    #[must_use]
    pub fn role_registry(&self) -> Shared<dyn RoleRegistry<P>> {
        self.role_registry.clone()
    }

    /// Shared handle to the permission registry (the catalogue of known permissions).
    ///
    /// Read-mostly: entries here describe what exists, not who holds it, so changes do
    /// not by themselves affect any cached decision.
    #[must_use]
    pub fn permission_registry(&self) -> Shared<dyn PermissionRegistry<P>> {
        self.permission_registry.clone()
    }

    /// Shared handle to the assignment store.
    ///
    /// This is how roles, extra permissions and explicit denials are written. Every
    /// write performed through it must be paired with a cache invalidation (see
    /// [`RbacEngine::invalidate_subject_cache`]) to be effective immediately.
    #[must_use]
    pub fn assignment_store(&self) -> Shared<A> {
        self.assignment_store.clone()
    }

    /// Shared handle to the permission cache.
    ///
    /// Exposed for inspection and manual eviction; entries in it are authorization
    /// decisions, so treat its contents as security state (do not log keys derived
    /// from credentials, and clear it after an out-of-band permission change).
    #[must_use]
    pub fn cache(&self) -> Shared<dyn PermissionCache<S, P>> {
        self.cache.clone()
    }

    /// Drop every cached decision for one subject.
    ///
    /// Required after changing that subject's roles, extra permissions or explicit
    /// denials; call it after the write commits, since a concurrent check may re-cache
    /// the pre-write answer in between.
    pub async fn invalidate_subject_cache(&self, subject: &S) {
        self.cache.invalidate_subject(subject).await;
    }

    /// Drop every cached decision.
    ///
    /// Required after a change to role definitions or to the permission catalogue,
    /// which can affect any subject at once. This is a global barrier: expect a burst
    /// of store traffic as the cache refills.
    pub async fn invalidate_all_cache(&self) {
        self.cache.invalidate_all().await;
    }

    /// Check cache, denied permissions, and extra permissions.
    /// Returns `Ok(Some(result))` if a decision was reached,
    /// `Err(e)` if a store error caused denial (error preserved),
    /// `Ok(None)` if role checking is still needed.
    async fn check_cached_deny_extra(&self, subject: &S, permission: &P) -> Result<Option<bool>> {
        if let Some(granted) = self.cache.get(subject, permission).await {
            return Ok(Some(granted));
        }

        match self.assignment_store.denied_permissions(subject).await {
            Ok(denied) => {
                if denied.contains(permission) {
                    self.cache.set(subject, permission, false).await;
                    return Ok(Some(false));
                }
            }
            Err(e) => {
                tracing::error!(target: "kirino::rbac::engine",
                    subject = %subject.subject_id(),
                    error = %e,
                    "failed to query denied permissions — denying access (not cached)"
                );
                return Err(e);
            }
        }

        match self.assignment_store.extra_permissions(subject).await {
            Ok(extra) => {
                if extra.contains(permission) {
                    self.cache.set(subject, permission, true).await;
                    return Ok(Some(true));
                }
            }
            Err(e) => {
                tracing::error!(target: "kirino::rbac::engine",
                    subject = %subject.subject_id(),
                    error = %e,
                    "failed to query extra permissions — denying access (not cached)"
                );
                return Err(e);
            }
        }

        Ok(None)
    }

    /// Decide whether `subject` holds `permission`, with deny-by-default semantics.
    ///
    /// Evaluates explicit denials first, then extra grants, then role membership, and
    /// caches the outcome. Any store error is logged and answered with `false` rather
    /// than propagated, so a caller cannot distinguish "denied" from "store
    /// unavailable": treat `false` as deny, never as "retry later and assume yes".
    /// Has no wildcard or inheritance expansion - use
    /// [`RbacEngine::check_permission`], or `RbacEngine::check_hierarchical`
    /// (feature `rbac-hierarchy`) for role inheritance.
    #[must_use]
    pub async fn check(&self, subject: &S, permission: &P) -> bool {
        match self.check_cached_deny_extra(subject, permission).await {
            Ok(Some(result)) => return result,
            Err(e) => {
                tracing::error!(target: "kirino::rbac::engine",
                    subject = %subject.subject_id(),
                    error = %e,
                    "store error during permission check — denying access"
                );
                return false;
            }
            Ok(None) => {}
        }

        match self.assignment_store.roles_of(subject).await {
            Ok(role_names) => {
                for role_name in &role_names {
                    if let Some(perms) = self.role_registry.get_role_permissions(role_name) {
                        if perms.contains(permission) {
                            self.cache.set(subject, permission, true).await;
                            return true;
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!(target: "kirino::rbac::engine",
                    subject = %subject.subject_id(),
                    error = %e,
                    "failed to query roles"
                );
            }
        }

        self.cache.set(subject, permission, false).await;
        false
    }

    /// Check many permissions for one subject, at most 64 store lookups in flight.
    ///
    /// Every permission is decided by [`RbacEngine::check`], so the same fail-closed
    /// rule applies per entry: a store error yields `false` for that permission and
    /// does not abort the batch. The result contains exactly the requested keys, so a
    /// missing key is a bug, not a denial.
    #[must_use]
    pub async fn check_batch(&self, subject: &S, permissions: &HashSet<P>) -> HashMap<P, bool> {
        use futures::stream::{self, StreamExt};

        let engine = self.clone();
        let subject = subject.clone();
        let perms: Vec<P> = permissions.iter().cloned().collect();
        let outcomes: Vec<bool> = stream::iter(perms.clone())
            .map(move |perm| {
                let engine = engine.clone();
                let subject = subject.clone();
                async move { engine.check(&subject, &perm).await }
            })
            .buffered(64)
            .collect()
            .await;
        perms.into_iter().zip(outcomes).collect()
    }

    /// Every permission the subject can exercise: role permissions plus extra grants,
    /// minus explicit denials.
    ///
    /// Unlike [`RbacEngine::check`] this propagates store errors instead of denying, so
    /// the caller decides how to fail; do not treat a partial answer as authoritative.
    /// Results are not served from cache.
    pub async fn effective_permissions(&self, subject: &S) -> Result<HashSet<P>> {
        let mut perms = HashSet::new();

        let role_names = self.assignment_store.roles_of(subject).await?;
        for role_name in &role_names {
            if let Some(role_perms) = self.role_registry.get_role_permissions(role_name) {
                perms.extend(role_perms);
            }
        }

        let extra = self.assignment_store.extra_permissions(subject).await?;
        perms.extend(extra);

        let denied = self.assignment_store.denied_permissions(subject).await?;
        perms.retain(|p| !denied.contains(p));

        Ok(perms)
    }

    /// Unified permission check with wildcard-supporting grant resolver.
    ///
    /// Uses `GrantResolver` to expand wildcard grants (e.g., a grant for
    /// `"agent"` covers all `agent.read` / `agent.write` / `agent.execute`
    /// leaf permissions).  Also enforces session-version freshness.
    pub async fn check_permission(
        &self,
        ctx: &PermissionContext,
        permission: &P,
        resource_id: Option<&str>,
        grant_resolver: &dyn GrantResolver<P>,
    ) -> Result<PermissionDecision> {
        if ctx.is_session_stale() {
            return Ok(PermissionDecision::Denied {
                reason: "session version is stale — re-authentication required".into(),
                source: None,
            });
        }

        grant_resolver.resolve(ctx, permission, resource_id).await
    }

    /// Resolve all effective permissions including wildcard grant expansion.
    ///
    /// Collects every leaf permission that the subject can exercise, taking
    /// wildcard grants into account.
    pub async fn resolve_effective_permissions(
        &self,
        ctx: &PermissionContext,
        grant_resolver: &dyn GrantResolver<P>,
    ) -> Result<Vec<P>> {
        let all_leaves = P::all();
        let mut granted = Vec::new();

        for perm in &all_leaves {
            match grant_resolver.resolve(ctx, perm, None).await {
                Ok(PermissionDecision::Granted { .. }) => granted.push(perm.clone()),
                Ok(PermissionDecision::Denied { .. }) => {}
                Err(e) => {
                    tracing::warn!(target: "kirino::rbac::engine",
                        permission = %perm.name(),
                        error = %e,
                        "failed to resolve permission, treating as denied"
                    );
                }
            }
        }

        Ok(granted)
    }
}

#[cfg(feature = "rbac-hierarchy")]
impl<S, P, A> RbacEngine<S, P, A>
where
    S: Subject,
    P: Permission,
    A: AssignmentStore<S, P>,
{
    /// Like [`RbacEngine::check`], but resolves each of the subject's roles through the
    /// role hierarchy (inherited permissions included).
    ///
    /// Only available with the `rbac-hierarchy` feature. Same invariants as `check`:
    /// expire-first ordering against the shared cache, store errors answered with
    /// `false`, and no wildcard expansion.
    #[must_use]
    pub async fn check_hierarchical(&self, subject: &S, permission: &P) -> bool {
        match self.check_cached_deny_extra(subject, permission).await {
            Ok(Some(result)) => return result,
            Err(e) => {
                tracing::error!(target: "kirino::rbac::engine",
                    subject = %subject.subject_id(),
                    error = %e,
                    "store error during hierarchical permission check — denying access"
                );
                return false;
            }
            Ok(None) => {}
        }

        match self.assignment_store.roles_of(subject).await {
            Ok(role_names) => {
                for role_name in &role_names {
                    let inherited = resolve_role_chain(role_name, &*self.role_registry);
                    if inherited.contains(permission) {
                        self.cache.set(subject, permission, true).await;
                        return true;
                    }
                }
            }
            Err(e) => {
                tracing::warn!(target: "kirino::rbac::engine",
                    subject = %subject.subject_id(),
                    error = %e,
                    "failed to query roles for hierarchical check"
                );
            }
        }

        self.cache.set(subject, permission, false).await;
        false
    }

    /// Hierarchy-aware variant of [`RbacEngine::effective_permissions`]: role
    /// permissions are expanded through the role chain before explicit denials are
    /// subtracted.
    ///
    /// Only available with the `rbac-hierarchy` feature. Propagates store errors, and
    /// is not cached, so it is safe to use as an authorization audit input.
    pub async fn effective_permissions_hierarchical(&self, subject: &S) -> Result<HashSet<P>> {
        let mut perms = HashSet::new();

        let role_names = self.assignment_store.roles_of(subject).await?;
        for role_name in &role_names {
            let inherited = resolve_role_chain(role_name, &*self.role_registry);
            perms.extend(inherited);
        }

        let extra = self.assignment_store.extra_permissions(subject).await?;
        perms.extend(extra);

        let denied = self.assignment_store.denied_permissions(subject).await?;
        perms.retain(|p| !denied.contains(p));

        Ok(perms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rbac::store::memory::InMemoryAssignmentStore;
    use crate::rbac::store::registry::{SimpleRole, StaticPermissionRegistry, StaticRoleRegistry};
    use crate::test_utils::{TestPerm, TestSubject};
    use anyhow::anyhow;

    fn build_engine(
    ) -> RbacEngine<TestSubject, TestPerm, InMemoryAssignmentStore<TestSubject, TestPerm>> {
        let mut role_reg = StaticRoleRegistry::new();
        role_reg.register(SimpleRole::new(
            "admin",
            [
                TestPerm::Read,
                TestPerm::Write,
                TestPerm::Delete,
                TestPerm::Admin,
            ]
            .into_iter()
            .collect(),
        ));
        role_reg.register(SimpleRole::new(
            "viewer",
            std::iter::once(TestPerm::Read).collect(),
        ));
        role_reg.register(SimpleRole::new(
            "editor",
            [TestPerm::Read, TestPerm::Write].into_iter().collect(),
        ));

        let perm_reg = StaticPermissionRegistry::new(
            [
                TestPerm::Read,
                TestPerm::Write,
                TestPerm::Delete,
                TestPerm::Admin,
            ]
            .into_iter()
            .collect(),
        );

        let store = InMemoryAssignmentStore::new();

        RbacEngine::new(role_reg, perm_reg, store)
    }

    #[tokio::test]
    async fn test_check_admin_role() {
        let engine = build_engine();
        let admin = TestSubject("admin-user".to_string());
        engine
            .assignment_store()
            .assign_role(&admin, "admin")
            .await
            .unwrap();

        assert!(engine.check(&admin, &TestPerm::Read).await);
        assert!(engine.check(&admin, &TestPerm::Write).await);
        assert!(engine.check(&admin, &TestPerm::Delete).await);
        assert!(engine.check(&admin, &TestPerm::Admin).await);
    }

    #[tokio::test]
    async fn test_check_viewer_role() {
        let engine = build_engine();
        let viewer = TestSubject("viewer-user".to_string());
        engine
            .assignment_store()
            .assign_role(&viewer, "viewer")
            .await
            .unwrap();

        assert!(engine.check(&viewer, &TestPerm::Read).await);
        assert!(!engine.check(&viewer, &TestPerm::Write).await);
        assert!(!engine.check(&viewer, &TestPerm::Delete).await);
    }

    #[tokio::test]
    async fn test_check_no_roles() {
        let engine = build_engine();
        let anon = TestSubject("anon".to_string());

        assert!(!engine.check(&anon, &TestPerm::Read).await);
    }

    #[tokio::test]
    async fn test_deny_override() {
        let engine = build_engine();
        let user = TestSubject("denied-user".to_string());
        engine
            .assignment_store()
            .assign_role(&user, "admin")
            .await
            .unwrap();
        engine
            .assignment_store()
            .set_denied_permissions(&user, std::iter::once(TestPerm::Admin).collect())
            .await
            .unwrap();

        assert!(engine.check(&user, &TestPerm::Read).await);
        assert!(!engine.check(&user, &TestPerm::Admin).await);
    }

    #[tokio::test]
    async fn test_deny_overrides_extra() {
        let engine = build_engine();
        let user = TestSubject("deny-extra-user".to_string());
        engine
            .assignment_store()
            .set_extra_permissions(&user, std::iter::once(TestPerm::Write).collect())
            .await
            .unwrap();
        engine
            .assignment_store()
            .set_denied_permissions(&user, std::iter::once(TestPerm::Write).collect())
            .await
            .unwrap();

        assert!(!engine.check(&user, &TestPerm::Write).await);
    }

    #[tokio::test]
    async fn test_extra_permissions() {
        let engine = build_engine();
        let user = TestSubject("extra-user".to_string());
        engine
            .assignment_store()
            .assign_role(&user, "viewer")
            .await
            .unwrap();
        engine
            .assignment_store()
            .set_extra_permissions(&user, std::iter::once(TestPerm::Write).collect())
            .await
            .unwrap();

        assert!(engine.check(&user, &TestPerm::Read).await);
        assert!(engine.check(&user, &TestPerm::Write).await);
        assert!(!engine.check(&user, &TestPerm::Delete).await);
    }

    #[tokio::test]
    async fn test_check_batch() {
        let engine = build_engine();
        let editor = TestSubject("editor-user".to_string());
        engine
            .assignment_store()
            .assign_role(&editor, "editor")
            .await
            .unwrap();

        let results = engine
            .check_batch(
                &editor,
                &[TestPerm::Read, TestPerm::Write, TestPerm::Delete]
                    .into_iter()
                    .collect(),
            )
            .await;

        assert!(results[&TestPerm::Read]);
        assert!(results[&TestPerm::Write]);
        assert!(!results[&TestPerm::Delete]);
    }

    #[tokio::test]
    async fn test_check_batch_empty() {
        let engine = build_engine();
        let user = TestSubject("batch-empty".to_string());
        let results = engine.check_batch(&user, &HashSet::new()).await;
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_effective_permissions() {
        let engine = build_engine();
        let user = TestSubject("ep-user".to_string());
        engine
            .assignment_store()
            .assign_role(&user, "editor")
            .await
            .unwrap();
        engine
            .assignment_store()
            .set_extra_permissions(&user, std::iter::once(TestPerm::Delete).collect())
            .await
            .unwrap();

        let eff = engine.effective_permissions(&user).await.unwrap();
        assert!(eff.contains(&TestPerm::Read));
        assert!(eff.contains(&TestPerm::Write));
        assert!(eff.contains(&TestPerm::Delete));
        assert!(!eff.contains(&TestPerm::Admin));
    }

    #[tokio::test]
    async fn test_effective_permissions_with_deny() {
        let engine = build_engine();
        let user = TestSubject("ep-deny-user".to_string());
        engine
            .assignment_store()
            .assign_role(&user, "admin")
            .await
            .unwrap();
        engine
            .assignment_store()
            .set_denied_permissions(
                &user,
                [TestPerm::Admin, TestPerm::Delete].into_iter().collect(),
            )
            .await
            .unwrap();

        let eff = engine.effective_permissions(&user).await.unwrap();
        assert!(eff.contains(&TestPerm::Read));
        assert!(eff.contains(&TestPerm::Write));
        assert!(!eff.contains(&TestPerm::Admin));
        assert!(!eff.contains(&TestPerm::Delete));
    }

    #[tokio::test]
    async fn test_effective_permissions_no_roles() {
        let engine = build_engine();
        let anon = TestSubject("ep-anon".to_string());
        let eff = engine.effective_permissions(&anon).await.unwrap();
        assert!(eff.is_empty());
    }

    #[tokio::test]
    async fn test_engine_copy_shared_access() {
        let engine = build_engine();
        let store = engine.assignment_store();
        let store2 = engine.assignment_store();
        assert!(store.ptr_eq(&store2));

        let user = TestSubject("copy-user".to_string());
        store.assign_role(&user, "admin").await.unwrap();
        assert!(engine.check(&user, &TestPerm::Admin).await);
    }

    #[tokio::test]
    async fn test_engine_multiple_independent_stores() {
        let mut role_reg = StaticRoleRegistry::new();
        role_reg.register(SimpleRole::new(
            "admin",
            [TestPerm::Read, TestPerm::Write].into_iter().collect(),
        ));

        let engine1 = RbacEngine::new(
            StaticRoleRegistry::<SimpleRole<TestPerm>, TestPerm>::new(),
            StaticPermissionRegistry::new([TestPerm::Read, TestPerm::Write].into_iter().collect()),
            InMemoryAssignmentStore::new(),
        );
        let engine2 = RbacEngine::new(
            role_reg,
            StaticPermissionRegistry::new([TestPerm::Read, TestPerm::Write].into_iter().collect()),
            InMemoryAssignmentStore::new(),
        );

        let user1 = TestSubject("u1".to_string());
        let user2 = TestSubject("u2".to_string());
        engine1
            .assignment_store()
            .assign_role(&user1, "admin")
            .await
            .unwrap();
        engine2
            .assignment_store()
            .assign_role(&user2, "admin")
            .await
            .unwrap();

        assert!(!engine1.check(&user1, &TestPerm::Read).await);
        assert!(engine2.check(&user2, &TestPerm::Read).await);
    }

    #[tokio::test]
    async fn test_role_registry_accessor() {
        let engine = build_engine();
        let reg = engine.role_registry();
        assert!(reg.get_role_permissions("admin").is_some());
        assert!(reg.get_role_permissions("nonexistent").is_none());
    }

    #[tokio::test]
    async fn test_permission_registry_accessor() {
        let engine = build_engine();
        let reg = engine.permission_registry();
        assert!(reg.get_permission("read").is_some());
        assert!(reg.get_permission("nonexistent").is_none());
        assert_eq!(reg.all_permissions().len(), 4);
    }

    #[tokio::test]
    async fn test_cache_invalidation() {
        let engine = build_engine();
        let user = TestSubject("cache-user".to_string());
        engine
            .assignment_store()
            .assign_role(&user, "admin")
            .await
            .unwrap();

        assert!(engine.check(&user, &TestPerm::Admin).await);

        engine.invalidate_subject_cache(&user).await;
        engine
            .assignment_store()
            .revoke_role(&user, "admin")
            .await
            .unwrap();

        assert!(!engine.check(&user, &TestPerm::Admin).await);
    }

    #[tokio::test]
    async fn test_cache_invalidate_all() {
        let engine = build_engine();
        let user1 = TestSubject("cache-u1".to_string());
        let user2 = TestSubject("cache-u2".to_string());
        engine
            .assignment_store()
            .assign_role(&user1, "viewer")
            .await
            .unwrap();
        engine
            .assignment_store()
            .assign_role(&user2, "viewer")
            .await
            .unwrap();

        assert!(engine.check(&user1, &TestPerm::Read).await);
        assert!(engine.check(&user2, &TestPerm::Read).await);

        engine.invalidate_all_cache().await;
        engine
            .assignment_store()
            .revoke_role(&user1, "viewer")
            .await
            .unwrap();

        assert!(!engine.check(&user1, &TestPerm::Read).await);
        assert!(engine.check(&user2, &TestPerm::Read).await);
    }

    #[tokio::test]
    async fn test_multiple_roles() {
        let engine = build_engine();
        let user = TestSubject("multi-role".to_string());
        engine
            .assignment_store()
            .assign_role(&user, "viewer")
            .await
            .unwrap();
        engine
            .assignment_store()
            .assign_role(&user, "editor")
            .await
            .unwrap();

        assert!(engine.check(&user, &TestPerm::Read).await);
        assert!(engine.check(&user, &TestPerm::Write).await);
        assert!(!engine.check(&user, &TestPerm::Admin).await);
    }

    #[tokio::test]
    async fn test_assign_duplicate_role() {
        let engine = build_engine();
        let user = TestSubject("dup-role".to_string());
        engine
            .assignment_store()
            .assign_role(&user, "viewer")
            .await
            .unwrap();
        engine
            .assignment_store()
            .assign_role(&user, "viewer")
            .await
            .unwrap();

        let roles = engine.assignment_store().roles_of(&user).await.unwrap();
        assert_eq!(roles.len(), 1);
    }

    #[tokio::test]
    async fn test_concurrent_checks() {
        let engine = Shared::new(build_engine());
        let user = TestSubject("user1".to_string());
        let read = TestPerm::Read;

        engine
            .assignment_store()
            .assign_role(&user, "admin")
            .await
            .unwrap();

        let handles: Vec<_> = (0..20)
            .map(|_| {
                let engine = engine.clone();
                let user = user.clone();
                tokio::spawn(async move { engine.check(&user, &read).await })
            })
            .collect();

        for h in handles {
            assert!(h.await.unwrap());
        }
    }

    #[tokio::test]
    async fn test_check_nonexistent_role_in_registry() {
        let engine = Shared::new(build_engine());
        let user = TestSubject("user1".to_string());

        engine
            .assignment_store()
            .assign_role(&user, "nonexistent-role")
            .await
            .unwrap();

        assert!(!engine.check(&user, &TestPerm::Write).await);
    }

    struct FailingAssignmentStore;

    #[async_trait::async_trait]
    impl AssignmentStore<TestSubject, TestPerm> for FailingAssignmentStore {
        async fn assign_role(&self, _: &TestSubject, _: &str) -> Result<()> {
            Ok(())
        }
        async fn revoke_role(&self, _: &TestSubject, _: &str) -> Result<()> {
            Ok(())
        }
        async fn roles_of(&self, _: &TestSubject) -> Result<Vec<String>> {
            Err(anyhow!("store error"))
        }
        async fn subjects_with_role(&self, _: &str) -> Result<Vec<String>> {
            Ok(vec![])
        }
        async fn extra_permissions(&self, _: &TestSubject) -> Result<HashSet<TestPerm>> {
            Err(anyhow!("store error"))
        }
        async fn set_extra_permissions(&self, _: &TestSubject, _: HashSet<TestPerm>) -> Result<()> {
            Ok(())
        }
        async fn denied_permissions(&self, _: &TestSubject) -> Result<HashSet<TestPerm>> {
            Err(anyhow!("store error"))
        }
        async fn set_denied_permissions(
            &self,
            _: &TestSubject,
            _: HashSet<TestPerm>,
        ) -> Result<()> {
            Ok(())
        }
    }

    struct DeniedOnlyFailingStore(InMemoryAssignmentStore<TestSubject, TestPerm>);

    #[async_trait::async_trait]
    impl AssignmentStore<TestSubject, TestPerm> for DeniedOnlyFailingStore {
        async fn assign_role(&self, subject: &TestSubject, role: &str) -> Result<()> {
            self.0.assign_role(subject, role).await
        }
        async fn revoke_role(&self, subject: &TestSubject, role: &str) -> Result<()> {
            self.0.revoke_role(subject, role).await
        }
        async fn roles_of(&self, subject: &TestSubject) -> Result<Vec<String>> {
            self.0.roles_of(subject).await
        }
        async fn subjects_with_role(&self, role: &str) -> Result<Vec<String>> {
            self.0.subjects_with_role(role).await
        }
        async fn extra_permissions(&self, subject: &TestSubject) -> Result<HashSet<TestPerm>> {
            self.0.extra_permissions(subject).await
        }
        async fn set_extra_permissions(
            &self,
            subject: &TestSubject,
            perms: HashSet<TestPerm>,
        ) -> Result<()> {
            self.0.set_extra_permissions(subject, perms).await
        }
        async fn denied_permissions(&self, _: &TestSubject) -> Result<HashSet<TestPerm>> {
            Err(anyhow!("denied store error"))
        }
        async fn set_denied_permissions(
            &self,
            subject: &TestSubject,
            perms: HashSet<TestPerm>,
        ) -> Result<()> {
            self.0.set_denied_permissions(subject, perms).await
        }
    }

    #[tokio::test]
    async fn test_deny_on_denied_permissions_store_error() {
        let engine = RbacEngine::<TestSubject, TestPerm, FailingAssignmentStore>::new(
            StaticRoleRegistry::<SimpleRole<TestPerm>, TestPerm>::new(),
            StaticPermissionRegistry::new(HashSet::new()),
            FailingAssignmentStore,
        );
        let user = TestSubject("user".to_string());
        assert!(!engine.check(&user, &TestPerm::Read).await);
    }

    struct ExtraOnlyFailingStore(InMemoryAssignmentStore<TestSubject, TestPerm>);

    #[async_trait::async_trait]
    impl AssignmentStore<TestSubject, TestPerm> for ExtraOnlyFailingStore {
        async fn assign_role(&self, subject: &TestSubject, role: &str) -> Result<()> {
            self.0.assign_role(subject, role).await
        }
        async fn revoke_role(&self, subject: &TestSubject, role: &str) -> Result<()> {
            self.0.revoke_role(subject, role).await
        }
        async fn roles_of(&self, subject: &TestSubject) -> Result<Vec<String>> {
            self.0.roles_of(subject).await
        }
        async fn subjects_with_role(&self, role: &str) -> Result<Vec<String>> {
            self.0.subjects_with_role(role).await
        }
        async fn extra_permissions(&self, _: &TestSubject) -> Result<HashSet<TestPerm>> {
            Err(anyhow!("extra store error"))
        }
        async fn set_extra_permissions(
            &self,
            subject: &TestSubject,
            perms: HashSet<TestPerm>,
        ) -> Result<()> {
            self.0.set_extra_permissions(subject, perms).await
        }
        async fn denied_permissions(&self, subject: &TestSubject) -> Result<HashSet<TestPerm>> {
            self.0.denied_permissions(subject).await
        }
        async fn set_denied_permissions(
            &self,
            subject: &TestSubject,
            perms: HashSet<TestPerm>,
        ) -> Result<()> {
            self.0.set_denied_permissions(subject, perms).await
        }
    }

    #[tokio::test]
    async fn test_deny_on_extra_permissions_store_error() {
        let mut role_reg = StaticRoleRegistry::new();
        role_reg.register(SimpleRole::new(
            "viewer",
            std::iter::once(TestPerm::Read).collect(),
        ));
        let perm_reg = StaticPermissionRegistry::new(std::iter::once(TestPerm::Read).collect());

        let engine = RbacEngine::<TestSubject, TestPerm, ExtraOnlyFailingStore>::new(
            role_reg,
            perm_reg,
            ExtraOnlyFailingStore(InMemoryAssignmentStore::new()),
        );

        let user = TestSubject("user".to_string());
        engine
            .assignment_store()
            .assign_role(&user, "viewer")
            .await
            .unwrap();

        assert!(!engine.check(&user, &TestPerm::Read).await);
    }

    #[tokio::test]
    async fn test_deny_on_denied_permissions_store_error_with_role() {
        let mut role_reg = StaticRoleRegistry::new();
        role_reg.register(SimpleRole::new(
            "admin",
            [TestPerm::Read, TestPerm::Write].into_iter().collect(),
        ));
        let perm_reg =
            StaticPermissionRegistry::new([TestPerm::Read, TestPerm::Write].into_iter().collect());

        let engine = RbacEngine::<TestSubject, TestPerm, DeniedOnlyFailingStore>::new(
            role_reg,
            perm_reg,
            DeniedOnlyFailingStore(InMemoryAssignmentStore::new()),
        );
        let user = TestSubject("user".to_string());
        engine
            .assignment_store()
            .assign_role(&user, "admin")
            .await
            .unwrap();

        assert!(!engine.check(&user, &TestPerm::Read).await);
        assert!(!engine.check(&user, &TestPerm::Write).await);
    }
}
