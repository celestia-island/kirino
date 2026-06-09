use futures::future::join_all;
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
    traits::{AssignmentStore, Permission, PermissionRegistry, RoleRegistry, Subject},
};

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

    #[must_use]
    pub fn with_cache(mut self, cache: impl PermissionCache<S, P> + 'static) -> Self {
        self.cache = Shared::from_arc_unsized(Arc::new(cache));
        self
    }

    #[must_use]
    pub fn role_registry(&self) -> Shared<dyn RoleRegistry<P>> {
        self.role_registry.clone()
    }

    #[must_use]
    pub fn permission_registry(&self) -> Shared<dyn PermissionRegistry<P>> {
        self.permission_registry.clone()
    }

    #[must_use]
    pub fn assignment_store(&self) -> Shared<A> {
        self.assignment_store.clone()
    }

    #[must_use]
    pub fn cache(&self) -> Shared<dyn PermissionCache<S, P>> {
        self.cache.clone()
    }

    pub async fn invalidate_subject_cache(&self, subject: &S) {
        self.cache.invalidate_subject(subject).await;
    }

    pub async fn invalidate_all_cache(&self) {
        self.cache.invalidate_all().await;
    }

    /// Check cache, denied permissions, and extra permissions.
    /// Returns `Ok(Some(result))` if a decision was reached,
    /// `Err(())` if a store error caused denial,
    /// `Ok(None)` if role checking is still needed.
    async fn check_cached_deny_extra(
        &self,
        subject: &S,
        permission: &P,
    ) -> Result<Option<bool>, ()> {
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
                return Err(());
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
                return Err(());
            }
        }

        Ok(None)
    }

    pub async fn check(&self, subject: &S, permission: &P) -> bool {
        match self.check_cached_deny_extra(subject, permission).await {
            Ok(Some(result)) => return result,
            Err(()) => return false,
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

    pub async fn check_batch(&self, subject: &S, permissions: &HashSet<P>) -> HashMap<P, bool> {
        let futs: Vec<_> = permissions
            .iter()
            .map(|perm| self.check(subject, perm))
            .collect();
        let outcomes = join_all(futs).await;
        permissions
            .iter()
            .zip(outcomes)
            .map(|(p, r)| (p.clone(), r))
            .collect()
    }

    pub async fn effective_permissions(&self, subject: &S) -> HashSet<P> {
        let mut perms = HashSet::new();

        match self.assignment_store.roles_of(subject).await {
            Ok(role_names) => {
                for role_name in &role_names {
                    if let Some(role_perms) = self.role_registry.get_role_permissions(role_name) {
                        perms.extend(role_perms);
                    }
                }
            }
            Err(e) => {
                tracing::warn!(target: "kirino::rbac::engine",
                    subject = %subject.subject_id(),
                    error = %e,
                    "failed to query roles for effective permissions"
                );
            }
        }

        if let Ok(extra) = self.assignment_store.extra_permissions(subject).await {
            perms.extend(extra);
        }

        if let Ok(denied) = self.assignment_store.denied_permissions(subject).await {
            perms.retain(|p| !denied.contains(p));
        }

        perms
    }
}

#[cfg(feature = "rbac-hierarchy")]
impl<S, P, A> RbacEngine<S, P, A>
where
    S: Subject,
    P: Permission,
    A: AssignmentStore<S, P>,
{
    pub async fn check_hierarchical(&self, subject: &S, permission: &P) -> bool {
        match self.check_cached_deny_extra(subject, permission).await {
            Ok(Some(result)) => return result,
            Err(()) => return false,
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

    pub async fn effective_permissions_hierarchical(&self, subject: &S) -> HashSet<P> {
        let mut perms = HashSet::new();

        if let Ok(role_names) = self.assignment_store.roles_of(subject).await {
            for role_name in &role_names {
                let inherited = resolve_role_chain(role_name, &*self.role_registry);
                perms.extend(inherited);
            }
        }

        if let Ok(extra) = self.assignment_store.extra_permissions(subject).await {
            perms.extend(extra);
        }

        if let Ok(denied) = self.assignment_store.denied_permissions(subject).await {
            perms.retain(|p| !denied.contains(p));
        }

        perms
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{KirinoError, KirinoResult};
    use crate::rbac::store::memory::InMemoryAssignmentStore;
    use crate::rbac::store::registry::{SimpleRole, StaticPermissionRegistry, StaticRoleRegistry};
    use crate::test_utils::{TestPerm, TestSubject};

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
            [TestPerm::Read].into_iter().collect(),
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
            .set_denied_permissions(&user, [TestPerm::Admin].into_iter().collect())
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
            .set_extra_permissions(&user, [TestPerm::Write].into_iter().collect())
            .await
            .unwrap();
        engine
            .assignment_store()
            .set_denied_permissions(&user, [TestPerm::Write].into_iter().collect())
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
            .set_extra_permissions(&user, [TestPerm::Write].into_iter().collect())
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
            .set_extra_permissions(&user, [TestPerm::Delete].into_iter().collect())
            .await
            .unwrap();

        let eff = engine.effective_permissions(&user).await;
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

        let eff = engine.effective_permissions(&user).await;
        assert!(eff.contains(&TestPerm::Read));
        assert!(eff.contains(&TestPerm::Write));
        assert!(!eff.contains(&TestPerm::Admin));
        assert!(!eff.contains(&TestPerm::Delete));
    }

    #[tokio::test]
    async fn test_effective_permissions_no_roles() {
        let engine = build_engine();
        let anon = TestSubject("ep-anon".to_string());
        let eff = engine.effective_permissions(&anon).await;
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
        async fn assign_role(&self, _: &TestSubject, _: &str) -> KirinoResult<()> {
            Ok(())
        }
        async fn revoke_role(&self, _: &TestSubject, _: &str) -> KirinoResult<()> {
            Ok(())
        }
        async fn roles_of(&self, _: &TestSubject) -> KirinoResult<Vec<String>> {
            Err(KirinoError::Store("store error".to_string()))
        }
        async fn subjects_with_role(&self, _: &str) -> KirinoResult<Vec<String>> {
            Ok(vec![])
        }
        async fn extra_permissions(&self, _: &TestSubject) -> KirinoResult<HashSet<TestPerm>> {
            Err(KirinoError::Store("store error".to_string()))
        }
        async fn set_extra_permissions(
            &self,
            _: &TestSubject,
            _: HashSet<TestPerm>,
        ) -> KirinoResult<()> {
            Ok(())
        }
        async fn denied_permissions(&self, _: &TestSubject) -> KirinoResult<HashSet<TestPerm>> {
            Err(KirinoError::Store("store error".to_string()))
        }
        async fn set_denied_permissions(
            &self,
            _: &TestSubject,
            _: HashSet<TestPerm>,
        ) -> KirinoResult<()> {
            Ok(())
        }
    }

    struct DeniedOnlyFailingStore(InMemoryAssignmentStore<TestSubject, TestPerm>);

    #[async_trait::async_trait]
    impl AssignmentStore<TestSubject, TestPerm> for DeniedOnlyFailingStore {
        async fn assign_role(&self, subject: &TestSubject, role: &str) -> KirinoResult<()> {
            self.0.assign_role(subject, role).await
        }
        async fn revoke_role(&self, subject: &TestSubject, role: &str) -> KirinoResult<()> {
            self.0.revoke_role(subject, role).await
        }
        async fn roles_of(&self, subject: &TestSubject) -> KirinoResult<Vec<String>> {
            self.0.roles_of(subject).await
        }
        async fn subjects_with_role(&self, role: &str) -> KirinoResult<Vec<String>> {
            self.0.subjects_with_role(role).await
        }
        async fn extra_permissions(
            &self,
            subject: &TestSubject,
        ) -> KirinoResult<HashSet<TestPerm>> {
            self.0.extra_permissions(subject).await
        }
        async fn set_extra_permissions(
            &self,
            subject: &TestSubject,
            perms: HashSet<TestPerm>,
        ) -> KirinoResult<()> {
            self.0.set_extra_permissions(subject, perms).await
        }
        async fn denied_permissions(&self, _: &TestSubject) -> KirinoResult<HashSet<TestPerm>> {
            Err(KirinoError::Store("denied store error".to_string()))
        }
        async fn set_denied_permissions(
            &self,
            subject: &TestSubject,
            perms: HashSet<TestPerm>,
        ) -> KirinoResult<()> {
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
        async fn assign_role(&self, subject: &TestSubject, role: &str) -> KirinoResult<()> {
            self.0.assign_role(subject, role).await
        }
        async fn revoke_role(&self, subject: &TestSubject, role: &str) -> KirinoResult<()> {
            self.0.revoke_role(subject, role).await
        }
        async fn roles_of(&self, subject: &TestSubject) -> KirinoResult<Vec<String>> {
            self.0.roles_of(subject).await
        }
        async fn subjects_with_role(&self, role: &str) -> KirinoResult<Vec<String>> {
            self.0.subjects_with_role(role).await
        }
        async fn extra_permissions(&self, _: &TestSubject) -> KirinoResult<HashSet<TestPerm>> {
            Err(KirinoError::Store("extra store error".to_string()))
        }
        async fn set_extra_permissions(
            &self,
            subject: &TestSubject,
            perms: HashSet<TestPerm>,
        ) -> KirinoResult<()> {
            self.0.set_extra_permissions(subject, perms).await
        }
        async fn denied_permissions(
            &self,
            subject: &TestSubject,
        ) -> KirinoResult<HashSet<TestPerm>> {
            self.0.denied_permissions(subject).await
        }
        async fn set_denied_permissions(
            &self,
            subject: &TestSubject,
            perms: HashSet<TestPerm>,
        ) -> KirinoResult<()> {
            self.0.set_denied_permissions(subject, perms).await
        }
    }

    #[tokio::test]
    async fn test_deny_on_extra_permissions_store_error() {
        let mut role_reg = StaticRoleRegistry::new();
        role_reg.register(SimpleRole::new(
            "viewer",
            [TestPerm::Read].into_iter().collect(),
        ));
        let perm_reg = StaticPermissionRegistry::new([TestPerm::Read].into_iter().collect());

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
