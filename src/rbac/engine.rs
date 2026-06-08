use std::{
    collections::{HashMap, HashSet},
    marker::PhantomData,
    sync::Arc,
    time::Duration,
};

use crate::rbac::{
    cache::{PermissionCache, TtlPermissionCache},
    hierarchy::{resolve_role_chain, HierarchicalRole},
    shared::Shared,
    traits::{AssignmentStore, Permission, PermissionRegistry, Role, RoleRegistry, Subject},
};

pub struct RbacEngine<S, P, R, A>
where
    S: Subject,
    P: Permission,
    R: Role<P>,
    A: AssignmentStore<S, P>,
{
    role_registry: Shared<dyn RoleRegistry<R, P>>,
    permission_registry: Shared<dyn PermissionRegistry<P>>,
    assignment_store: Shared<A>,
    cache: Shared<dyn PermissionCache<S, P>>,
    _phantom: PhantomData<(S, R)>,
}

impl<S, P, R, A> Clone for RbacEngine<S, P, R, A>
where
    S: Subject,
    P: Permission,
    R: Role<P>,
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

impl<S, P, R, A> RbacEngine<S, P, R, A>
where
    S: Subject,
    P: Permission,
    R: Role<P>,
    A: AssignmentStore<S, P>,
{
    pub fn new(
        role_registry: impl RoleRegistry<R, P> + 'static,
        permission_registry: impl PermissionRegistry<P> + 'static,
        assignment_store: A,
    ) -> Self {
        Self {
            role_registry: Shared::from_arc_unsized(Arc::new(role_registry)),
            permission_registry: Shared::from_arc_unsized(Arc::new(permission_registry)),
            assignment_store: Shared::new(assignment_store),
            cache: Shared::from_arc_unsized(Arc::new(TtlPermissionCache::new(
                Duration::from_mins(5),
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
    pub fn role_registry(&self) -> Shared<dyn RoleRegistry<R, P>> {
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

    pub async fn check(&self, subject: &S, permission: &P) -> bool {
        if let Some(granted) = self.cache.get(subject, permission) {
            return granted;
        }

        if let Ok(denied) = self.assignment_store.denied_permissions(subject).await {
            if denied.contains(permission) {
                self.cache.set(subject, permission, false);
                return false;
            }
        }

        if let Ok(extra) = self.assignment_store.extra_permissions(subject).await {
            if extra.contains(permission) {
                self.cache.set(subject, permission, true);
                return true;
            }
        }

        if let Ok(role_names) = self.assignment_store.roles_of(subject).await {
            for role_name in &role_names {
                if let Some(role) = self.role_registry.get_role(role_name) {
                    if role.permissions().contains(permission) {
                        self.cache.set(subject, permission, true);
                        return true;
                    }
                }
            }
        }

        self.cache.set(subject, permission, false);
        false
    }

    pub async fn check_batch(&self, subject: &S, permissions: &HashSet<P>) -> HashMap<P, bool> {
        let mut results = HashMap::with_capacity(permissions.len());
        for perm in permissions {
            results.insert(perm.clone(), self.check(subject, perm).await);
        }
        results
    }

    pub async fn effective_permissions(&self, subject: &S) -> HashSet<P> {
        let mut perms = HashSet::new();

        if let Ok(role_names) = self.assignment_store.roles_of(subject).await {
            for role_name in &role_names {
                if let Some(role) = self.role_registry.get_role(role_name) {
                    perms.extend(role.permissions().iter().cloned());
                }
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

impl<S, P, R, A> RbacEngine<S, P, R, A>
where
    S: Subject,
    P: Permission,
    R: HierarchicalRole<P>,
    A: AssignmentStore<S, P>,
{
    pub async fn check_hierarchical(&self, subject: &S, permission: &P) -> bool {
        if let Some(granted) = self.cache.get(subject, permission) {
            return granted;
        }

        if let Ok(denied) = self.assignment_store.denied_permissions(subject).await {
            if denied.contains(permission) {
                self.cache.set(subject, permission, false);
                return false;
            }
        }

        if let Ok(extra) = self.assignment_store.extra_permissions(subject).await {
            if extra.contains(permission) {
                self.cache.set(subject, permission, true);
                return true;
            }
        }

        if let Ok(role_names) = self.assignment_store.roles_of(subject).await {
            for role_name in &role_names {
                let inherited = resolve_role_chain(role_name, &*self.role_registry);
                if inherited.contains(permission) {
                    self.cache.set(subject, permission, true);
                    return true;
                }
            }
        }

        self.cache.set(subject, permission, false);
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
    use crate::rbac::store::memory::InMemoryAssignmentStore;
    use crate::rbac::store::registry::{SimpleRole, StaticPermissionRegistry, StaticRoleRegistry};

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    enum TestPerm {
        Read,
        Write,
        Delete,
        Admin,
    }

    impl Permission for TestPerm {
        fn name(&self) -> &str {
            match self {
                TestPerm::Read => "read",
                TestPerm::Write => "write",
                TestPerm::Delete => "delete",
                TestPerm::Admin => "admin",
            }
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    struct TestSubject(String);

    impl Subject for TestSubject {
        fn subject_id(&self) -> &str {
            &self.0
        }
    }

    fn build_engine() -> RbacEngine<
        TestSubject,
        TestPerm,
        SimpleRole<TestPerm>,
        InMemoryAssignmentStore<TestSubject, TestPerm>,
    > {
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
        assert!(reg.get_role("admin").is_some());
        assert!(reg.get_role("nonexistent").is_none());
    }

    #[tokio::test]
    async fn test_permission_registry_accessor() {
        let engine = build_engine();
        let reg = engine.permission_registry();
        assert!(reg.get_permission("read").is_some());
        assert!(reg.get_permission("nonexistent").is_none());
        assert_eq!(reg.all_permissions().len(), 4);
    }
}
