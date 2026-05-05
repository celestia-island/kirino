use std::collections::{HashMap, HashSet};
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;

use crate::rbac::cache::{PermissionCache, TtlPermissionCache};
use crate::rbac::hierarchy::{HierarchicalRole, resolve_role_chain};
use crate::rbac::traits::{
    AssignmentStore, Permission, PermissionRegistry, Role, RoleRegistry, Subject,
};

pub struct RbacEngine<S, P, R, A>
where
    S: Subject,
    P: Permission,
    R: Role<P>,
    A: AssignmentStore<S, P>,
{
    role_registry: Arc<dyn RoleRegistry<R, P>>,
    permission_registry: Arc<dyn PermissionRegistry<P>>,
    assignment_store: Arc<A>,
    cache: Arc<dyn PermissionCache<S, P>>,
    _phantom: PhantomData<(S, R)>,
}

impl<S, P, R, A> RbacEngine<S, P, R, A>
where
    S: Subject,
    P: Permission,
    R: Role<P>,
    A: AssignmentStore<S, P>,
{
    pub fn new(
        role_registry: Arc<dyn RoleRegistry<R, P>>,
        permission_registry: Arc<dyn PermissionRegistry<P>>,
        assignment_store: Arc<A>,
    ) -> Self {
        Self {
            role_registry,
            permission_registry,
            assignment_store,
            cache: Arc::new(TtlPermissionCache::new(Duration::from_secs(300))),
            _phantom: PhantomData,
        }
    }

    pub fn with_cache(mut self, cache: Arc<dyn PermissionCache<S, P>>) -> Self {
        self.cache = cache;
        self
    }

    pub fn role_registry(&self) -> &Arc<dyn RoleRegistry<R, P>> {
        &self.role_registry
    }

    pub fn permission_registry(&self) -> &Arc<dyn PermissionRegistry<P>> {
        &self.permission_registry
    }

    pub fn assignment_store(&self) -> &Arc<A> {
        &self.assignment_store
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
                let inherited = resolve_role_chain(role_name, self.role_registry.as_ref());
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
                let inherited = resolve_role_chain(role_name, self.role_registry.as_ref());
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

    fn build_engine() -> RbacEngine<TestSubject, TestPerm, SimpleRole<TestPerm>, InMemoryAssignmentStore<TestSubject, TestPerm>> {
        let mut role_reg = StaticRoleRegistry::new();
        role_reg.register(SimpleRole::new(
            "admin",
            [TestPerm::Read, TestPerm::Write, TestPerm::Delete, TestPerm::Admin]
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
            [TestPerm::Read, TestPerm::Write, TestPerm::Delete, TestPerm::Admin]
                .into_iter()
                .collect(),
        );

        let store = InMemoryAssignmentStore::new();

        RbacEngine::new(
            Arc::new(role_reg),
            Arc::new(perm_reg),
            Arc::new(store),
        )
    }

    #[tokio::test]
    async fn test_check_admin_role() {
        let engine = build_engine();
        let admin = TestSubject("admin-user".to_string());
        engine.assignment_store().assign_role(&admin, "admin").await.unwrap();

        assert!(engine.check(&admin, &TestPerm::Read).await);
        assert!(engine.check(&admin, &TestPerm::Write).await);
        assert!(engine.check(&admin, &TestPerm::Delete).await);
        assert!(engine.check(&admin, &TestPerm::Admin).await);
    }

    #[tokio::test]
    async fn test_check_viewer_role() {
        let engine = build_engine();
        let viewer = TestSubject("viewer-user".to_string());
        engine.assignment_store().assign_role(&viewer, "viewer").await.unwrap();

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
        engine.assignment_store().assign_role(&user, "admin").await.unwrap();
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
        engine.assignment_store().assign_role(&user, "viewer").await.unwrap();
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
        engine.assignment_store().assign_role(&editor, "editor").await.unwrap();

        let results = engine
            .check_batch(
                &editor,
                &[TestPerm::Read, TestPerm::Write, TestPerm::Delete].into_iter().collect(),
            )
            .await;

        assert_eq!(results[&TestPerm::Read], true);
        assert_eq!(results[&TestPerm::Write], true);
        assert_eq!(results[&TestPerm::Delete], false);
    }

    #[tokio::test]
    async fn test_effective_permissions() {
        let engine = build_engine();
        let user = TestSubject("ep-user".to_string());
        engine.assignment_store().assign_role(&user, "editor").await.unwrap();
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
        engine.assignment_store().assign_role(&user, "admin").await.unwrap();
        engine
            .assignment_store()
            .set_denied_permissions(&user, [TestPerm::Admin, TestPerm::Delete].into_iter().collect())
            .await
            .unwrap();

        let eff = engine.effective_permissions(&user).await;
        assert!(eff.contains(&TestPerm::Read));
        assert!(eff.contains(&TestPerm::Write));
        assert!(!eff.contains(&TestPerm::Admin));
        assert!(!eff.contains(&TestPerm::Delete));
    }
}
