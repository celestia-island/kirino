use anyhow::Result;
use std::{
    collections::{HashMap, HashSet},
    marker::PhantomData,
};
use tokio::sync::RwLock;

use async_trait::async_trait;

use crate::rbac::traits::{AssignmentStore, Permission, RoleStore, Subject};

/// In-memory implementation of [`AssignmentStore`] backed by `tokio::sync::RwLock`.
///
/// Stores role assignments, extra permissions, and denied permissions per subject
/// in separate `HashMap`s keyed by `subject_id`. All operations are thread-safe.
pub struct InMemoryAssignmentStore<S, P>
where
    S: Subject,
    P: Permission,
{
    role_assignments: RwLock<HashMap<String, HashSet<String>>>,
    extra_perms: RwLock<HashMap<String, HashSet<P>>>,
    denied_perms: RwLock<HashMap<String, HashSet<P>>>,
    _phantom: PhantomData<S>,
}

impl<S, P> InMemoryAssignmentStore<S, P>
where
    S: Subject,
    P: Permission,
{
    #[must_use]
    pub fn new() -> Self {
        Self {
            role_assignments: RwLock::new(HashMap::new()),
            extra_perms: RwLock::new(HashMap::new()),
            denied_perms: RwLock::new(HashMap::new()),
            _phantom: PhantomData,
        }
    }
}

impl<S, P> Default for InMemoryAssignmentStore<S, P>
where
    S: Subject,
    P: Permission,
{
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl<S, P> AssignmentStore<S, P> for InMemoryAssignmentStore<S, P>
where
    S: Subject,
    P: Permission,
{
    async fn assign_role(&self, subject: &S, role_name: &str) -> Result<()> {
        let key = subject.subject_id().to_string();
        let mut assignments = self.role_assignments.write().await;
        let roles = assignments.entry(key).or_default();
        roles.insert(role_name.to_string());
        Ok(())
    }

    async fn revoke_role(&self, subject: &S, role_name: &str) -> Result<()> {
        let key = subject.subject_id().to_string();
        let mut assignments = self.role_assignments.write().await;
        if let Some(roles) = assignments.get_mut(&key) {
            roles.retain(|r| r != role_name);
        }
        Ok(())
    }

    async fn roles_of(&self, subject: &S) -> Result<Vec<String>> {
        let key = subject.subject_id().to_string();
        let assignments = self.role_assignments.read().await;
        Ok(assignments
            .get(&key)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default())
    }

    async fn subjects_with_role(&self, role_name: &str) -> Result<Vec<String>> {
        let assignments = self.role_assignments.read().await;
        let subjects: Vec<String> = assignments
            .iter()
            .filter(|(_, roles)| roles.iter().any(|r| r == role_name))
            .map(|(sid, _)| sid.clone())
            .collect();
        Ok(subjects)
    }

    async fn extra_permissions(&self, subject: &S) -> Result<HashSet<P>> {
        let key = subject.subject_id().to_string();
        let perms = self.extra_perms.read().await;
        Ok(perms.get(&key).cloned().unwrap_or_default())
    }

    async fn set_extra_permissions(&self, subject: &S, perms: HashSet<P>) -> Result<()> {
        let key = subject.subject_id().to_string();
        let mut extra = self.extra_perms.write().await;
        extra.insert(key, perms);
        Ok(())
    }

    async fn denied_permissions(&self, subject: &S) -> Result<HashSet<P>> {
        let key = subject.subject_id().to_string();
        let perms = self.denied_perms.read().await;
        Ok(perms.get(&key).cloned().unwrap_or_default())
    }

    async fn set_denied_permissions(&self, subject: &S, perms: HashSet<P>) -> Result<()> {
        let key = subject.subject_id().to_string();
        let mut denied = self.denied_perms.write().await;
        denied.insert(key, perms);
        Ok(())
    }
}

/// In-memory implementation of [`RoleStore`] backed by `tokio::sync::RwLock`.
///
/// Stores role definitions (name → set of permissions) in a `HashMap`.
pub struct InMemoryRoleStore<P: Permission> {
    roles: RwLock<HashMap<String, HashSet<P>>>,
}

impl<P: Permission> InMemoryRoleStore<P> {
    #[must_use]
    pub fn new() -> Self {
        Self {
            roles: RwLock::new(HashMap::new()),
        }
    }
}

impl<P: Permission> Default for InMemoryRoleStore<P> {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl<P: Permission> RoleStore<P> for InMemoryRoleStore<P> {
    async fn create_role(&self, role_name: &str, permissions: HashSet<P>) -> Result<()> {
        let mut roles = self.roles.write().await;
        if roles.contains_key(role_name) {
            tracing::warn!(
                target: "kirino::rbac::store::memory",
                "overwriting existing role '{}'",
                role_name
            );
        }
        roles.insert(role_name.to_string(), permissions);
        Ok(())
    }

    async fn delete_role(&self, role_name: &str) -> Result<bool> {
        let mut roles = self.roles.write().await;
        Ok(roles.remove(role_name).is_some())
    }

    async fn get_role_permissions(&self, role_name: &str) -> Result<Option<HashSet<P>>> {
        let roles = self.roles.read().await;
        Ok(roles.get(role_name).cloned())
    }

    async fn list_roles(&self) -> Result<Vec<String>> {
        let roles = self.roles.read().await;
        Ok(roles.keys().cloned().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TestSubject;
    use std::collections::HashSet;

    // We cannot use the shared TestPerm enum here because these tests
    // need to express arbitrary permission names like "deploy" or "system_write",
    // whereas the shared TestPerm is a fixed enum (Read/Write/Delete/Admin).
    // This module tests generic CRUD behavior of the storage layer.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    struct TestPerm(&'static str);

    impl Permission for TestPerm {
        fn name(&self) -> &str {
            self.0
        }
    }

    #[tokio::test]
    async fn test_assign_and_revoke_role() {
        let store = InMemoryAssignmentStore::<TestSubject, TestPerm>::new();
        let subj = TestSubject("user1".to_string());

        store.assign_role(&subj, "admin").await.unwrap();
        let roles = store.roles_of(&subj).await.unwrap();
        assert_eq!(roles, vec!["admin".to_string()]);

        store.assign_role(&subj, "admin").await.unwrap();
        let roles = store.roles_of(&subj).await.unwrap();
        assert_eq!(roles, vec!["admin".to_string()]);

        store.revoke_role(&subj, "admin").await.unwrap();
        let roles = store.roles_of(&subj).await.unwrap();
        assert!(roles.is_empty());
    }

    #[tokio::test]
    async fn test_extra_and_denied_permissions() {
        let store = InMemoryAssignmentStore::<TestSubject, TestPerm>::new();
        let subj = TestSubject("user1".to_string());

        let extra: HashSet<TestPerm> = std::iter::once(TestPerm("deploy")).collect();
        store.set_extra_permissions(&subj, extra).await.unwrap();
        let got = store.extra_permissions(&subj).await.unwrap();
        assert!(got.contains(&TestPerm("deploy")));

        let denied: HashSet<TestPerm> = std::iter::once(TestPerm("system_write")).collect();
        store.set_denied_permissions(&subj, denied).await.unwrap();
        let got = store.denied_permissions(&subj).await.unwrap();
        assert!(got.contains(&TestPerm("system_write")));
    }

    #[tokio::test]
    async fn test_subjects_with_role() {
        let store = InMemoryAssignmentStore::<TestSubject, TestPerm>::new();
        let u1 = TestSubject("user1".to_string());
        let u2 = TestSubject("user2".to_string());
        let u3 = TestSubject("user3".to_string());

        store.assign_role(&u1, "admin").await.unwrap();
        store.assign_role(&u2, "admin").await.unwrap();
        store.assign_role(&u3, "viewer").await.unwrap();

        let admins = store.subjects_with_role("admin").await.unwrap();
        assert_eq!(admins.len(), 2);
        assert!(admins.contains(&"user1".to_string()));
        assert!(admins.contains(&"user2".to_string()));
    }

    #[tokio::test]
    async fn test_in_memory_role_store() {
        let store = InMemoryRoleStore::<TestPerm>::new();
        let perms: HashSet<TestPerm> = [TestPerm("read"), TestPerm("write")].into_iter().collect();

        store.create_role("editor", perms.clone()).await.unwrap();
        let got = store.get_role_permissions("editor").await.unwrap().unwrap();
        assert_eq!(got.len(), 2);

        let roles = store.list_roles().await.unwrap();
        assert_eq!(roles, vec!["editor".to_string()]);

        assert!(store.delete_role("editor").await.unwrap());
        assert!(store
            .get_role_permissions("editor")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn test_revoke_nonexistent_role_noop() {
        let store = InMemoryAssignmentStore::<TestSubject, TestPerm>::new();
        let subj = TestSubject("user1".to_string());
        store.revoke_role(&subj, "nonexistent").await.unwrap();
        assert!(store.roles_of(&subj).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_revoke_nonexistent_subject_noop() {
        let store = InMemoryAssignmentStore::<TestSubject, TestPerm>::new();
        let subj = TestSubject("ghost".to_string());
        store.revoke_role(&subj, "admin").await.unwrap();
    }

    #[tokio::test]
    async fn test_roles_of_nonexistent_subject() {
        let store = InMemoryAssignmentStore::<TestSubject, TestPerm>::new();
        let subj = TestSubject("ghost".to_string());
        let roles = store.roles_of(&subj).await.unwrap();
        assert!(roles.is_empty());
    }

    #[tokio::test]
    async fn test_extra_perms_nonexistent_subject() {
        let store = InMemoryAssignmentStore::<TestSubject, TestPerm>::new();
        let subj = TestSubject("ghost".to_string());
        let perms = store.extra_permissions(&subj).await.unwrap();
        assert!(perms.is_empty());
    }

    #[tokio::test]
    async fn test_denied_perms_nonexistent_subject() {
        let store = InMemoryAssignmentStore::<TestSubject, TestPerm>::new();
        let subj = TestSubject("ghost".to_string());
        let perms = store.denied_permissions(&subj).await.unwrap();
        assert!(perms.is_empty());
    }

    #[tokio::test]
    async fn test_subjects_with_role_nonexistent() {
        let store = InMemoryAssignmentStore::<TestSubject, TestPerm>::new();
        assert!(store
            .subjects_with_role("nonexistent")
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn test_extra_perms_overwrite() {
        let store = InMemoryAssignmentStore::<TestSubject, TestPerm>::new();
        let subj = TestSubject("user1".to_string());

        let first: HashSet<TestPerm> = std::iter::once(TestPerm("read")).collect();
        store.set_extra_permissions(&subj, first).await.unwrap();

        let second: HashSet<TestPerm> = std::iter::once(TestPerm("write")).collect();
        store.set_extra_permissions(&subj, second).await.unwrap();

        let got = store.extra_permissions(&subj).await.unwrap();
        assert!(!got.contains(&TestPerm("read")));
        assert!(got.contains(&TestPerm("write")));
    }

    #[tokio::test]
    async fn test_role_store_list_roles_empty() {
        let store = InMemoryRoleStore::<TestPerm>::new();
        assert!(store.list_roles().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_role_store_delete_nonexistent() {
        let store = InMemoryRoleStore::<TestPerm>::new();
        assert!(!store.delete_role("ghost").await.unwrap());
    }

    #[tokio::test]
    async fn test_role_store_duplicate_create_overwrites() {
        let store = InMemoryRoleStore::<TestPerm>::new();
        let p1: HashSet<TestPerm> = std::iter::once(TestPerm("read")).collect();
        let p2: HashSet<TestPerm> = std::iter::once(TestPerm("write")).collect();

        store.create_role("role", p1).await.unwrap();
        store.create_role("role", p2).await.unwrap();

        let got = store.get_role_permissions("role").await.unwrap().unwrap();
        assert_eq!(got.len(), 1);
        assert!(got.contains(&TestPerm("write")));
    }

    #[tokio::test]
    async fn test_concurrent_assign_and_read() {
        let store = std::sync::Arc::new(InMemoryAssignmentStore::<TestSubject, TestPerm>::new());

        let store_w = store.clone();
        let writer = tokio::spawn(async move {
            let subj = TestSubject("user1".to_string());
            for i in 0..100 {
                store_w
                    .assign_role(&subj, &format!("role{i}"))
                    .await
                    .unwrap();
            }
        });

        let store_r = store.clone();
        let reader = tokio::spawn(async move {
            let subj = TestSubject("user1".to_string());
            for _ in 0..100 {
                let _ = store_r.roles_of(&subj).await;
            }
        });

        writer.await.unwrap();
        reader.await.unwrap();

        let roles = store
            .roles_of(&TestSubject("user1".to_string()))
            .await
            .unwrap();
        assert!(!roles.is_empty());
    }
}
