use std::{
    collections::{HashMap, HashSet},
    marker::PhantomData,
};
use tokio::sync::RwLock;

use async_trait::async_trait;

use crate::rbac::traits::{AssignmentStore, Permission, RoleStore, Subject};

pub struct InMemoryAssignmentStore<S, P>
where
    S: Subject,
    P: Permission,
{
    role_assignments: RwLock<HashMap<String, Vec<String>>>,
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
    async fn assign_role(&self, subject: &S, role_name: &str) -> anyhow::Result<()> {
        let key = subject.subject_id().to_string();
        let mut assignments = self.role_assignments.write().await;
        let roles = assignments.entry(key).or_default();
        if !roles.contains(&role_name.to_string()) {
            roles.push(role_name.to_string());
        }
        Ok(())
    }

    async fn revoke_role(&self, subject: &S, role_name: &str) -> anyhow::Result<()> {
        let key = subject.subject_id().to_string();
        let mut assignments = self.role_assignments.write().await;
        if let Some(roles) = assignments.get_mut(&key) {
            roles.retain(|r| r != role_name);
        }
        Ok(())
    }

    async fn roles_of(&self, subject: &S) -> anyhow::Result<Vec<String>> {
        let key = subject.subject_id().to_string();
        let assignments = self.role_assignments.read().await;
        Ok(assignments.get(&key).cloned().unwrap_or_default())
    }

    async fn subjects_with_role(&self, role_name: &str) -> anyhow::Result<Vec<String>> {
        let assignments = self.role_assignments.read().await;
        let subjects: Vec<String> = assignments
            .iter()
            .filter(|(_, roles)| roles.iter().any(|r| r == role_name))
            .map(|(sid, _)| sid.clone())
            .collect();
        Ok(subjects)
    }

    async fn extra_permissions(&self, subject: &S) -> anyhow::Result<HashSet<P>> {
        let key = subject.subject_id().to_string();
        let perms = self.extra_perms.read().await;
        Ok(perms.get(&key).cloned().unwrap_or_default())
    }

    async fn set_extra_permissions(&self, subject: &S, perms: HashSet<P>) -> anyhow::Result<()> {
        let key = subject.subject_id().to_string();
        let mut extra = self.extra_perms.write().await;
        extra.insert(key, perms);
        Ok(())
    }

    async fn denied_permissions(&self, subject: &S) -> anyhow::Result<HashSet<P>> {
        let key = subject.subject_id().to_string();
        let perms = self.denied_perms.read().await;
        Ok(perms.get(&key).cloned().unwrap_or_default())
    }

    async fn set_denied_permissions(&self, subject: &S, perms: HashSet<P>) -> anyhow::Result<()> {
        let key = subject.subject_id().to_string();
        let mut denied = self.denied_perms.write().await;
        denied.insert(key, perms);
        Ok(())
    }
}

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
    async fn create_role(&self, role_name: &str, permissions: HashSet<P>) -> anyhow::Result<()> {
        let mut roles = self.roles.write().await;
        roles.insert(role_name.to_string(), permissions);
        Ok(())
    }

    async fn delete_role(&self, role_name: &str) -> anyhow::Result<bool> {
        let mut roles = self.roles.write().await;
        Ok(roles.remove(role_name).is_some())
    }

    async fn get_role_permissions(&self, role_name: &str) -> anyhow::Result<Option<HashSet<P>>> {
        let roles = self.roles.read().await;
        Ok(roles.get(role_name).cloned())
    }

    async fn list_roles(&self) -> anyhow::Result<Vec<String>> {
        let roles = self.roles.read().await;
        Ok(roles.keys().cloned().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    struct TestPerm(&'static str);

    impl Permission for TestPerm {
        fn name(&self) -> &str {
            self.0
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    struct TestSubject(String);

    impl Subject for TestSubject {
        fn subject_id(&self) -> &str {
            &self.0
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

        let extra: HashSet<TestPerm> = [TestPerm("deploy")].into_iter().collect();
        store.set_extra_permissions(&subj, extra).await.unwrap();
        let got = store.extra_permissions(&subj).await.unwrap();
        assert!(got.contains(&TestPerm("deploy")));

        let denied: HashSet<TestPerm> = [TestPerm("system_write")].into_iter().collect();
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
}
