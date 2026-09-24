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
///
/// Security semantics: this is the development/test backend and holds the
/// authoritative inputs to every decision in process memory. Nothing is
/// persisted, so a restart drops all assignments, extra grants and denies at
/// once - the process comes back with every subject unprivileged (fail-closed)
/// and cannot recover the previous state. It is per-process too: several
/// replicas do not share it, so a write through one replica is invisible to the
/// others.
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
    /// Creates an empty store: no subject holds any role, extra permission or
    /// deny until one is written. An empty store denies everything it is asked
    /// about, so this is the safe starting state.
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
    /// Same as [`new`](InMemoryAssignmentStore::new): an empty, unprivileged
    /// store.
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
    /// Inserts the role into the subject's set: idempotent, and a repeated
    /// assignment is not an error. The role name is not checked against any
    /// registry, so a nonexistent role is stored and later resolves to no
    /// permissions. Callers must invalidate the subject's permission cache
    /// after this (the engine's `invalidate_subject_cache`).
    async fn assign_role(&self, subject: &S, role_name: &str) -> Result<()> {
        let key = subject.subject_id().to_string();
        let mut assignments = self.role_assignments.write().await;
        let roles = assignments.entry(key).or_default();
        roles.insert(role_name.to_string());
        Ok(())
    }

    /// Removes the role from the subject's set. Idempotent and never an error:
    /// revoking a role the subject does not hold, or revoking for an unknown
    /// subject, succeeds silently, so the result cannot be used to prove that a
    /// revocation had an effect.
    async fn revoke_role(&self, subject: &S, role_name: &str) -> Result<()> {
        let key = subject.subject_id().to_string();
        let mut assignments = self.role_assignments.write().await;
        if let Some(roles) = assignments.get_mut(&key) {
            roles.retain(|r| r != role_name);
        }
        Ok(())
    }

    /// Roles held by the subject; an unknown subject yields an empty list,
    /// which the engine reads as "no roles" (no authority). This never fails,
    /// so a typo in a subject id looks exactly like a subject with no
    /// assignments.
    async fn roles_of(&self, subject: &S) -> Result<Vec<String>> {
        let key = subject.subject_id().to_string();
        let assignments = self.role_assignments.read().await;
        Ok(assignments
            .get(&key)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default())
    }

    /// Subjects holding the role, for admin listings and audits only; the
    /// result is unordered and gates nothing.
    async fn subjects_with_role(&self, role_name: &str) -> Result<Vec<String>> {
        let assignments = self.role_assignments.read().await;
        let subjects: Vec<String> = assignments
            .iter()
            .filter(|(_, roles)| roles.iter().any(|r| r == role_name))
            .map(|(sid, _)| sid.clone())
            .collect();
        Ok(subjects)
    }

    /// The subject's direct grants on top of its roles; an unknown subject
    /// yields an empty set, so "no row" and "no extra permissions" are
    /// indistinguishable (both grant nothing extra).
    async fn extra_permissions(&self, subject: &S) -> Result<HashSet<P>> {
        let key = subject.subject_id().to_string();
        let perms = self.extra_perms.read().await;
        Ok(perms.get(&key).cloned().unwrap_or_default())
    }

    /// Replaces the whole extra-permission set for the subject (last write
    /// wins, not a merge). Passing an empty set therefore revokes every direct
    /// grant the subject had. Invalidating the permission cache afterwards is
    /// required, otherwise the old grants keep passing until their TTL elapses.
    async fn set_extra_permissions(&self, subject: &S, perms: HashSet<P>) -> Result<()> {
        let key = subject.subject_id().to_string();
        let mut extra = self.extra_perms.write().await;
        extra.insert(key, perms);
        Ok(())
    }

    /// The subject's explicit deny set; an unknown subject yields an empty set.
    /// Empty means "no denies recorded", never "allow": the engine's grant
    /// checks still apply.
    async fn denied_permissions(&self, subject: &S) -> Result<HashSet<P>> {
        let key = subject.subject_id().to_string();
        let perms = self.denied_perms.read().await;
        Ok(perms.get(&key).cloned().unwrap_or_default())
    }

    /// Replaces the whole deny set for the subject (last write wins, not a
    /// merge). An empty set clears every explicit deny, which widens the
    /// subject's effective authority back to whatever its roles and extra
    /// permissions grant - the opposite direction from most write APIs, so
    /// callers should treat clearing denies as a privilege change.
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
///
/// Security semantics: a role definition is the authority every holder of that
/// role receives, so editing one changes the effective permissions of all its
/// holders at the next check (subject to the permission cache TTL). The store
/// is per-process and not persisted: after a restart no roles exist, so every
/// assignment resolves to nothing (fail-closed) until roles are recreated.
pub struct InMemoryRoleStore<P: Permission> {
    roles: RwLock<HashMap<String, HashSet<P>>>,
}

impl<P: Permission> InMemoryRoleStore<P> {
    /// Creates a store with no roles defined. Assignments referring to those
    /// roles resolve to no permissions until the roles are created here.
    #[must_use]
    pub fn new() -> Self {
        Self {
            roles: RwLock::new(HashMap::new()),
        }
    }
}

impl<P: Permission> Default for InMemoryRoleStore<P> {
    /// Same as [`new`](InMemoryRoleStore::new): an empty role catalogue.
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl<P: Permission> RoleStore<P> for InMemoryRoleStore<P> {
    /// Upsert: creating a role that already exists OVERWRITES its permission
    /// set (logging a warning). The previous authority is lost immediately, so
    /// this doubles as "widen or narrow an existing role" - a widening here
    /// silently grants every holder of the role the new permissions.
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

    /// Removes a role definition. `false` means no such role existed (not an
    /// error); assignments that still name the deleted role keep existing but
    /// resolve to no permissions, so deletion silently strips authority from
    /// its holders.
    async fn delete_role(&self, role_name: &str) -> Result<bool> {
        let mut roles = self.roles.write().await;
        Ok(roles.remove(role_name).is_some())
    }

    /// Permission set of a role. `None` for an unknown role; a caller that
    /// treats that as "no restrictions" instead of "no authority" would fail
    /// open, so unknown must stay a denial.
    async fn get_role_permissions(&self, role_name: &str) -> Result<Option<HashSet<P>>> {
        let roles = self.roles.read().await;
        Ok(roles.get(role_name).cloned())
    }

    /// All role names currently defined, for listings and audits; unordered,
    /// and a name appearing here grants nothing by itself.
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
        // Revoking a role from a subject that was never assigned anything
        // must succeed (idempotent) AND leave the store visibly empty for
        // that subject — proving the no-op contract, not just the absence of
        // a panic.
        store.revoke_role(&subj, "admin").await.unwrap();
        assert!(
            store.roles_of(&subj).await.unwrap().is_empty(),
            "revoking from a never-assigned subject must leave an empty role set"
        );
        // The ghost subject must not show up in any role's member list either.
        let admins = store.subjects_with_role("admin").await.unwrap();
        assert!(
            !admins.iter().any(|s| s == "ghost"),
            "revoking a nonexistent subject must not register that subject under any role"
        );
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
