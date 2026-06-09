use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use uuid::Uuid;

use crate::error::{KirinoError, KirinoResult};
use crate::rbac::{
    shared::Shared,
    traits::{AssignmentStore, Permission, Subject},
};

#[cfg(feature = "rbac-constraints")]
use crate::rbac::constraints::store::ConstraintStore;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session<S: Subject> {
    pub id: Uuid,
    pub subject: S,
    pub active_roles: HashSet<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl<S: Subject> Session<S> {
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }
}

#[async_trait::async_trait]
pub trait SessionManager<S: Subject>: Send + Sync {
    async fn create_session(
        &self,
        subject: &S,
        active_roles: HashSet<String>,
        ttl: Duration,
    ) -> KirinoResult<Session<S>>;
    async fn activate_role(&self, session_id: Uuid, role_name: &str) -> KirinoResult<()>;
    async fn deactivate_role(&self, session_id: Uuid, role_name: &str) -> KirinoResult<()>;
    async fn get_session(&self, session_id: Uuid) -> KirinoResult<Option<Session<S>>>;
    async fn destroy_session(&self, session_id: Uuid) -> KirinoResult<()>;
}

pub struct InMemorySessionManager<S, P>
where
    S: Subject,
    P: Permission,
{
    sessions: tokio::sync::RwLock<HashMap<Uuid, Session<S>>>,
    assignment_store: Shared<dyn AssignmentStore<S, P>>,
    #[cfg(feature = "rbac-constraints")]
    constraint_store: Option<Shared<dyn ConstraintStore>>,
}

impl<S, P> InMemorySessionManager<S, P>
where
    S: Subject,
    P: Permission,
{
    pub fn new(assignment_store: impl AssignmentStore<S, P> + 'static) -> Self {
        Self {
            sessions: tokio::sync::RwLock::new(HashMap::new()),
            assignment_store: Shared::from_arc_unsized(Arc::new(assignment_store)),
            #[cfg(feature = "rbac-constraints")]
            constraint_store: None,
        }
    }

    #[must_use]
    #[cfg(feature = "rbac-constraints")]
    pub fn with_constraint_store(mut self, store: impl ConstraintStore + 'static) -> Self {
        self.constraint_store = Some(Shared::from_arc_unsized(Arc::new(store)));
        self
    }

    pub fn assignment_store(&self) -> Shared<dyn AssignmentStore<S, P>> {
        self.assignment_store.clone()
    }

    pub async fn cleanup_expired(&self) -> usize {
        let mut sessions = self.sessions.write().await;
        let before = sessions.len();
        sessions.retain(|_, session| !session.is_expired());
        before - sessions.len()
    }

    #[cfg(feature = "rbac-constraints")]
    async fn validate_dsd_with_store(
        &self,
        roles: &HashSet<String>,
        constraint_store: &Shared<dyn ConstraintStore>,
    ) -> KirinoResult<()> {
        let policies = constraint_store.list_dsd_policies().await?;
        let roles_vec: Vec<String> = roles.iter().cloned().collect();
        for policy in &policies {
            if !policy.validate(&roles_vec) {
                return Err(KirinoError::ConstraintViolation(format!(
                    "DSD policy '{}' violated for roles {:?}",
                    policy.name,
                    roles,
                )));
            }
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl<S, P> SessionManager<S> for InMemorySessionManager<S, P>
where
    S: Subject,
    P: Permission,
{
    async fn create_session(
        &self,
        subject: &S,
        mut active_roles: HashSet<String>,
        ttl: Duration,
    ) -> KirinoResult<Session<S>> {
        let assigned = self.assignment_store.roles_of(subject).await?;
        let assigned_set: HashSet<String> = assigned.into_iter().collect();
        active_roles.retain(|r| assigned_set.contains(r));

        #[cfg(feature = "rbac-constraints")]
        if let Some(ref cs) = self.constraint_store {
            self.validate_dsd_with_store(&active_roles, cs).await?;
        }

        let session = Session {
            id: Uuid::now_v7(),
            subject: subject.clone(),
            active_roles,
            created_at: Utc::now(),
            expires_at: Utc::now() + ttl,
        };

        let mut sessions = self.sessions.write().await;
        sessions.insert(session.id, session.clone());
        Ok(session)
    }

    async fn activate_role(&self, session_id: Uuid, role_name: &str) -> KirinoResult<()> {
        let (subject, current_roles) = {
            let sessions = self.sessions.read().await;
            let session = sessions
                .get(&session_id)
                .ok_or(KirinoError::SessionNotFound)?;
            if session.is_expired() {
                return Err(KirinoError::SessionExpired);
            }
            (session.subject.clone(), session.active_roles.clone())
        };

        let assigned = self.assignment_store.roles_of(&subject).await?;
        let role_str = role_name.to_string();
        if !assigned.contains(&role_str) {
            return Err(KirinoError::NotFound(format!(
                "role '{role_name}' not assigned to subject"
            )));
        }

        let mut test_roles = current_roles;
        test_roles.insert(role_str);

        #[cfg(feature = "rbac-constraints")]
        if let Some(ref cs) = self.constraint_store {
            self.validate_dsd_with_store(&test_roles, cs).await?;
        }

        let mut sessions = self.sessions.write().await;
        let session = sessions
            .get_mut(&session_id)
            .ok_or(KirinoError::SessionNotFound)?;
        if session.is_expired() {
            return Err(KirinoError::SessionExpired);
        }
        session.active_roles.insert(role_name.to_string());
        Ok(())
    }

    async fn deactivate_role(&self, session_id: Uuid, role_name: &str) -> KirinoResult<()> {
        let mut sessions = self.sessions.write().await;
        let session = sessions
            .get_mut(&session_id)
            .ok_or(KirinoError::SessionNotFound)?;

        if session.is_expired() {
            return Err(KirinoError::SessionExpired);
        }

        session.active_roles.remove(role_name);
        Ok(())
    }

    async fn get_session(&self, session_id: Uuid) -> KirinoResult<Option<Session<S>>> {
        let sessions = self.sessions.read().await;
        Ok(sessions.get(&session_id).cloned())
    }

    async fn destroy_session(&self, session_id: Uuid) -> KirinoResult<()> {
        let mut sessions = self.sessions.write().await;
        sessions.remove(&session_id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rbac::store::memory::InMemoryAssignmentStore;
    use crate::rbac::subject::StringSubject;

    #[cfg(feature = "rbac-constraints")]
    use crate::rbac::constraints::policies::DsdPolicy;
    #[cfg(feature = "rbac-constraints")]
    use crate::rbac::constraints::store::InMemoryConstraintStore;

    fn make_store() -> InMemoryAssignmentStore<StringSubject, TestPerm> {
        InMemoryAssignmentStore::new()
    }

    fn make_mgr(
        store: InMemoryAssignmentStore<StringSubject, TestPerm>,
    ) -> InMemorySessionManager<StringSubject, TestPerm> {
        InMemorySessionManager::new(store)
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    #[allow(dead_code)]
    enum TestPerm {
        Read,
        Write,
    }

    impl Permission for TestPerm {
        fn name(&self) -> &str {
            match self {
                TestPerm::Read => "read",
                TestPerm::Write => "write",
            }
        }
    }

    #[tokio::test]
    async fn test_create_and_get_session() {
        let mgr = make_mgr(make_store());
        let store = mgr.assignment_store();
        let subj = StringSubject::new("user1");

        store.assign_role(&subj, "admin").await.unwrap();
        store.assign_role(&subj, "viewer").await.unwrap();

        let session = mgr
            .create_session(&subj, ["admin".to_string()].into(), Duration::hours(1))
            .await
            .unwrap();

        assert!(!session.is_expired());
        assert!(session.active_roles.contains("admin"));

        let got = mgr.get_session(session.id).await.unwrap().unwrap();
        assert_eq!(got.id, session.id);
    }

    #[tokio::test]
    async fn test_create_session_filters_unassigned_roles() {
        let mgr = make_mgr(make_store());
        let store = mgr.assignment_store();
        let subj = StringSubject::new("user1");

        store.assign_role(&subj, "viewer").await.unwrap();

        let session = mgr
            .create_session(
                &subj,
                ["admin".to_string(), "viewer".to_string()].into(),
                Duration::hours(1),
            )
            .await
            .unwrap();

        assert!(session.active_roles.contains("viewer"));
        assert!(!session.active_roles.contains("admin"));
    }

    #[tokio::test]
    async fn test_activate_deactivate_role() {
        let mgr = make_mgr(make_store());
        let store = mgr.assignment_store();
        let subj = StringSubject::new("user1");

        store.assign_role(&subj, "admin").await.unwrap();
        store.assign_role(&subj, "viewer").await.unwrap();

        let session = mgr
            .create_session(&subj, ["admin".to_string()].into(), Duration::hours(1))
            .await
            .unwrap();

        mgr.activate_role(session.id, "viewer").await.unwrap();
        let got = mgr.get_session(session.id).await.unwrap().unwrap();
        assert!(got.active_roles.contains("viewer"));

        mgr.deactivate_role(session.id, "admin").await.unwrap();
        let got = mgr.get_session(session.id).await.unwrap().unwrap();
        assert!(!got.active_roles.contains("admin"));
        assert!(got.active_roles.contains("viewer"));
    }

    #[tokio::test]
    async fn test_activate_unassigned_role_fails() {
        let mgr = make_mgr(make_store());
        let store = mgr.assignment_store();
        let subj = StringSubject::new("user1");

        store.assign_role(&subj, "viewer").await.unwrap();

        let session = mgr
            .create_session(&subj, HashSet::new(), Duration::hours(1))
            .await
            .unwrap();

        assert!(mgr.activate_role(session.id, "admin").await.is_err());
    }

    #[tokio::test]
    async fn test_destroy_session() {
        let mgr = make_mgr(make_store());
        let subj = StringSubject::new("user1");

        let session = mgr
            .create_session(&subj, HashSet::new(), Duration::hours(1))
            .await
            .unwrap();

        mgr.destroy_session(session.id).await.unwrap();
        assert!(mgr.get_session(session.id).await.unwrap().is_none());
    }

    #[cfg(feature = "rbac-constraints")]
    #[tokio::test]
    async fn test_dsd_constraint_on_create() {
        let cs = InMemoryConstraintStore::new();
        cs.add_dsd_policy(DsdPolicy::new(
            "exclusive",
            ["admin".to_string(), "auditor".to_string()].into(),
            2,
        ))
        .await
        .unwrap();

        let mgr = make_mgr(make_store()).with_constraint_store(cs);
        let store = mgr.assignment_store();

        let subj = StringSubject::new("user1");
        store.assign_role(&subj, "admin").await.unwrap();
        store.assign_role(&subj, "auditor").await.unwrap();

        let result = mgr
            .create_session(
                &subj,
                ["admin".to_string(), "auditor".to_string()].into(),
                Duration::hours(1),
            )
            .await;

        assert!(result.is_err());
    }

    #[cfg(feature = "rbac-constraints")]
    #[tokio::test]
    async fn test_dsd_constraint_on_activate() {
        let cs = InMemoryConstraintStore::new();
        cs.add_dsd_policy(DsdPolicy::new(
            "exclusive",
            ["admin".to_string(), "auditor".to_string()].into(),
            2,
        ))
        .await
        .unwrap();

        let mgr = make_mgr(make_store()).with_constraint_store(cs);
        let store = mgr.assignment_store();

        let subj = StringSubject::new("user1");
        store.assign_role(&subj, "admin").await.unwrap();
        store.assign_role(&subj, "auditor").await.unwrap();

        let session = mgr
            .create_session(&subj, ["admin".to_string()].into(), Duration::hours(1))
            .await
            .unwrap();

        assert!(mgr.activate_role(session.id, "auditor").await.is_err());
    }

    #[tokio::test]
    async fn test_shared_store_identity() {
        let mgr = make_mgr(make_store());
        let s1 = mgr.assignment_store();
        let s2 = mgr.assignment_store();
        assert!(s1.ptr_eq(&s2));
    }

    #[tokio::test]
    async fn test_session_expiry() {
        let mgr = make_mgr(make_store());
        let subj = StringSubject::new("user1");
        let session = mgr
            .create_session(&subj, HashSet::new(), Duration::milliseconds(10))
            .await
            .unwrap();
        assert!(!session.is_expired());
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert!(session.is_expired());
    }

    #[tokio::test]
    async fn test_activate_on_expired_session_fails() {
        let mgr = make_mgr(make_store());
        let store = mgr.assignment_store();
        let subj = StringSubject::new("user1");
        store.assign_role(&subj, "admin").await.unwrap();

        let session = mgr
            .create_session(&subj, HashSet::new(), Duration::milliseconds(10))
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert!(mgr.activate_role(session.id, "admin").await.is_err());
    }

    #[tokio::test]
    async fn test_deactivate_on_expired_session_fails() {
        let mgr = make_mgr(make_store());
        let subj = StringSubject::new("user1");

        let session = mgr
            .create_session(
                &subj,
                ["admin".to_string()].into(),
                Duration::milliseconds(10),
            )
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert!(mgr.deactivate_role(session.id, "admin").await.is_err());
    }

    #[tokio::test]
    async fn test_activate_invalid_session_fails() {
        let mgr = make_mgr(make_store());
        assert!(mgr
            .activate_role(uuid::Uuid::now_v7(), "admin")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_deactivate_invalid_session_fails() {
        let mgr = make_mgr(make_store());
        assert!(mgr
            .deactivate_role(uuid::Uuid::now_v7(), "admin")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_deactivate_role_not_in_set_is_noop() {
        let mgr = make_mgr(make_store());
        let store = mgr.assignment_store();
        let subj = StringSubject::new("user1");
        store.assign_role(&subj, "admin").await.unwrap();

        let session = mgr
            .create_session(&subj, ["admin".to_string()].into(), Duration::hours(1))
            .await
            .unwrap();

        mgr.deactivate_role(session.id, "viewer").await.unwrap();
        let got = mgr.get_session(session.id).await.unwrap().unwrap();
        assert!(got.active_roles.contains("admin"));
    }

    #[tokio::test]
    async fn test_cleanup_expired() {
        let mgr = make_mgr(make_store());
        let subj = StringSubject::new("user1");

        let s1 = mgr
            .create_session(&subj, HashSet::new(), Duration::milliseconds(10))
            .await
            .unwrap();
        let _s2 = mgr
            .create_session(&subj, HashSet::new(), Duration::hours(1))
            .await
            .unwrap();

        assert!(mgr.get_session(s1.id).await.unwrap().is_some());
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let removed = mgr.cleanup_expired().await;
        assert_eq!(removed, 1);
        assert!(mgr.get_session(s1.id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_cleanup_no_expired() {
        let mgr = make_mgr(make_store());
        let subj = StringSubject::new("user1");
        mgr.create_session(&subj, HashSet::new(), Duration::hours(1))
            .await
            .unwrap();
        mgr.create_session(&subj, HashSet::new(), Duration::hours(2))
            .await
            .unwrap();
        assert_eq!(mgr.cleanup_expired().await, 0);
    }

    #[tokio::test]
    async fn test_destroy_invalid_session_is_ok() {
        let mgr = make_mgr(make_store());
        mgr.destroy_session(uuid::Uuid::now_v7()).await.unwrap();
    }
}
