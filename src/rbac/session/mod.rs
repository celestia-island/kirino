use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use uuid::Uuid;

#[cfg(feature = "rbac-constraints")]
use crate::rbac::constraints::store::ConstraintStore;
use crate::{
    error::KirinoError,
    rbac::{
        shared::Shared,
        traits::{AssignmentStore, Permission, Subject},
    },
};

/// Validates a candidate role set against every stored DSD policy, returning
/// an error for the first violation.
///
/// Security semantics: this is a fail-closed gate - a store error propagates
/// and the caller must abort the session change rather than continue without
/// the check, since DSD policies exist to stop two mutually exclusive roles
/// from being active together. A store with no policies accepts every set, so
/// enforcement depends entirely on the policies having been seeded.
#[cfg(feature = "rbac-constraints")]
pub(crate) async fn validate_dsd_with_store(
    roles: &HashSet<String>,
    constraint_store: &Shared<dyn ConstraintStore>,
) -> Result<()> {
    let policies = constraint_store.list_dsd_policies().await?;
    let roles_vec: Vec<String> = roles.iter().cloned().collect();
    for policy in &policies {
        if !policy.validate(&roles_vec) {
            return Err(KirinoError::ConstraintViolation(format!(
                "DSD policy '{}' violated for roles {:?}",
                policy.name, roles,
            ))
            .into());
        }
    }
    Ok(())
}

/// An established session: which subject it authenticates, which roles it has
/// activated, and until when it is valid.
///
/// Security semantics: the session is the caller's credential for role-scoped
/// access, so `active_roles` must stay a subset of the subject's assignments
/// (both managers filter it on creation) and `version` is the anti-replay
/// counter compared against the subject's current version. `serde` derives
/// mean the whole struct is serializable, but a deserialized session is only a
/// claim: it must be re-validated against the store (expiry, version, and
/// still-assigned roles) before it is trusted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session<S: Subject> {
    /// Unique session identifier presented by the client.
    pub id: Uuid,
    /// The authenticated subject this session belongs to.
    pub subject: S,
    /// Roles activated for this session; a subset of the subject's assigned
    /// roles, never a superset.
    pub active_roles: HashSet<String>,
    /// Opaque caller-supplied context; must not carry credentials or secrets.
    pub context: Option<serde_json::Value>,
    /// Version at creation; a session is stale once the subject's current
    /// version is higher.
    pub version: u64,
    /// Creation time, for audit and for computing idleness.
    pub created_at: DateTime<Utc>,
    /// Hard expiry; the session must not be honoured at or after this instant.
    pub expires_at: DateTime<Utc>,
}

impl<S: Subject> Session<S> {
    /// Whether the hard expiry has passed.
    ///
    /// Security semantics: this is a pure read - it neither removes nor
    /// refreshes the session - so every caller must check it before honouring
    /// a session, and a manager returning a session from `get_session` may
    /// well return an expired one. The boundary is exclusive: a session is
    /// expired only once `now` has passed `expires_at`.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }
}

/// Server-side session lifecycle: creation, role activation, lookup, and
/// revocation.
///
/// Security semantics: three independent mechanisms decide whether a session
/// is still good, and all are the caller's responsibility to enforce -
/// expiry ([`Session::is_expired`]), the version counter (a session whose
/// version is below the subject's current version is stale), and the
/// assignments that back its active roles.
/// [`SessionManager::bump_version_for_subject`] is the mechanism that
/// invalidates stale sessions after a privilege change, and
/// [`revoke_all_for_subject`](SessionManager::revoke_all_for_subject) is the
/// bulk kill switch; note that each implementation defines the latter's blast
/// radius (see the individual implementations). Every method returns
/// `Result` so a storage failure is visible: callers must treat `Err` as
/// "cannot confirm the session", which is a denial.
#[async_trait::async_trait]
pub trait SessionManager<S: Subject>: Send + Sync {
    /// Creates a session for the subject, limited to `ttl` starting now.
    ///
    /// Security semantics: the requested `active_roles` are filtered against
    /// the subject's assignments, so a caller cannot activate a role the
    /// subject does not hold; a store error propagates with no session created
    /// (fail-closed). An empty role set is valid and yields a session with no
    /// role authority.
    async fn create_session(
        &self,
        subject: &S,
        active_roles: HashSet<String>,
        ttl: Duration,
    ) -> Result<Session<S>>;
    /// Activates one role inside an existing session. The role must be
    /// assigned to the subject; activation is additive and idempotent
    /// (re-activating an already active role succeeds without change).
    async fn activate_role(&self, session_id: Uuid, role_name: &str) -> Result<()>;
    /// Deactivates one role inside an existing session. Idempotent:
    /// deactivating a role that is not active leaves the session unchanged and
    /// still reports success.
    async fn deactivate_role(&self, session_id: Uuid, role_name: &str) -> Result<()>;
    /// Loads a session by id. `Ok(None)` means unknown or already destroyed;
    /// the returned session may already be expired, so callers must check
    /// [`Session::is_expired`] and the version before honouring it.
    async fn get_session(&self, session_id: Uuid) -> Result<Option<Session<S>>>;
    /// Destroys one session. Idempotent: destroying a missing session succeeds
    /// without error, so the result does not prove that a session existed.
    async fn destroy_session(&self, session_id: Uuid) -> Result<()>;

    /// Revoke all active sessions for a subject (e.g., after role/grant change).
    async fn revoke_all_for_subject(&self, subject: &S) -> Result<usize>;

    /// Return the current version counter for a subject.
    async fn current_version(&self, subject: &S) -> Result<u64>;

    /// Increment the version counter for a subject, invalidating all prior sessions.
    async fn bump_version_for_subject(&self, subject: &S) -> Result<u64>;
}

/// In-memory session manager: sessions and version counters live in this
/// process only.
///
/// Security semantics: nothing is persisted and nothing is shared between
/// replicas, which has two opposite consequences. A restart loses every
/// session, so all clients must re-authenticate (fail-closed), and a replica
/// that did not create a session reports it as unknown (`Ok(None)`) even while
/// another replica still serves it - so a deployment must either pin a client
/// to one replica or use the database-backed manager. Version counters start
/// at 0 for an unknown subject.
pub struct InMemorySessionManager<S, P>
where
    S: Subject,
    P: Permission,
{
    sessions: tokio::sync::RwLock<HashMap<Uuid, Session<S>>>,
    subject_versions: tokio::sync::RwLock<HashMap<String, u64>>,
    assignment_store: Shared<dyn AssignmentStore<S, P>>,
    #[cfg(feature = "rbac-constraints")]
    constraint_store: Option<Shared<dyn ConstraintStore>>,
}

impl<S, P> InMemorySessionManager<S, P>
where
    S: Subject,
    P: Permission,
{
    /// Creates an empty manager that validates roles against the given
    /// assignment store. No session exists yet, so every lookup returns
    /// "unknown" until one is created.
    #[must_use]
    pub fn new(assignment_store: impl AssignmentStore<S, P> + 'static) -> Self {
        Self {
            sessions: tokio::sync::RwLock::new(HashMap::new()),
            subject_versions: tokio::sync::RwLock::new(HashMap::new()),
            assignment_store: Shared::from_arc_unsized(Arc::new(assignment_store)),
            #[cfg(feature = "rbac-constraints")]
            constraint_store: None,
        }
    }

    /// Attaches a constraint store so DSD policies are enforced on session
    /// creation and role activation.
    ///
    /// Security semantics: without this call there is NO constraint enforcement
    /// at all, so mutually exclusive roles can be activated together. A
    /// deployment that seeds DSD policies must wire the store here, or enforce
    /// the check at another layer.
    #[must_use]
    #[cfg(feature = "rbac-constraints")]
    pub fn with_constraint_store(mut self, store: impl ConstraintStore + 'static) -> Self {
        self.constraint_store = Some(Shared::from_arc_unsized(Arc::new(store)));
        self
    }

    /// The assignment store sessions are validated against; shared, so
    /// mutations through it are visible to this manager immediately.
    #[must_use]
    pub fn assignment_store(&self) -> Shared<dyn AssignmentStore<S, P>> {
        self.assignment_store.clone()
    }

    /// Drops expired sessions and reports how many were removed.
    ///
    /// Security semantics: housekeeping only - expiry is already enforced on
    /// use, so not calling this costs memory, not correctness. It does not
    /// touch version counters, so it cannot resurrect or invalidate any
    /// session that is still within its TTL.
    #[must_use]
    pub async fn cleanup_expired(&self) -> usize {
        let mut sessions = self.sessions.write().await;
        let before = sessions.len();
        sessions.retain(|_, session| !session.is_expired());
        before - sessions.len()
    }
}

#[async_trait::async_trait]
impl<S, P> SessionManager<S> for InMemorySessionManager<S, P>
where
    S: Subject,
    P: Permission,
{
    /// Filters the requested roles against the subject's assignments, then
    /// stamps the session with the subject's current version.
    ///
    /// Failure mode: a `roles_of` error propagates and NO session is created
    /// (fail-closed); a DSD violation also propagates. Roles the subject does
    /// not hold are silently dropped rather than rejected, so the resulting
    /// session may hold fewer roles than requested - never more. Stamping the
    /// current version is what makes a later bump invalidate this session.
    async fn create_session(
        &self,
        subject: &S,
        mut active_roles: HashSet<String>,
        ttl: Duration,
    ) -> Result<Session<S>> {
        let assigned = self.assignment_store.roles_of(subject).await?;
        let assigned_set: HashSet<String> = assigned.into_iter().collect();
        active_roles.retain(|r| assigned_set.contains(r));

        #[cfg(feature = "rbac-constraints")]
        if let Some(ref cs) = self.constraint_store {
            validate_dsd_with_store(&active_roles, cs).await?;
        }

        let version = {
            let versions = self.subject_versions.read().await;
            versions.get(subject.subject_id()).copied().unwrap_or(0)
        };

        let session = Session {
            id: Uuid::now_v7(),
            subject: subject.clone(),
            active_roles,
            context: None,
            version,
            created_at: Utc::now(),
            expires_at: Utc::now() + ttl,
        };

        let mut sessions = self.sessions.write().await;
        sessions.insert(session.id, session.clone());
        Ok(session)
    }

    /// Adds a role to a live session after re-checking it against the
    /// subject's current assignments and the DSD policies.
    ///
    /// Failure mode: unknown session (`SessionNotFound`), expired session
    /// (`SessionExpired`), a role the subject no longer holds (`NotFound`), a
    /// store error, and a DSD violation all leave the session unchanged
    /// (fail-closed). Re-activating an already active role is a no-op success.
    async fn activate_role(&self, session_id: Uuid, role_name: &str) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        let session = sessions
            .get_mut(&session_id)
            .ok_or(KirinoError::SessionNotFound)?;
        if session.is_expired() {
            return Err(KirinoError::SessionExpired.into());
        }
        if session.active_roles.contains(role_name) {
            return Ok(());
        }

        let assigned = self.assignment_store.roles_of(&session.subject).await?;
        let role_str = role_name.to_string();
        if !assigned.contains(&role_str) {
            return Err(KirinoError::NotFound(format!(
                "role '{role_name}' not assigned to subject"
            ))
            .into());
        }

        #[cfg(feature = "rbac-constraints")]
        {
            let mut test_roles = session.active_roles.clone();
            test_roles.insert(role_str);
            if let Some(ref cs) = self.constraint_store {
                validate_dsd_with_store(&test_roles, cs).await?;
            }
        }

        session.active_roles.insert(role_name.to_string());
        Ok(())
    }

    /// Removes a role from a live session; it does not touch the subject's
    /// assignment, so the role can be activated again later.
    ///
    /// Failure mode: an unknown session is `SessionNotFound` and an expired
    /// session is `SessionExpired` - unlike `activate_role`, removing a role
    /// from an expired session is refused rather than allowed, so a stale
    /// session cannot be edited. Removing a role that is not active is a
    /// successful no-op.
    async fn deactivate_role(&self, session_id: Uuid, role_name: &str) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        let session = sessions
            .get_mut(&session_id)
            .ok_or(KirinoError::SessionNotFound)?;

        if session.is_expired() {
            return Err(KirinoError::SessionExpired.into());
        }

        session.active_roles.remove(role_name);
        Ok(())
    }

    /// Returns a clone of the stored session, expired or not. `Ok(None)` means
    /// unknown id; callers must check expiry and version before honouring the
    /// result.
    async fn get_session(&self, session_id: Uuid) -> Result<Option<Session<S>>> {
        let sessions = self.sessions.read().await;
        Ok(sessions.get(&session_id).cloned())
    }

    /// Removes the session from the map; removing an unknown id is a
    /// successful no-op, so a double logout is not an error.
    async fn destroy_session(&self, session_id: Uuid) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        sessions.remove(&session_id);
        Ok(())
    }

    /// Deletes every session whose subject id matches and reports how many
    /// were removed. Subject ids are compared as strings, so the whole id must
    /// match exactly; only this manager's own sessions are affected.
    async fn revoke_all_for_subject(&self, subject: &S) -> Result<usize> {
        let mut sessions = self.sessions.write().await;
        let before = sessions.len();
        sessions.retain(|_, s| s.subject.subject_id() != subject.subject_id());
        Ok(before - sessions.len())
    }

    /// The subject's version counter, or 0 when no bump has ever happened.
    /// A session is stale when its own version is lower than this value.
    async fn current_version(&self, subject: &S) -> Result<u64> {
        let versions = self.subject_versions.read().await;
        Ok(versions.get(subject.subject_id()).copied().unwrap_or(0))
    }

    /// Increments the subject's version and returns the new value; every
    /// session stamped with an older version is now stale.
    ///
    /// Security semantics: this is the revocation primitive for privilege
    /// changes - it does not delete sessions, it makes them unusable, so a
    /// check that compares versions denies them. The counter wraps on overflow
    /// (`wrapping_add`), which is an accepted risk of a `u64` counter rather
    /// than a guarded rollover.
    async fn bump_version_for_subject(&self, subject: &S) -> Result<u64> {
        let mut versions = self.subject_versions.write().await;
        let current = versions.get(subject.subject_id()).copied().unwrap_or(0);
        let next = current.wrapping_add(1);
        versions.insert(subject.subject_id().to_string(), next);
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rbac::store::memory::InMemoryAssignmentStore;
    use crate::rbac::subject::StringSubject;
    use crate::test_utils::TestPerm;

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
        // Pre-seed a real session so we can prove the destroy call is a
        // targeted no-op rather than a "nothing existed" trivial pass.
        let keeper_subj = StringSubject::new("keeper");
        let keeper = mgr
            .create_session(&keeper_subj, HashSet::new(), Duration::hours(1))
            .await
            .unwrap();
        // Destroying an unrelated (nonexistent) session id must succeed AND
        // leave the seeded session untouched.
        mgr.destroy_session(uuid::Uuid::now_v7()).await.unwrap();
        assert!(
            mgr.get_session(keeper.id).await.unwrap().is_some(),
            "destroying an unrelated session id must not evict other sessions"
        );
    }
}

#[cfg(feature = "rbac-db-session")]
pub mod db;
