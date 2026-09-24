use anyhow::Result;
use chrono::{Duration, Utc};
use std::collections::HashSet;
use uuid::Uuid;

#[cfg(feature = "rbac-constraints")]
use super::validate_dsd_with_store;
use super::{Session, SessionManager};
#[cfg(feature = "rbac-constraints")]
use crate::rbac::constraints::store::ConstraintStore;

use crate::{
    error::KirinoError,
    rbac::{
        shared::Shared,
        store::persistence::{PersistentSessionStore, SessionRow},
        traits::{AssignmentStore, Permission, Subject},
    },
};

/// Database-backed session manager: sessions and versions live in a
/// [`PersistentSessionStore`], so they survive restarts and are shared between
/// replicas.
///
/// Security semantics: unlike the in-memory manager, a session created on one
/// replica is visible to every other one, which is what makes it safe behind a
/// load balancer. It inherits the same three validity checks (expiry, version
/// staleness, roles still assigned) and delegates revocation to the store, so
/// the store's durability guarantees are the revocation guarantees. Note that
/// [`SessionManager::revoke_all_for_subject`] on this type removes the
/// subject's ROLE ASSIGNMENTS rather than its session rows - see that method's
/// documentation for the consequence.
pub struct DbSessionManager<S, P>
where
    S: Subject,
    P: Permission,
{
    store: Shared<dyn PersistentSessionStore>,
    assignment_store: Shared<dyn AssignmentStore<S, P>>,
    #[cfg(feature = "rbac-constraints")]
    constraint_store: Option<Shared<dyn ConstraintStore>>,
    _phantom: std::marker::PhantomData<P>,
}

impl<S, P> DbSessionManager<S, P>
where
    S: Subject,
    P: Permission,
{
    /// Creates a manager over the given session store and assignment store; no
    /// constraint enforcement is configured yet.
    ///
    /// Security semantics: the session store is authoritative for whether a
    /// session exists, so a store that is unreachable makes every lookup fail
    /// (fail-closed) rather than fall back to an in-memory guess.
    pub fn new(
        store: impl PersistentSessionStore + 'static,
        assignment_store: impl AssignmentStore<S, P> + 'static,
    ) -> Self {
        Self {
            store: Shared::from_arc_unsized(std::sync::Arc::new(store)),
            assignment_store: Shared::from_arc_unsized(std::sync::Arc::new(assignment_store)),
            #[cfg(feature = "rbac-constraints")]
            constraint_store: None,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Attaches a constraint store so DSD policies are enforced on session
    /// creation and role activation.
    ///
    /// Security semantics: without this call there is NO constraint
    /// enforcement - mutually exclusive roles can be active in one session - so
    /// a deployment that seeds DSD policies must wire them here or enforce the
    /// check elsewhere.
    #[cfg(feature = "rbac-constraints")]
    pub fn with_constraint_store(mut self, store: impl ConstraintStore + 'static) -> Self {
        self.constraint_store = Some(Shared::from_arc_unsized(std::sync::Arc::new(store)));
        self
    }

    /// The assignment store used to validate roles; shared, so writes through
    /// it are visible to this manager immediately.
    pub fn assignment_store(&self) -> Shared<dyn AssignmentStore<S, P>> {
        self.assignment_store.clone()
    }

    /// Asks the session store to delete expired rows and reports how many were
    /// removed.
    ///
    /// Security semantics: housekeeping only. Expiry is enforced when a
    /// session is used, so a failing or skipped cleanup cannot extend any
    /// session's life; an error here must not be read as "no sessions are
    /// expired".
    pub async fn cleanup_expired(&self) -> Result<usize> {
        self.store.cleanup_expired().await
    }
}

#[async_trait::async_trait]
impl<S, P> SessionManager<S> for DbSessionManager<S, P>
where
    S: Subject,
    P: Permission,
{
    /// Persists a new session row after filtering the requested roles against
    /// the subject's current assignments.
    ///
    /// Failure mode: a `roles_of` error, a DSD violation or a store write error
    /// propagates and no session exists (fail-closed) - the returned session is
    /// only produced after `save_session` succeeded. Roles the subject does not
    /// hold are dropped silently, so the session can hold fewer roles than
    /// requested, never more. The row is written with `version: 0` (this
    /// manager does not read the subject's current version at creation), so
    /// version-based staleness for a new session depends on the store's
    /// version metadata being bumped afterwards.
    async fn create_session(
        &self,
        subject: &S,
        active_roles: HashSet<String>,
        ttl: Duration,
    ) -> Result<Session<S>> {
        let assigned_roles = self
            .assignment_store
            .roles_of(subject)
            .await?
            .into_iter()
            .collect::<HashSet<_>>();
        let validated_roles: HashSet<String> = active_roles
            .into_iter()
            .filter(|r| assigned_roles.contains(r))
            .collect();

        #[cfg(feature = "rbac-constraints")]
        if let Some(ref cs) = self.constraint_store {
            validate_dsd_with_store(&validated_roles, cs).await?;
        }

        let now = Utc::now();
        let session = Session {
            id: Uuid::now_v7(),
            subject: subject.clone(),
            active_roles: validated_roles.clone(),
            context: None,
            version: 0,
            created_at: now,
            expires_at: now + ttl,
        };

        let row = SessionRow {
            id: session.id,
            subject_id: subject.subject_id().to_string(),
            active_roles: validated_roles.into_iter().collect(),
            context: None,
            version: 0,
            expires_at: session.expires_at,
            created_at: now,
        };
        self.store.save_session(&row).await?;

        Ok(session)
    }

    /// Activates a role in a stored session after reloading it and re-checking
    /// the subject's assignments and the DSD policies.
    ///
    /// Failure mode: an unknown session is `SessionNotFound`, an expired one is
    /// `SessionExpired`, an id that no longer parses as a subject id is an
    /// error (the row is refused rather than downgraded), the role must still
    /// be assigned (`NotFound` otherwise), and any store error propagates with
    /// the stored role list unchanged (fail-closed). Re-activating an active
    /// role is a successful no-op.
    async fn activate_role(&self, session_id: Uuid, role_name: &str) -> Result<()> {
        let row = self
            .store
            .load_session(session_id)
            .await?
            .ok_or(KirinoError::SessionNotFound)?;

        if Utc::now() > row.expires_at {
            return Err(KirinoError::SessionExpired.into());
        }

        let mut roles: HashSet<String> = row.active_roles.into_iter().collect();
        if roles.contains(role_name) {
            return Ok(());
        }

        let subject = S::try_from_subject_id(&row.subject_id).map_err(|e| {
            anyhow::anyhow!(
                "invalid subject_id '{}' in session {}: {e}",
                row.subject_id,
                session_id
            )
        })?;
        let assigned = self.assignment_store.roles_of(&subject).await?;
        let role_str = role_name.to_string();
        if !assigned.contains(&role_str) {
            return Err(KirinoError::NotFound(format!(
                "role '{role_name}' not assigned to subject"
            ))
            .into());
        }

        roles.insert(role_str);

        #[cfg(feature = "rbac-constraints")]
        if let Some(ref cs) = self.constraint_store {
            validate_dsd_with_store(&roles, cs).await?;
        }

        let roles_vec: Vec<String> = roles.into_iter().collect();
        self.store.update_roles(session_id, &roles_vec).await
    }

    /// Removes a role from a stored session. The subject's assignment is
    /// untouched, so the role can be activated again later.
    ///
    /// Failure mode: `SessionNotFound` for an unknown id and `SessionExpired`
    /// for an expired one (an expired session is refused rather than edited);
    /// removing a role that is not active is a successful no-op. A store error
    /// propagates, leaving the persisted list unchanged.
    async fn deactivate_role(&self, session_id: Uuid, role_name: &str) -> Result<()> {
        let row = self
            .store
            .load_session(session_id)
            .await?
            .ok_or(KirinoError::SessionNotFound)?;

        if Utc::now() > row.expires_at {
            return Err(KirinoError::SessionExpired.into());
        }

        let mut roles: HashSet<String> = row.active_roles.into_iter().collect();
        roles.remove(role_name);

        let roles_vec: Vec<String> = roles.into_iter().collect();
        self.store.update_roles(session_id, &roles_vec).await
    }

    /// Rebuilds a session from its stored row. `Ok(None)` means no such
    /// session.
    ///
    /// Security semantics: the row is re-validated, not trusted - a
    /// `subject_id` that no longer parses as a subject id is an error
    /// (fail-closed) instead of a fallback principal - but the returned session
    /// may still be expired, so callers must check `Session::is_expired` and
    /// the version before honouring it.
    async fn get_session(&self, session_id: Uuid) -> Result<Option<Session<S>>> {
        let row = self.store.load_session(session_id).await?;
        match row {
            Some(r) => {
                let subject = S::try_from_subject_id(&r.subject_id).map_err(|e| {
                    anyhow::anyhow!(
                        "invalid subject_id '{}' in session {}: {e}",
                        r.subject_id,
                        r.id
                    )
                })?;
                Ok(Some(Session {
                    id: r.id,
                    subject,
                    active_roles: r.active_roles.into_iter().collect(),
                    context: r.context,
                    version: r.version,
                    created_at: r.created_at,
                    expires_at: r.expires_at,
                }))
            }
            None => Ok(None),
        }
    }

    /// Deletes the stored session row. Idempotent: deleting an unknown or
    /// already-deleted session succeeds, so the result does not prove the
    /// session existed. This is the logout path, so its durability is the
    /// point at which the session stops being honoured.
    async fn destroy_session(&self, session_id: Uuid) -> Result<()> {
        self.store.delete_session(session_id).await
    }

    /// WARNING - semantics differ from the in-memory manager: this REVOKES
    /// every role assignment held by the subject and reports how many
    /// assignments were removed. It does not delete session rows at all, so
    /// existing sessions survive with their `active_roles` intact; what stops
    /// them is the missing assignments (a role the subject no longer holds
    /// fails the "still assigned" check on activation and grants nothing in a
    /// fresh resolution). It is destructive and not reversible by calling it
    /// again: the assignments are gone, not merely suspended.
    ///
    /// Failure mode: an error from `roles_of` or from any individual
    /// `revoke_role` propagates, and a mid-loop failure leaves the subject
    /// partially stripped. Callers that need sessions to be unusable
    /// immediately should use
    /// [`bump_version_for_subject`](SessionManager::bump_version_for_subject)
    /// instead.
    async fn revoke_all_for_subject(&self, subject: &S) -> Result<usize> {
        let assignments = self.assignment_store.roles_of(subject).await?;
        for role in &assignments {
            self.assignment_store.revoke_role(subject, role).await?;
        }
        Ok(assignments.len())
    }

    /// Reads the subject's version from the store's session metadata; 0 when no
    /// version is recorded.
    ///
    /// Security semantics: this is the reference value a session's own version
    /// is compared against, so a store that cannot answer makes the comparison
    /// impossible - the error propagates and the caller must deny rather than
    /// assume 0, which would resurrect sessions invalidated by an earlier bump.
    async fn current_version(&self, subject: &S) -> Result<u64> {
        let session = self
            .store
            .load_session_metadata(subject.subject_id())
            .await?;
        Ok(session.map(|s| s.version).unwrap_or(0))
    }

    /// Persists `current + 1` and returns it, making every session that carries
    /// an older version stale. The write is delegated to the store and must be
    /// durable before the caller treats the revocation as effective; the
    /// counter wraps on overflow (`wrapping_add`).
    async fn bump_version_for_subject(&self, subject: &S) -> Result<u64> {
        let current = self.current_version(subject).await?;
        let next = current.wrapping_add(1);
        self.store.bump_version(subject.subject_id(), next).await?;
        Ok(next)
    }
}
