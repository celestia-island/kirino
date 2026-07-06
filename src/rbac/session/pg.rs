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

pub struct PgSessionManager<S, P>
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

impl<S, P> PgSessionManager<S, P>
where
    S: Subject,
    P: Permission,
{
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

    #[cfg(feature = "rbac-constraints")]
    pub fn with_constraint_store(mut self, store: impl ConstraintStore + 'static) -> Self {
        self.constraint_store = Some(Shared::from_arc_unsized(std::sync::Arc::new(store)));
        self
    }

    pub fn assignment_store(&self) -> Shared<dyn AssignmentStore<S, P>> {
        self.assignment_store.clone()
    }

    pub async fn cleanup_expired(&self) -> Result<usize> {
        self.store.cleanup_expired().await
    }
}

#[async_trait::async_trait]
impl<S, P> SessionManager<S> for PgSessionManager<S, P>
where
    S: Subject,
    P: Permission,
{
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
            created_at: now,
            expires_at: now + ttl,
        };

        let row = SessionRow {
            id: session.id,
            subject_id: subject.subject_id().to_string(),
            active_roles: validated_roles.into_iter().collect(),
            context: None,
            expires_at: session.expires_at,
            created_at: now,
        };
        self.store.save_session(&row).await?;

        Ok(session)
    }

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
                    created_at: r.created_at,
                    expires_at: r.expires_at,
                }))
            }
            None => Ok(None),
        }
    }

    async fn destroy_session(&self, session_id: Uuid) -> Result<()> {
        self.store.delete_session(session_id).await
    }
}
