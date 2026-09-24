//! Fail-closed constraint validation gate.
//!
//! Each check reads the constraint store and returns `Err` both for a violation and
//! for a store failure; a caller on a security path must treat either as a denial.
//! The gate keeps no cache and takes no lock across calls, so it validates the state
//! that was stored when it read and is not atomic with the write it guards.

use anyhow::Result;

use super::store::ConstraintStore;
use crate::error::KirinoError;

/// Applies the stored constraint policies to role assignment and activation.
///
/// Semantics worth relying on:
/// - fail-closed: a store error propagates as `Err` (via `?`), so an unreadable
///   store denies rather than permits, and the caller must deny too;
/// - default-permit by absence: a role with no stored constraint of a given kind
///   passes that check, so an unseeded store enforces nothing;
/// - no cache and no staleness window: every call re-reads the store, so a policy
///   change applies from the next call, at the cost of store reads per check;
/// - advisory, not transactional: the validator performs no write and holds no lock
///   between a check and the caller's write, so two concurrent assignments can both
///   pass a cardinality check (TOCTOU). Enforcement depends on the caller invoking a
///   check before committing the assignment, and on denying when a check errors.
pub struct ConstraintValidator<S: ConstraintStore> {
    store: S,
}

impl<S: ConstraintStore> ConstraintValidator<S> {
    /// Wraps an existing store; the store is neither seeded nor verified here.
    ///
    /// Passing an empty store yields a validator that permits everything, so store
    /// population is a security-critical precondition.
    #[must_use]
    pub fn new(store: S) -> Self {
        Self { store }
    }

    /// Checks SSD policies before assigning `new_role` to `current_roles`.
    ///
    /// Re-assigning a role that is already held short-circuits to `Ok(())`, so the
    /// call is idempotent for held roles. Otherwise the existing roles plus the new
    /// one are tested against every stored policy and the first violation denies.
    /// A store error propagates and must be treated as denial (fail-closed); with no
    /// SSD policy stored the check passes.
    /// # Errors
    /// Returns an error if adding the new role would violate an SSD policy.
    pub async fn validate_ssd(&self, current_roles: &[String], new_role: &str) -> Result<()> {
        let policies = self.store.list_ssd_policies().await?;
        if current_roles.contains(&new_role.to_string()) {
            return Ok(());
        }
        let mut test_roles = current_roles.to_vec();
        test_roles.push(new_role.to_string());

        for policy in &policies {
            if !policy.validate(&test_roles) {
                return Err(KirinoError::ConstraintViolation(format!(
                    "SSD policy '{}' violated: adding '{}' would exceed cardinality {}",
                    policy.name, new_role, policy.cardinality,
                ))
                .into());
            }
        }
        Ok(())
    }

    /// Checks DSD policies before activating `new_role` in an active role set.
    ///
    /// Same shape as `validate_ssd`: a role that is already active short-circuits to
    /// `Ok(())`, the first violating policy denies, and a store error propagates and
    /// must be treated as denial (fail-closed). With no DSD policy stored the check
    /// passes.
    /// # Errors
    /// Returns an error if activating the new role would violate a DSD policy.
    pub async fn validate_dsd(&self, active_roles: &[String], new_role: &str) -> Result<()> {
        let policies = self.store.list_dsd_policies().await?;
        if active_roles.contains(&new_role.to_string()) {
            return Ok(());
        }
        let mut test_roles = active_roles.to_vec();
        test_roles.push(new_role.to_string());

        for policy in &policies {
            if !policy.validate(&test_roles) {
                return Err(KirinoError::ConstraintViolation(format!(
                    "DSD policy '{}' violated: activating '{}' exceeds cardinality {}",
                    policy.name, new_role, policy.cardinality,
                ))
                .into());
            }
        }
        Ok(())
    }

    /// Checks that `role_name` has no temporal window that is currently invalid.
    ///
    /// Every stored window for the role is examined, so one expired or not-yet-started
    /// window denies the role even when another window is current. Roles with no
    /// stored window pass. The verdict comes from the wall clock at call time and is
    /// not cached, so a system clock change changes the outcome.
    /// # Errors
    /// Returns an error if any temporal constraint is violated at the current time.
    pub async fn validate_temporal(&self, role_name: &str) -> Result<()> {
        let constraints = self.store.list_temporal_constraints().await?;
        for constraint in &constraints {
            if constraint.role_name == role_name && !constraint.is_valid() {
                return Err(KirinoError::ConstraintViolation(format!(
                    "Temporal constraint: role '{}' is not available at the current time",
                    role_name,
                ))
                .into());
            }
        }
        Ok(())
    }

    /// Checks the stored cardinality bound for `role_name` against a caller count.
    ///
    /// The count is supplied by the caller and is neither read from nor verified
    /// against the store, so an under-count weakens the bound (fail-open); pass an
    /// authoritative assignment count. Roles with no stored bound pass, and a store
    /// error propagates as denial.
    /// # Errors
    /// Returns an error if the cardinality constraint for the role would be exceeded.
    pub async fn validate_cardinality(
        &self,
        role_name: &str,
        current_subject_count: usize,
    ) -> Result<()> {
        let constraints = self.store.list_cardinality_constraints().await?;
        for constraint in &constraints {
            if constraint.role_name == role_name && !constraint.validate(current_subject_count) {
                return Err(KirinoError::ConstraintViolation(format!(
                    "Cardinality constraint: role '{}' already has {} subjects (max {})",
                    role_name, current_subject_count, constraint.max_subjects,
                ))
                .into());
            }
        }
        Ok(())
    }

    /// Checks that every prerequisite stored for `role_name` is in `current_roles`.
    ///
    /// A missing prerequisite denies; role hierarchies are not resolved here, so a
    /// prerequisite satisfied only transitively still denies. A store error
    /// propagates as denial, and roles with no stored prerequisite pass.
    /// # Errors
    /// Returns an error if the prerequisite role is not present in `current_roles`.
    pub async fn validate_prerequisite(
        &self,
        role_name: &str,
        current_roles: &[String],
    ) -> Result<()> {
        let constraints = self.store.list_prerequisite_constraints().await?;
        for constraint in &constraints {
            if constraint.role_name == role_name && !constraint.validate(current_roles) {
                return Err(KirinoError::ConstraintViolation(format!(
                    "Prerequisite constraint: role '{}' requires '{}'",
                    role_name, constraint.requires,
                ))
                .into());
            }
        }
        Ok(())
    }

    /// Runs the assignment-time checks in order: SSD, cardinality, prerequisite,
    /// then temporal. Stops at the first failure and propagates store errors.
    ///
    /// DSD is not part of this path: it is enforced when a role is activated in a
    /// session. The method performs no write, so it must be called before the
    /// assignment is committed, and an empty or unseeded store makes it a no-op
    /// (default-permit by absence of policy).
    /// # Errors
    /// Returns an error if any SSD, cardinality, prerequisite, or temporal constraint is violated.
    pub async fn validate_assignment(
        &self,
        current_roles: &[String],
        new_role: &str,
        current_subject_count: usize,
    ) -> Result<()> {
        self.validate_ssd(current_roles, new_role).await?;
        self.validate_cardinality(new_role, current_subject_count)
            .await?;
        self.validate_prerequisite(new_role, current_roles).await?;
        self.validate_temporal(new_role).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rbac::constraints::policies::{
        CardinalityConstraint, DsdPolicy, PrerequisiteConstraint, SsdPolicy, TemporalConstraint,
    };
    use crate::rbac::constraints::store::InMemoryConstraintStore;

    #[tokio::test]
    async fn test_validate_ssd_pass() {
        let store = InMemoryConstraintStore::new();
        store
            .add_ssd_policy(SsdPolicy::new(
                "exclusive",
                ["admin".to_string(), "auditor".to_string()].into(),
                2,
            ))
            .await
            .unwrap();

        let validator = ConstraintValidator::new(store);
        assert!(validator
            .validate_ssd(&["viewer".to_string()], "admin")
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn test_validate_ssd_fail() {
        let store = InMemoryConstraintStore::new();
        store
            .add_ssd_policy(SsdPolicy::new(
                "exclusive",
                ["admin".to_string(), "auditor".to_string()].into(),
                2,
            ))
            .await
            .unwrap();

        let validator = ConstraintValidator::new(store);
        assert!(validator
            .validate_ssd(&["admin".to_string()], "auditor")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_validate_dsd_pass() {
        let store = InMemoryConstraintStore::new();
        store
            .add_dsd_policy(DsdPolicy::new(
                "exclusive",
                ["admin".to_string(), "auditor".to_string()].into(),
                2,
            ))
            .await
            .unwrap();

        let validator = ConstraintValidator::new(store);
        assert!(validator
            .validate_dsd(&["viewer".to_string()], "admin")
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn test_validate_dsd_fail() {
        let store = InMemoryConstraintStore::new();
        store
            .add_dsd_policy(DsdPolicy::new(
                "session_exclusive",
                ["ops".to_string(), "audit".to_string()].into(),
                2,
            ))
            .await
            .unwrap();

        let validator = ConstraintValidator::new(store);
        assert!(validator
            .validate_dsd(&["ops".to_string()], "audit")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_validate_cardinality_fail() {
        let store = InMemoryConstraintStore::new();
        store
            .add_cardinality_constraint(CardinalityConstraint::new("admin", 1))
            .await
            .unwrap();

        let validator = ConstraintValidator::new(store);
        assert!(validator.validate_cardinality("admin", 1).await.is_err());
        assert!(validator.validate_cardinality("admin", 0).await.is_ok());
    }

    #[tokio::test]
    async fn test_validate_prerequisite_fail() {
        let store = InMemoryConstraintStore::new();
        store
            .add_prerequisite_constraint(PrerequisiteConstraint::new("admin", "operator"))
            .await
            .unwrap();

        let validator = ConstraintValidator::new(store);
        assert!(validator
            .validate_prerequisite("admin", &["viewer".to_string()])
            .await
            .is_err());
        assert!(validator
            .validate_prerequisite("admin", &["operator".to_string()])
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn test_validate_assignment_full() {
        let store = InMemoryConstraintStore::new();
        store
            .add_ssd_policy(SsdPolicy::new(
                "exclusive",
                ["admin".to_string(), "auditor".to_string()].into(),
                2,
            ))
            .await
            .unwrap();
        store
            .add_prerequisite_constraint(PrerequisiteConstraint::new("admin", "operator"))
            .await
            .unwrap();

        let validator = ConstraintValidator::new(store);

        assert!(validator
            .validate_assignment(&["operator".to_string()], "admin", 0)
            .await
            .is_ok());

        assert!(validator
            .validate_assignment(&["auditor".to_string()], "admin", 0)
            .await
            .is_err());

        assert!(validator
            .validate_assignment(&["viewer".to_string()], "admin", 0)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_validate_temporal_pass() {
        let store = InMemoryConstraintStore::new();
        let now = chrono::Utc::now();
        store
            .add_temporal_constraint(
                TemporalConstraint::new(
                    "seasonal",
                    now - chrono::Duration::hours(1),
                    now + chrono::Duration::hours(1),
                )
                .unwrap(),
            )
            .await
            .unwrap();

        let validator = ConstraintValidator::new(store);
        assert!(validator.validate_temporal("seasonal").await.is_ok());
    }

    #[tokio::test]
    async fn test_validate_temporal_fail() {
        let store = InMemoryConstraintStore::new();
        let now = chrono::Utc::now();
        store
            .add_temporal_constraint(
                TemporalConstraint::new(
                    "expired_role",
                    now - chrono::Duration::hours(2),
                    now - chrono::Duration::hours(1),
                )
                .unwrap(),
            )
            .await
            .unwrap();

        let validator = ConstraintValidator::new(store);
        assert!(validator.validate_temporal("expired_role").await.is_err());
    }

    #[tokio::test]
    async fn test_validate_temporal_nonexistent_role() {
        let store = InMemoryConstraintStore::new();
        let now = chrono::Utc::now();
        store
            .add_temporal_constraint(
                TemporalConstraint::new(
                    "seasonal",
                    now - chrono::Duration::hours(1),
                    now + chrono::Duration::hours(1),
                )
                .unwrap(),
            )
            .await
            .unwrap();

        let validator = ConstraintValidator::new(store);
        assert!(validator.validate_temporal("other").await.is_ok());
    }

    #[tokio::test]
    async fn test_validate_assignment_cardinality_fail() {
        let store = InMemoryConstraintStore::new();
        store
            .add_cardinality_constraint(CardinalityConstraint::new("admin", 1))
            .await
            .unwrap();

        let validator = ConstraintValidator::new(store);
        assert!(validator
            .validate_assignment(&[], "admin", 1)
            .await
            .is_err());
        assert!(validator
            .validate_assignment(&[], "viewer", 1)
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn test_validate_assignment_temporal_fail() {
        let store = InMemoryConstraintStore::new();
        let now = chrono::Utc::now();
        store
            .add_temporal_constraint(
                TemporalConstraint::new(
                    "expired_role",
                    now - chrono::Duration::hours(2),
                    now - chrono::Duration::hours(1),
                )
                .unwrap(),
            )
            .await
            .unwrap();

        let validator = ConstraintValidator::new(store);
        assert!(validator
            .validate_assignment(&[], "expired_role", 0)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_empty_store_pass_all() {
        let store = InMemoryConstraintStore::new();
        let validator = ConstraintValidator::new(store);
        assert!(validator.validate_ssd(&[], "admin").await.is_ok());
        assert!(validator.validate_dsd(&[], "admin").await.is_ok());
        assert!(validator.validate_cardinality("admin", 100).await.is_ok());
        assert!(validator.validate_prerequisite("admin", &[]).await.is_ok());
        assert!(validator.validate_temporal("admin").await.is_ok());
        assert!(validator
            .validate_assignment(&[], "admin", 100)
            .await
            .is_ok());
    }
}
