use super::store::ConstraintStore;
use crate::error::{KirinoError, KirinoResult};

pub struct ConstraintValidator<S: ConstraintStore> {
    store: S,
}

impl<S: ConstraintStore> ConstraintValidator<S> {
    pub fn new(store: S) -> Self {
        Self { store }
    }

    /// # Errors
    /// Returns an error if adding the new role would violate an SSD policy.
    pub async fn validate_ssd(&self, current_roles: &[String], new_role: &str) -> KirinoResult<()> {
        let policies = self.store.list_ssd_policies().await?;
        let mut test_roles = current_roles.to_vec();
        test_roles.push(new_role.to_string());

        for policy in &policies {
            if !policy.validate(&test_roles) {
                return Err(KirinoError::ConstraintViolation(format!(
                    "SSD policy '{}' violated: adding '{}' would exceed cardinality {}",
                    policy.name, new_role, policy.cardinality,
                )));
            }
        }
        Ok(())
    }

    /// # Errors
    /// Returns an error if activating the new role would violate a DSD policy.
    pub async fn validate_dsd(&self, active_roles: &[String], new_role: &str) -> KirinoResult<()> {
        let policies = self.store.list_dsd_policies().await?;
        let mut test_roles = active_roles.to_vec();
        test_roles.push(new_role.to_string());

        for policy in &policies {
            if !policy.validate(&test_roles) {
                return Err(KirinoError::ConstraintViolation(format!(
                    "DSD policy '{}' violated: activating '{}' exceeds cardinality {}",
                    policy.name, new_role, policy.cardinality,
                )));
            }
        }
        Ok(())
    }

    /// # Errors
    /// Returns an error if any temporal constraint is violated at the current time.
    pub async fn validate_temporal(&self, role_name: &str) -> KirinoResult<()> {
        let constraints = self.store.list_temporal_constraints().await?;
        for constraint in &constraints {
            if constraint.role_name == role_name && !constraint.is_valid() {
                return Err(KirinoError::ConstraintViolation(format!(
                    "Temporal constraint: role '{}' is not available at the current time",
                    role_name,
                )));
            }
        }
        Ok(())
    }

    /// # Errors
    /// Returns an error if the cardinality constraint for the role would be exceeded.
    pub async fn validate_cardinality(
        &self,
        role_name: &str,
        current_subject_count: usize,
    ) -> KirinoResult<()> {
        let constraints = self.store.list_cardinality_constraints().await?;
        for constraint in &constraints {
            if constraint.role_name == role_name && !constraint.validate(current_subject_count) {
                return Err(KirinoError::ConstraintViolation(format!(
                    "Cardinality constraint: role '{}' already has {} subjects (max {})",
                    role_name, current_subject_count, constraint.max_subjects,
                )));
            }
        }
        Ok(())
    }

    /// # Errors
    /// Returns an error if the prerequisite role is not present in `current_roles`.
    pub async fn validate_prerequisite(
        &self,
        role_name: &str,
        current_roles: &[String],
    ) -> KirinoResult<()> {
        let constraints = self.store.list_prerequisite_constraints().await?;
        for constraint in &constraints {
            if constraint.role_name == role_name && !constraint.validate(current_roles) {
                return Err(KirinoError::ConstraintViolation(format!(
                    "Prerequisite constraint: role '{}' requires '{}'",
                    role_name, constraint.requires,
                )));
            }
        }
        Ok(())
    }

    /// # Errors
    /// Returns an error if any SSD, cardinality, prerequisite, or temporal constraint is violated.
    pub async fn validate_assignment(
        &self,
        current_roles: &[String],
        new_role: &str,
        current_subject_count: usize,
    ) -> KirinoResult<()> {
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
            .add_temporal_constraint(TemporalConstraint::new(
                "seasonal",
                now - chrono::Duration::hours(1),
                now + chrono::Duration::hours(1),
            ))
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
            .add_temporal_constraint(TemporalConstraint::new(
                "expired_role",
                now - chrono::Duration::hours(2),
                now - chrono::Duration::hours(1),
            ))
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
            .add_temporal_constraint(TemporalConstraint::new(
                "seasonal",
                now - chrono::Duration::hours(1),
                now + chrono::Duration::hours(1),
            ))
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
            .add_temporal_constraint(TemporalConstraint::new(
                "expired_role",
                now - chrono::Duration::hours(2),
                now - chrono::Duration::hours(1),
            ))
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
