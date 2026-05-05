use anyhow::{anyhow, Result};

use super::store::ConstraintStore;

pub struct ConstraintValidator<S: ConstraintStore> {
    store: S,
}

impl<S: ConstraintStore> ConstraintValidator<S> {
    pub fn new(store: S) -> Self {
        Self { store }
    }

    pub async fn validate_ssd(&self, current_roles: &[String], new_role: &str) -> Result<()> {
        let policies = self.store.list_ssd_policies().await?;
        let mut test_roles = current_roles.to_vec();
        test_roles.push(new_role.to_string());

        for policy in &policies {
            if !policy.validate(&test_roles) {
                return Err(anyhow!(
                    "SSD policy '{}' violated: adding '{}' would exceed cardinality {}",
                    policy.name,
                    new_role,
                    policy.cardinality,
                ));
            }
        }
        Ok(())
    }

    pub async fn validate_dsd(&self, active_roles: &[String], new_role: &str) -> Result<()> {
        let policies = self.store.list_dsd_policies().await?;
        let mut test_roles = active_roles.to_vec();
        test_roles.push(new_role.to_string());

        for policy in &policies {
            if !policy.validate(&test_roles) {
                return Err(anyhow!(
                    "DSD policy '{}' violated: activating '{}' exceeds cardinality {}",
                    policy.name,
                    new_role,
                    policy.cardinality,
                ));
            }
        }
        Ok(())
    }

    pub async fn validate_cardinality(
        &self,
        role_name: &str,
        current_subject_count: usize,
    ) -> Result<()> {
        let constraints = self.store.list_cardinality_constraints().await?;
        for constraint in &constraints {
            if constraint.role_name == role_name && !constraint.validate(current_subject_count) {
                return Err(anyhow!(
                    "Cardinality constraint: role '{}' already has {} subjects (max {})",
                    role_name,
                    current_subject_count,
                    constraint.max_subjects,
                ));
            }
        }
        Ok(())
    }

    pub async fn validate_prerequisite(
        &self,
        role_name: &str,
        current_roles: &[String],
    ) -> Result<()> {
        let constraints = self.store.list_prerequisite_constraints().await?;
        for constraint in &constraints {
            if constraint.role_name == role_name && !constraint.validate(current_roles) {
                return Err(anyhow!(
                    "Prerequisite constraint: role '{}' requires '{}'",
                    role_name,
                    constraint.requires,
                ));
            }
        }
        Ok(())
    }

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
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rbac::constraints::policies::{
        CardinalityConstraint, DsdPolicy, PrerequisiteConstraint, SsdPolicy,
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
}
