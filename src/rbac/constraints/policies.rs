use std::collections::HashSet;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsdPolicy {
    pub name: String,
    pub roles: HashSet<String>,
    pub cardinality: usize,
}

impl SsdPolicy {
    pub fn new(name: impl Into<String>, roles: HashSet<String>, cardinality: usize) -> Self {
        Self {
            name: name.into(),
            roles,
            cardinality,
        }
    }

    pub fn validate(&self, assigned_roles: &[String]) -> bool {
        let count = assigned_roles
            .iter()
            .filter(|r| self.roles.contains(*r))
            .count();
        count < self.cardinality
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DsdPolicy {
    pub name: String,
    pub roles: HashSet<String>,
    pub cardinality: usize,
}

impl DsdPolicy {
    pub fn new(name: impl Into<String>, roles: HashSet<String>, cardinality: usize) -> Self {
        Self {
            name: name.into(),
            roles,
            cardinality,
        }
    }

    pub fn validate(&self, active_roles: &[String]) -> bool {
        let count = active_roles
            .iter()
            .filter(|r| self.roles.contains(*r))
            .count();
        count < self.cardinality
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CardinalityConstraint {
    pub role_name: String,
    pub max_subjects: usize,
}

impl CardinalityConstraint {
    pub fn new(role_name: impl Into<String>, max_subjects: usize) -> Self {
        Self {
            role_name: role_name.into(),
            max_subjects,
        }
    }

    pub fn validate(&self, current_count: usize) -> bool {
        current_count < self.max_subjects
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrerequisiteConstraint {
    pub role_name: String,
    pub requires: String,
}

impl PrerequisiteConstraint {
    pub fn new(role_name: impl Into<String>, requires: impl Into<String>) -> Self {
        Self {
            role_name: role_name.into(),
            requires: requires.into(),
        }
    }

    pub fn validate(&self, assigned_roles: &[String]) -> bool {
        assigned_roles.contains(&self.requires)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalConstraint {
    pub role_name: String,
    pub valid_from: chrono::DateTime<chrono::Utc>,
    pub valid_until: chrono::DateTime<chrono::Utc>,
}

impl TemporalConstraint {
    pub fn new(
        role_name: impl Into<String>,
        valid_from: chrono::DateTime<chrono::Utc>,
        valid_until: chrono::DateTime<chrono::Utc>,
    ) -> Self {
        Self {
            role_name: role_name.into(),
            valid_from,
            valid_until,
        }
    }

    pub fn is_valid(&self) -> bool {
        let now = chrono::Utc::now();
        now >= self.valid_from && now <= self.valid_until
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssd_policy_allows() {
        let policy = SsdPolicy::new(
            "admin_auditor_exclusive",
            ["admin".to_string(), "auditor".to_string()].into(),
            2,
        );
        assert!(policy.validate(&["admin".to_string()]));
        assert!(policy.validate(&["viewer".to_string()]));
    }

    #[test]
    fn test_ssd_policy_rejects() {
        let policy = SsdPolicy::new(
            "admin_auditor_exclusive",
            ["admin".to_string(), "auditor".to_string()].into(),
            2,
        );
        assert!(!policy.validate(&["admin".to_string(), "auditor".to_string()]));
    }

    #[test]
    fn test_dsd_policy() {
        let policy = DsdPolicy::new(
            "ops_audit_session",
            ["operator".to_string(), "auditor".to_string()].into(),
            2,
        );
        assert!(policy.validate(&["operator".to_string()]));
        assert!(!policy.validate(&["operator".to_string(), "auditor".to_string()]));
    }

    #[test]
    fn test_cardinality_constraint() {
        let c = CardinalityConstraint::new("admin", 2);
        assert!(c.validate(1));
        assert!(c.validate(0));
        assert!(!c.validate(2));
    }

    #[test]
    fn test_prerequisite_constraint() {
        let c = PrerequisiteConstraint::new("admin", "operator");
        assert!(!c.validate(&["viewer".to_string()]));
        assert!(c.validate(&["operator".to_string(), "viewer".to_string()]));
    }

    #[test]
    fn test_temporal_constraint() {
        let now = chrono::Utc::now();
        let valid = TemporalConstraint::new("temp_role", now - chrono::Duration::hours(1), now + chrono::Duration::hours(1));
        assert!(valid.is_valid());

        let expired = TemporalConstraint::new("temp_role", now - chrono::Duration::hours(2), now - chrono::Duration::hours(1));
        assert!(!expired.is_valid());
    }
}
