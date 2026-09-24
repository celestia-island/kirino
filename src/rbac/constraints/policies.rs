//! Constraint policy definitions for the fail-closed constraint gate.
//!
//! These types are inert data plus pure predicates: they describe a constraint and
//! evaluate a caller-supplied view of the world. They never read or write a store,
//! so a policy that was removed, never seeded or left stale is invisible to them;
//! the `store` and `validator` modules own loading and enforcement. A predicate
//! returning `false` means denial, never "unknown".

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

macro_rules! define_sod_policy {
    ($name:ident) => {
        /// Separation-of-duty policy over a fixed set of `roles`.
        ///
        /// `validate` allows a role set only while fewer than `cardinality` of the
        /// listed roles are present, so the policy caps how many of them may be held
        /// at once. The concrete expansions are `SsdPolicy` (checked when a role is
        /// assigned) and `DsdPolicy` (checked when a role is activated in a session).
        /// This models those SSD/DSD concepts; it is not a full ANSI RBAC
        /// implementation. The type holds no store handle, so it cannot detect that
        /// the policy it was loaded from has since changed or been removed.
        #[derive(Debug, Clone, Serialize, Deserialize)]
        pub struct $name {
            /// Operator-facing identifier; uniqueness key for the store's add
            /// methods and echoed in violation errors. Compared by exact equality.
            pub name: String,
            /// Roles counted by the policy. Matching is exact string equality; a role
            /// absent from this set never contributes to the count.
            pub roles: HashSet<String>,
            /// Largest number of listed roles that may be present simultaneously;
            /// reaching this many denies the operation. Clamped to at least 1 by
            /// `new`, so a policy built with 0 forbids the set entirely.
            pub cardinality: usize,
        }

        impl $name {
            /// Builds a policy, clamping `cardinality` to a floor of 1.
            ///
            /// A requested cardinality of 0 therefore becomes "none of the listed
            /// roles may be present" instead of "no restriction". The floor of 1 is a
            /// default with no documented basis in this code:
            /// basis to be confirmed with security review.
            #[must_use]
            pub fn new(
                name: impl Into<String>,
                roles: HashSet<String>,
                cardinality: usize,
            ) -> Self {
                Self {
                    name: name.into(),
                    roles,
                    cardinality: cardinality.max(1),
                }
            }

            /// Pure predicate: `true` while fewer than `cardinality` of the policy's
            /// roles appear in `roles`, i.e. the caller may proceed.
            ///
            /// Counting is per occurrence, not per distinct role, so duplicate entries
            /// in `roles` inflate the count and can only make the predicate stricter.
            /// The store is not consulted: this cannot distinguish "policy satisfied"
            /// from "policy never loaded", and `false` must be treated as a denial.
            #[must_use]
            pub fn validate(&self, roles: &[String]) -> bool {
                let count = roles.iter().filter(|r| self.roles.contains(*r)).count();
                count < self.cardinality
            }
        }
    };
}

define_sod_policy!(SsdPolicy);
define_sod_policy!(DsdPolicy);

/// Upper bound on how many subjects may hold one role at the same time.
///
/// The bound is checked against a subject count supplied by the caller, so its
/// accuracy is the caller's responsibility: an under-count weakens the constraint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CardinalityConstraint {
    /// Role the bound applies to; matching is by exact string equality.
    pub role_name: String,
    /// Largest permitted number of subjects holding the role; clamped to at least 1
    /// by `new`, so a bound of 1 admits the first subject and denies the rest.
    pub max_subjects: usize,
}

impl CardinalityConstraint {
    /// Builds the constraint, clamping `max_subjects` to a floor of 1.
    ///
    /// A requested bound of 0 therefore becomes 1 rather than "nobody may hold this
    /// role". The floor of 1 is a default with no documented basis in this code:
    /// basis to be confirmed with security review.
    #[must_use]
    pub fn new(role_name: impl Into<String>, max_subjects: usize) -> Self {
        Self {
            role_name: role_name.into(),
            max_subjects: max_subjects.max(1),
        }
    }

    /// Pure predicate: `true` while `current_count` is below `max_subjects`.
    ///
    /// The comparison is strict, so `max_subjects` is the largest permitted
    /// population rather than the first rejected one. The count is caller-supplied
    /// and is not verified against the store; a caller that under-counts weakens the
    /// constraint (fail-open), so pass an authoritative assignment count.
    #[must_use]
    pub fn validate(&self, current_count: usize) -> bool {
        current_count < self.max_subjects
    }
}

/// Requires another role to already be held before `role_name` may be granted.
///
/// This is a single-role implication evaluated against a caller-supplied role list;
/// role hierarchies are not resolved here, so a prerequisite satisfied only
/// transitively still looks unsatisfied and the check fails closed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrerequisiteConstraint {
    /// Role that carries the requirement; matching is by exact string equality.
    pub role_name: String,
    /// Role that must already be present; compared by exact string equality.
    pub requires: String,
}

impl PrerequisiteConstraint {
    /// Builds the constraint without validating the role names.
    ///
    /// An empty or self-referential `requires` is accepted here and then fails closed
    /// at check time, which leaves `role_name` unassignable until the constraint is
    /// removed; the names are not resolved against any role registry.
    #[must_use]
    pub fn new(role_name: impl Into<String>, requires: impl Into<String>) -> Self {
        Self {
            role_name: role_name.into(),
            requires: requires.into(),
        }
    }

    /// Pure predicate: `true` when `assigned_roles` contains `requires`.
    ///
    /// Returns `false` (deny) when the prerequisite is missing. It sees only the
    /// slice it is given: roles held outside that slice, or implied by a hierarchy,
    /// are invisible, so an incomplete call-site list denies rather than permits.
    #[must_use]
    pub fn validate(&self, assigned_roles: &[String]) -> bool {
        assigned_roles.contains(&self.requires)
    }
}

/// Time window during which a role may be held or activated.
///
/// The window is data, not a scheduled revocation: when it closes, stored role
/// assignments are not modified, they are only refused by later checks that consult
/// this constraint. Any path that skips the temporal check ignores the window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalConstraint {
    /// Role the window applies to; matching is by exact string equality.
    pub role_name: String,
    /// Inclusive start of the window, in UTC.
    pub valid_from: chrono::DateTime<chrono::Utc>,
    /// Inclusive end of the window, in UTC.
    pub valid_until: chrono::DateTime<chrono::Utc>,
}

impl TemporalConstraint {
    /// Builds the constraint, rejecting an inverted or empty window.
    ///
    /// Fails closed at construction time: unless `valid_from` is strictly before
    /// `valid_until`, the constructor returns `KirinoError::Validation` instead of
    /// storing a window whose meaning is undefined.
    pub fn new(
        role_name: impl Into<String>,
        valid_from: chrono::DateTime<chrono::Utc>,
        valid_until: chrono::DateTime<chrono::Utc>,
    ) -> Result<Self> {
        if valid_from >= valid_until {
            return Err(crate::error::KirinoError::Validation(format!(
                "TemporalConstraint: valid_from ({}) must be before valid_until ({})",
                valid_from, valid_until
            ))
            .into());
        }
        Ok(Self {
            role_name: role_name.into(),
            valid_from,
            valid_until,
        })
    }

    /// `true` while the wall clock lies inside the inclusive window.
    ///
    /// The time is read from `chrono::Utc::now()` on every call, so the verdict is
    /// not cached and follows the system clock rather than a monotonic source: a
    /// clock set backwards can revive an expired window. Both endpoints count as
    /// inside, and there is no grace period.
    #[must_use]
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
        let valid = TemporalConstraint::new(
            "temp_role",
            now - chrono::Duration::hours(1),
            now + chrono::Duration::hours(1),
        )
        .unwrap();
        assert!(valid.is_valid());

        let expired = TemporalConstraint::new(
            "temp_role",
            now - chrono::Duration::hours(2),
            now - chrono::Duration::hours(1),
        )
        .unwrap();
        assert!(!expired.is_valid());
    }

    #[test]
    fn test_temporal_constraint_inverted_dates_rejected() {
        let now = chrono::Utc::now();
        let result = TemporalConstraint::new(
            "temp_role",
            now + chrono::Duration::hours(1),
            now - chrono::Duration::hours(1),
        );
        assert!(result.is_err());
    }
}
