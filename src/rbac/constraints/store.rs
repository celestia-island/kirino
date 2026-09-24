//! Persistence boundary for constraint policies, plus an in-memory implementation.
//!
//! The store is the fail-closed gate's only data source. `ConstraintValidator`
//! propagates any `Err` from these methods and the caller must deny on it, so an
//! implementation that turns a backend failure into an empty list silently opens
//! the gate. Implementations must therefore report read failures as errors.

use anyhow::Result;

use async_trait::async_trait;

use super::policies::{
    CardinalityConstraint, DsdPolicy, PrerequisiteConstraint, SsdPolicy, TemporalConstraint,
};

/// Async storage of the constraint definitions applied by `ConstraintValidator`.
///
/// Contract for implementors, in security terms:
/// - every method returns `Result`, and a read failure must surface as `Err` rather
///   than as an empty list, because an empty list means "no restriction";
/// - `add_*` methods are not idempotent: re-adding an existing entry fails and leaves
///   the stored entry unchanged, so an update is a remove followed by an add and is
///   not atomic (a failure between the two leaves the constraint absent);
/// - `remove_*` methods return `Ok(false)` when nothing matched; removing a missing
///   entry is not an error and does not create one;
/// - `list_*` methods return a snapshot the caller owns; no ordering is promised.
#[async_trait]
pub trait ConstraintStore: Send + Sync {
    /// Returns a snapshot of all stored SSD policies.
    /// An `Err` here aborts the check; callers must deny rather than continue with
    /// an empty list.
    async fn list_ssd_policies(&self) -> Result<Vec<SsdPolicy>>;
    /// Stores an SSD policy. Fails if one with the same `name` already exists; there
    /// is no upsert, so a failed re-add leaves the previously stored policy in force.
    async fn add_ssd_policy(&self, policy: SsdPolicy) -> Result<()>;
    /// Removes every SSD policy named `name`; `Ok(false)` means none matched, which
    /// is not an error. Deleting an absent policy is not itself a security event.
    async fn remove_ssd_policy(&self, name: &str) -> Result<bool>;

    /// Returns a snapshot of all stored DSD policies. DSD is enforced when a role is
    /// activated in a session, not when it is assigned.
    async fn list_dsd_policies(&self) -> Result<Vec<DsdPolicy>>;
    /// Stores a DSD policy. Fails on a duplicate `name` without overwriting; an
    /// administrator tightening an existing policy must remove it first.
    async fn add_dsd_policy(&self, policy: DsdPolicy) -> Result<()>;
    /// Removes every DSD policy named `name`; `Ok(false)` when none matched.
    async fn remove_dsd_policy(&self, name: &str) -> Result<bool>;

    /// Returns a snapshot of all stored cardinality constraints.
    /// Stored bounds are inert until a check runs against a caller-supplied count.
    async fn list_cardinality_constraints(&self) -> Result<Vec<CardinalityConstraint>>;
    /// Stores a cardinality constraint. Fails when a constraint for the same
    /// `role_name` already exists, leaving the old bound in force (no upsert).
    async fn add_cardinality_constraint(&self, constraint: CardinalityConstraint) -> Result<()>;
    /// Removes the cardinality constraint for `role_name`; `Ok(false)` when the role
    /// has none. After removal the role is unbounded, so removal is fail-open.
    async fn remove_cardinality_constraint(&self, role_name: &str) -> Result<bool>;

    /// Returns a snapshot of all stored prerequisite constraints.
    async fn list_prerequisite_constraints(&self) -> Result<Vec<PrerequisiteConstraint>>;
    /// Stores a prerequisite constraint. The uniqueness key is the
    /// `(role_name, requires)` pair, so one role may carry several prerequisites and
    /// only an identical pair is rejected.
    async fn add_prerequisite_constraint(&self, constraint: PrerequisiteConstraint) -> Result<()>;
    /// Removes **all** prerequisite constraints for the given role.
    /// Returns `Ok(false)` when the role has none; removal is fail-open for the role.
    async fn remove_prerequisite_constraint(&self, role_name: &str) -> Result<bool>;
    /// Removes a specific prerequisite constraint matching `(role_name, requires)`.
    /// Returns `Ok(false)` when no pair matches, so a miss cannot be told apart from
    /// a successful removal except by the returned flag.
    async fn remove_prerequisite_constraint_for(
        &self,
        role_name: &str,
        requires: &str,
    ) -> Result<bool>;

    /// Returns a snapshot of all stored temporal constraints.
    /// Windows are not filtered by the current time here; expiry is decided later by
    /// `TemporalConstraint::is_valid`, which reads the wall clock.
    async fn list_temporal_constraints(&self) -> Result<Vec<TemporalConstraint>>;
    /// Stores a temporal constraint. The uniqueness key is the role and both window
    /// endpoints, so a role may hold several windows; because the validator denies
    /// when any matching window is not current, adding an expired window for a role
    /// denies that role outright.
    async fn add_temporal_constraint(&self, constraint: TemporalConstraint) -> Result<()>;
    /// Removes **all** temporal constraints for the given role.
    /// `Ok(false)` means the role had none; after removal the role has no time bound.
    async fn remove_temporal_constraint(&self, role_name: &str) -> Result<bool>;
    /// Removes a specific temporal constraint by index position.
    /// Matching is on the role plus exactly equal `valid_from` and `valid_until`
    /// values; `Ok(false)` when no such window is stored.
    async fn remove_temporal_constraint_for(
        &self,
        role_name: &str,
        valid_from: &chrono::DateTime<chrono::Utc>,
        valid_until: &chrono::DateTime<chrono::Utc>,
    ) -> Result<bool>;
}

/// Process-local, non-durable `ConstraintStore` backed by vectors behind locks.
///
/// Security caveats: the state is in memory only, so it is lost on restart and is
/// not shared between processes; a restarted or freshly built store holds no
/// constraints and therefore permits everything until it is re-seeded (fail-open).
/// Entries are appended without any size cap, so seeding must stay bounded by the
/// caller. Each method takes one lock for the duration of a single read or mutation
/// and no lock is held across methods, so a validator check and the write it guards
/// are not atomic with respect to concurrent writers.
pub struct InMemoryConstraintStore {
    ssd_policies: tokio::sync::RwLock<Vec<SsdPolicy>>,
    dsd_policies: tokio::sync::RwLock<Vec<DsdPolicy>>,
    cardinality: tokio::sync::RwLock<Vec<CardinalityConstraint>>,
    prerequisites: tokio::sync::RwLock<Vec<PrerequisiteConstraint>>,
    temporal: tokio::sync::RwLock<Vec<TemporalConstraint>>,
}

impl InMemoryConstraintStore {
    /// Creates an empty store.
    ///
    /// An empty store enforces nothing, so every check passes; loading the intended
    /// constraints before serving requests is a security-critical precondition.
    #[must_use]
    pub fn new() -> Self {
        Self {
            ssd_policies: tokio::sync::RwLock::new(Vec::new()),
            dsd_policies: tokio::sync::RwLock::new(Vec::new()),
            cardinality: tokio::sync::RwLock::new(Vec::new()),
            prerequisites: tokio::sync::RwLock::new(Vec::new()),
            temporal: tokio::sync::RwLock::new(Vec::new()),
        }
    }
}

impl Default for InMemoryConstraintStore {
    /// Same as `new`: builds an unseeded store, which permits everything until
    /// constraints are added. Provided so `Default` callers cannot get a store that
    /// looks configured but is not.
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ConstraintStore for InMemoryConstraintStore {
    /// Clones the current contents under a read lock; the caller owns the copy, so
    /// later mutations of this store do not affect the returned vector.
    async fn list_ssd_policies(&self) -> Result<Vec<SsdPolicy>> {
        Ok(self.ssd_policies.read().await.clone())
    }

    /// Appends the policy, or returns `Err` if a policy with the same name is already
    /// stored. It never overwrites: a duplicate add fails and the stored policy is
    /// unchanged, so re-adding is not idempotent and the old policy stays in force.
    async fn add_ssd_policy(&self, policy: SsdPolicy) -> Result<()> {
        let mut policies = self.ssd_policies.write().await;
        if policies.iter().any(|p| p.name == policy.name) {
            return Err(anyhow::anyhow!(
                "SSD policy with name '{}' already exists",
                policy.name
            ));
        }
        policies.push(policy);
        Ok(())
    }

    /// Removes all policies with the given name and reports whether the store
    /// changed; `Ok(false)` means the name was absent and nothing was removed.
    async fn remove_ssd_policy(&self, name: &str) -> Result<bool> {
        let mut policies = self.ssd_policies.write().await;
        let before = policies.len();
        policies.retain(|p| p.name != name);
        Ok(policies.len() < before)
    }

    /// Clones the current contents under a read lock; the caller owns the copy.
    async fn list_dsd_policies(&self) -> Result<Vec<DsdPolicy>> {
        Ok(self.dsd_policies.read().await.clone())
    }

    /// Appends the policy, or returns `Err` on a duplicate name without overwriting.
    /// Loosening or tightening a stored policy requires removing it first, which is
    /// not atomic with the add.
    async fn add_dsd_policy(&self, policy: DsdPolicy) -> Result<()> {
        let mut policies = self.dsd_policies.write().await;
        if policies.iter().any(|p| p.name == policy.name) {
            return Err(anyhow::anyhow!(
                "DSD policy with name '{}' already exists",
                policy.name
            ));
        }
        policies.push(policy);
        Ok(())
    }

    /// Removes all policies with the given name; `Ok(false)` when none matched,
    /// which leaves the store untouched and is not an error.
    async fn remove_dsd_policy(&self, name: &str) -> Result<bool> {
        let mut policies = self.dsd_policies.write().await;
        let before = policies.len();
        policies.retain(|p| p.name != name);
        Ok(policies.len() < before)
    }

    /// Clones the current contents under a read lock; the caller owns the copy.
    async fn list_cardinality_constraints(&self) -> Result<Vec<CardinalityConstraint>> {
        Ok(self.cardinality.read().await.clone())
    }

    /// Appends the constraint, or returns `Err` when the role already has one; the
    /// existing bound is kept, so a limit can only be changed by removing it first.
    async fn add_cardinality_constraint(&self, constraint: CardinalityConstraint) -> Result<()> {
        let mut constraints = self.cardinality.write().await;
        if constraints
            .iter()
            .any(|c| c.role_name == constraint.role_name)
        {
            return Err(anyhow::anyhow!(
                "cardinality constraint for role '{}' already exists",
                constraint.role_name
            ));
        }
        constraints.push(constraint);
        Ok(())
    }

    /// Removes the bound for the role; `Ok(false)` when the role had none. Until a
    /// bound is re-added the role is effectively uncapped.
    async fn remove_cardinality_constraint(&self, role_name: &str) -> Result<bool> {
        let mut constraints = self.cardinality.write().await;
        let before = constraints.len();
        constraints.retain(|c| c.role_name != role_name);
        Ok(constraints.len() < before)
    }

    /// Clones the current contents under a read lock; the caller owns the copy.
    async fn list_prerequisite_constraints(&self) -> Result<Vec<PrerequisiteConstraint>> {
        Ok(self.prerequisites.read().await.clone())
    }

    /// Appends the constraint, or returns `Err` when the identical
    /// `(role_name, requires)` pair is already stored. Distinct prerequisites for the
    /// same role coexist, and all of them must hold for the assignment to pass.
    async fn add_prerequisite_constraint(&self, constraint: PrerequisiteConstraint) -> Result<()> {
        let mut constraints = self.prerequisites.write().await;
        if constraints
            .iter()
            .any(|c| c.role_name == constraint.role_name && c.requires == constraint.requires)
        {
            return Err(anyhow::anyhow!(
                "prerequisite constraint for role '{}' requiring '{}' already exists",
                constraint.role_name,
                constraint.requires
            ));
        }
        constraints.push(constraint);
        Ok(())
    }

    /// Removes every prerequisite of the role, not one of them; `Ok(false)` when the
    /// role had none. Dropping prerequisites makes the role easier to assign.
    async fn remove_prerequisite_constraint(&self, role_name: &str) -> Result<bool> {
        let mut constraints = self.prerequisites.write().await;
        let before = constraints.len();
        constraints.retain(|c| c.role_name != role_name);
        Ok(constraints.len() < before)
    }

    /// Removes only the `(role_name, requires)` pair; other prerequisites of the role
    /// are untouched. `Ok(false)` when no pair matched, so a miss is silent apart
    /// from the returned flag.
    async fn remove_prerequisite_constraint_for(
        &self,
        role_name: &str,
        requires: &str,
    ) -> Result<bool> {
        let mut constraints = self.prerequisites.write().await;
        let before = constraints.len();
        constraints.retain(|c| !(c.role_name == role_name && c.requires == requires));
        Ok(constraints.len() < before)
    }

    /// Clones the current contents under a read lock; the caller owns the copy.
    /// Expired windows are still returned, because expiry is evaluated at check time.
    async fn list_temporal_constraints(&self) -> Result<Vec<TemporalConstraint>> {
        Ok(self.temporal.read().await.clone())
    }

    /// Appends the constraint, or returns `Err` when the role already has a window
    /// with exactly the same endpoints. Several distinct windows may be stored for
    /// one role, and the validator denies the role while any of them is not current.
    async fn add_temporal_constraint(&self, constraint: TemporalConstraint) -> Result<()> {
        let mut constraints = self.temporal.write().await;
        if constraints.iter().any(|c| {
            c.role_name == constraint.role_name
                && c.valid_from == constraint.valid_from
                && c.valid_until == constraint.valid_until
        }) {
            return Err(anyhow::anyhow!(
                "identical temporal constraint for role '{}' already exists",
                constraint.role_name
            ));
        }
        constraints.push(constraint);
        Ok(())
    }

    /// Removes every temporal window of the role; `Ok(false)` when the role had none.
    /// With no window left the role is no longer time-bounded at all.
    async fn remove_temporal_constraint(&self, role_name: &str) -> Result<bool> {
        let mut constraints = self.temporal.write().await;
        let before = constraints.len();
        constraints.retain(|c| c.role_name != role_name);
        Ok(constraints.len() < before)
    }

    /// Removes only the window whose role and both endpoints are exactly equal;
    /// other windows of the role are untouched. `Ok(false)` when none matched.
    async fn remove_temporal_constraint_for(
        &self,
        role_name: &str,
        valid_from: &chrono::DateTime<chrono::Utc>,
        valid_until: &chrono::DateTime<chrono::Utc>,
    ) -> Result<bool> {
        let mut constraints = self.temporal.write().await;
        let before = constraints.len();
        constraints.retain(|c| {
            !(c.role_name == role_name
                && c.valid_from == *valid_from
                && c.valid_until == *valid_until)
        });
        Ok(constraints.len() < before)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ssd_crud() {
        let store = InMemoryConstraintStore::new();

        store
            .add_ssd_policy(SsdPolicy::new(
                "test",
                ["a".to_string(), "b".to_string()].into(),
                2,
            ))
            .await
            .unwrap();

        let policies = store.list_ssd_policies().await.unwrap();
        assert_eq!(policies.len(), 1);

        assert!(store.remove_ssd_policy("test").await.unwrap());
        assert!(store.list_ssd_policies().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_dsd_crud() {
        let store = InMemoryConstraintStore::new();

        store
            .add_dsd_policy(DsdPolicy::new(
                "dsd1",
                ["x".to_string(), "y".to_string()].into(),
                2,
            ))
            .await
            .unwrap();

        let policies = store.list_dsd_policies().await.unwrap();
        assert_eq!(policies.len(), 1);

        assert!(store.remove_dsd_policy("dsd1").await.unwrap());
    }

    #[tokio::test]
    async fn test_cardinality_crud() {
        let store = InMemoryConstraintStore::new();
        store
            .add_cardinality_constraint(CardinalityConstraint::new("admin", 3))
            .await
            .unwrap();

        let constraints = store.list_cardinality_constraints().await.unwrap();
        assert_eq!(constraints.len(), 1);
        assert_eq!(constraints[0].max_subjects, 3);

        assert!(store.remove_cardinality_constraint("admin").await.unwrap());
    }

    #[tokio::test]
    async fn test_prerequisite_crud() {
        let store = InMemoryConstraintStore::new();
        store
            .add_prerequisite_constraint(PrerequisiteConstraint::new("admin", "operator"))
            .await
            .unwrap();

        let constraints = store.list_prerequisite_constraints().await.unwrap();
        assert_eq!(constraints.len(), 1);
    }

    #[tokio::test]
    async fn test_temporal_crud() {
        let store = InMemoryConstraintStore::new();
        let now = chrono::Utc::now();
        store
            .add_temporal_constraint(
                TemporalConstraint::new("temp_role", now, now + chrono::Duration::hours(1))
                    .unwrap(),
            )
            .await
            .unwrap();

        let constraints = store.list_temporal_constraints().await.unwrap();
        assert_eq!(constraints.len(), 1);

        assert!(store.remove_temporal_constraint("temp_role").await.unwrap());
    }

    #[tokio::test]
    async fn test_prerequisite_remove() {
        let store = InMemoryConstraintStore::new();
        store
            .add_prerequisite_constraint(PrerequisiteConstraint::new("admin", "operator"))
            .await
            .unwrap();
        store
            .add_prerequisite_constraint(PrerequisiteConstraint::new("superadmin", "admin"))
            .await
            .unwrap();

        assert_eq!(
            store.list_prerequisite_constraints().await.unwrap().len(),
            2
        );

        assert!(store.remove_prerequisite_constraint("admin").await.unwrap());
        assert_eq!(
            store.list_prerequisite_constraints().await.unwrap().len(),
            1
        );
    }

    #[tokio::test]
    async fn test_remove_nonexistent_returns_false() {
        let store = InMemoryConstraintStore::new();
        assert!(!store.remove_ssd_policy("ghost").await.unwrap());
        assert!(!store.remove_dsd_policy("ghost").await.unwrap());
        assert!(!store.remove_cardinality_constraint("ghost").await.unwrap());
        assert!(!store.remove_prerequisite_constraint("ghost").await.unwrap());
        assert!(!store.remove_temporal_constraint("ghost").await.unwrap());
    }

    #[tokio::test]
    async fn test_duplicate_ssd_policy_names_rejected() {
        let store = InMemoryConstraintStore::new();
        store
            .add_ssd_policy(SsdPolicy::new("dup", ["a".into()].into(), 1))
            .await
            .unwrap();
        assert!(store
            .add_ssd_policy(SsdPolicy::new("dup", ["b".into()].into(), 1))
            .await
            .is_err());

        let policies = store.list_ssd_policies().await.unwrap();
        assert_eq!(policies.len(), 1);

        assert!(store.remove_ssd_policy("dup").await.unwrap());
        assert!(store.list_ssd_policies().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_duplicate_dsd_policy_names_rejected() {
        let store = InMemoryConstraintStore::new();
        store
            .add_dsd_policy(DsdPolicy::new("dup", ["a".into()].into(), 1))
            .await
            .unwrap();
        assert!(store
            .add_dsd_policy(DsdPolicy::new("dup", ["b".into()].into(), 1))
            .await
            .is_err());

        assert_eq!(store.list_dsd_policies().await.unwrap().len(), 1);
        assert!(store.remove_dsd_policy("dup").await.unwrap());
        assert!(store.list_dsd_policies().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_prerequisite_remove_specific() {
        let store = InMemoryConstraintStore::new();
        store
            .add_prerequisite_constraint(PrerequisiteConstraint::new("admin", "operator"))
            .await
            .unwrap();
        store
            .add_prerequisite_constraint(PrerequisiteConstraint::new("admin", "viewer"))
            .await
            .unwrap();

        assert_eq!(
            store.list_prerequisite_constraints().await.unwrap().len(),
            2
        );

        assert!(store
            .remove_prerequisite_constraint_for("admin", "operator")
            .await
            .unwrap());
        let remaining = store.list_prerequisite_constraints().await.unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].requires, "viewer");
    }

    #[tokio::test]
    async fn test_prerequisite_remove_specific_nonexistent() {
        let store = InMemoryConstraintStore::new();
        assert!(!store
            .remove_prerequisite_constraint_for("admin", "operator")
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn test_temporal_remove_specific() {
        let store = InMemoryConstraintStore::new();
        let now = chrono::Utc::now();
        let t1_from = now;
        let t1_until = now + chrono::Duration::hours(1);
        let t2_from = now + chrono::Duration::hours(2);
        let t2_until = now + chrono::Duration::hours(3);

        store
            .add_temporal_constraint(TemporalConstraint::new("role", t1_from, t1_until).unwrap())
            .await
            .unwrap();
        store
            .add_temporal_constraint(TemporalConstraint::new("role", t2_from, t2_until).unwrap())
            .await
            .unwrap();

        assert_eq!(store.list_temporal_constraints().await.unwrap().len(), 2);

        assert!(store
            .remove_temporal_constraint_for("role", &t1_from, &t1_until)
            .await
            .unwrap());
        let remaining = store.list_temporal_constraints().await.unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].valid_from, t2_from);
    }

    #[tokio::test]
    async fn test_temporal_remove_specific_nonexistent() {
        let store = InMemoryConstraintStore::new();
        let now = chrono::Utc::now();
        assert!(!store
            .remove_temporal_constraint_for("ghost", &now, &(now + chrono::Duration::hours(1)))
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn test_multiple_constraint_types_coexist() {
        let store = InMemoryConstraintStore::new();

        store
            .add_ssd_policy(SsdPolicy::new("ssd1", ["a".into()].into(), 1))
            .await
            .unwrap();
        store
            .add_dsd_policy(DsdPolicy::new("dsd1", ["a".into()].into(), 1))
            .await
            .unwrap();
        store
            .add_cardinality_constraint(CardinalityConstraint::new("role1", 5))
            .await
            .unwrap();
        store
            .add_prerequisite_constraint(PrerequisiteConstraint::new("role1", "role0"))
            .await
            .unwrap();
        let now = chrono::Utc::now();
        store
            .add_temporal_constraint(
                TemporalConstraint::new("temp", now, now + chrono::Duration::hours(1)).unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(store.list_ssd_policies().await.unwrap().len(), 1);
        assert_eq!(store.list_dsd_policies().await.unwrap().len(), 1);
        assert_eq!(store.list_cardinality_constraints().await.unwrap().len(), 1);
        assert_eq!(
            store.list_prerequisite_constraints().await.unwrap().len(),
            1
        );
        assert_eq!(store.list_temporal_constraints().await.unwrap().len(), 1);
    }
}
