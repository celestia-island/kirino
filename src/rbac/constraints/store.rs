use anyhow::Result;

use async_trait::async_trait;

use super::policies::{
    CardinalityConstraint, DsdPolicy, PrerequisiteConstraint, SsdPolicy, TemporalConstraint,
};

#[async_trait]
pub trait ConstraintStore: Send + Sync {
    #[must_use]
    async fn list_ssd_policies(&self) -> Result<Vec<SsdPolicy>>;
    async fn add_ssd_policy(&self, policy: SsdPolicy) -> Result<()>;
    async fn remove_ssd_policy(&self, name: &str) -> Result<bool>;

    #[must_use]
    async fn list_dsd_policies(&self) -> Result<Vec<DsdPolicy>>;
    async fn add_dsd_policy(&self, policy: DsdPolicy) -> Result<()>;
    async fn remove_dsd_policy(&self, name: &str) -> Result<bool>;

    #[must_use]
    async fn list_cardinality_constraints(&self) -> Result<Vec<CardinalityConstraint>>;
    async fn add_cardinality_constraint(&self, constraint: CardinalityConstraint) -> Result<()>;
    async fn remove_cardinality_constraint(&self, role_name: &str) -> Result<bool>;

    #[must_use]
    async fn list_prerequisite_constraints(&self) -> Result<Vec<PrerequisiteConstraint>>;
    async fn add_prerequisite_constraint(&self, constraint: PrerequisiteConstraint) -> Result<()>;
    /// Removes **all** prerequisite constraints for the given role.
    #[must_use]
    async fn remove_prerequisite_constraint(&self, role_name: &str) -> Result<bool>;
    /// Removes a specific prerequisite constraint matching `(role_name, requires)`.
    #[must_use]
    async fn remove_prerequisite_constraint_for(
        &self,
        role_name: &str,
        requires: &str,
    ) -> Result<bool>;

    #[must_use]
    async fn list_temporal_constraints(&self) -> Result<Vec<TemporalConstraint>>;
    async fn add_temporal_constraint(&self, constraint: TemporalConstraint) -> Result<()>;
    /// Removes **all** temporal constraints for the given role.
    #[must_use]
    async fn remove_temporal_constraint(&self, role_name: &str) -> Result<bool>;
    /// Removes a specific temporal constraint by index position.
    #[must_use]
    async fn remove_temporal_constraint_for(
        &self,
        role_name: &str,
        valid_from: &chrono::DateTime<chrono::Utc>,
        valid_until: &chrono::DateTime<chrono::Utc>,
    ) -> Result<bool>;
}

pub struct InMemoryConstraintStore {
    ssd_policies: tokio::sync::RwLock<Vec<SsdPolicy>>,
    dsd_policies: tokio::sync::RwLock<Vec<DsdPolicy>>,
    cardinality: tokio::sync::RwLock<Vec<CardinalityConstraint>>,
    prerequisites: tokio::sync::RwLock<Vec<PrerequisiteConstraint>>,
    temporal: tokio::sync::RwLock<Vec<TemporalConstraint>>,
}

impl InMemoryConstraintStore {
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
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ConstraintStore for InMemoryConstraintStore {
    async fn list_ssd_policies(&self) -> Result<Vec<SsdPolicy>> {
        Ok(self.ssd_policies.read().await.clone())
    }

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

    async fn remove_ssd_policy(&self, name: &str) -> Result<bool> {
        let mut policies = self.ssd_policies.write().await;
        let before = policies.len();
        policies.retain(|p| p.name != name);
        Ok(policies.len() < before)
    }

    async fn list_dsd_policies(&self) -> Result<Vec<DsdPolicy>> {
        Ok(self.dsd_policies.read().await.clone())
    }

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

    async fn remove_dsd_policy(&self, name: &str) -> Result<bool> {
        let mut policies = self.dsd_policies.write().await;
        let before = policies.len();
        policies.retain(|p| p.name != name);
        Ok(policies.len() < before)
    }

    async fn list_cardinality_constraints(&self) -> Result<Vec<CardinalityConstraint>> {
        Ok(self.cardinality.read().await.clone())
    }

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

    async fn remove_cardinality_constraint(&self, role_name: &str) -> Result<bool> {
        let mut constraints = self.cardinality.write().await;
        let before = constraints.len();
        constraints.retain(|c| c.role_name != role_name);
        Ok(constraints.len() < before)
    }

    async fn list_prerequisite_constraints(&self) -> Result<Vec<PrerequisiteConstraint>> {
        Ok(self.prerequisites.read().await.clone())
    }

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

    async fn remove_prerequisite_constraint(&self, role_name: &str) -> Result<bool> {
        let mut constraints = self.prerequisites.write().await;
        let before = constraints.len();
        constraints.retain(|c| c.role_name != role_name);
        Ok(constraints.len() < before)
    }

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

    async fn list_temporal_constraints(&self) -> Result<Vec<TemporalConstraint>> {
        Ok(self.temporal.read().await.clone())
    }

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

    async fn remove_temporal_constraint(&self, role_name: &str) -> Result<bool> {
        let mut constraints = self.temporal.write().await;
        let before = constraints.len();
        constraints.retain(|c| c.role_name != role_name);
        Ok(constraints.len() < before)
    }

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
            .add_temporal_constraint(TemporalConstraint::new(
                "temp_role",
                now,
                now + chrono::Duration::hours(1),
            ).unwrap())
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
            .add_temporal_constraint(TemporalConstraint::new(
                "temp",
                now,
                now + chrono::Duration::hours(1),
            ).unwrap())
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
