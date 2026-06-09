use async_trait::async_trait;

use crate::error::KirinoResult;

use super::policies::{
    CardinalityConstraint, DsdPolicy, PrerequisiteConstraint, SsdPolicy, TemporalConstraint,
};

#[async_trait]
pub trait ConstraintStore: Send + Sync {
    async fn list_ssd_policies(&self) -> KirinoResult<Vec<SsdPolicy>>;
    async fn add_ssd_policy(&self, policy: SsdPolicy) -> KirinoResult<()>;
    async fn remove_ssd_policy(&self, name: &str) -> KirinoResult<bool>;

    async fn list_dsd_policies(&self) -> KirinoResult<Vec<DsdPolicy>>;
    async fn add_dsd_policy(&self, policy: DsdPolicy) -> KirinoResult<()>;
    async fn remove_dsd_policy(&self, name: &str) -> KirinoResult<bool>;

    async fn list_cardinality_constraints(&self) -> KirinoResult<Vec<CardinalityConstraint>>;
    async fn add_cardinality_constraint(&self, constraint: CardinalityConstraint) -> KirinoResult<()>;
    async fn remove_cardinality_constraint(&self, role_name: &str) -> KirinoResult<bool>;

    async fn list_prerequisite_constraints(&self) -> KirinoResult<Vec<PrerequisiteConstraint>>;
    async fn add_prerequisite_constraint(&self, constraint: PrerequisiteConstraint) -> KirinoResult<()>;
    async fn remove_prerequisite_constraint(&self, role_name: &str) -> KirinoResult<bool>;

    async fn list_temporal_constraints(&self) -> KirinoResult<Vec<TemporalConstraint>>;
    async fn add_temporal_constraint(&self, constraint: TemporalConstraint) -> KirinoResult<()>;
    async fn remove_temporal_constraint(&self, role_name: &str) -> KirinoResult<bool>;
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
    async fn list_ssd_policies(&self) -> KirinoResult<Vec<SsdPolicy>> {
        Ok(self.ssd_policies.read().await.clone())
    }

    async fn add_ssd_policy(&self, policy: SsdPolicy) -> KirinoResult<()> {
        self.ssd_policies.write().await.push(policy);
        Ok(())
    }

    async fn remove_ssd_policy(&self, name: &str) -> KirinoResult<bool> {
        let mut policies = self.ssd_policies.write().await;
        let before = policies.len();
        policies.retain(|p| p.name != name);
        Ok(policies.len() < before)
    }

    async fn list_dsd_policies(&self) -> KirinoResult<Vec<DsdPolicy>> {
        Ok(self.dsd_policies.read().await.clone())
    }

    async fn add_dsd_policy(&self, policy: DsdPolicy) -> KirinoResult<()> {
        self.dsd_policies.write().await.push(policy);
        Ok(())
    }

    async fn remove_dsd_policy(&self, name: &str) -> KirinoResult<bool> {
        let mut policies = self.dsd_policies.write().await;
        let before = policies.len();
        policies.retain(|p| p.name != name);
        Ok(policies.len() < before)
    }

    async fn list_cardinality_constraints(&self) -> KirinoResult<Vec<CardinalityConstraint>> {
        Ok(self.cardinality.read().await.clone())
    }

    async fn add_cardinality_constraint(&self, constraint: CardinalityConstraint) -> KirinoResult<()> {
        self.cardinality.write().await.push(constraint);
        Ok(())
    }

    async fn remove_cardinality_constraint(&self, role_name: &str) -> KirinoResult<bool> {
        let mut constraints = self.cardinality.write().await;
        let before = constraints.len();
        constraints.retain(|c| c.role_name != role_name);
        Ok(constraints.len() < before)
    }

    async fn list_prerequisite_constraints(&self) -> KirinoResult<Vec<PrerequisiteConstraint>> {
        Ok(self.prerequisites.read().await.clone())
    }

    async fn add_prerequisite_constraint(&self, constraint: PrerequisiteConstraint) -> KirinoResult<()> {
        self.prerequisites.write().await.push(constraint);
        Ok(())
    }

    async fn remove_prerequisite_constraint(&self, role_name: &str) -> KirinoResult<bool> {
        let mut constraints = self.prerequisites.write().await;
        let before = constraints.len();
        constraints.retain(|c| c.role_name != role_name);
        Ok(constraints.len() < before)
    }

    async fn list_temporal_constraints(&self) -> KirinoResult<Vec<TemporalConstraint>> {
        Ok(self.temporal.read().await.clone())
    }

    async fn add_temporal_constraint(&self, constraint: TemporalConstraint) -> KirinoResult<()> {
        self.temporal.write().await.push(constraint);
        Ok(())
    }

    async fn remove_temporal_constraint(&self, role_name: &str) -> KirinoResult<bool> {
        let mut constraints = self.temporal.write().await;
        let before = constraints.len();
        constraints.retain(|c| c.role_name != role_name);
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
            ))
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
    async fn test_duplicate_ssd_policy_names() {
        let store = InMemoryConstraintStore::new();
        store
            .add_ssd_policy(SsdPolicy::new("dup", ["a".into()].into(), 1))
            .await
            .unwrap();
        store
            .add_ssd_policy(SsdPolicy::new("dup", ["b".into()].into(), 1))
            .await
            .unwrap();

        let policies = store.list_ssd_policies().await.unwrap();
        assert_eq!(policies.len(), 2);

        assert!(store.remove_ssd_policy("dup").await.unwrap());
        assert!(store.list_ssd_policies().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_duplicate_dsd_policy_names() {
        let store = InMemoryConstraintStore::new();
        store
            .add_dsd_policy(DsdPolicy::new("dup", ["a".into()].into(), 1))
            .await
            .unwrap();
        store
            .add_dsd_policy(DsdPolicy::new("dup", ["b".into()].into(), 1))
            .await
            .unwrap();

        assert_eq!(store.list_dsd_policies().await.unwrap().len(), 2);
        assert!(store.remove_dsd_policy("dup").await.unwrap());
        assert!(store.list_dsd_policies().await.unwrap().is_empty());
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
            ))
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
