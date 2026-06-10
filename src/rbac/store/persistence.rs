use async_trait::async_trait;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AssignmentRow {
    pub subject_id: String,
    pub role_name: String,
    pub extra_permissions: Vec<String>,
    pub denied_permissions: Vec<String>,
    pub assigned_at: Option<chrono::DateTime<chrono::Utc>>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RoleRow {
    pub role_name: String,
    pub parent_roles: Vec<String>,
    pub permissions: Vec<String>,
    pub created_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ConstraintRow {
    pub id: Option<i64>,
    pub constraint_type: String,
    pub config: serde_json::Value,
    pub created_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuditRow {
    pub id: Option<i64>,
    pub subject_id: String,
    pub subject_type: String,
    pub permission: String,
    pub endpoint: String,
    pub granted: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub verdict: Option<serde_json::Value>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SessionRow {
    pub id: uuid::Uuid,
    pub subject_id: String,
    pub active_roles: Vec<String>,
    pub context: Option<serde_json::Value>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[async_trait]
pub trait PersistentSessionStore: Send + Sync {
    async fn save_session(&self, row: &SessionRow) -> anyhow::Result<()>;
    async fn load_session(&self, id: uuid::Uuid) -> anyhow::Result<Option<SessionRow>>;
    async fn delete_session(&self, id: uuid::Uuid) -> anyhow::Result<()>;
    async fn update_roles(&self, id: uuid::Uuid, active_roles: &[String]) -> anyhow::Result<()>;
    async fn cleanup_expired(&self) -> anyhow::Result<usize>;
}

/// SPI for persisting role assignments to an external store (e.g. PostgreSQL, Redis).
///
/// The crate provides in-memory implementations only; implement this trait
/// to connect a production database backend.
#[async_trait]
pub trait PersistentAssignmentStore: Send + Sync {
    async fn load_assignments(&self) -> anyhow::Result<Vec<AssignmentRow>>;
    async fn save_assignment(&self, row: &AssignmentRow) -> anyhow::Result<()>;
    async fn delete_assignment(&self, subject_id: &str, role_name: &str) -> anyhow::Result<bool>;
    async fn save_extra_permissions(
        &self,
        subject_id: &str,
        permissions: &[String],
    ) -> anyhow::Result<()>;
    async fn save_denied_permissions(
        &self,
        subject_id: &str,
        permissions: &[String],
    ) -> anyhow::Result<()>;
}

/// SPI for persisting role definitions to an external store.
#[async_trait]
pub trait PersistentRoleStore: Send + Sync {
    async fn load_roles(&self) -> anyhow::Result<Vec<RoleRow>>;
    async fn save_role(&self, row: &RoleRow) -> anyhow::Result<()>;
    async fn delete_role(&self, role_name: &str) -> anyhow::Result<bool>;
}

/// SPI for persisting RBAC constraints (SSD/DSD/cardinality/prerequisite/temporal) to an external store.
#[async_trait]
pub trait PersistentConstraintStore: Send + Sync {
    async fn load_constraints(&self) -> anyhow::Result<Vec<ConstraintRow>>;
    async fn save_constraint(&self, row: &ConstraintRow) -> anyhow::Result<()>;
    async fn delete_constraint(&self, constraint_type: &str, id: i64) -> anyhow::Result<bool>;
}

/// SPI for persisting audit log entries to an external store.
#[async_trait]
pub trait PersistentAuditStore: Send + Sync {
    async fn append_entry(&self, row: &AuditRow) -> anyhow::Result<()>;
    async fn query_entries(
        &self,
        subject_id: Option<&str>,
        granted: Option<bool>,
        limit: Option<usize>,
        offset: Option<usize>,
    ) -> anyhow::Result<Vec<AuditRow>>;
    async fn count_entries(
        &self,
        subject_id: Option<&str>,
        granted: Option<bool>,
    ) -> anyhow::Result<u64>;
}

/// SPI for persisting dynamic-authorization trust scores to an external store.
#[cfg(feature = "rbac-dynamic")]
#[async_trait]
pub trait PersistentTrustStore: Send + Sync {
    async fn load_trust_score(
        &self,
        delegator_id: &str,
    ) -> anyhow::Result<Option<crate::rbac::dynamic::trust::TrustScore>>;
    async fn save_trust_score(
        &self,
        delegator_id: &str,
        score: &crate::rbac::dynamic::trust::TrustScore,
    ) -> anyhow::Result<()>;
    async fn list_delegator_ids(&self) -> anyhow::Result<Vec<String>>;
}

pub trait PersistentStore:
    PersistentAssignmentStore + PersistentRoleStore + PersistentConstraintStore + Send + Sync
{
}

impl<T> PersistentStore for T where
    T: PersistentAssignmentStore + PersistentRoleStore + PersistentConstraintStore + Send + Sync
{
}
