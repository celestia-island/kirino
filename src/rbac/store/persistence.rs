use async_trait::async_trait;

/// One persisted role assignment row, flattened with its direct grants.
///
/// Security semantics: this is the durable form of a subject's authority, so a
/// row written with a stale or attacker-influenced `extra_permissions` list
/// survives restarts. `expires_at` is carried here but is not honoured by the
/// in-crate assignment stores - an expired row must be filtered by whoever
/// reads it, or the assignment outlives its intended window.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AssignmentRow {
    /// Subject the assignment belongs to; the key used by every lookup.
    pub subject_id: String,
    /// Role granted to the subject; an unknown name resolves to no authority.
    pub role_name: String,
    /// Extra permissions granted directly to the subject, as permission names.
    pub extra_permissions: Vec<String>,
    /// Permissions explicitly denied to the subject; denies outrank grants.
    pub denied_permissions: Vec<String>,
    /// When the assignment was created, for audit only if present.
    pub assigned_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Intended expiry; `None` means no expiry is recorded.
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// One persisted role definition.
///
/// Security semantics: this row is the authority template for every holder of
/// the role, so a modified `permissions` list silently changes what all of
/// them may do. `parent_roles` introduces inheritance, which widens authority -
/// cycles in that list must be handled by the traversal
/// (`rbac::hierarchy::detect_cycle`), not by the store.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RoleRow {
    /// Unique role name; assignment rows reference it by this string.
    pub role_name: String,
    /// Parent role names whose permissions are inherited, if the caller
    /// evaluates the hierarchy.
    pub parent_roles: Vec<String>,
    /// Permission names this role grants; the full authority of the role.
    pub permissions: Vec<String>,
    /// Creation timestamp, metadata only.
    pub created_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// One persisted RBAC constraint (SSD/DSD/cardinality/prerequisite/temporal).
///
/// Security semantics: constraints are restrictions, so this row is one of the
/// few places where persisted data only ever removes authority. `config` is
/// schemaless JSON interpreted by constraint type, so a malformed config must
/// be treated as a violation or an error, never as "no constraint".
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ConstraintRow {
    /// Database identity of the row; `None` before the first insert.
    pub id: Option<i64>,
    /// Which constraint family `config` is interpreted as. An unrecognized
    /// type must not be silently dropped.
    pub constraint_type: String,
    /// Constraint parameters; shape depends on `constraint_type`.
    pub config: serde_json::Value,
    /// Creation timestamp, metadata only.
    pub created_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// One persisted audit-log entry.
///
/// Security semantics: audit rows are the record of who was allowed to do
/// what, so they must be append-only at the storage layer and must never be
/// rewritten to reflect a later decision. They are evidence, not an
/// authorization input: reading them back must not affect a decision.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuditRow {
    /// Database identity of the row; `None` before the first insert.
    pub id: Option<i64>,
    /// Subject the decision was about.
    pub subject_id: String,
    /// Subject kind at decision time (for example `user`), kept as text so the
    /// record survives changes to the subject types.
    pub subject_type: String,
    /// Permission that was checked, as its stable name.
    pub permission: String,
    /// Request endpoint or operation the decision was made for; free text used
    /// to attribute the decision, not an authorization input.
    pub endpoint: String,
    /// Whether the check was granted; `false` records a denial.
    pub granted: bool,
    /// When the decision happened; the ordering key for an audit trail.
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Optional structured detail about the decision.
    pub verdict: Option<serde_json::Value>,
}

/// One persisted session record.
///
/// Security semantics: a session row is a live credential's server-side state,
/// so deleting it (or expiring it) is what ends the session. `version` is the
/// counter compared against the subject's current version to detect a stale
/// session; a row whose `version` is behind the subject's current version must
/// be treated as invalid, not merely old. `active_roles` is already filtered
/// against the subject's assignments when the session is created.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SessionRow {
    /// Session identifier presented by the client.
    pub id: uuid::Uuid,
    /// Subject the session authenticates, stored as a string id.
    pub subject_id: String,
    /// Roles activated for this session; a subset of the subject's assignments.
    pub active_roles: Vec<String>,
    /// Opaque session context (never credential material).
    pub context: Option<serde_json::Value>,
    /// Session version at creation; staleness is `version <
    /// current_user_version`.
    pub version: u64,
    /// Hard expiry; a session at or past this instant must not be honoured.
    pub expires_at: chrono::DateTime<chrono::Utc>,
    /// Creation timestamp, for audit and for ordering.
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Persistence SPI for sessions, used by
/// [`DbSessionManager`](crate::rbac::session::db::DbSessionManager).
///
/// Security semantics: this store is authoritative for whether a session is
/// alive, so every method's error must surface as an error (fail-closed) - a
/// lookup failure must never be reported as "session absent" by pretending
/// success, and `load_session` returning `Ok(None)` must mean "no such
/// session" and nothing else. Implementations must make `delete_session` and
/// `bump_version` durable before returning, because they are the revocation
/// primitives: returning before the write is visible lets a revoked session
/// keep passing checks on another replica.
#[async_trait]
pub trait PersistentSessionStore: Send + Sync {
    /// Inserts or replaces the session row. Must be durable before returning,
    /// as the caller treats a successful return as "the session exists".
    async fn save_session(&self, row: &SessionRow) -> anyhow::Result<()>;
    /// Loads a session row by id. `Ok(None)` means the session does not exist
    /// (or was deleted) and callers must treat it as unauthenticated; an `Err`
    /// must not be converted into `Ok(None)` by callers or implementors.
    async fn load_session(&self, id: uuid::Uuid) -> anyhow::Result<Option<SessionRow>>;
    /// Removes a session row. Must be idempotent (deleting a missing session is
    /// not an error) and durable before returning, since it is the logout and
    /// revocation path.
    async fn delete_session(&self, id: uuid::Uuid) -> anyhow::Result<()>;
    /// Replaces the session's active-role list. Whole-list replacement; the
    /// caller has already filtered the roles against the subject's
    /// assignments.
    async fn update_roles(&self, id: uuid::Uuid, active_roles: &[String]) -> anyhow::Result<()>;
    /// Deletes every expired session and reports how many were removed. Purely
    /// housekeeping: expired sessions must already be rejected at read time,
    /// so a failure here must not be treated as evidence that none are
    /// expired.
    async fn cleanup_expired(&self) -> anyhow::Result<usize>;
    /// Loads the version/metadata row for a subject, used to detect stale
    /// sessions. `Ok(None)` means no version is recorded and callers read that
    /// as version 0, i.e. no invalidation has happened yet.
    async fn load_session_metadata(&self, subject_id: &str) -> anyhow::Result<Option<SessionRow>>;
    /// Persists the subject's new version counter. Every session created
    /// before this write becomes stale, so the implementation must apply it
    /// durably and atomically; a partial update could leave some replicas
    /// honouring the old sessions.
    async fn bump_version(&self, subject_id: &str, version: u64) -> anyhow::Result<()>;
}

/// SPI for persisting role assignments to an external store (e.g. PostgreSQL, Redis).
///
/// The crate provides in-memory implementations only; implement this trait
/// to connect a production database backend.
///
/// Security semantics: writes are authority changes. Each save/delete must be
/// durable and idempotent, and an `Err` must propagate so the caller can fail
/// closed; returning `Ok` before the change is visible would leave the
/// revoking process believing an assignment is gone while readers still see
/// it. Deletes report `Ok(false)` for a missing row, which is not an error but
/// also proves nothing about the row's prior existence on another replica.
#[async_trait]
pub trait PersistentAssignmentStore: Send + Sync {
    /// Loads every assignment row, typically to warm a cache or to export
    /// state. An `Err` must not be downgraded to an empty list, which callers
    /// would read as "nobody has any authority".
    async fn load_assignments(&self) -> anyhow::Result<Vec<AssignmentRow>>;
    /// Inserts or replaces one assignment row, keyed by subject and role.
    async fn save_assignment(&self, row: &AssignmentRow) -> anyhow::Result<()>;
    /// Deletes one assignment. Returns whether a row existed; `false` is not a
    /// failure.
    async fn delete_assignment(&self, subject_id: &str, role_name: &str) -> anyhow::Result<bool>;
    /// Replaces the subject's extra-permission list wholesale; an empty list
    /// revokes every direct grant.
    async fn save_extra_permissions(
        &self,
        subject_id: &str,
        permissions: &[String],
    ) -> anyhow::Result<()>;
    /// Replaces the subject's deny list wholesale; an empty list clears all
    /// denies and therefore widens the subject's effective authority.
    async fn save_denied_permissions(
        &self,
        subject_id: &str,
        permissions: &[String],
    ) -> anyhow::Result<()>;
}

/// SPI for persisting role definitions to an external store.
///
/// Security semantics: saving a role rewrites the authority of every holder,
/// so it must be durable before returning and must not silently merge with the
/// existing definition. An `Err` propagates (fail-closed): a role edit that
/// could not be persisted must not be treated as applied.
#[async_trait]
pub trait PersistentRoleStore: Send + Sync {
    /// Loads every role definition. An `Err` must not be reported as "no roles
    /// defined", since that strips every holder's authority.
    async fn load_roles(&self) -> anyhow::Result<Vec<RoleRow>>;
    /// Inserts or replaces a role definition, including its parent list.
    async fn save_role(&self, row: &RoleRow) -> anyhow::Result<()>;
    /// Deletes a role definition. Returns whether a row existed; `false` is not
    /// a failure. Holders of the deleted role keep their assignments, which
    /// then resolve to no permissions.
    async fn delete_role(&self, role_name: &str) -> anyhow::Result<bool>;
}

/// SPI for persisting RBAC constraints (SSD/DSD/cardinality/prerequisite/temporal) to an external store.
///
/// Security semantics: constraints only remove authority, so losing one is a
/// privilege escalation. A load error must therefore surface as an error
/// rather than an empty constraint list, which a validator would read as "no
/// restrictions".
#[async_trait]
pub trait PersistentConstraintStore: Send + Sync {
    /// Loads every stored constraint. Must not map a read failure to an empty
    /// list.
    async fn load_constraints(&self) -> anyhow::Result<Vec<ConstraintRow>>;
    /// Inserts or replaces one constraint row.
    async fn save_constraint(&self, row: &ConstraintRow) -> anyhow::Result<()>;
    /// Deletes one constraint by type and id. Returns whether a row existed;
    /// removing a constraint widens authority, so the caller must have
    /// authorization for that change.
    async fn delete_constraint(&self, constraint_type: &str, id: i64) -> anyhow::Result<bool>;
}

/// SPI for persisting audit log entries to an external store.
///
/// Security semantics: the audit log is evidence, so the storage contract is
/// append-only - implementations must not overwrite or delete entries, and
/// `append_entry` must be durable before returning. A failed append must
/// surface as an error; callers decide whether to fail the operation, but they
/// must not assume the entry was recorded.
#[async_trait]
pub trait PersistentAuditStore: Send + Sync {
    /// Appends one entry. Implementations must not deduplicate or update in
    /// place.
    async fn append_entry(&self, row: &AuditRow) -> anyhow::Result<()>;
    /// Queries entries newest-first (or in a documented stable order) with
    /// optional filters. `limit`/`offset` bound the result; `None` means no
    /// bound, so callers exposing this over an API must impose their own.
    async fn query_entries(
        &self,
        subject_id: Option<&str>,
        granted: Option<bool>,
        limit: Option<usize>,
        offset: Option<usize>,
    ) -> anyhow::Result<Vec<AuditRow>>;
    /// Counts entries matching the same filters; used for pagination and for
    /// detecting gaps in the trail.
    async fn count_entries(
        &self,
        subject_id: Option<&str>,
        granted: Option<bool>,
    ) -> anyhow::Result<u64>;
}

/// SPI for persisting dynamic-authorization trust scores to an external store.
///
/// Security semantics: a trust score feeds the dynamic-authorization verdict,
/// so a stale or attacker-influenced score changes an authorization outcome.
/// A missing score (`Ok(None)`) must be handled by the policy's own default
/// rather than by this store inventing one, and an `Err` must propagate so the
/// caller can fail closed.
#[cfg(feature = "rbac-dynamic")]
#[async_trait]
pub trait PersistentTrustStore: Send + Sync {
    /// Loads the stored score for a delegator; `Ok(None)` means none recorded,
    /// which leaves the decision to the caller's default policy.
    async fn load_trust_score(
        &self,
        delegator_id: &str,
    ) -> anyhow::Result<Option<crate::rbac::dynamic::trust::TrustScore>>;
    /// Persists a score, replacing the previous value for that delegator. Must
    /// be durable before returning, because the next decision reads it.
    async fn save_trust_score(
        &self,
        delegator_id: &str,
        score: &crate::rbac::dynamic::trust::TrustScore,
    ) -> anyhow::Result<()>;
    /// Lists every delegator with a stored score, for maintenance jobs (for
    /// example trust decay). Not an authorization input.
    async fn list_delegator_ids(&self) -> anyhow::Result<Vec<String>>;
}

/// Convenience supertrait for a backend that implements the assignment, role
/// and constraint stores together; implementing all three grants this blanket
/// implementation automatically.
///
/// Security semantics: it aggregates the three stores' contracts unchanged
/// (errors propagate, deletes are idempotent, writes are authority changes). It
/// deliberately does not include the session or audit stores, so having a
/// `PersistentStore` says nothing about session or audit durability.
pub trait PersistentStore:
    PersistentAssignmentStore + PersistentRoleStore + PersistentConstraintStore + Send + Sync
{
}

impl<T> PersistentStore for T where
    T: PersistentAssignmentStore + PersistentRoleStore + PersistentConstraintStore + Send + Sync
{
}
