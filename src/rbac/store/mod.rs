//! Storage backends for the RBAC engine: in-memory implementations for tests
//! and development, plus the persistence SPI traits a deployment implements
//! against its own database.
//!
//! Security semantics shared by this layer: reads are the authoritative input
//! to every decision, so a store error must surface as an error and never as
//! an empty result (an empty result means "no authority" for grants but "no
//! restriction" for constraints, and guessing either way is wrong); writes are
//! authority changes and must be durable before returning; deletes are
//! idempotent and report whether a row existed. The in-memory backends are
//! per-process and not persistent, so a restart drops all authority
//! (fail-closed) and replicas do not share state.

/// In-memory assignment and role stores, for tests and single-process use.
pub mod memory;
/// Persistence SPI traits and row types for external databases.
#[cfg(any(feature = "rbac-db-session", feature = "rbac-dynamic"))]
pub mod persistence;
/// Static, in-process permission and role registries.
pub mod registry;

pub use memory::{InMemoryAssignmentStore, InMemoryRoleStore};
/// Trust-score persistence, available with the dynamic-authorization feature.
#[cfg(feature = "rbac-dynamic")]
pub use persistence::PersistentTrustStore;
/// Persistence SPI for assignments, roles, constraints and audit entries.
#[cfg(any(feature = "rbac-db-session", feature = "rbac-dynamic"))]
pub use persistence::{
    AssignmentRow, AuditRow, ConstraintRow, PersistentAssignmentStore, PersistentAuditStore,
    PersistentConstraintStore, PersistentRoleStore, PersistentStore, RoleRow,
};
pub use registry::{SimpleRole, StaticPermissionRegistry, StaticRoleRegistry};
