pub mod memory;
pub mod persistence;
pub mod registry;

pub use memory::{InMemoryAssignmentStore, InMemoryRoleStore};
#[cfg(feature = "rbac-dynamic")]
pub use persistence::PersistentTrustStore;
pub use persistence::{
    AssignmentRow, AuditRow, ConstraintRow, PersistentAssignmentStore, PersistentAuditStore,
    PersistentConstraintStore, PersistentRoleStore, PersistentStore, RoleRow,
};
pub use registry::{SimpleRole, StaticPermissionRegistry, StaticRoleRegistry};
