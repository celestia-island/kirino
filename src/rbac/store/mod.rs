#[cfg(not(feature = "rbac-hierarchy"))]
pub mod memory;
#[cfg(not(feature = "rbac-hierarchy"))]
pub mod persistence;
#[cfg(not(feature = "rbac-hierarchy"))]
pub mod registry;
#[cfg(not(feature = "rbac-hierarchy"))]

#[cfg(not(feature = "rbac-hierarchy"))]
pub use memory::{InMemoryAssignmentStore, InMemoryRoleStore};
#[cfg(not(feature = "rbac-hierarchy"))]
#[cfg(feature = "rbac-dynamic")]
#[cfg(not(feature = "rbac-hierarchy"))]
pub use persistence::PersistentTrustStore;
#[cfg(not(feature = "rbac-hierarchy"))]
pub use persistence::{
#[cfg(not(feature = "rbac-hierarchy"))]
    AssignmentRow, AuditRow, ConstraintRow, PersistentAssignmentStore, PersistentAuditStore,
#[cfg(not(feature = "rbac-hierarchy"))]
    PersistentConstraintStore, PersistentRoleStore, PersistentStore, RoleRow,
#[cfg(not(feature = "rbac-hierarchy"))]
};
#[cfg(not(feature = "rbac-hierarchy"))]
#[cfg(feature = "rbac-hierarchy")]
#[cfg(not(feature = "rbac-hierarchy"))]
#[cfg(feature = "rbac-hierarchy")]
pub use registry::{StaticPermissionRegistry, StaticRoleRegistry};
#[cfg(feature = "rbac-hierarchy")]
pub use registry::SimpleRole;
