pub mod cache;
pub mod compat;
pub mod engine;
pub mod store;
pub mod traits;

pub mod prelude {
    pub use crate::rbac::cache::{PermissionCache, TtlPermissionCache};
    pub use crate::rbac::engine::RbacEngine;
    pub use crate::rbac::store::{
        InMemoryAssignmentStore, InMemoryRoleStore, SimpleRole, StaticPermissionRegistry,
        StaticRoleRegistry,
    };
    pub use crate::rbac::traits::{
        AssignmentStore, Permission, PermissionRegistry, Role, RoleRegistry, RoleStore, Subject,
    };
}
