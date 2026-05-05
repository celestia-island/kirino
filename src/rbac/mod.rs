pub mod audit;
pub mod cache;
pub mod constraints;
pub mod engine;
pub mod hierarchy;
pub mod identity_subject;
pub mod session;
pub mod store;
pub mod subject;
pub mod traits;

pub mod prelude {
    pub use crate::rbac::audit::{AuditEntry, AuditLogger, InMemoryAuditLogger};
    pub use crate::rbac::cache::{PermissionCache, TtlPermissionCache};
    pub use crate::rbac::constraints::{
        CardinalityConstraint, ConstraintStore, ConstraintValidator, DsdPolicy,
        InMemoryConstraintStore, PrerequisiteConstraint, SsdPolicy, TemporalConstraint,
    };
    pub use crate::rbac::engine::RbacEngine;
    pub use crate::rbac::hierarchy::{
        detect_cycle, resolve_role_chain, HierarchicalRole, HierarchyNode,
    };
    pub use crate::rbac::identity_subject::{Delegatable, IdentitySubject};
    pub use crate::rbac::session::{InMemorySessionManager, Session, SessionManager};
    pub use crate::rbac::store::{
        InMemoryAssignmentStore, InMemoryRoleStore, SimpleRole, StaticPermissionRegistry,
        StaticRoleRegistry,
    };
    pub use crate::rbac::subject::StringSubject;
    pub use crate::rbac::traits::{
        AssignmentStore, Permission, PermissionRegistry, Role, RoleRegistry, RoleStore, Subject,
    };
}
