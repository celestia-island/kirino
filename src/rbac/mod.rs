pub mod audit;
pub mod cache;
#[cfg(feature = "rbac-constraints")]
pub mod constraints;
#[cfg(feature = "rbac-dynamic")]
pub mod dynamic;
pub mod engine;
#[cfg(feature = "rbac-hierarchy")]
pub mod hierarchy;
pub mod identity_subject;
pub mod permission;
pub mod session;
pub mod shared;
pub mod store;
pub mod subject;
pub mod traits;
pub mod workspace_guard;
pub mod prelude {

    #[cfg(feature = "rbac-constraints")]
    pub use crate::rbac::constraints::{
        CardinalityConstraint, ConstraintStore, ConstraintValidator, DsdPolicy,
        InMemoryConstraintStore, PrerequisiteConstraint, SsdPolicy, TemporalConstraint,
    };
    #[cfg(feature = "rbac-dynamic")]
    pub use crate::rbac::dynamic::{
        anomaly::{AnomalyDetector, AnomalyScore, BehaviorBaseline},
        arbiter::AuthorizationArbiter,
        delegator::{Delegator, DelegatorType},
        domain::{DomainMatch, DomainScope, TaskDomain},
        metrics::{ActionCategory, ActionRequest, ActionSensitivity},
        policy::{default_dynamic_policy, DynamicPolicy},
        trust::{
            InMemoryTrustScoreStore, TrustDecayHandle, TrustDecayWorker, TrustScore,
            TrustScoreStore,
        },
        verdict::{
            ActionOutcome, AuthorizationVerdict, AutonomyLevel, RiskScore, Strategy, SubScores,
        },
    };
    #[cfg(feature = "rbac-hierarchy")]
    pub use crate::rbac::hierarchy::{
        detect_cycle, resolve_role_chain, HierarchicalRole, HierarchyNode,
    };
    #[cfg(feature = "rbac-dynamic")]
    pub use crate::rbac::store::persistence::PersistentTrustStore;
    #[cfg(feature = "rbac-constraints")]
    pub use crate::rbac::store::persistence::{
        AssignmentRow, AuditRow, ConstraintRow, PersistentAssignmentStore, PersistentAuditStore,
        PersistentConstraintStore, PersistentRoleStore, PersistentStore, RoleRow,
    };
    pub use crate::rbac::{
        audit::{
            AuditAction, AuditAlert, AuditAnalyzer, AuditCondition, AuditEntry, AuditFilter,
            AuditLogger, AuditPolicyEngine, AuditRule, AuditSeverity, AuditSink, AuditVerdict,
            DefaultAuditAnalyzer, InMemoryAuditPolicyEngine, InMemoryAuditSink,
        },
        cache::{PermissionCache, TtlPermissionCache},
        engine::RbacEngine,
        identity_subject::{Delegatable, IdentitySubject},
        permission::Permission,
        session::{InMemorySessionManager, Session, SessionManager},
        shared::Shared,
        store::{
            InMemoryAssignmentStore, InMemoryRoleStore, SimpleRole, StaticPermissionRegistry,
            StaticRoleRegistry,
        },
        subject::StringSubject,
        traits::{
            AssignmentStore, GrantResolver, GrantSource, Permission as PermissionTrait,
            PermissionContext, PermissionDecision, PermissionRegistry, Role, RoleRegistry,
            RoleStore, Subject, SystemRole, WorkspaceRole,
        },
        workspace_guard::{
            InMemoryWorkspaceStore, ScopedPermission, WorkspaceGuard, WorkspaceStore,
        },
    };
}
