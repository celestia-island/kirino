pub mod audit;
pub mod cache;
pub mod constraints;
pub mod dynamic;
pub mod engine;
pub mod hierarchy;
pub mod identity_subject;
pub mod session;
pub mod shared;
pub mod store;
pub mod subject;
pub mod traits;
pub mod prelude {

    pub use crate::rbac::{
        audit::{
            AuditAction, AuditAlert, AuditAnalyzer, AuditCondition, AuditEntry, AuditFilter,
            AuditLogger, AuditPolicyEngine, AuditRule, AuditSeverity, AuditSink, AuditVerdict,
            DefaultAuditAnalyzer, InMemoryAuditPolicyEngine, InMemoryAuditSink,
        },
        cache::{PermissionCache, TtlPermissionCache},
        constraints::{
            CardinalityConstraint, ConstraintStore, ConstraintValidator, DsdPolicy,
            InMemoryConstraintStore, PrerequisiteConstraint, SsdPolicy, TemporalConstraint,
        },
        dynamic::{
            anomaly::{AnomalyDetector, AnomalyScore, BehaviorBaseline},
            arbiter::AuthorizationArbiter,
            delegator::{Delegator, DelegatorType},
            domain::{DomainMatch, DomainScope, TaskDomain},
            metrics::{ActionCategory, ActionRequest, ActionSensitivity},
            policy::{default_dynamic_policy, DynamicPolicy},
            trust::{InMemoryTrustScoreStore, TrustDecayWorker, TrustScore, TrustScoreStore},
            verdict::{
                ActionOutcome, AuthorizationVerdict, AutonomyLevel, RiskScore, Strategy, SubScores,
            },
        },
        engine::RbacEngine,
        hierarchy::{detect_cycle, resolve_role_chain, HierarchicalRole, HierarchyNode},
        identity_subject::{Delegatable, IdentitySubject},
        session::{InMemorySessionManager, Session, SessionManager},
        shared::Shared,
        store::{
            InMemoryAssignmentStore, InMemoryRoleStore, SimpleRole, StaticPermissionRegistry,
            StaticRoleRegistry,
        },
        subject::StringSubject,
        traits::{
            AssignmentStore, Permission, PermissionRegistry, Role, RoleRegistry, RoleStore, Subject,
        },
    };
}
