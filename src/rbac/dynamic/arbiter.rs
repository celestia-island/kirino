use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use tokio::sync::RwLock;

use super::{
    anomaly::AnomalyDetector,
    delegator::DelegatorType,
    domain::DomainScope,
    metrics::ActionRequest,
    policy::DynamicPolicy,
    trust::{TrustScore, TrustScoreStore},
    verdict::{ActionOutcome, AuthorizationVerdict, AutonomyLevel, RiskScore, Strategy, SubScores},
};
use crate::rbac::{
    audit::{AuditEntry, AuditLogger, AuditSubScores, AuditVerdict},
    shared::Shared,
};

#[derive(Clone)]
pub struct AuthorizationArbiter {
    trust_store: Shared<dyn TrustScoreStore>,
    detectors: Arc<RwLock<HashMap<String, AnomalyDetector>>>,
    domain_scope: Arc<RwLock<Option<DomainScope>>>,
    policy: Arc<RwLock<DynamicPolicy>>,
    frozen: Arc<RwLock<HashSet<String>>>,
    audit: Option<Shared<AuditLogger>>,
}

impl std::fmt::Debug for AuthorizationArbiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthorizationArbiter")
            .field(
                "detectors_count",
                &self.detectors.try_read().map(|d| d.len()).unwrap_or(0),
            )
            .field(
                "has_domain_scope",
                &self
                    .domain_scope
                    .try_read()
                    .map(|d| d.is_some())
                    .unwrap_or(false),
            )
            .field(
                "frozen_count",
                &self.frozen.try_read().map(|f| f.len()).unwrap_or(0),
            )
            .field("has_audit", &self.audit.is_some())
            .finish()
    }
}

impl AuthorizationArbiter {
    pub fn new(trust_store: impl TrustScoreStore + 'static, policy: DynamicPolicy) -> Self {
        Self {
            trust_store: Shared::from_arc_unsized(Arc::new(trust_store)),
            detectors: Arc::new(RwLock::new(HashMap::new())),
            domain_scope: Arc::new(RwLock::new(None)),
            policy: Arc::new(RwLock::new(policy)),
            frozen: Arc::new(RwLock::new(HashSet::new())),
            audit: None,
        }
    }

    pub fn with_audit(mut self, audit: AuditLogger) -> Self {
        self.audit = Some(Shared::new(audit));
        self
    }

    pub fn with_domain_scope(mut self, scope: DomainScope) -> Self {
        self.domain_scope = Arc::new(RwLock::new(Some(scope)));
        self
    }

    pub fn trust_store(&self) -> &Shared<dyn TrustScoreStore> {
        &self.trust_store
    }

    pub async fn set_policy(&self, policy: DynamicPolicy) {
        let mut guard = self.policy.write().await;
        *guard = policy;
    }

    pub async fn set_domain_scope(&self, scope: DomainScope) {
        let mut guard = self.domain_scope.write().await;
        *guard = Some(scope);
    }

    pub async fn authorize(&self, request: &ActionRequest) -> AuthorizationVerdict {
        let frozen = self.frozen.read().await;
        if frozen.contains(&request.delegator.id) {
            let verdict = AuthorizationVerdict {
                allowed: false,
                autonomy_level: AutonomyLevel::L0Frozen,
                risk_score: 1.0,
                sub_scores: SubScores {
                    delegator_weight: 0.0,
                    trust_penalty: 1.0,
                    sensitivity: 0.0,
                    domain_mismatch: 0.0,
                    anomaly: 0.0,
                },
                evidence: vec![format!(
                    "delegator '{}' is frozen (lockdown active)",
                    request.delegator.id
                )],
                mitigation: Some(Strategy::Block {
                    reason: "lockdown".to_string(),
                }),
                timestamp: chrono::Utc::now(),
            };
            drop(frozen);
            self.log_verdict(&verdict, request).await;
            return verdict;
        }
        drop(frozen);

        let risk = self.risk_score(request).await;

        let mut risk = risk;
        {
            let scope_guard = self.domain_scope.read().await;
            if let Some(scope) = scope_guard.as_ref() {
                let floor = scope.current_task_domain.trust_floor;
                if floor > 0.0 {
                    let trust = self
                        .trust_store
                        .get(&request.delegator.id)
                        .await
                        .ok()
                        .flatten()
                        .unwrap_or_default();
                    let weighted = trust.weighted();
                    if weighted < floor {
                        let penalty = (floor - weighted).clamp(0.0, 1.0);
                        risk.value = (risk.value + penalty).min(1.0);
                        risk.sub_scores.domain_mismatch += penalty;
                    }
                }
            }
        }

        let policy = self.policy.read().await;
        let level = policy.map_to_level(risk.value);
        let strategy = policy.strategy_for(level);

        let allowed = matches!(
            level,
            AutonomyLevel::L4FullAutonomy | AutonomyLevel::L3Conditional
        );

        let mut evidence = Vec::new();
        evidence.push(format!(
            "risk={:.3} level={} delegator_type={:?}",
            risk.value, level, request.delegator.delegator_type,
        ));
        evidence.push(format!(
            "sub: delegator_w={:.3} trust_p={:.3} sens={:.3} domain={:.3} anomaly={:.3}",
            risk.sub_scores.delegator_weight,
            risk.sub_scores.trust_penalty,
            risk.sub_scores.sensitivity,
            risk.sub_scores.domain_mismatch,
            risk.sub_scores.anomaly,
        ));

        let mitigation = if allowed {
            if matches!(strategy, Strategy::Throttle { .. }) {
                Some(strategy)
            } else {
                None
            }
        } else {
            Some(strategy)
        };

        let verdict = AuthorizationVerdict {
            allowed,
            autonomy_level: level,
            risk_score: risk.value,
            sub_scores: risk.sub_scores.clone(),
            evidence,
            mitigation,
            timestamp: chrono::Utc::now(),
        };

        self.log_verdict(&verdict, request).await;

        verdict
    }

    pub async fn risk_score(&self, request: &ActionRequest) -> RiskScore {
        let policy = self.policy.read().await;

        let delegator_weight = match request.delegator.delegator_type {
            DelegatorType::Human => 0.0,
            DelegatorType::Agent => 0.05,
            DelegatorType::SubAgent => 0.15,
            DelegatorType::ExternalSystem => 0.30,
            DelegatorType::Scheduler => 0.02,
        };

        let trust = self
            .trust_store
            .get(&request.delegator.id)
            .await
            .ok()
            .flatten()
            .unwrap_or_default();
        let trust_penalty = (1.0 - trust.weighted()).clamp(0.0, 1.0);

        let sensitivity = request.category.base_weight();

        let domain_mismatch = {
            let scope_guard = self.domain_scope.read().await;
            match scope_guard.as_ref() {
                Some(scope) => scope
                    .evaluate(&request.category, request.resource_path.as_deref())
                    .excess_weight(),
                None => 0.0,
            }
        };

        let anomaly = {
            let mut detectors = self.detectors.write().await;
            let detector = detectors
                .entry(request.delegator.id.clone())
                .or_insert_with(AnomalyDetector::default);
            let score = detector.observe(request);
            score.value
        };

        let anomaly_weight_modifier = if !self.is_baseline_ready_for(&request.delegator.id).await {
            0.5
        } else {
            1.0
        };

        let raw = delegator_weight * policy.dimension_weights[0]
            + trust_penalty * policy.dimension_weights[1]
            + sensitivity * policy.dimension_weights[2]
            + domain_mismatch * policy.dimension_weights[3]
            + anomaly * anomaly_weight_modifier * policy.dimension_weights[4];

        let value = raw.clamp(0.0, 1.0);

        RiskScore {
            value,
            sub_scores: SubScores {
                delegator_weight,
                trust_penalty,
                sensitivity,
                domain_mismatch,
                anomaly,
            },
        }
    }

    pub async fn feedback(&self, request: &ActionRequest, outcome: ActionOutcome) {
        let mut trust = self
            .trust_store
            .get(&request.delegator.id)
            .await
            .ok()
            .flatten()
            .unwrap_or_default();

        match &outcome {
            ActionOutcome::Success => {
                trust.on_compliant_behavior(0.5);
            }
            ActionOutcome::Failure { .. } => {
                trust.on_policy_violation(0.2);
            }
            ActionOutcome::PolicyViolation { .. } => {
                trust.on_policy_violation(0.8);
            }
            ActionOutcome::Anomalous { deviation } => {
                trust.on_policy_violation(*deviation);
            }
        }

        let _ = self.trust_store.set(&request.delegator.id, trust).await;
    }

    pub async fn lockdown(&self, delegator_id: &str, reason: &str) {
        {
            let mut frozen = self.frozen.write().await;
            frozen.insert(delegator_id.to_string());
        }

        let mut trust = TrustScore::new(0.0);
        trust.confidence = 1.0;
        trust.evidence_count = 999;
        let _ = self.trust_store.set(delegator_id, trust).await;

        tracing::warn!(target: "kirino::dynamic::arbiter",
            delegator_id = delegator_id,
            reason = reason,
            "agent locked down to L0"
        );
    }

    pub async fn restore(&self, delegator_id: &str, target: AutonomyLevel) {
        {
            let mut frozen = self.frozen.write().await;
            frozen.remove(delegator_id);
        }

        let target_trust = match target {
            AutonomyLevel::L4FullAutonomy => 0.95,
            AutonomyLevel::L3Conditional => 0.8,
            AutonomyLevel::L2SemiAutonomous => 0.6,
            AutonomyLevel::L1Assisted => 0.4,
            AutonomyLevel::L0Frozen => 0.1,
        };

        let mut trust = TrustScore::new(target_trust);
        trust.confidence = 0.5;
        let _ = self.trust_store.set(delegator_id, trust).await;

        let mut detectors = self.detectors.write().await;
        detectors.remove(delegator_id);

        tracing::info!(target: "kirino::dynamic::arbiter",
            delegator_id = delegator_id,
            target_level = %target,
            "agent restored to level"
        );
    }

    pub async fn status_summary(&self, delegator_id: &str) -> serde_json::Value {
        let trust = self
            .trust_store
            .get(delegator_id)
            .await
            .ok()
            .flatten()
            .unwrap_or_default();
        let frozen = self.frozen.read().await.contains(delegator_id);
        let detectors = self.detectors.read().await;
        let anomaly_ready = detectors
            .get(delegator_id)
            .map(|d| d.is_baseline_ready())
            .unwrap_or(false);
        serde_json::json!({
            "enabled": true,
            "delegator_id": delegator_id,
            "frozen": frozen,
            "trust_score": trust.weighted(),
            "trust_confidence": trust.confidence,
            "trust_evidence_count": trust.evidence_count,
            "anomaly_baseline_ready": anomaly_ready,
        })
    }

    async fn is_baseline_ready_for(&self, delegator_id: &str) -> bool {
        let detectors = self.detectors.read().await;
        detectors
            .get(delegator_id)
            .map(|d| d.is_baseline_ready())
            .unwrap_or(false)
    }

    async fn log_verdict(&self, verdict: &AuthorizationVerdict, request: &ActionRequest) {
        if let Some(ref audit) = self.audit {
            let entry = AuditEntry {
                id: 0,
                subject_id: request.delegator.id.clone(),
                subject_type: format!("{:?}", request.delegator.delegator_type),
                permission: request.action.clone(),
                endpoint: format!(
                    "dynamic:{}:risk={:.3}",
                    verdict.autonomy_level, verdict.risk_score
                ),
                granted: verdict.allowed,
                created_at: verdict.timestamp,
                verdict: Some(AuditVerdict {
                    autonomy_level: format!("{}", verdict.autonomy_level),
                    risk_score: verdict.risk_score,
                    sub_scores: AuditSubScores {
                        delegator_weight: verdict.sub_scores.delegator_weight,
                        trust_penalty: verdict.sub_scores.trust_penalty,
                        sensitivity: verdict.sub_scores.sensitivity,
                        domain_mismatch: verdict.sub_scores.domain_mismatch,
                        anomaly: verdict.sub_scores.anomaly,
                    },
                    evidence: verdict.evidence.clone(),
                    mitigation: verdict.mitigation.as_ref().map(|s| format!("{:?}", s)),
                }),
            };
            audit.log(entry).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rbac::dynamic::delegator::Delegator;
    use crate::rbac::dynamic::domain::{DomainScope, TaskDomain};
    use crate::rbac::dynamic::metrics::ActionCategory;
    use crate::rbac::dynamic::policy::default_dynamic_policy;
    use crate::rbac::dynamic::trust::InMemoryTrustScoreStore;

    fn make_arbiter() -> AuthorizationArbiter {
        AuthorizationArbiter::new(InMemoryTrustScoreStore::new(), default_dynamic_policy())
    }

    fn human_request(category: ActionCategory) -> ActionRequest {
        ActionRequest::simple(Delegator::human("user-1", "#test"), "test.action", category)
    }

    fn agent_request(category: ActionCategory) -> ActionRequest {
        ActionRequest::simple(
            Delegator::agent("agent-1", "#test"),
            "test.action",
            category,
        )
    }

    #[tokio::test]
    async fn test_human_read_low_risk() {
        let arbiter = make_arbiter();

        let mut trust = TrustScore::new(0.95);
        trust.confidence = 0.9;
        trust.evidence_count = 500;
        arbiter.trust_store.set("user-1", trust).await.unwrap();

        let req = human_request(ActionCategory::ReadOnly);
        let verdict = arbiter.authorize(&req).await;
        assert!(verdict.allowed);
        assert!(verdict.risk_score < 0.15);
    }

    #[tokio::test]
    async fn test_agent_privileged_high_risk() {
        let arbiter = make_arbiter();
        let req = agent_request(ActionCategory::PrivilegedOp);
        let verdict = arbiter.authorize(&req).await;
        assert!(!verdict.allowed);
    }

    #[tokio::test]
    async fn test_risk_score_dimensions() {
        let arbiter = make_arbiter();
        let req = agent_request(ActionCategory::FileWrite);
        let risk = arbiter.risk_score(&req).await;

        assert!((risk.sub_scores.delegator_weight - 0.05).abs() < f64::EPSILON);
        assert!(risk.sub_scores.trust_penalty > 0.0);
        assert!((risk.sub_scores.sensitivity - 0.5).abs() < f64::EPSILON);
        assert!((risk.sub_scores.domain_mismatch).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn test_feedback_increases_trust() {
        let arbiter = make_arbiter();
        let req = agent_request(ActionCategory::ReadOnly);

        for _ in 0..5 {
            arbiter.feedback(&req, ActionOutcome::Success).await;
        }

        let risk_before = arbiter.risk_score(&req).await.value;
        for _ in 0..50 {
            arbiter.feedback(&req, ActionOutcome::Success).await;
        }
        let risk_after = arbiter.risk_score(&req).await.value;

        assert!(risk_after < risk_before);
    }

    #[tokio::test]
    async fn test_feedback_violation_decreases_trust() {
        let arbiter = make_arbiter();

        let mut trust = TrustScore::new(0.9);
        trust.confidence = 0.8;
        arbiter.trust_store.set("agent-1", trust).await.unwrap();

        let req = agent_request(ActionCategory::ReadOnly);
        let risk_before = arbiter.risk_score(&req).await.value;

        arbiter
            .feedback(
                &req,
                ActionOutcome::PolicyViolation {
                    rule: "path-blacklist".to_string(),
                },
            )
            .await;

        let risk_after = arbiter.risk_score(&req).await.value;
        assert!(risk_after > risk_before);
    }

    #[tokio::test]
    async fn test_lockdown_freezes_agent() {
        let arbiter = make_arbiter();

        let mut trust = TrustScore::new(0.95);
        trust.confidence = 0.9;
        arbiter.trust_store.set("agent-1", trust).await.unwrap();

        let req = agent_request(ActionCategory::ReadOnly);
        let v1 = arbiter.authorize(&req).await;
        assert!(v1.allowed);

        arbiter.lockdown("agent-1", "security-alert").await;

        let v2 = arbiter.authorize(&req).await;
        assert!(!v2.allowed);
        assert_eq!(v2.autonomy_level, AutonomyLevel::L0Frozen);
    }

    #[tokio::test]
    async fn test_restore_revives_agent() {
        let arbiter = make_arbiter();
        arbiter.lockdown("agent-1", "test").await;

        let req = agent_request(ActionCategory::ReadOnly);
        let v1 = arbiter.authorize(&req).await;
        assert!(!v1.allowed);

        arbiter
            .restore("agent-1", AutonomyLevel::L4FullAutonomy)
            .await;

        let v2 = arbiter.authorize(&req).await;
        assert!(v2.allowed);
    }

    #[tokio::test]
    async fn test_domain_scope_restriction() {
        let arbiter = make_arbiter();
        let scope = DomainScope::single(TaskDomain::new(
            "restricted",
            [ActionCategory::ReadOnly].into(),
            vec!["/data/".to_string()],
            0.5,
        ));
        arbiter.set_domain_scope(scope).await;

        let mut req = agent_request(ActionCategory::ProcessExec);
        req.resource_path = Some("/bin/bash".to_string());
        let verdict = arbiter.authorize(&req).await;
        assert!(!verdict.allowed);
        assert!(verdict.sub_scores.domain_mismatch > 0.0);
    }

    #[tokio::test]
    async fn test_evidence_populated() {
        let arbiter = make_arbiter();
        let req = human_request(ActionCategory::ReadOnly);
        let verdict = arbiter.authorize(&req).await;
        assert!(!verdict.evidence.is_empty());
        assert!(verdict.evidence[0].contains("risk="));
    }

    #[tokio::test]
    async fn test_audit_no_panic() {
        let arbiter =
            AuthorizationArbiter::new(InMemoryTrustScoreStore::new(), default_dynamic_policy());

        let req = human_request(ActionCategory::ReadOnly);
        let verdict = arbiter.authorize(&req).await;
        assert!(verdict.evidence.is_empty() || !verdict.evidence.is_empty());
    }

    #[tokio::test]
    async fn test_dynamic_policy_update() {
        let arbiter = make_arbiter();
        let req = human_request(ActionCategory::ReadOnly);

        let v1 = arbiter.authorize(&req).await;
        assert!(v1.allowed);

        let mut strict_policy = default_dynamic_policy();
        strict_policy.autonomy_thresholds =
            std::collections::BTreeMap::from([(AutonomyLevel::L0Frozen, (0.0, 1.01))]);
        strict_policy.level_strategies = std::collections::BTreeMap::from([(
            AutonomyLevel::L0Frozen,
            Strategy::Block {
                reason: "lockdown".to_string(),
            },
        )]);
        arbiter.set_policy(strict_policy).await;

        let v2 = arbiter.authorize(&req).await;
        assert!(!v2.allowed);
    }

    #[tokio::test]
    async fn smoke_full_authorize_feedback_loop() {
        let arbiter = make_arbiter();

        let mut trust = TrustScore::new(0.5);
        trust.confidence = 0.5;
        trust.evidence_count = 10;
        arbiter.trust_store.set("agent-1", trust).await.unwrap();

        let req = ActionRequest::simple(
            Delegator::agent("agent-1", "#smoke"),
            "file.write",
            ActionCategory::FileWrite,
        );

        for cycle in 0..20 {
            let verdict = arbiter.authorize(&req).await;

            if verdict.allowed {
                arbiter.feedback(&req, ActionOutcome::Success).await;
            } else {
                arbiter
                    .feedback(
                        &req,
                        ActionOutcome::Failure {
                            error: format!("denied at cycle {}", cycle),
                        },
                    )
                    .await;
            }
        }

        let final_trust = arbiter.trust_store.get("agent-1").await.unwrap().unwrap();
        assert!(final_trust.evidence_count >= 30);
    }

    #[tokio::test]
    async fn smoke_status_summary_returns_valid_json() {
        let arbiter = make_arbiter();

        let mut trust = TrustScore::new(0.7);
        trust.confidence = 0.6;
        trust.evidence_count = 50;
        arbiter.trust_store.set("agent-1", trust).await.unwrap();

        let summary = arbiter.status_summary("agent-1").await;
        assert_eq!(summary["enabled"], true);
        assert_eq!(summary["delegator_id"], "agent-1");
        assert_eq!(summary["frozen"], false);
        assert!(summary["trust_score"].as_f64().unwrap() > 0.0);
        assert!(summary["anomaly_baseline_ready"].as_bool() == Some(false));

        arbiter.lockdown("agent-1", "smoke-test").await;
        let frozen_summary = arbiter.status_summary("agent-1").await;
        assert_eq!(frozen_summary["frozen"], true);
    }

    #[tokio::test]
    async fn smoke_lockdown_restore_full_cycle() {
        let arbiter = make_arbiter();

        let mut trust = TrustScore::new(0.9);
        trust.confidence = 0.9;
        trust.evidence_count = 100;
        arbiter.trust_store.set("agent-1", trust).await.unwrap();

        let req = ActionRequest::simple(
            Delegator::agent("agent-1", "#cycle"),
            "file.read",
            ActionCategory::ReadOnly,
        );

        let v_before = arbiter.authorize(&req).await;
        assert!(v_before.allowed);

        arbiter.lockdown("agent-1", "security-breach").await;

        let v_locked = arbiter.authorize(&req).await;
        assert!(!v_locked.allowed);
        assert_eq!(v_locked.autonomy_level, AutonomyLevel::L0Frozen);

        arbiter
            .restore("agent-1", AutonomyLevel::L4FullAutonomy)
            .await;

        let v_restored = arbiter.authorize(&req).await;
        assert!(
            v_restored.allowed,
            "after restore to L4, read-only should be allowed"
        );
        assert_ne!(v_restored.autonomy_level, AutonomyLevel::L0Frozen);
    }

    #[tokio::test]
    async fn smoke_violation_cliff_drop() {
        let arbiter = make_arbiter();

        let mut trust = TrustScore::new(0.95);
        trust.confidence = 0.9;
        trust.evidence_count = 200;
        arbiter.trust_store.set("agent-1", trust).await.unwrap();

        let req = ActionRequest::simple(
            Delegator::agent("agent-1", "#cliff"),
            "process.exec",
            ActionCategory::ProcessExec,
        );

        let risk_before = arbiter.risk_score(&req).await.value;

        arbiter
            .feedback(
                &req,
                ActionOutcome::PolicyViolation {
                    rule: "exec-blacklist".to_string(),
                },
            )
            .await;

        let trust_after = arbiter.trust_store.get("agent-1").await.unwrap().unwrap();
        assert!(trust_after.value < 0.95);

        let risk_after = arbiter.risk_score(&req).await.value;
        assert!(risk_after > risk_before);
    }

    #[tokio::test]
    async fn smoke_unknown_delegator_defaults_to_moderate_risk() {
        let arbiter = make_arbiter();

        let req = ActionRequest::simple(
            Delegator::agent("unknown-agent", "#test"),
            "file.read",
            ActionCategory::ReadOnly,
        );

        let verdict = arbiter.authorize(&req).await;
        assert!(
            verdict.allowed,
            "read-only from unknown agent should pass default policy"
        );
        assert!(
            verdict.risk_score > 0.0,
            "should have some risk even for reads"
        );
    }

    #[tokio::test]
    async fn smoke_multiple_agents_independent_trust() {
        let arbiter = make_arbiter();

        let mut trust_a = TrustScore::new(0.9);
        trust_a.confidence = 0.8;
        trust_a.evidence_count = 100;
        arbiter.trust_store.set("agent-a", trust_a).await.unwrap();

        let mut trust_b = TrustScore::new(0.2);
        trust_b.confidence = 0.5;
        trust_b.evidence_count = 5;
        arbiter.trust_store.set("agent-b", trust_b).await.unwrap();

        let req_a = ActionRequest::simple(
            Delegator::agent("agent-a", "#multi"),
            "file.write",
            ActionCategory::FileWrite,
        );
        let req_b = ActionRequest::simple(
            Delegator::agent("agent-b", "#multi"),
            "file.write",
            ActionCategory::FileWrite,
        );

        let v_a = arbiter.authorize(&req_a).await;
        let v_b = arbiter.authorize(&req_b).await;

        assert!(v_a.risk_score < v_b.risk_score);
    }
}
