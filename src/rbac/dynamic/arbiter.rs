//! The authorization arbiter: risk scoring, policy mapping and verdict creation.
//!
//! Fail-closed summary: a lockdown is checked before any scoring, only L3/L4
//! verdicts allow, an unmapped risk maps to L0, and trust-store or missing-evidence
//! failures only raise risk. Trust state is bounded by decay, mitigations are
//! advisory to the host, and verdicts are audited on a best-effort basis.
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
    trust::{TrustDecayHandle, TrustDecayWorker, TrustScore, TrustScoreStore},
    verdict::{ActionOutcome, AuthorizationVerdict, AutonomyLevel, RiskScore, Strategy, SubScores},
};
use crate::rbac::{
    audit::{AuditEntry, AuditLogger, AuditSubScores, AuditVerdict},
    shared::Shared,
};

/// Hard cap on the number of per-delegator anomaly detectors kept in memory
/// (threat model section 2.6). It is a resource-exhaustion bound, not a security
/// threshold: above it, delegators without a detector are charged
/// `DEFAULT_ANOMALY_SCORE_WHEN_AT_CAPACITY` instead of a real deviation. The map
/// only shrinks when `AuthorizationArbiter::restore` drops an entry, so once the
/// cap is reached new delegators stay undetected for the life of the process.
const MAX_ANOMALY_DETECTORS: usize = 10_000;

/// Anomaly score charged to a delegator whose detector could not be created
/// because the cap was reached.
///
/// It is deliberately above the 0.1 cold-start score, so a saturated arbiter errs
/// toward more risk (the threat model calls it a conservative default), but the
/// exact value has no derivation recorded in the repository (basis to be
/// confirmed with security review).
const DEFAULT_ANOMALY_SCORE_WHEN_AT_CAPACITY: f64 = 0.15;

/// Sentinel `evidence_count` written into the trust record by
/// `AuthorizationArbiter::lockdown`.
///
/// No code compares against this value; it is copied into the record so the next
/// `feedback` recomputes `confidence` from a large evidence count (about 0.91)
/// instead of collapsing toward zero, which keeps the near-zero post-lockdown
/// trust at full weight. The exact magnitude has no derivation recorded in the
/// repository (basis to be confirmed with security review).
const LOCKDOWN_EVIDENCE_COUNT: u64 = 999;

/// Risk-based authorization arbiter: the entry point of the dynamic layer.
///
/// `authorize` turns an `ActionRequest` into an `AuthorizationVerdict` by scoring
/// five dimensions, mapping the total risk to an autonomy level with the installed
/// `DynamicPolicy` and deriving `allowed` from that level (L3/L4 only). Every
/// failure path is meant to deny: a locked-down delegator is rejected before any
/// scoring, an unmapped risk maps to `L0Frozen`, a missing strategy degrades to
/// an explicit `Block` at lookup time, and a missing trust record or a lying trust
/// store can only raise the penalty.
/// The struct is `Clone`, but a clone shares the same trust store, detectors,
/// policy and frozen set (all behind `Arc`/`Shared`), so it is another handle to
/// the *same* authorization state, not an independent instance.
#[derive(Clone)]
pub struct AuthorizationArbiter {
    /// Trust records, the only source of the trust dimension; shared with every
    /// clone of this arbiter.
    trust_store: Shared<dyn TrustScoreStore>,
    /// Per-delegator behavioral state, capped at `max_detectors` to bound memory
    /// (threat model section 2.6).
    detectors: Arc<RwLock<HashMap<String, AnomalyDetector>>>,
    /// Cap applied to `detectors`; see `with_max_detectors`.
    max_detectors: usize,
    /// Domain confinement in force; `None` means the domain dimension contributes
    /// 0.0 and no `trust_floor` is applied.
    domain_scope: Arc<RwLock<Option<DomainScope>>>,
    /// Risk-to-level policy. Validated by `set_policy`, not by `new`, and read on
    /// every scoring call.
    policy: Arc<RwLock<DynamicPolicy>>,
    /// In-process lockdown set: the authoritative deny gate for lockdown, and
    /// deliberately not persisted, so it is lost on restart.
    frozen: Arc<RwLock<HashSet<String>>>,
    /// Optional audit logger. `None` means verdicts are computed and returned but
    /// never recorded anywhere, for allows and denies alike.
    audit: Option<Shared<AuditLogger>>,
}

/// Manual `Debug`: reports structure only (detector count, whether a domain scope
/// and an audit sink are configured, frozen count) and never trust values or
/// policy contents, so it is safe to log. The counts come from `try_read`, which
/// yields 0 / false under contention, so the output must not be used as a metric.
impl std::fmt::Debug for AuthorizationArbiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthorizationArbiter")
            .field(
                "detectors_count",
                &self.detectors.try_read().map_or(0, |d| d.len()),
            )
            .field(
                "has_domain_scope",
                &self.domain_scope.try_read().is_ok_and(|d| d.is_some()),
            )
            .field(
                "frozen_count",
                &self.frozen.try_read().map_or(0, |f| f.len()),
            )
            .field("has_audit", &self.audit.is_some())
            .finish_non_exhaustive()
    }
}

impl AuthorizationArbiter {
    /// Creates a new `AuthorizationArbiter`.
    ///
    /// Starts with no domain scope, no audit sink and an empty lockdown set, and
    /// with the detector cap at its built-in maximum. The `policy` argument is
    /// *not* validated here: an invalid policy silently rescales risk (weights
    /// that sum to 5.0 saturate every score), and only `set_policy` runs
    /// `DynamicPolicy::validate`. The trust store is wrapped in `Shared`, which is
    /// how clones of an arbiter end up sharing trust state.
    ///
    /// # Internal lock ordering
    ///
    /// Methods acquire internal locks in a consistent order to prevent deadlocks:
    /// 1. `frozen` (read or write)
    /// 2. `policy` (read)
    /// 3. `domain_scope` (read)
    /// 4. `detectors` (write)
    /// 5. `trust_store` (via async trait methods, external locking)
    ///
    /// Do **not** acquire these locks in a different order in any new method.
    #[must_use]
    pub fn new(trust_store: impl TrustScoreStore + 'static, policy: DynamicPolicy) -> Self {
        Self {
            trust_store: Shared::from_arc_unsized(Arc::new(trust_store)),
            detectors: Arc::new(RwLock::new(HashMap::new())),
            max_detectors: MAX_ANOMALY_DETECTORS,
            domain_scope: Arc::new(RwLock::new(None)),
            policy: Arc::new(RwLock::new(policy)),
            frozen: Arc::new(RwLock::new(HashSet::new())),
            audit: None,
        }
    }

    /// Sets the maximum number of anomaly detectors.
    /// When exceeded, new delegators will use a default anomaly score.
    ///
    /// Delegators that already have a detector keep it; only delegators without
    /// one are charged the fixed default (0.15, above the 0.1 cold-start value, so
    /// the fallback leans toward more risk) and a warning is logged. The cap is a
    /// resource-exhaustion bound: because the map only shrinks when `restore`
    /// drops an entry, a saturated arbiter leaves every further delegator without
    /// anomaly detection for the rest of the process, so size it for the expected
    /// number of distinct delegator ids. Setting `0` disables anomaly detection
    /// entirely.
    #[must_use]
    pub fn with_max_detectors(mut self, max: usize) -> Self {
        self.max_detectors = max;
        self
    }

    /// Installs the audit logger used for every verdict, and returns the arbiter
    /// (builder form).
    ///
    /// Without it, verdicts are returned to the caller and never recorded: allow
    /// and deny decisions are equally unlogged, so an arbiter without a sink fails
    /// open on the audit axis (audit durability is explicitly out of scope in
    /// `docs/THREAT_MODEL.md` section 3). Logging is best-effort and cannot change
    /// a decision: `AuditLogger::log` is infallible and alert-hook panics are
    /// caught inside the audit layer.
    #[must_use]
    pub fn with_audit(mut self, audit: AuditLogger) -> Self {
        self.audit = Some(Shared::new(audit));
        self
    }

    /// Installs the initial domain scope and returns the arbiter (builder form).
    ///
    /// It replaces rather than merges any existing scope, and it is configuration
    /// trusted by the host. A domain whose resource prefix list is empty imposes
    /// no resource confinement at all (see `TaskDomain::is_resource_allowed`);
    /// with no scope installed the domain dimension is charged 0.0 and no
    /// `trust_floor` applies, so the *default* is unconfined and a scope should be
    /// installed for any confined workload.
    #[must_use]
    pub fn with_domain_scope(mut self, scope: DomainScope) -> Self {
        self.domain_scope = Arc::new(RwLock::new(Some(scope)));
        self
    }

    /// Borrowed handle to the shared trust store, for direct reads and writes that
    /// bypass the arbiter.
    ///
    /// Writing through it changes future scoring with no evidence accounting, and
    /// reading it exposes per-delegator trust, so treat every caller as
    /// control-plane code with the same authority as `feedback`. Exposing this
    /// handle to request-handling code lets that code forge trust (raise it, or
    /// zero out another delegator's) without going through a verdict.
    #[must_use]
    pub fn trust_store(&self) -> &Shared<dyn TrustScoreStore> {
        &self.trust_store
    }

    /// Spawns the resilient trust-decay worker for this arbiter's store and
    /// returns its abort-on-drop handle.
    ///
    /// The interval is both the tick period and the amount of decay charged per
    /// tick, so it defines the staleness bound on trust. Keep the returned handle
    /// alive: dropping it stops decay immediately (see `TrustDecayHandle`), which
    /// silently removes that bound and lets stale trust keep granting autonomy.
    /// Requires a Tokio runtime; spawning panics outside one.
    pub fn spawn_trust_decay(&self, interval: std::time::Duration) -> TrustDecayHandle {
        let store = self.trust_store.clone_arc();
        TrustDecayWorker::spawn_resilient(store, interval)
    }

    /// Validates and installs a new policy; on failure the previous policy stays
    /// in force.
    ///
    /// `DynamicPolicy::validate` is the only gate. It checks the weight sum
    /// (within 0.05 of 1.0), individual weights, band ordering/ranges and that
    /// every banded level has a strategy, but it does not check band coverage, so
    /// a policy with gaps silently turns the uncovered risks into denies.
    ///
    /// Ordering caveat: `authorize` scores risk before it reads the policy, so a
    /// concurrent `set_policy` can pair a score produced under the old weights
    /// with the new bands -- a narrow window of mixed-policy verdicts, and one
    /// that is not necessarily fail-closed because weights and bands can move in
    /// either direction. A writer also waits for in-flight scoring to release the
    /// policy read lock (which is held across the trust-store lookup).
    ///
    /// # Errors
    ///
    /// Returns the validation error unchanged and writes nothing when the policy
    /// is invalid.
    pub async fn set_policy(&self, policy: DynamicPolicy) -> anyhow::Result<()> {
        policy.validate()?;
        let mut guard = self.policy.write().await;
        *guard = policy;
        Ok(())
    }

    /// Replaces the domain scope, with no validation at all (contrast
    /// `set_policy`).
    ///
    /// The scope is read on every `risk_score` call, so the change applies to
    /// requests scored after it and never re-scores a verdict that was already
    /// returned. There is no way to remove a scope once set, only to replace it,
    /// and a scope with empty resource prefix lists silently disables resource
    /// confinement for that domain.
    pub async fn set_domain_scope(&self, scope: DomainScope) {
        let mut guard = self.domain_scope.write().await;
        *guard = Some(scope);
    }

    /// Produces the authorization verdict for one action request.
    ///
    /// Decision order, which later refactors must preserve:
    /// 1. the in-process lockdown set is checked first and a frozen delegator is
    ///    denied outright (`allowed: false`, `L0Frozen`, risk 1.0) without scoring
    ///    or consulting the policy, so a lockdown cannot be outvoted by a good
    ///    score;
    /// 2. the risk is scored on five dimensions (which mutates the delegator's
    ///    anomaly window -- see `risk_score`);
    /// 3. the level comes from `DynamicPolicy::map_to_level` and `allowed` is true
    ///    only for `L4FullAutonomy` / `L3Conditional`;
    /// 4. `mitigation` carries the level's strategy for every denied verdict, and
    ///    for allowed verdicts only when that strategy is a `Throttle`.
    ///
    /// Every verdict is written to the audit logger when one is installed, on the
    /// lockdown path as well; the audit write cannot fail the decision.
    /// Mitigations are advisory to the host: this method does not rate-limit and
    /// does not request human confirmation, so ignoring `mitigation` silently
    /// upgrades a confirmation-gated verdict to plain access, and an L3 verdict is
    /// an allow whether or not its throttle is actually enforced.
    #[must_use]
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

    /// Scores a request on the five risk dimensions, without applying the policy
    /// thresholds, and returns the clamped total alongside the raw sub-scores.
    ///
    /// Dimension sources: `delegator_weight` from the delegator type (Human 0.0,
    /// Scheduler 0.02, Agent 0.05, SubAgent 0.15, ExternalSystem 0.30);
    /// `trust_penalty` is `1.0 - value * confidence` of the stored score, raised
    /// when the current domain's `trust_floor` is not met; `sensitivity` is the
    /// claimed category's base weight; `domain_mismatch` is the scope's excess
    /// weight (0.0 when no scope is installed); `anomaly` is the detector's
    /// deviation. The total is their weighted sum with
    /// `DynamicPolicy::dimension_weights`, clamped to `[0, 1]` (`NaN` is preserved
    /// and denied later by the policy's unmatched-band fallback).
    ///
    /// Fail-closed failure handling, none of which blocks the call: a trust-store
    /// `get` error is logged and scored as zero trust (maximum penalty); a missing
    /// trust record uses `TrustScore::default()`, which also yields zero trust; a
    /// delegator beyond the detector cap is charged the fixed 0.15 default. The
    /// trust store is authoritative when it answers, so a host that returns
    /// forged scores can lower the penalty, which is why store correctness is the
    /// host's responsibility (threat model section 3).
    ///
    /// Side effect and ordering caveat: this is not read-only. It observes the
    /// request in the delegator's anomaly detector, so calling it in addition to
    /// `authorize` (for logging, previews or tests) double-counts the action and
    /// skews the behavioral baseline. It reads the trust store while holding the
    /// policy read lock, so a slow or hanging store delays `set_policy`; the
    /// detector write lock is taken only afterwards.
    #[must_use]
    pub async fn risk_score(&self, request: &ActionRequest) -> RiskScore {
        let policy = self.policy.read().await;

        let delegator_weight = match request.delegator.delegator_type {
            DelegatorType::Human => 0.0,
            DelegatorType::Agent => 0.05,
            DelegatorType::SubAgent => 0.15,
            DelegatorType::ExternalSystem => 0.30,
            DelegatorType::Scheduler => 0.02,
        };

        let trust = match self.trust_store.get(&request.delegator.id).await {
            Ok(Some(score)) => score,
            Ok(None) => TrustScore::default(),
            Err(e) => {
                tracing::warn!(target: "kirino::dynamic::arbiter",
                    delegator_id = %request.delegator.id,
                    error = %e,
                    "trust store unavailable, using conservative trust penalty"
                );
                TrustScore {
                    value: 0.0,
                    confidence: 1.0,
                    ..TrustScore::default()
                }
            }
        };
        let mut trust_penalty = (1.0 - trust.weighted()).clamp(0.0, 1.0);

        let sensitivity = request.category.base_weight();

        let domain_mismatch = {
            let scope_guard = self.domain_scope.read().await;
            match scope_guard.as_ref() {
                Some(scope) => {
                    let mism = scope
                        .evaluate(&request.category, request.resource_path.as_deref())
                        .excess_weight();

                    let floor = scope.current_task_domain.trust_floor;
                    if floor > 0.0 {
                        let weighted = trust.weighted();
                        if weighted < floor {
                            let penalty = (floor - weighted).clamp(0.0, 1.0);
                            trust_penalty = (trust_penalty + penalty).min(1.0);
                        }
                    }

                    mism
                }
                None => 0.0,
            }
        };

        let anomaly = {
            let mut detectors = self.detectors.write().await;
            let detector = if detectors.len() >= self.max_detectors
                && !detectors.contains_key(&request.delegator.id)
            {
                tracing::warn!(target: "kirino::dynamic::arbiter",
                    delegator_id = %request.delegator.id,
                    max = self.max_detectors,
                    "anomaly detector limit reached, using default score"
                );
                None
            } else {
                Some(
                    detectors
                        .entry(request.delegator.id.clone())
                        .or_insert_with(AnomalyDetector::default),
                )
            };
            match detector {
                Some(d) => d.observe(request).value,
                None => DEFAULT_ANOMALY_SCORE_WHEN_AT_CAPACITY,
            }
        };

        let raw = delegator_weight * policy.dimension_weights[0]
            + trust_penalty * policy.dimension_weights[1]
            + sensitivity * policy.dimension_weights[2]
            + domain_mismatch * policy.dimension_weights[3]
            + anomaly * policy.dimension_weights[4];

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

    /// Records the observed outcome of a previously authorized action and updates
    /// the delegator's trust score accordingly.
    ///
    /// Severity mapping: `Success` is compliant 0.5 (+0.005 trust), `Failure` is a
    /// violation of 0.2 (-0.02), `PolicyViolation` a violation of 0.8 (-0.08), and
    /// `Anomalous` uses its `deviation` verbatim as the violation severity (not
    /// clamped, so it must be in `[0, 1]`).
    ///
    /// Who may call it: this is a privileged control-plane operation. The outcome
    /// is taken on faith and the delegator id comes from the caller's request, so
    /// an untrusted caller could inflate trust with invented successes or deflate
    /// another delegator's trust by naming its id. Only report outcomes actually
    /// observed by the enforcement point.
    ///
    /// Failure handling: a `get` error falls back to `TrustScore::default()`, so
    /// the outcome is applied to a fresh record and then written back -- a
    /// transient store blip therefore *resets* accumulated trust (fail-closed but
    /// lossy, and a denial-of-service on that delegator). A `set` error is logged
    /// and dropped, which leaves the previous score in force and can keep a more
    /// permissive trust level alive than the outcome implies. Outcome payloads
    /// (`error`, `rule`) are not stored by this call; the caller must log them.
    pub async fn feedback(&self, request: &ActionRequest, outcome: ActionOutcome) {
        let mut trust = self
            .trust_store
            .get(&request.delegator.id)
            .await
            .map_err(|e| tracing::warn!("trust store get failed (feedback): {e}"))
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

        if let Err(e) = self.trust_store.set(&request.delegator.id, trust).await {
            tracing::error!(target: "kirino::dynamic::arbiter",
                delegator_id = %request.delegator.id,
                error = %e,
                "failed to persist trust score after feedback"
            );
        }
    }

    /// Freezes a delegator to L0: every later `authorize` call for that id is
    /// denied with risk 1.0, regardless of policy, trust or domain state.
    ///
    /// Enforcement is the in-process `frozen` set, so it takes effect immediately
    /// and cannot be outvoted -- but it is *not* persisted: after a restart the
    /// entry is gone and the delegator is scored normally again, with only the
    /// persisted near-zero trust raising its risk. Re-apply lockdowns from durable
    /// state at startup if they must survive a restart. Also note that the arbiter
    /// does not check who calls this, so exposing it to request handling lets any
    /// caller freeze any delegator (a denial-of-service) -- gate it behind an
    /// operator/admin permission.
    ///
    /// The trust record is written best-effort (`value` 0.0, `confidence` 1.0,
    /// `evidence_count` 999): a store failure is logged and does not weaken the
    /// in-process freeze. `reason` is only logged, never stored on the verdict.
    pub async fn lockdown(&self, delegator_id: &str, reason: &str) {
        {
            let mut frozen = self.frozen.write().await;
            frozen.insert(delegator_id.to_string());
        }

        let mut trust = TrustScore::new(0.0);
        trust.confidence = 1.0;
        trust.evidence_count = LOCKDOWN_EVIDENCE_COUNT;
        if let Err(e) = self.trust_store.set(delegator_id, trust).await {
            tracing::error!(target: "kirino::dynamic::arbiter",
                delegator_id = delegator_id,
                error = %e,
                "failed to persist lockdown trust score"
            );
        }

        tracing::warn!(target: "kirino::dynamic::arbiter",
            delegator_id = delegator_id,
            reason = reason,
            "agent locked down to L0"
        );
    }

    /// Lifts a lockdown and re-seeds the delegator's trust from `target`.
    ///
    /// Operator control with no authorization check inside (see `lockdown`), so
    /// the host must gate it. Effects, in order: the id is removed from the frozen
    /// set, a fresh score is written (`L4` 0.95, `L3` 0.8, `L2` 0.6, `L1` 0.4,
    /// `L0` 0.1, with `confidence` forced to 0.8 and `evidence_count` 10), and the
    /// delegator's anomaly detector is dropped, so its behavioral baseline is
    /// re-learned from scratch.
    ///
    /// Caveats operators should expect: the seeded confidence is not durable,
    /// because the next `feedback` recomputes `confidence` from `evidence_count`
    /// (10) and collapses it to about 0.10, multiplying the seeded value down, so
    /// a restore is a temporary reprieve unless evidence accumulates.
    /// `restore(.., L0Frozen)` does *not* deny: it unfreezes with a 0.1 seed, and
    /// the delegator is then scored normally. Dropping the baseline also means
    /// anomaly-based containment is blind right after a restore (the next 100
    /// observations contribute only the cold-start 0.1), so risk is dominated by
    /// trust, sensitivity and domain in that window.
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
        trust.confidence = 0.8;
        trust.evidence_count = 10;
        if let Err(e) = self.trust_store.set(delegator_id, trust).await {
            tracing::error!(target: "kirino::dynamic::arbiter",
                delegator_id = delegator_id,
                error = %e,
                "failed to persist restored trust score"
            );
        }

        let mut detectors = self.detectors.write().await;
        detectors.remove(delegator_id);

        tracing::info!(target: "kirino::dynamic::arbiter",
            delegator_id = delegator_id,
            target_level = %target,
            "agent restored to level"
        );
    }

    /// Returns a JSON snapshot of one delegator's dynamic-authz state: the frozen
    /// flag, effective trust, confidence, evidence count, whether the anomaly
    /// baseline is ready, and a constant `"enabled": true` (this subsystem has no
    /// disable switch).
    ///
    /// Read-only, and deliberately explicit about failures: when the trust store
    /// errors it reports `trust_store_ok: false` alongside a *default* (zero) trust
    /// score, so consumers must check `trust_store_ok` before drawing conclusions
    /// from `trust_score` or `trust_confidence`. `frozen` reflects only this
    /// process (a lockdown in another replica is invisible here), and
    /// `anomaly_baseline_ready` is false for delegators without a detector (for
    /// example above the detector cap, or right after `restore`). The payload
    /// contains the delegator id, so treat it as operator-facing data and gate
    /// access to it.
    #[must_use]
    pub async fn status_summary(&self, delegator_id: &str) -> serde_json::Value {
        let (trust, store_ok) = match self.trust_store.get(delegator_id).await {
            Ok(Some(score)) => (score, true),
            Ok(None) => (TrustScore::default(), true),
            Err(e) => {
                tracing::warn!(target: "kirino::dynamic::arbiter",
                    delegator_id = delegator_id,
                    error = %e,
                    "trust store unavailable for status summary"
                );
                (TrustScore::default(), false)
            }
        };
        let frozen = self.frozen.read().await.contains(delegator_id);
        let detectors = self.detectors.read().await;
        let anomaly_ready = detectors
            .get(delegator_id)
            .is_some_and(super::anomaly::AnomalyDetector::is_baseline_ready);
        serde_json::json!({
            "enabled": true,
            "delegator_id": delegator_id,
            "frozen": frozen,
            "trust_store_ok": store_ok,
            "trust_score": trust.weighted(),
            "trust_confidence": trust.confidence,
            "trust_evidence_count": trust.evidence_count,
            "anomaly_baseline_ready": anomaly_ready,
        })
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
                    mitigation: verdict.mitigation.as_ref().map(|s| s.to_string()),
                }),
            };
            let alerts = audit.log(entry).await;
            if !alerts.is_empty() {
                tracing::debug!(target: "kirino::dynamic::arbiter",
                    alert_count = alerts.len(),
                    "audit alerts fired for dynamic authorization verdict"
                );
            }
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

        assert!((risk.sub_scores.delegator_weight - 0.05).abs() < 1e-10);

        assert!(risk.sub_scores.trust_penalty > 0.0);
        assert!((risk.sub_scores.sensitivity - 0.5).abs() < 1e-10);
        assert!((risk.sub_scores.domain_mismatch).abs() < 1e-10);
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
        assert!(
            !verdict.evidence.is_empty(),
            "evidence should be populated after authorize"
        );
        assert!(
            verdict.evidence[0].contains("risk="),
            "evidence should contain risk info"
        );
        assert!(verdict.timestamp.timestamp() > 0, "timestamp should be set");
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
        arbiter.set_policy(strict_policy).await.unwrap();

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
