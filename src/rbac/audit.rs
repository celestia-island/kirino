use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
};
use tokio::sync::RwLock;

type AlertHook = Box<dyn Fn(AuditAlert) + Send + Sync>;

#[derive(Debug, Clone, Serialize, Deserialize)]
/// One recorded authorization decision - the unit of audit evidence.
///
/// Appended by [`AuditLogger::log`] before any rule runs, so a decision is on
/// record even when no [`AuditRule`] matches. `granted == false` is the signal
/// policy rules and analyzers key on. The sink, not the caller, owns identity:
/// [`AuditSink::append`] assigns `id`, so treat any pre-set value as advisory.
pub struct AuditEntry {
    /// Sink-assigned identifier, unique within one [`AuditSink`] instance.
    pub id: u64,
    /// Opaque id of the acting subject; the join key for per-subject queries.
    pub subject_id: String,
    /// Subject kind (for example `user` or `agent`); attribution, not a trust claim.
    pub subject_type: String,
    /// The permission that was checked, in the checker's own wire form.
    pub permission: String,
    /// Entry point that requested the check; correlates a denial burst with one API surface.
    pub endpoint: String,
    /// The decision. `false` (a denial) is the security-relevant case rules act on.
    pub granted: bool,
    /// Decision time (UTC). Recency queries sort on this field, not on `id`.
    pub created_at: DateTime<Utc>,
    /// Risk verdict when the entry was scored; `None` means unscored, never "safe".
    pub verdict: Option<AuditVerdict>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Dynamic-authorization verdict attached to an [`AuditEntry`].
///
/// Produced by `rbac::dynamic` (risk score plus the autonomy level it mapped to).
/// It is advisory evidence only and never grants anything by itself.
pub struct AuditVerdict {
    /// Autonomy level the risk score mapped to (see `rbac::dynamic::verdict`).
    pub autonomy_level: String,
    /// Overall risk in `[0.0, 1.0]`; [`AuditEntry::is_high_risk`] cuts at 0.6.
    pub risk_score: f64,
    /// Per-factor breakdown backing `risk_score`; kept so alerts stay explainable.
    pub sub_scores: AuditSubScores,
    /// Human-readable reasons for the score. Never put credentials, tokens or
    /// password material here: audit entries are persisted and exported.
    pub evidence: Vec<String>,
    /// Mitigation applied to the decision, if any; `None` means it stood unmitigated.
    pub mitigation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The per-factor contributions that produced an [`AuditVerdict`] risk score.
///
/// Kept for attribution: an investigator needs to know whether risk came from
/// trust decay, resource sensitivity, domain mismatch, delegation weight or
/// anomaly - not just the total.
pub struct AuditSubScores {
    /// Risk contributed by the delegator's privilege level.
    pub delegator_weight: f64,
    /// Risk contributed by trust decay; `1.0 - trust_penalty` is the trust score
    /// compared by [`AuditCondition::TrustBelow`].
    pub trust_penalty: f64,
    /// Risk contributed by the target resource's sensitivity category.
    pub sensitivity: f64,
    /// Risk contributed by acting outside the delegator's task domain.
    pub domain_mismatch: f64,
    /// Risk contributed by behavioral anomaly detection against the subject baseline.
    pub anomaly: f64,
}

impl AuditEntry {
    /// Whether this entry records a denial.
    ///
    /// Denials are what alert rules and [`AuditCondition::Denied`] act on, and what
    /// [`AuditAnalysisResult::denied_rate`] counts; prefer this predicate over
    /// reading `granted` directly.
    #[must_use]
    pub fn is_denied(&self) -> bool {
        !self.granted
    }

    /// Whether the entry carries a risk verdict at or above the high-risk cut (0.6).
    ///
    /// Triage helper only: the authoritative threshold is the one on each
    /// deployment's [`AuditCondition::HighRisk`] rule, which may differ. An entry
    /// with no verdict is never high risk - unscored is not the same as safe.
    #[must_use]
    pub fn is_high_risk(&self) -> bool {
        self.verdict.as_ref().is_some_and(|v| v.risk_score >= 0.6)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Side effect a matched [`AuditRule`] asks for.
///
/// Actions are observability and response only: they run after the decision has
/// been recorded and must never feed back into [`AuditEntry::granted`]. Keep
/// alert text and `params` free of credentials - alerts are exported to
/// operators and log sinks.
pub enum AuditAction {
    /// Emit a human-facing alert carrying `message` at `severity`.
    Alert {
        message: String,
        severity: AuditSeverity,
    },
    /// Notify a specific `target` (webhook, queue, chat channel) with `message`.
    Notify { target: String, message: String },
    /// Request an automated response named `action` with `params`.
    ///
    /// Deliberately free-form: the audit subsystem records the request, it does
    /// not execute countermeasures.
    Countermeasure {
        action: String,
        params: HashMap<String, String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
/// Triage level of an alert; carries no authorization weight on its own.
pub enum AuditSeverity {
    /// Informational - recorded, not paged.
    Info,
    /// Needs operator attention at the next opportunity.
    Warning,
    /// Urgent; assume an active or attempted compromise until triaged.
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// A policy rule: when `condition` holds and the cooldown has elapsed, `action` runs.
///
/// Rules observe already-recorded decisions, so a disabled or broken rule
/// degrades detection but never enforcement. `cooldown_secs` suppresses per rule
/// id, not per subject, and a suppressed match is not re-evaluated: a long
/// cooldown can hide a later, more severe match for the same rule.
pub struct AuditRule {
    /// Stable rule id; the cooldown key and what [`AuditAlert::rule_id`] reports.
    pub id: String,
    /// Operator-facing rule name, used in alert text and panic logs.
    pub name: String,
    /// Disabled rules are skipped entirely: no evaluation and no cooldown update.
    pub enabled: bool,
    /// Predicate selecting the entries this rule reacts to.
    pub condition: AuditCondition,
    /// What to do when the rule fires; it cannot change the triggering decision.
    pub action: AuditAction,
    /// Minimum seconds between two firings of this rule id; `0` fires on every match.
    pub cooldown_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Predicate over a single [`AuditEntry`], evaluated by [`AuditPolicyEngine::evaluate`].
///
/// Every variant except [`AuditCondition::RapidDenials`] is a pure function of one
/// entry. An unscored entry (`verdict: None`) fails each risk-based condition, so
/// treat a missing verdict as "unknown, not safe" when writing rules.
pub enum AuditCondition {
    /// Matches every denial.
    Denied,
    /// Matches entries whose `risk_score` is at or above `threshold`.
    ///
    /// The threshold lives on the rule so deployments can tune it without touching
    /// the scoring engine; it is unrelated to [`AuditEntry::is_high_risk`]'s 0.6.
    HighRisk { threshold: f64 },
    /// Matches entries whose resource-sensitivity sub-score is at or above `min_weight`.
    CategorySensitive { min_weight: f64 },
    /// Matches entries whose domain-mismatch sub-score is at or above `min_weight`.
    DomainMismatch { min_weight: f64 },
    /// Matches when the subject accumulated `min_count` denials within `window_secs`.
    ///
    /// The one history-dependent condition: it needs the [`AuditSink`] the policy
    /// engine was built with, and [`AuditCondition::evaluate`] alone always returns
    /// `false` for it. An engine without a sink therefore never fires it - a silent
    /// detection gap, not a fail-closed default.
    RapidDenials { window_secs: u64, min_count: u32 },
    /// Matches when the entry's trust score (`1.0 - trust_penalty`) is at or below `threshold`.
    ///
    /// Note the polarity: a low trust score matches. An unscored entry has no trust
    /// reading and never matches.
    TrustBelow { threshold: f64 },
    /// Combines sub-conditions with `operator` (all / any).
    ///
    /// Degenerate cases follow `Iterator::all`/`any`: an empty `All` matches
    /// everything, an empty `Any` matches nothing.
    Composite {
        conditions: Vec<AuditCondition>,
        operator: LogicalOp,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
/// Boolean connective for [`AuditCondition::Composite`].
pub enum LogicalOp {
    /// Fire only when every sub-condition matches.
    All,
    /// Fire when at least one sub-condition matches.
    Any,
}

impl AuditCondition {
    /// Evaluate the condition against one entry; `true` means the rule fires.
    ///
    /// Pure and side-effect free: it must not touch the sink, which is why
    /// [`AuditCondition::RapidDenials`] always returns `false` here and is resolved
    /// by [`AuditPolicyEngine::evaluate`] instead. Keep it pure - the condition may
    /// be evaluated for entries that are never persisted.
    #[must_use]
    pub fn evaluate(&self, entry: &AuditEntry) -> bool {
        match self {
            AuditCondition::Denied => entry.is_denied(),
            AuditCondition::HighRisk { threshold } => entry
                .verdict
                .as_ref()
                .is_some_and(|v| v.risk_score >= *threshold),
            AuditCondition::CategorySensitive { min_weight } => entry
                .verdict
                .as_ref()
                .is_some_and(|v| v.sub_scores.sensitivity >= *min_weight),
            AuditCondition::DomainMismatch { min_weight } => entry
                .verdict
                .as_ref()
                .is_some_and(|v| v.sub_scores.domain_mismatch >= *min_weight),
            // RapidDenials cannot be evaluated at the condition level because it
            // requires access to the AuditSink. Evaluation happens in
            // InMemoryAuditPolicyEngine::evaluate which has access to the sink.
            AuditCondition::RapidDenials { .. } => false,
            AuditCondition::TrustBelow { threshold } => entry.verdict.as_ref().is_some_and(|v| {
                let trust = 1.0 - v.sub_scores.trust_penalty;
                trust <= *threshold
            }),
            AuditCondition::Composite {
                conditions,
                operator,
            } => match operator {
                LogicalOp::All => conditions.iter().all(|c| c.evaluate(entry)),
                LogicalOp::Any => conditions.iter().any(|c| c.evaluate(entry)),
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// A fired rule: what matched, what to do about it, and the evidence.
///
/// Delivered to hooks registered with [`AuditLogger::on_alert`]. A hook is
/// arbitrary caller code, so it must not be able to fail the audit write, and its
/// output is never the authorization decision.
pub struct AuditAlert {
    /// Id of the rule that fired (also its cooldown key).
    pub rule_id: String,
    /// Name of the rule that fired, for operator-facing text.
    pub rule_name: String,
    /// The action the rule asked for; dispatching it is the consumer's job.
    pub action: AuditAction,
    /// Snapshot of the matching entry, so the alert stays meaningful after retention
    /// evicts the original from the sink.
    pub triggering_entry: Box<AuditEntry>,
    /// When the rule fired (UTC), not when the underlying decision was made.
    pub created_at: DateTime<Utc>,
}

/// Storage for audit entries.
///
/// Implementations must attempt to persist every appended entry and must not fail
/// or block the caller: `append` returns nothing, so a sink that cannot write is
/// expected to record that internally (log/metric) rather than drop it silently.
/// `query` and `count` must agree with what `append` accepted; retention belongs to
/// the sink, so callers cannot assume an entry survives forever.
#[async_trait::async_trait]
pub trait AuditSink: Send + Sync {
    /// Persist one decision. Idempotence is not required; the sink assigns `id`.
    async fn append(&self, entry: AuditEntry);
    /// Return matching entries newest first; `filter.limit` is applied here.
    async fn query(&self, filter: &AuditFilter) -> Vec<AuditEntry>;
    /// Count matching entries without materializing them.
    async fn count(&self, filter: &AuditFilter) -> u64;
}

#[derive(Debug, Clone, Default)]
/// Selector for [`AuditSink::query`] and [`AuditSink::count`].
///
/// Every field is optional and `Default` matches everything; the fields combine
/// conjunctively (AND), there is no OR form. `min_risk` compares an unscored
/// entry against 0.0, so a bound above zero excludes entries with no verdict.
pub struct AuditFilter {
    /// Restrict to one subject id.
    pub subject_id: Option<String>,
    /// Restrict to grants (`true`) or denials (`false`).
    pub granted: Option<bool>,
    /// Restrict to one permission string (exact match, no wildcards).
    pub permission: Option<String>,
    /// Inclusive lower bound on `created_at`.
    pub since: Option<DateTime<Utc>>,
    /// Inclusive upper bound on `created_at`.
    pub until: Option<DateTime<Utc>>,
    /// Inclusive lower bound on `risk_score`; an entry with no verdict reads as 0.0.
    pub min_risk: Option<f64>,
    /// Cap on returned entries, applied after sorting newest first; `count` ignores it.
    pub limit: Option<usize>,
}

/// Evaluates [`AuditRule`]s against entries and reports the ones that fired.
///
/// Implementations own their rule state, including per-rule cooldown timestamps,
/// so two engines loaded with the same rules can both fire - cooldown is local,
/// not global. Rule changes made through this trait are not persisted.
#[async_trait::async_trait]
pub trait AuditPolicyEngine: Send + Sync {
    /// Evaluate every enabled rule against `entry` and return the alerts that fired.
    ///
    /// Must not mutate the entry: it has already been persisted by the caller.
    async fn evaluate(&self, entry: &AuditEntry) -> Vec<AuditAlert>;
    /// Append a rule. A duplicate `id` is not rejected, and each copy keeps its own
    /// cooldown slot.
    async fn add_rule(&self, rule: AuditRule);
    /// Remove every rule with `rule_id`; `Ok(false)` means nothing matched.
    async fn remove_rule(&self, rule_id: &str) -> Result<bool>;
    /// Snapshot of the current rules; mutating the returned vector does not affect
    /// the engine.
    async fn list_rules(&self) -> Vec<AuditRule>;
}

/// Computes aggregate statistics over a batch of entries.
///
/// Read-only and advisory: analysis summarizes what the sink already holds and must
/// never be used as an authorization input.
#[async_trait::async_trait]
pub trait AuditAnalyzer: Send + Sync {
    /// Summarize one batch. The batch is a snapshot; results do not update later.
    async fn analyze(&self, entries: &[AuditEntry]) -> AuditAnalysisResult;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Summary an [`AuditAnalyzer`] produced over one batch of entries.
///
/// A one-shot snapshot, not a live view. `top_risk_entries` is capped by the
/// analyzer (10 for [`DefaultAuditAnalyzer`]), so it is not the full denial set.
pub struct AuditAnalysisResult {
    /// Number of entries in the analyzed batch.
    pub total_entries: u64,
    /// Denials in the batch.
    pub denied_count: u64,
    /// `denied_count / total_entries`, or 0.0 for an empty batch.
    pub denied_rate: f64,
    /// Entries at or above the analyzer's high-risk cut (0.6).
    pub high_risk_count: u64,
    /// Per-subject rollup, keyed by subject id.
    pub by_subject: HashMap<String, SubjectStats>,
    /// Decision counts per permission string, grants and denials combined.
    pub by_permission: HashMap<String, u64>,
    /// Highest-risk entries, descending, capped by the analyzer.
    pub top_risk_entries: Vec<AuditEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Per-subject aggregate inside an [`AuditAnalysisResult`].
pub struct SubjectStats {
    /// Decisions recorded for this subject in the batch.
    pub total: u64,
    /// Denials among them.
    pub denied: u64,
    /// Mean risk across the subject's entries (unscored entries count as 0.0).
    pub avg_risk: f64,
    /// Highest risk seen for this subject.
    pub max_risk: f64,
}

// Retention cap for the in-memory sink. Matches the same 10k bound used by
// `TtlPermissionCache` and the login rate limiter, so one process's in-memory
// security state has a single, predictable ceiling.
const DEFAULT_MAX_AUDIT_ENTRIES: usize = 10000;

/// Bounded in-memory [`AuditSink`] backed by a ring buffer.
///
/// On overflow the oldest entries are dropped, so this sink is neither durable nor
/// tamper-evident: it is for tests, examples and single-process deployments that
/// ship entries elsewhere. Size `max_entries` so the retention window covers the
/// longest investigation you need; evidence beyond it is gone.
pub struct InMemoryAuditSink {
    entries: RwLock<VecDeque<AuditEntry>>,
    next_id: std::sync::atomic::AtomicU64,
    max_entries: usize,
}

impl InMemoryAuditSink {
    /// Create a sink retaining the default maximum of 10 000 entries.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(VecDeque::new()),
            next_id: std::sync::atomic::AtomicU64::new(1),
            max_entries: DEFAULT_MAX_AUDIT_ENTRIES,
        }
    }

    /// Create a sink retaining at most `max_entries` entries, evicting oldest first.
    ///
    /// The bound is the whole retention policy: there is no time-based expiry, so a
    /// quiet system keeps entries indefinitely.
    #[must_use]
    pub fn with_max_entries(max_entries: usize) -> Self {
        Self {
            entries: RwLock::new(VecDeque::new()),
            next_id: std::sync::atomic::AtomicU64::new(1),
            max_entries,
        }
    }
}

impl Default for InMemoryAuditSink {
    fn default() -> Self {
        Self::new()
    }
}

fn matches_filter(entry: &AuditEntry, filter: &AuditFilter) -> bool {
    if let Some(ref sid) = filter.subject_id {
        if entry.subject_id != *sid {
            return false;
        }
    }
    if let Some(g) = filter.granted {
        if entry.granted != g {
            return false;
        }
    }
    if let Some(ref perm) = filter.permission {
        if entry.permission != *perm {
            return false;
        }
    }
    if let Some(since) = filter.since {
        if entry.created_at < since {
            return false;
        }
    }
    if let Some(until) = filter.until {
        if entry.created_at > until {
            return false;
        }
    }
    if let Some(min_risk) = filter.min_risk {
        let risk = entry.verdict.as_ref().map_or(0.0, |v| v.risk_score);
        if risk < min_risk {
            return false;
        }
    }
    true
}

#[async_trait::async_trait]
impl AuditSink for InMemoryAuditSink {
    async fn append(&self, mut entry: AuditEntry) {
        let mut entries = self.entries.write().await;
        let id = self
            .next_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        entry.id = id;
        entries.push_back(entry);
        while entries.len() > self.max_entries {
            entries.pop_front();
        }
    }

    async fn query(&self, filter: &AuditFilter) -> Vec<AuditEntry> {
        let entries = self.entries.read().await;
        let mut result: Vec<AuditEntry> = entries
            .iter()
            .filter(|e| matches_filter(e, filter))
            .cloned()
            .collect();

        result.sort_by_key(|b| std::cmp::Reverse(b.created_at));
        if let Some(limit) = filter.limit {
            result.truncate(limit);
        }
        result
    }

    async fn count(&self, filter: &AuditFilter) -> u64 {
        let entries = self.entries.read().await;
        entries.iter().filter(|e| matches_filter(e, filter)).count() as u64
    }
}

/// Rule engine with in-memory rules, cooldown state and an optional [`AuditSink`].
///
/// Holds no persistence - [`AuditPolicyEngine::add_rule`] affects this instance
/// only. Without a sink the history-dependent [`AuditCondition::RapidDenials`] can
/// never fire, so a deployment relying on it must use
/// [`InMemoryAuditPolicyEngine::with_sink`].
pub struct InMemoryAuditPolicyEngine {
    rules: RwLock<Vec<AuditRule>>,
    last_triggered: RwLock<HashMap<String, DateTime<Utc>>>,
    sink: Option<Arc<dyn AuditSink>>,
}

impl InMemoryAuditPolicyEngine {
    /// Create an engine with no rules and no sink (RapidDenials cannot fire).
    #[must_use]
    pub fn new() -> Self {
        Self {
            rules: RwLock::new(Vec::new()),
            last_triggered: RwLock::new(HashMap::new()),
            sink: None,
        }
    }

    /// Create an engine that resolves history-dependent conditions against `sink`.
    ///
    /// The sink is also the source RapidDenials counts from, so it should be the same
    /// sink the decisions are written to; otherwise the rule counts a different history.
    #[must_use]
    pub fn with_sink(sink: Arc<dyn AuditSink>) -> Self {
        Self {
            rules: RwLock::new(Vec::new()),
            last_triggered: RwLock::new(HashMap::new()),
            sink: Some(sink),
        }
    }
}

impl Default for InMemoryAuditPolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl AuditPolicyEngine for InMemoryAuditPolicyEngine {
    async fn evaluate(&self, entry: &AuditEntry) -> Vec<AuditAlert> {
        let rules_snapshot = {
            let rules = self.rules.read().await;
            rules.clone()
        };

        let mut last_triggered_snapshot = {
            let last_triggered = self.last_triggered.read().await;
            last_triggered.clone()
        };

        let now = Utc::now();
        let mut alerts = Vec::new();

        for rule in &rules_snapshot {
            if !rule.enabled {
                continue;
            }

            if let Some(&last_time) = last_triggered_snapshot.get(&rule.id) {
                let elapsed_secs = (now - last_time).num_seconds();
                if elapsed_secs < 0 || (elapsed_secs as u64) < rule.cooldown_secs {
                    continue;
                }
            }

            let matched = match &rule.condition {
                AuditCondition::RapidDenials {
                    window_secs,
                    min_count,
                } => {
                    if let Some(ref sink) = self.sink {
                        let window_secs_i64 = i64::try_from(*window_secs).unwrap_or(i64::MAX);
                        let since = now - chrono::Duration::seconds(window_secs_i64);
                        let filter = AuditFilter {
                            subject_id: Some(entry.subject_id.clone()),
                            granted: Some(false),
                            since: Some(since),
                            ..Default::default()
                        };
                        let query_len = sink.count(&filter).await as usize;
                        query_len >= (*min_count as usize)
                    } else {
                        false
                    }
                }
                other => other.evaluate(entry),
            };

            if matched {
                last_triggered_snapshot.insert(rule.id.clone(), now);
                alerts.push(AuditAlert {
                    rule_id: rule.id.clone(),
                    rule_name: rule.name.clone(),
                    action: rule.action.clone(),
                    triggering_entry: Box::new(entry.clone()),
                    created_at: now,
                });
            }
        }

        {
            let mut last_triggered = self.last_triggered.write().await;
            for (id, time) in &last_triggered_snapshot {
                last_triggered.insert(id.clone(), *time);
            }
        }

        alerts
    }

    async fn add_rule(&self, rule: AuditRule) {
        let mut rules = self.rules.write().await;
        rules.push(rule);
    }

    async fn remove_rule(&self, rule_id: &str) -> Result<bool> {
        let mut rules = self.rules.write().await;
        let before = rules.len();
        rules.retain(|r| r.id != rule_id);
        Ok(rules.len() < before)
    }

    async fn list_rules(&self) -> Vec<AuditRule> {
        let rules = self.rules.read().await;
        rules.clone()
    }
}

/// Stateless [`AuditAnalyzer`] computing the bundled summary statistics.
///
/// Counts denials and high-risk entries (risk >= 0.6) and keeps the ten riskiest
/// entries, so the result is a triage aid rather than a complete denial inventory.
pub struct DefaultAuditAnalyzer;

impl DefaultAuditAnalyzer {
    /// Create the analyzer; it holds no state, so one instance serves every query.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for DefaultAuditAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl AuditAnalyzer for DefaultAuditAnalyzer {
    async fn analyze(&self, entries: &[AuditEntry]) -> AuditAnalysisResult {
        let total = entries.len() as u64;
        let denied_count = entries.iter().filter(|e| e.is_denied()).count() as u64;
        let high_risk_count = entries.iter().filter(|e| e.is_high_risk()).count() as u64;

        let mut by_subject: HashMap<String, SubjectStats> = HashMap::new();
        let mut by_permission: HashMap<String, u64> = HashMap::new();
        let mut top_risk: Vec<AuditEntry> = entries.to_vec();

        for entry in entries {
            let stats = by_subject
                .entry(entry.subject_id.clone())
                .or_insert_with(|| SubjectStats {
                    total: 0,
                    denied: 0,
                    avg_risk: 0.0,
                    max_risk: 0.0,
                });
            stats.total += 1;
            if entry.is_denied() {
                stats.denied += 1;
            }
            let risk = entry.verdict.as_ref().map_or(0.0, |v| v.risk_score);
            stats.avg_risk += risk;
            stats.max_risk = stats.max_risk.max(risk);

            *by_permission.entry(entry.permission.clone()).or_insert(0) += 1;
        }

        for stats in by_subject.values_mut() {
            if stats.total > 0 {
                #[allow(clippy::cast_precision_loss)]
                {
                    stats.avg_risk /= stats.total as f64;
                }
            }
        }

        top_risk.sort_by(|a, b| {
            let ra = a.verdict.as_ref().map_or(0.0, |v| v.risk_score);
            let rb = b.verdict.as_ref().map_or(0.0, |v| v.risk_score);
            rb.partial_cmp(&ra).unwrap_or(std::cmp::Ordering::Equal)
        });
        top_risk.truncate(10);

        AuditAnalysisResult {
            total_entries: total,
            denied_count,
            denied_rate: if total > 0 {
                #[allow(clippy::cast_precision_loss)]
                {
                    denied_count as f64 / total as f64
                }
            } else {
                0.0
            },
            high_risk_count,
            by_subject,
            by_permission,
            top_risk_entries: top_risk,
        }
    }
}

/// Audit front door: persist a decision, evaluate policy, dispatch alerts.
///
/// [`AuditLogger::log`] appends to the sink first, so evidence survives a slow or
/// panicking policy engine and hook. Hooks run synchronously on the caller's task;
/// a panicking hook is caught and logged, and the remaining hooks still run.
/// Cloning shares sink, engine, analyzer and hook list - the clone is a handle,
/// not a copy of the state.
pub struct AuditLogger {
    sink: Arc<dyn AuditSink>,
    policy_engine: Option<Arc<dyn AuditPolicyEngine>>,
    analyzer: Option<Arc<dyn AuditAnalyzer>>,
    alert_hooks: Arc<RwLock<Vec<AlertHook>>>,
}

impl AuditLogger {
    /// Build a logger over `sink`, with no policy engine and no analyzer yet.
    pub fn new(sink: impl AuditSink + 'static) -> Self {
        Self {
            sink: Arc::new(sink),
            policy_engine: None,
            analyzer: None,
            alert_hooks: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Attach the rule engine whose alerts [`AuditLogger::log`] returns and dispatches.
    #[must_use]
    pub fn with_policy_engine(mut self, engine: impl AuditPolicyEngine + 'static) -> Self {
        self.policy_engine = Some(Arc::new(engine));
        self
    }

    /// Attach the analyzer used by [`AuditLogger::analyze_recent`].
    #[must_use]
    pub fn with_analyzer(mut self, analyzer: impl AuditAnalyzer + 'static) -> Self {
        self.analyzer = Some(Arc::new(analyzer));
        self
    }

    /// Register a callback invoked for every fired alert.
    ///
    /// Hooks run while the logger's hook lock is held, so a blocking hook delays every
    /// later [`AuditLogger::log`] call. A panicking hook is caught and logged; it can
    /// never poison the audit path. Registering is not idempotent.
    pub async fn on_alert(&self, hook: impl Fn(AuditAlert) + Send + Sync + 'static) {
        let mut hooks = self.alert_hooks.write().await;
        hooks.push(Box::new(hook));
    }

    /// Record `entry` and return the alerts its rules produced.
    ///
    /// The entry is appended before rules run, so the audit write does not depend on
    /// policy success. Returned alerts have also been handed to the hooks. The logger
    /// reports; it never grants or denies - the caller owns the decision.
    #[must_use]
    pub async fn log(&self, entry: AuditEntry) -> Vec<AuditAlert> {
        self.sink.append(entry.clone()).await;

        let mut alerts = Vec::new();
        if let Some(ref engine) = self.policy_engine {
            let fired = engine.evaluate(&entry).await;
            if !fired.is_empty() {
                let hooks = self.alert_hooks.read().await;
                for alert in &fired {
                    for hook in hooks.iter() {
                        if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            hook(alert.clone());
                        }))
                        .is_err()
                        {
                            tracing::error!(target: "kirino::audit", "alert hook panicked for rule '{}'", alert.rule_name);
                        }
                    }
                }
                alerts = fired;
            }
        }

        alerts
    }

    /// Read matching entries from the sink, newest first.
    #[must_use]
    pub async fn query(&self, filter: &AuditFilter) -> Vec<AuditEntry> {
        self.sink.query(filter).await
    }

    /// Count matching entries in the sink.
    #[must_use]
    pub async fn count(&self, filter: &AuditFilter) -> u64 {
        self.sink.count(filter).await
    }

    /// Query the sink and analyze the result; `None` when no analyzer is attached.
    ///
    /// Runs over one snapshot, so entries appended afterwards are not reflected and
    /// `filter.limit` bounds the analysis window.
    #[must_use]
    pub async fn analyze_recent(&self, filter: &AuditFilter) -> Option<AuditAnalysisResult> {
        let analyzer = self.analyzer.as_ref()?;
        let entries = self.sink.query(filter).await;
        Some(analyzer.analyze(&entries).await)
    }
}

impl Clone for AuditLogger {
    fn clone(&self) -> Self {
        Self {
            sink: self.sink.clone(),
            policy_engine: self.policy_engine.clone(),
            analyzer: self.analyzer.clone(),
            alert_hooks: self.alert_hooks.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(subject: &str, permission: &str, granted: bool, risk: f64) -> AuditEntry {
        AuditEntry {
            id: 0,
            subject_id: subject.to_string(),
            subject_type: "user".to_string(),
            permission: permission.to_string(),
            endpoint: "/api/test".to_string(),
            granted,
            created_at: Utc::now(),
            verdict: Some(AuditVerdict {
                autonomy_level: if granted { "L4" } else { "L0" }.to_string(),
                risk_score: risk,
                sub_scores: AuditSubScores {
                    delegator_weight: 0.0,
                    trust_penalty: 1.0 - risk,
                    sensitivity: 0.5,
                    domain_mismatch: 0.0,
                    anomaly: 0.0,
                },
                evidence: vec![],
                mitigation: None,
            }),
        }
    }

    #[tokio::test]
    async fn test_sink_append_and_query() {
        let sink = InMemoryAuditSink::new();
        sink.append(make_entry("user1", "read", true, 0.1)).await;
        sink.append(make_entry("user2", "write", false, 0.8)).await;
        sink.append(make_entry("user1", "delete", false, 0.9)).await;

        let all = sink.query(&AuditFilter::default()).await;
        assert_eq!(all.len(), 3);

        let user1 = sink
            .query(&AuditFilter {
                subject_id: Some("user1".to_string()),
                ..Default::default()
            })
            .await;
        assert_eq!(user1.len(), 2);

        let denied = sink
            .query(&AuditFilter {
                granted: Some(false),
                ..Default::default()
            })
            .await;
        assert_eq!(denied.len(), 2);

        let high = sink
            .query(&AuditFilter {
                min_risk: Some(0.7),
                ..Default::default()
            })
            .await;
        assert_eq!(high.len(), 2);
    }

    #[tokio::test]
    async fn test_sink_count() {
        let sink = InMemoryAuditSink::new();
        sink.append(make_entry("u1", "read", true, 0.1)).await;
        sink.append(make_entry("u2", "write", false, 0.8)).await;

        let count = sink
            .count(&AuditFilter {
                granted: Some(false),
                ..Default::default()
            })
            .await;
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn test_filter_limit() {
        let sink = InMemoryAuditSink::new();
        for i in 0..10 {
            sink.append(make_entry(&format!("u{}", i), "read", true, 0.1))
                .await;
        }
        let result = sink
            .query(&AuditFilter {
                limit: Some(3),
                ..Default::default()
            })
            .await;
        assert_eq!(result.len(), 3);
    }

    #[tokio::test]
    async fn test_sink_max_entries_eviction() {
        let sink = InMemoryAuditSink::with_max_entries(5);
        for i in 0..10 {
            sink.append(make_entry(&format!("u{}", i), "read", true, 0.1))
                .await;
        }
        let all = sink.query(&AuditFilter::default()).await;
        assert_eq!(all.len(), 5);
        let mut subjects: Vec<String> = all.iter().map(|e| e.subject_id.clone()).collect();
        subjects.sort();
        assert_eq!(subjects, vec!["u5", "u6", "u7", "u8", "u9"]);
    }

    #[tokio::test]
    async fn test_policy_engine_rules() {
        let engine = InMemoryAuditPolicyEngine::new();
        engine
            .add_rule(AuditRule {
                id: "r1".to_string(),
                name: "deny-alert".to_string(),
                enabled: true,
                condition: AuditCondition::Denied,
                action: AuditAction::Alert {
                    message: "denied".to_string(),
                    severity: AuditSeverity::Warning,
                },
                cooldown_secs: 0,
            })
            .await;

        let rules = engine.list_rules().await;
        assert_eq!(rules.len(), 1);

        let alerts = engine.evaluate(&make_entry("u1", "read", true, 0.1)).await;
        assert!(alerts.is_empty());

        let alerts = engine
            .evaluate(&make_entry("u1", "write", false, 0.8))
            .await;
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule_id, "r1");
    }

    #[tokio::test]
    async fn test_policy_engine_cooldown() {
        let engine = InMemoryAuditPolicyEngine::new();
        engine
            .add_rule(AuditRule {
                id: "r1".to_string(),
                name: "deny".to_string(),
                enabled: true,
                condition: AuditCondition::Denied,
                action: AuditAction::Alert {
                    message: "denied".to_string(),
                    severity: AuditSeverity::Warning,
                },
                cooldown_secs: 3600,
            })
            .await;

        let a1 = engine
            .evaluate(&make_entry("u1", "write", false, 0.8))
            .await;
        assert_eq!(a1.len(), 1);

        let a2 = engine
            .evaluate(&make_entry("u1", "write", false, 0.9))
            .await;
        assert!(a2.is_empty());
    }

    #[tokio::test]
    async fn test_policy_engine_composite() {
        let engine = InMemoryAuditPolicyEngine::new();
        engine
            .add_rule(AuditRule {
                id: "r1".to_string(),
                name: "high-risk-denial".to_string(),
                enabled: true,
                condition: AuditCondition::Composite {
                    conditions: vec![
                        AuditCondition::Denied,
                        AuditCondition::HighRisk { threshold: 0.7 },
                    ],
                    operator: LogicalOp::All,
                },
                action: AuditAction::Alert {
                    message: "critical".to_string(),
                    severity: AuditSeverity::Critical,
                },
                cooldown_secs: 0,
            })
            .await;

        let alerts = engine.evaluate(&make_entry("u1", "read", true, 0.1)).await;
        assert!(alerts.is_empty());

        let alerts = engine
            .evaluate(&make_entry("u1", "write", false, 0.5))
            .await;
        assert!(alerts.is_empty());

        let alerts = engine
            .evaluate(&make_entry("u1", "write", false, 0.9))
            .await;
        assert_eq!(alerts.len(), 1);
    }

    #[tokio::test]
    async fn test_analyzer() {
        let analyzer = DefaultAuditAnalyzer::new();
        let entries = vec![
            make_entry("u1", "read", true, 0.1),
            make_entry("u1", "write", false, 0.8),
            make_entry("u2", "read", true, 0.2),
            make_entry("u2", "delete", false, 0.9),
            make_entry("u2", "write", false, 0.7),
        ];

        let result = analyzer.analyze(&entries).await;
        assert_eq!(result.total_entries, 5);
        assert_eq!(result.denied_count, 3);
        assert!((result.denied_rate - 0.6).abs() < 1e-10);
        assert_eq!(result.high_risk_count, 3);

        let u1 = result.by_subject.get("u1").unwrap();
        assert_eq!(u1.total, 2);
        assert_eq!(u1.denied, 1);

        let u2 = result.by_subject.get("u2").unwrap();
        assert_eq!(u2.total, 3);
        assert_eq!(u2.denied, 2);
        assert!((u2.max_risk - 0.9).abs() < 1e-10);

        assert_eq!(result.top_risk_entries.len(), 5);
        let top_risk = result.top_risk_entries[0]
            .verdict
            .as_ref()
            .unwrap()
            .risk_score;
        assert!((top_risk - 0.9).abs() < 1e-10);
    }

    #[tokio::test]
    async fn test_audit_logger_full_pipeline() {
        let logger = AuditLogger::new(InMemoryAuditSink::new())
            .with_policy_engine(InMemoryAuditPolicyEngine::new())
            .with_analyzer(DefaultAuditAnalyzer::new());

        let _ = logger.log(make_entry("u1", "read", true, 0.1)).await;
        let _ = logger.log(make_entry("u1", "write", false, 0.8)).await;
        let _ = logger.log(make_entry("u2", "delete", false, 0.9)).await;

        let all = logger.query(&AuditFilter::default()).await;
        assert_eq!(all.len(), 3);

        let result = logger
            .analyze_recent(&AuditFilter::default())
            .await
            .unwrap();
        assert_eq!(result.total_entries, 3);
        assert_eq!(result.denied_count, 2);
    }

    #[tokio::test]
    async fn test_audit_logger_with_alert_hook() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();

        let engine = InMemoryAuditPolicyEngine::new();
        engine
            .add_rule(AuditRule {
                id: "r1".to_string(),
                name: "deny".to_string(),
                enabled: true,
                condition: AuditCondition::Denied,
                action: AuditAction::Alert {
                    message: "denied".to_string(),
                    severity: AuditSeverity::Warning,
                },
                cooldown_secs: 0,
            })
            .await;

        let logger = AuditLogger::new(InMemoryAuditSink::new()).with_policy_engine(engine);

        logger
            .on_alert(move |_alert| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            })
            .await;

        let _ = logger.log(make_entry("u1", "read", true, 0.1)).await;
        let _ = logger.log(make_entry("u1", "write", false, 0.8)).await;

        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_remove_rule() {
        let engine = InMemoryAuditPolicyEngine::new();
        engine
            .add_rule(AuditRule {
                id: "r1".to_string(),
                name: "deny".to_string(),
                enabled: true,
                condition: AuditCondition::Denied,
                action: AuditAction::Alert {
                    message: "denied".to_string(),
                    severity: AuditSeverity::Warning,
                },
                cooldown_secs: 0,
            })
            .await;

        assert_eq!(engine.list_rules().await.len(), 1);
        assert!(engine.remove_rule("r1").await.unwrap());
        assert!(engine.list_rules().await.is_empty());
    }

    #[tokio::test]
    async fn test_trust_below_condition() {
        let cond = AuditCondition::TrustBelow { threshold: 0.5 };
        let entry_low_trust = make_entry("u1", "read", true, 0.1);
        assert!(cond.evaluate(&entry_low_trust));

        let entry_high_trust = make_entry("u1", "read", true, 0.9);
        assert!(!cond.evaluate(&entry_high_trust));
    }

    #[tokio::test]
    async fn test_rapid_denials_with_sink() {
        let sink = Arc::new(InMemoryAuditSink::new());
        let engine = InMemoryAuditPolicyEngine::with_sink(sink.clone());
        engine
            .add_rule(AuditRule {
                id: "rapid".to_string(),
                name: "rapid-denials".to_string(),
                enabled: true,
                condition: AuditCondition::RapidDenials {
                    window_secs: 60,
                    min_count: 3,
                },
                action: AuditAction::Alert {
                    message: "rapid denials detected".to_string(),
                    severity: AuditSeverity::Critical,
                },
                cooldown_secs: 0,
            })
            .await;

        let denied_entry = make_entry("u1", "write", false, 0.8);

        sink.append(make_entry("u1", "write", false, 0.8)).await;
        sink.append(make_entry("u1", "write", false, 0.7)).await;
        let alerts = engine.evaluate(&denied_entry).await;
        assert!(alerts.is_empty());

        sink.append(make_entry("u1", "write", false, 0.9)).await;
        let alerts = engine.evaluate(&denied_entry).await;
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule_id, "rapid");
    }

    #[tokio::test]
    async fn test_rapid_denials_without_sink() {
        let engine = InMemoryAuditPolicyEngine::new();
        engine
            .add_rule(AuditRule {
                id: "rapid".to_string(),
                name: "rapid".to_string(),
                enabled: true,
                condition: AuditCondition::RapidDenials {
                    window_secs: 60,
                    min_count: 1,
                },
                action: AuditAction::Alert {
                    message: "rapid".to_string(),
                    severity: AuditSeverity::Critical,
                },
                cooldown_secs: 0,
            })
            .await;

        let entry = make_entry("u1", "write", false, 0.8);
        let alerts = engine.evaluate(&entry).await;
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_category_sensitive_condition() {
        let cond = AuditCondition::CategorySensitive { min_weight: 0.4 };
        let entry = make_entry("u1", "write", true, 0.3);
        assert!(cond.evaluate(&entry));

        let entry_low = {
            let mut e = make_entry("u1", "write", true, 0.3);
            if let Some(ref mut v) = e.verdict {
                v.sub_scores.sensitivity = 0.1;
            }
            e
        };
        assert!(!cond.evaluate(&entry_low));
    }

    #[test]
    fn test_domain_mismatch_condition() {
        let cond = AuditCondition::DomainMismatch { min_weight: 0.3 };
        let entry = {
            let mut e = make_entry("u1", "write", true, 0.3);
            if let Some(ref mut v) = e.verdict {
                v.sub_scores.domain_mismatch = 0.5;
            }
            e
        };
        assert!(cond.evaluate(&entry));

        let entry_low = make_entry("u1", "write", true, 0.3);
        assert!(!cond.evaluate(&entry_low));
    }

    #[test]
    fn test_composite_any_operator() {
        let cond = AuditCondition::Composite {
            conditions: vec![
                AuditCondition::Denied,
                AuditCondition::HighRisk { threshold: 0.9 },
            ],
            operator: LogicalOp::Any,
        };

        let denied_entry = make_entry("u1", "write", false, 0.1);
        assert!(cond.evaluate(&denied_entry));

        let high_risk_entry = make_entry("u1", "write", true, 0.95);
        assert!(cond.evaluate(&high_risk_entry));

        let normal_entry = make_entry("u1", "write", true, 0.1);
        assert!(!cond.evaluate(&normal_entry));
    }

    #[test]
    fn test_disabled_rule_not_evaluated() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        rt.block_on(async {
            let engine = InMemoryAuditPolicyEngine::new();
            engine
                .add_rule(AuditRule {
                    id: "disabled-rule".to_string(),
                    name: "should-not-fire".to_string(),
                    enabled: false,
                    condition: AuditCondition::Denied,
                    action: AuditAction::Alert {
                        message: "should not fire".to_string(),
                        severity: AuditSeverity::Warning,
                    },
                    cooldown_secs: 0,
                })
                .await;

            let entry = make_entry("u1", "write", false, 0.5);
            let alerts = engine.evaluate(&entry).await;
            assert!(alerts.is_empty());
        });
    }

    #[test]
    fn test_entry_without_verdict() {
        let entry = AuditEntry {
            id: 1,
            subject_id: "u1".to_string(),
            subject_type: "user".to_string(),
            permission: "read".to_string(),
            endpoint: "/test".to_string(),
            granted: false,
            created_at: Utc::now(),
            verdict: None,
        };

        let cond = AuditCondition::HighRisk { threshold: 0.5 };
        assert!(!cond.evaluate(&entry));

        let cond = AuditCondition::CategorySensitive { min_weight: 0.1 };
        assert!(!cond.evaluate(&entry));

        let cond = AuditCondition::DomainMismatch { min_weight: 0.1 };
        assert!(!cond.evaluate(&entry));

        let cond = AuditCondition::TrustBelow { threshold: 0.5 };
        assert!(!cond.evaluate(&entry));

        assert!(AuditCondition::Denied.evaluate(&entry));
    }
}
