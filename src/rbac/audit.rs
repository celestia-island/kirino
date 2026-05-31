use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;

type AlertHook = Box<dyn Fn(AuditAlert) + Send + Sync>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: u64,
    pub subject_id: String,
    pub subject_type: String,
    pub permission: String,
    pub endpoint: String,
    pub granted: bool,
    pub created_at: DateTime<Utc>,
    pub verdict: Option<AuditVerdict>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditVerdict {
    pub autonomy_level: String,
    pub risk_score: f64,
    pub sub_scores: AuditSubScores,
    pub evidence: Vec<String>,
    pub mitigation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditSubScores {
    pub delegator_weight: f64,
    pub trust_penalty: f64,
    pub sensitivity: f64,
    pub domain_mismatch: f64,
    pub anomaly: f64,
}

impl AuditEntry {
    pub fn is_denied(&self) -> bool {
        !self.granted
    }

    pub fn is_high_risk(&self) -> bool {
        self.verdict
            .as_ref()
            .map(|v| v.risk_score >= 0.6)
            .unwrap_or(false)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditAction {
    Alert {
        message: String,
        severity: AuditSeverity,
    },
    Notify {
        target: String,
        message: String,
    },
    Countermeasure {
        action: String,
        params: HashMap<String, String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditSeverity {
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRule {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub condition: AuditCondition,
    pub action: AuditAction,
    pub cooldown_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditCondition {
    Denied,
    HighRisk {
        threshold: f64,
    },
    CategorySensitive {
        min_weight: f64,
    },
    DomainMismatch {
        min_weight: f64,
    },
    RapidDenials {
        window_secs: u64,
        min_count: u32,
    },
    TrustBelow {
        threshold: f64,
    },
    Composite {
        conditions: Vec<AuditCondition>,
        operator: LogicalOp,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum LogicalOp {
    All,
    Any,
}

impl AuditCondition {
    pub fn evaluate(&self, entry: &AuditEntry) -> bool {
        match self {
            AuditCondition::Denied => entry.is_denied(),
            AuditCondition::HighRisk { threshold } => entry
                .verdict
                .as_ref()
                .map(|v| v.risk_score >= *threshold)
                .unwrap_or(false),
            AuditCondition::CategorySensitive { min_weight } => entry
                .verdict
                .as_ref()
                .map(|v| v.sub_scores.sensitivity >= *min_weight)
                .unwrap_or(false),
            AuditCondition::DomainMismatch { min_weight } => entry
                .verdict
                .as_ref()
                .map(|v| v.sub_scores.domain_mismatch >= *min_weight)
                .unwrap_or(false),
            AuditCondition::RapidDenials { .. } => false,
            AuditCondition::TrustBelow { threshold } => entry
                .verdict
                .as_ref()
                .map(|v| v.sub_scores.trust_penalty >= 1.0 - *threshold)
                .unwrap_or(false),
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
pub struct AuditAlert {
    pub rule_id: String,
    pub rule_name: String,
    pub action: AuditAction,
    pub triggering_entry: Box<AuditEntry>,
    pub created_at: DateTime<Utc>,
}

#[async_trait::async_trait]
pub trait AuditSink: Send + Sync {
    async fn append(&self, entry: AuditEntry);
    async fn query(&self, filter: &AuditFilter) -> Vec<AuditEntry>;
    async fn count(&self, filter: &AuditFilter) -> u64;
}

#[derive(Debug, Clone, Default)]
pub struct AuditFilter {
    pub subject_id: Option<String>,
    pub granted: Option<bool>,
    pub permission: Option<String>,
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
    pub min_risk: Option<f64>,
    pub limit: Option<usize>,
}

#[async_trait::async_trait]
pub trait AuditPolicyEngine: Send + Sync {
    async fn evaluate(&self, entry: &AuditEntry) -> Vec<AuditAlert>;
    async fn add_rule(&self, rule: AuditRule);
    async fn remove_rule(&self, rule_id: &str);
    async fn list_rules(&self) -> Vec<AuditRule>;
}

#[async_trait::async_trait]
pub trait AuditAnalyzer: Send + Sync {
    async fn analyze(&self, entries: &[AuditEntry]) -> AuditAnalysisResult;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditAnalysisResult {
    pub total_entries: u64,
    pub denied_count: u64,
    pub denied_rate: f64,
    pub high_risk_count: u64,
    pub by_subject: HashMap<String, SubjectStats>,
    pub by_permission: HashMap<String, u64>,
    pub top_risk_entries: Vec<AuditEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubjectStats {
    pub total: u64,
    pub denied: u64,
    pub avg_risk: f64,
    pub max_risk: f64,
}

pub struct InMemoryAuditSink {
    entries: RwLock<Vec<AuditEntry>>,
    next_id: RwLock<u64>,
}

impl InMemoryAuditSink {
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(Vec::new()),
            next_id: RwLock::new(1),
        }
    }
}

impl Default for InMemoryAuditSink {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl AuditSink for InMemoryAuditSink {
    async fn append(&self, mut entry: AuditEntry) {
        let mut next_id = self.next_id.write().await;
        entry.id = *next_id;
        *next_id += 1;
        let mut entries = self.entries.write().await;
        entries.push(entry);
    }

    async fn query(&self, filter: &AuditFilter) -> Vec<AuditEntry> {
        let entries = self.entries.read().await;
        let mut result: Vec<AuditEntry> = entries
            .iter()
            .filter(|e| {
                if let Some(ref sid) = filter.subject_id {
                    if e.subject_id != *sid {
                        return false;
                    }
                }
                if let Some(g) = filter.granted {
                    if e.granted != g {
                        return false;
                    }
                }
                if let Some(ref perm) = filter.permission {
                    if e.permission != *perm {
                        return false;
                    }
                }
                if let Some(since) = filter.since {
                    if e.created_at < since {
                        return false;
                    }
                }
                if let Some(until) = filter.until {
                    if e.created_at > until {
                        return false;
                    }
                }
                if let Some(min_risk) = filter.min_risk {
                    let risk = e.verdict.as_ref().map(|v| v.risk_score).unwrap_or(0.0);
                    if risk < min_risk {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect();

        result.sort_by_key(|b| std::cmp::Reverse(b.created_at));
        if let Some(limit) = filter.limit {
            result.truncate(limit);
        }
        result
    }

    async fn count(&self, filter: &AuditFilter) -> u64 {
        self.query(filter).await.len() as u64
    }
}

pub struct InMemoryAuditPolicyEngine {
    rules: RwLock<Vec<AuditRule>>,
    last_triggered: RwLock<HashMap<String, DateTime<Utc>>>,
    sink: Option<Arc<dyn AuditSink>>,
}

impl InMemoryAuditPolicyEngine {
    pub fn new() -> Self {
        Self {
            rules: RwLock::new(Vec::new()),
            last_triggered: RwLock::new(HashMap::new()),
            sink: None,
        }
    }

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
        let rules = self.rules.read().await;
        let mut last_triggered = self.last_triggered.write().await;
        let now = Utc::now();
        let mut alerts = Vec::new();

        for rule in rules.iter() {
            if !rule.enabled {
                continue;
            }

            if let Some(&last_time) = last_triggered.get(&rule.id) {
                let elapsed = (now - last_time).num_seconds() as u64;
                if elapsed < rule.cooldown_secs {
                    continue;
                }
            }

            let matched = match &rule.condition {
                AuditCondition::RapidDenials {
                    window_secs,
                    min_count,
                } => {
                    if let Some(ref sink) = self.sink {
                        let since = now - chrono::Duration::seconds(*window_secs as i64);
                        let filter = AuditFilter {
                            subject_id: Some(entry.subject_id.clone()),
                            granted: Some(false),
                            since: Some(since),
                            ..Default::default()
                        };
                        let count = sink.query(&filter).await.len() as u32;
                        count >= *min_count
                    } else {
                        false
                    }
                }
                other => other.evaluate(entry),
            };

            if matched {
                last_triggered.insert(rule.id.clone(), now);
                alerts.push(AuditAlert {
                    rule_id: rule.id.clone(),
                    rule_name: rule.name.clone(),
                    action: rule.action.clone(),
                    triggering_entry: Box::new(entry.clone()),
                    created_at: now,
                });
            }
        }

        alerts
    }

    async fn add_rule(&self, rule: AuditRule) {
        let mut rules = self.rules.write().await;
        rules.push(rule);
    }

    async fn remove_rule(&self, rule_id: &str) {
        let mut rules = self.rules.write().await;
        rules.retain(|r| r.id != rule_id);
    }

    async fn list_rules(&self) -> Vec<AuditRule> {
        let rules = self.rules.read().await;
        rules.clone()
    }
}

pub struct DefaultAuditAnalyzer;

impl DefaultAuditAnalyzer {
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
            let risk = entry.verdict.as_ref().map(|v| v.risk_score).unwrap_or(0.0);
            stats.avg_risk += risk;
            stats.max_risk = stats.max_risk.max(risk);

            *by_permission.entry(entry.permission.clone()).or_insert(0) += 1;
        }

        for stats in by_subject.values_mut() {
            if stats.total > 0 {
                stats.avg_risk /= stats.total as f64;
            }
        }

        top_risk.sort_by(|a, b| {
            let ra = a.verdict.as_ref().map(|v| v.risk_score).unwrap_or(0.0);
            let rb = b.verdict.as_ref().map(|v| v.risk_score).unwrap_or(0.0);
            rb.partial_cmp(&ra).unwrap_or(std::cmp::Ordering::Equal)
        });
        top_risk.truncate(10);

        AuditAnalysisResult {
            total_entries: total,
            denied_count,
            denied_rate: if total > 0 {
                denied_count as f64 / total as f64
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

pub struct AuditLogger {
    sink: Arc<dyn AuditSink>,
    policy_engine: Option<Arc<dyn AuditPolicyEngine>>,
    analyzer: Option<Arc<dyn AuditAnalyzer>>,
    alert_hooks: Arc<RwLock<Vec<AlertHook>>>,
}

impl AuditLogger {
    pub fn new(sink: impl AuditSink + 'static) -> Self {
        Self {
            sink: Arc::new(sink),
            policy_engine: None,
            analyzer: None,
            alert_hooks: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub fn with_policy_engine(mut self, engine: impl AuditPolicyEngine + 'static) -> Self {
        self.policy_engine = Some(Arc::new(engine));
        self
    }

    pub fn with_analyzer(mut self, analyzer: impl AuditAnalyzer + 'static) -> Self {
        self.analyzer = Some(Arc::new(analyzer));
        self
    }

    pub async fn on_alert(&self, hook: impl Fn(AuditAlert) + Send + Sync + 'static) {
        let mut hooks = self.alert_hooks.write().await;
        hooks.push(Box::new(hook));
    }

    pub async fn log(&self, entry: AuditEntry) -> Vec<AuditAlert> {
        let mut alerts = Vec::new();

        if let Some(ref engine) = self.policy_engine {
            let fired = engine.evaluate(&entry).await;
            if !fired.is_empty() {
                let hooks = self.alert_hooks.read().await;
                for alert in &fired {
                    for hook in hooks.iter() {
                        hook(alert.clone());
                    }
                }
                alerts = fired;
            }
        }

        self.sink.append(entry).await;
        alerts
    }

    pub async fn query(&self, filter: &AuditFilter) -> Vec<AuditEntry> {
        self.sink.query(filter).await
    }

    pub async fn count(&self, filter: &AuditFilter) -> u64 {
        self.sink.count(filter).await
    }

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
        assert!((result.denied_rate - 0.6).abs() < f64::EPSILON);
        assert_eq!(result.high_risk_count, 3);

        let u1 = result.by_subject.get("u1").unwrap();
        assert_eq!(u1.total, 2);
        assert_eq!(u1.denied, 1);

        let u2 = result.by_subject.get("u2").unwrap();
        assert_eq!(u2.total, 3);
        assert_eq!(u2.denied, 2);
        assert!((u2.max_risk - 0.9).abs() < f64::EPSILON);

        assert_eq!(result.top_risk_entries.len(), 5);
        let top_risk = result.top_risk_entries[0]
            .verdict
            .as_ref()
            .unwrap()
            .risk_score;
        assert!((top_risk - 0.9).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn test_audit_logger_full_pipeline() {
        let logger = AuditLogger::new(InMemoryAuditSink::new())
            .with_policy_engine(InMemoryAuditPolicyEngine::new())
            .with_analyzer(DefaultAuditAnalyzer::new());

        logger.log(make_entry("u1", "read", true, 0.1)).await;
        logger.log(make_entry("u1", "write", false, 0.8)).await;
        logger.log(make_entry("u2", "delete", false, 0.9)).await;

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

        logger.log(make_entry("u1", "read", true, 0.1)).await;
        logger.log(make_entry("u1", "write", false, 0.8)).await;

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
        engine.remove_rule("r1").await;
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
}
