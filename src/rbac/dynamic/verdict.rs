use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AutonomyLevel {
    L0Frozen = 0,
    L1Assisted = 1,
    L2SemiAutonomous = 2,
    L3Conditional = 3,
    L4FullAutonomy = 4,
}

impl fmt::Display for AutonomyLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AutonomyLevel::L0Frozen => write!(f, "L0-Frozen"),
            AutonomyLevel::L1Assisted => write!(f, "L1-Assisted"),
            AutonomyLevel::L2SemiAutonomous => write!(f, "L2-SemiAutonomous"),
            AutonomyLevel::L3Conditional => write!(f, "L3-Conditional"),
            AutonomyLevel::L4FullAutonomy => write!(f, "L4-FullAutonomy"),
        }
    }
}

impl AutonomyLevel {
    #[must_use]
    pub fn is_operational(&self) -> bool {
        *self >= AutonomyLevel::L2SemiAutonomous
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Strategy {
    Allow { auto_approve: bool },
    Throttle { max_rate_per_min: u32 },
    RequireConfirmation,
    Block { reason: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubScores {
    pub delegator_weight: f64,
    pub trust_penalty: f64,
    pub sensitivity: f64,
    pub domain_mismatch: f64,
    pub anomaly: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScore {
    pub value: f64,
    pub sub_scores: SubScores,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ActionOutcome {
    Success,
    Failure { error: String },
    PolicyViolation { rule: String },
    Anomalous { deviation: f64 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationVerdict {
    pub allowed: bool,
    pub autonomy_level: AutonomyLevel,
    pub risk_score: f64,
    pub sub_scores: SubScores,
    pub evidence: Vec<String>,
    pub mitigation: Option<Strategy>,
    pub timestamp: DateTime<Utc>,
}

impl AuthorizationVerdict {
    #[must_use]
    pub fn denied(level: AutonomyLevel, risk: f64, sub_scores: SubScores, reason: &str) -> Self {
        Self {
            allowed: false,
            autonomy_level: level,
            risk_score: risk,
            sub_scores,
            evidence: vec![reason.to_string()],
            mitigation: Some(Strategy::Block {
                reason: reason.to_string(),
            }),
            timestamp: Utc::now(),
        }
    }
}
