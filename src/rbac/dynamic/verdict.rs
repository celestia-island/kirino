//! Verdict types: autonomy levels, mitigation strategies, risk sub-scores and the
//! authorization verdict itself.
//!
//! `AuthorizationVerdict::allowed` is derived from the autonomy level (L3/L4 only)
//! and is the single field an enforcement point acts on; the remaining fields are
//! audit evidence, and the attached strategy is advisory to the host.
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Autonomy level granted by a verdict, from L0 (frozen) to L4 (fully
/// autonomous).
///
/// Ordering is meaningful (`PartialOrd`/`Ord` follow the discriminants) and the
/// decision rule is level-based rather than score-based:
/// `AuthorizationArbiter::authorize` allows an action only for `L3Conditional`
/// and `L4FullAutonomy`. L0-L2 are deny verdicts even though their names suggest
/// assisted operation: under the default policy they carry
/// `Strategy::RequireConfirmation` and the host must obtain that confirmation out
/// of band. The level names are DO-178C inspired (per the README), which is a
/// design inspiration, not a compliance or certification claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AutonomyLevel {
    /// No autonomy: the action is denied. This is also the fail-closed fallback
    /// of `DynamicPolicy::map_to_level` for a risk score that matches no band,
    /// and the level reported while a delegator is locked down.
    L0Frozen = 0,
    /// Assisted operation: denied by the arbiter, with `RequireConfirmation`
    /// attached under the default policy so a human can approve the action.
    L1Assisted = 1,
    /// Semi-autonomous: still denied, with confirmation attached under the
    /// default policy. More trust (or less sensitivity/domain excess) is needed
    /// to leave this band.
    L2SemiAutonomous = 2,
    /// Conditional autonomy: the only allow band besides L4, throttled to
    /// 30 actions per minute by the default policy (enforced by the host, not
    /// here).
    L3Conditional = 3,
    /// Full autonomy: allowed with no mitigation attached under the default
    /// policy. Reaching the lowest risk band is dominated by the 30 % trust
    /// dimension, so a delegator without accumulated trust cannot get here.
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
    /// Whether the level is at least `L2SemiAutonomous`.
    ///
    /// This is not the authorization gate: `L2SemiAutonomous` is still denied by
    /// `AuthorizationArbiter::authorize`. The predicate is meant for hosts that
    /// decide whether a delegator may keep running at all (for example to keep a
    /// task alive without issuing new actions), so using it to allow actions
    /// would be a privilege escalation.
    #[must_use]
    pub fn is_operational(&self) -> bool {
        *self >= AutonomyLevel::L2SemiAutonomous
    }
}

/// Mitigation attached to a verdict: what the host is expected to do in
/// addition to (or instead of) allowing the action.
///
/// The arbiter only attaches strategies; it enforces none of them. On an allowed
/// verdict only `Throttle` is carried (an `Allow` strategy produces
/// `mitigation: None`), while a denied verdict carries the strategy configured
/// for its level, so `Block`/`RequireConfirmation` there is both the reason for
/// the denial and the guidance for what would lift it. A host that ignores
/// `mitigation` silently upgrades confirmation-gated verdicts to plain access.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Strategy {
    /// Allow the action. `auto_approve` records that the policy pre-approved it
    /// (true for the default L4 strategy); the flag is data for the host and is
    /// not re-checked by the arbiter.
    Allow { auto_approve: bool },
    /// Allow at most `max_rate_per_min` actions per minute; the arbiter does not
    /// rate-limit, so an unenforced value means unthrottled access. The value
    /// comes from policy data and is neither validated nor bounded here; the
    /// default L3 value of 30/min has no derivation recorded in the repository
    /// (basis to be confirmed with security review).
    Throttle { max_rate_per_min: u32 },
    /// Deny unless a human confirms out of band. The verdict stays
    /// `allowed: false`; this crate provides no confirmation channel, so the
    /// host owns the whole flow (and must not treat the verdict as an allow).
    RequireConfirmation,
    /// Deny. `reason` is operator-facing text, not a stable code, and the
    /// default L0 policy ships it empty, so branching on it is unsafe.
    Block { reason: String },
}

impl fmt::Display for Strategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Strategy::Allow { auto_approve } => {
                write!(f, "Allow(auto_approve={auto_approve})")
            }
            Strategy::Throttle { max_rate_per_min } => {
                write!(f, "Throttle(max={max_rate_per_min}/min)")
            }
            Strategy::RequireConfirmation => write!(f, "RequireConfirmation"),
            Strategy::Block { reason } => write!(f, "Block({reason})"),
        }
    }
}

/// The five raw risk dimensions behind one verdict, kept for audit and
/// debugging.
///
/// The field order is the contract for `DynamicPolicy::dimension_weights`
/// (`[delegator_weight, trust_penalty, sensitivity, domain_mismatch, anomaly]`);
/// reordering these fields without reordering those weights silently mis-weights
/// every score. All five values are produced in `[0, 1]` except
/// `delegator_weight`, which the type ladder caps at 0.30.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubScores {
    /// Inherent weight of the delegator type; see `DelegatorType` for the ladder
    /// (0.0 to 0.30).
    pub delegator_weight: f64,
    /// `1.0 - value * confidence` of the stored trust score, raised further when
    /// the domain's `trust_floor` is not met. A missing trust record or a
    /// trust-store error yields the maximum 1.0, which makes this the
    /// fail-closed dimension.
    pub trust_penalty: f64,
    /// `ActionCategory::base_weight()` of the category the caller claimed.
    pub sensitivity: f64,
    /// Excess weight from the domain scope (0.0 for in-domain, up to 0.6 for
    /// out-of-domain); 0.0 when no scope is installed.
    pub domain_mismatch: f64,
    /// Behavioral deviation from the delegator's baseline: 0.1 while the
    /// detector is cold (fewer than 100 observations), 0.15 when the detector
    /// cap was reached, otherwise the computed deviation.
    pub anomaly: f64,
}

/// Total risk for one request: the weighted sum of the five sub-scores, with the
/// raw sub-scores alongside for audit.
///
/// `value` is clamped to `[0, 1]` defensively; `NaN` is preserved rather than
/// converted to zero and is denied downstream by the policy's unmatched-band
/// fallback. The value is not a decision: the autonomy level derived from the
/// configured bands decides, so hosts must not re-derive allow/deny from this
/// number (that would bypass policy ownership of the thresholds).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScore {
    /// Clamped total risk in `[0, 1]`.
    pub value: f64,
    /// Raw per-dimension contributions; see `SubScores`.
    pub sub_scores: SubScores,
}

/// Observed outcome of an action, fed back through
/// `AuthorizationArbiter::feedback` to adjust the delegator's trust.
///
/// The outcome is accepted on faith and never checked against the request that
/// was authorized, so it must come from the enforcement point that actually ran
/// or blocked the action. Payload strings are not persisted by the trust update
/// (`error` and `rule` are dropped there), so the caller owns recording them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ActionOutcome {
    /// The action completed as intended: the mildest positive signal, worth
    /// +0.005 trust (compliant severity 0.5).
    Success,
    /// The action failed for a non-policy reason (I/O, validation, timeout):
    /// charged as a violation of severity 0.2 (-0.02 trust). Infrastructure
    /// flakiness therefore erodes trust too, deliberately, so a broken agent is
    /// not rewarded. `error` is caller-facing detail.
    Failure { error: String },
    /// The action violated a policy rule: severity 0.8 (-0.08 trust, plus the
    /// cliff term for severities above 0.8). `rule` identifies the rule for the
    /// caller's own logging and has no effect on the trust delta.
    PolicyViolation { rule: String },
    /// The action deviated from the delegator's behavioral baseline.
    /// `deviation` is used verbatim as the violation severity and is not
    /// clamped, so it must be in `[0, 1]`: a larger value over-penalizes, and a
    /// negative value inverts the penalty into a trust gain.
    Anomalous { deviation: f64 },
}

/// The decision returned by `AuthorizationArbiter::authorize`.
///
/// Enforcement contract: read `allowed` (the only decision field) and honor
/// `mitigation`. Everything else is evidence for audit and operators:
/// `risk_score` and `sub_scores` explain the score, `evidence` holds pre-rendered
/// human-readable lines (no stable keys), `autonomy_level` names the band, and
/// `timestamp` is the server-side time of the decision. `allowed` is derived from
/// `autonomy_level`, never from `risk_score`, so a host must not recompute it
/// from the score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationVerdict {
    /// The decision: true only for L3/L4 verdicts, i.e. risk below the policy's
    /// deny boundary. The single field an enforcement point must act on.
    pub allowed: bool,
    /// Autonomy level the risk score mapped to; the source of `allowed`.
    pub autonomy_level: AutonomyLevel,
    /// Clamped total risk that produced the level. Explanatory: hosts must not
    /// compare it against their own thresholds, which would drift from the
    /// policy.
    pub risk_score: f64,
    /// Per-dimension contributions. Persist these with the verdict to make the
    /// decision auditable after the fact.
    pub sub_scores: SubScores,
    /// Pre-rendered justification lines (risk, level, delegator type, sub-scores,
    /// and the lockdown note when frozen). Free text: do not parse it, and treat
    /// it as untrusted input when displaying it.
    pub evidence: Vec<String>,
    /// Mitigation the host must apply: the level's strategy for a denied verdict,
    /// and for an allowed verdict only when that strategy is a `Throttle`
    /// (otherwise `None`). `None` therefore means "no extra obligation", not
    /// "no decision was made".
    pub mitigation: Option<Strategy>,
    /// Server-side time at which the verdict was built; also the audit entry's
    /// creation time. It is not the request's `timestamp`, so a backdated request
    /// cannot backdate the record.
    pub timestamp: DateTime<Utc>,
}

impl AuthorizationVerdict {
    /// Builds a deny verdict: `allowed: false`, one evidence line, and
    /// `mitigation: Some(Strategy::Block { reason })`.
    ///
    /// A constructor for callers that deny outside the scoring path (for example
    /// on a separate policy failure). It makes no decision itself and performs no
    /// policy lookup, so `level` and `risk` are the caller's claim. The level is
    /// not forced to L0Frozen: pass L0 when the level is unknown, since L0 is the
    /// only band this subsystem treats as unambiguously frozen.
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
