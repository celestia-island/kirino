//! Risk-to-autonomy policy: the five dimension weights, the L0-L4 risk bands and
//! the mitigation strategy per level.
//!
//! The policy, not the code, owns how much risk is tolerated: validation is
//! advisory (only `AuthorizationArbiter::set_policy` enforces it), an unmatched
//! risk band denies, and a missing strategy degrades to a blocking strategy at
//! lookup time. The allow set of L3/L4 is hard-coded in the arbiter.
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::verdict::{AutonomyLevel, Strategy};

/// Risk-to-autonomy policy: the dimension weights, the autonomy bands and the
/// mitigation strategy per level.
///
/// This is the trust anchor of the dynamic layer. A verdict is
/// `map_to_level(risk)` plus `strategy_for(level)`, and the allow set is
/// hard-coded to L3/L4 in `AuthorizationArbiter::authorize`, so changing bands
/// or strategies here can tighten or loosen *how much* risk is tolerated but
/// cannot make L0-L2 allow. The fields are public, so a policy can be built
/// without validation: `validate` (run by
/// `AuthorizationArbiter::set_policy`) is the only enforcement point, and a
/// directly constructed policy may have weights that do not sum to 1.0 or bands
/// with gaps, in which case the unmatched risks deny.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicPolicy {
    /// Per-dimension multipliers, ordered exactly as the `SubScores` fields:
    /// `[delegator_weight, trust_penalty, sensitivity, domain_mismatch,
    /// anomaly]`. They are expected to sum to ~1.0 (tolerance 0.05 in `validate`)
    /// so the total risk stays in `[0, 1]`; the default 0.30 trust weight makes
    /// trust the dominant dimension, and the 0.10 anomaly weight makes the
    /// behavioral dimension the weakest signal.
    pub dimension_weights: [f64; 5],
    /// Risk band per autonomy level, `(min, max)` meaning `min <= risk < max`.
    /// Bands need not cover the whole range: an unmatched risk (a gap, an
    /// out-of-range value, or `NaN`, for which every comparison is false) denies
    /// through the L0 fallback in `map_to_level`.
    pub autonomy_thresholds: BTreeMap<AutonomyLevel, (f64, f64)>,
    /// Strategy attached to a verdict for each level. A level missing here yields
    /// `Strategy::Block { reason: "no-strategy-defined" }` from `strategy_for`;
    /// because that lookup result does not deny an otherwise-allowed level (see
    /// `strategy_for`), `validate` requiring one entry per banded level is the
    /// real guard against an unmapped level.
    pub level_strategies: BTreeMap<AutonomyLevel, Strategy>,
}

impl DynamicPolicy {
    /// Maps a total risk score to an autonomy level by scanning the configured
    /// bands for the first `min <= risk < max`.
    ///
    /// Fail-closed fallback: a risk matching no band (gaps, out-of-range values,
    /// `NaN`) is reported as `L0Frozen` with a warning, and L0 is never in the
    /// arbiter's allow set. Bands are half-open, so the upper bound of the last
    /// band must exceed 1.0 (the default policy uses 1.01) or a clamped risk of
    /// exactly 1.0 would fall through to the warning path.
    #[must_use]
    pub fn map_to_level(&self, risk: f64) -> AutonomyLevel {
        for (level, &(min, max)) in self.autonomy_thresholds.iter().rev() {
            if risk >= min && risk < max {
                return *level;
            }
        }
        tracing::warn!(target: "kirino::dynamic::policy", risk = risk, "risk score unmatched by any threshold, defaulting to L0Frozen");
        AutonomyLevel::L0Frozen
    }

    /// Returns the mitigation strategy configured for `level`.
    ///
    /// A lookup never has to invent a mitigation: an unconfigured level returns
    /// `Strategy::Block { reason: "no-strategy-defined" }` instead of nothing.
    /// That fallback does not deny by itself, because `authorize` derives
    /// `allowed` from the level and only asks for the strategy to decide whether
    /// to attach a throttle to an allowed verdict -- so a missing entry on an
    /// L3/L4 band produces an *allowed* verdict with `mitigation: None`, exactly
    /// as a valid `Allow` strategy would. `DynamicPolicy::validate` rejects
    /// banded levels without a strategy, which is what keeps that path
    /// unreachable for validated policies. Enforcing whatever is returned (rate
    /// limiting, human confirmation) is the host's job.
    #[must_use]
    pub fn strategy_for(&self, level: AutonomyLevel) -> Strategy {
        self.level_strategies
            .get(&level)
            .cloned()
            .unwrap_or(Strategy::Block {
                reason: "no-strategy-defined".to_string(),
            })
    }

    /// Validates the policy configuration.
    ///
    /// Checks: the weights sum to 1.0 within 0.05, each weight is in `[0, 1]`,
    /// every band has `min < max` and lies within `[0.0, 1.1]`, and every banded
    /// level has an entry in `level_strategies`. `set_policy` calls this before
    /// installing a policy, so an invalid policy is rejected instead of silently
    /// rescaling risk.
    ///
    /// Not checked, and therefore the host's responsibility: band coverage and
    /// overlap (an uncovered risk band denies via the L0 fallback), whether
    /// L0-L2 are actually mapped to blocking strategies, whether `auto_approve`
    /// is only set on L4, and whether thresholds are sane for the deployment.
    /// `validate` also cannot see a policy that is constructed and used without
    /// being installed through `set_policy`.
    ///
    /// # Errors
    ///
    /// Returns `Err(description)` if dimension weights do not sum to ~1.0 or
    /// any weight is outside [0, 1].
    pub fn validate(&self) -> Result<()> {
        let w: f64 = self.dimension_weights.iter().sum();
        if (w - 1.0).abs() > 0.05 {
            bail!("dimension weights must sum to ~1.0, got {w}");
        }

        for &w in &self.dimension_weights {
            if !(0.0..=1.0).contains(&w) {
                bail!("dimension weight must be in [0, 1], got {w}");
            }
        }

        for (&level, &(min, max)) in &self.autonomy_thresholds {
            if min >= max {
                bail!("threshold for {level:?} has min ({min}) >= max ({max})");
            }
            if min < 0.0 || max > 1.1 {
                bail!("threshold for {level:?} out of range [{min}, {max})");
            }
            if !self.level_strategies.contains_key(&level) {
                bail!("no strategy defined for {level:?}");
            }
        }

        Ok(())
    }
}

/// Returns the built-in policy: weights 0.10 delegator / 0.30 trust /
/// 0.25 sensitivity / 0.25 domain / 0.10 anomaly, and bands L4 `[0.00, 0.15)`,
/// L3 `[0.15, 0.35)`, L2 `[0.35, 0.60)`, L1 `[0.60, 0.80)`, L0 `[0.80, 1.01)`.
///
/// The weight split matches the README (trust 30 %, sensitivity 25 %, domain
/// 25 %, anomaly 10 %, delegator type 10 %) and the design is described there as
/// inspired by NIST SP 800-207/162 and DO-178C, which is not a claim of
/// compliance with either. The numeric band boundaries and the 30/min throttle
/// have no derivation recorded in the repository: basis to be confirmed with
/// security review.
///
/// Consequences to know before relying on the defaults: only `risk < 0.35`
/// allows; because the trust dimension is charged as a *penalty* (0.30 for an
/// unknown delegator) rather than as a gate, a zero-trust delegator can still be
/// allowed for a minimal-risk in-domain read -- the crate's own
/// `smoke_unknown_delegator_defaults_to_moderate_risk` test asserts exactly
/// that, with only 0.01 of margin to the deny boundary, so any additional
/// penalty flips it back to deny. The L0 entry carries
/// `Strategy::Block { reason: String::new() }`, i.e. an empty reason that
/// consumers must not interpret as a code.
#[must_use]
pub fn default_dynamic_policy() -> DynamicPolicy {
    DynamicPolicy {
        dimension_weights: [0.10, 0.30, 0.25, 0.25, 0.10],
        autonomy_thresholds: BTreeMap::from([
            (AutonomyLevel::L4FullAutonomy, (0.0, 0.15)),
            (AutonomyLevel::L3Conditional, (0.15, 0.35)),
            (AutonomyLevel::L2SemiAutonomous, (0.35, 0.60)),
            (AutonomyLevel::L1Assisted, (0.60, 0.80)),
            (AutonomyLevel::L0Frozen, (0.80, 1.01)),
        ]),
        level_strategies: BTreeMap::from([
            (
                AutonomyLevel::L4FullAutonomy,
                Strategy::Allow { auto_approve: true },
            ),
            (
                AutonomyLevel::L3Conditional,
                Strategy::Throttle {
                    max_rate_per_min: 30,
                },
            ),
            (
                AutonomyLevel::L2SemiAutonomous,
                Strategy::RequireConfirmation,
            ),
            (AutonomyLevel::L1Assisted, Strategy::RequireConfirmation),
            (
                AutonomyLevel::L0Frozen,
                Strategy::Block {
                    reason: String::new(),
                },
            ),
        ]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_policy_validates() {
        let policy = default_dynamic_policy();
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn test_map_to_level_low_risk() {
        let policy = default_dynamic_policy();
        assert_eq!(policy.map_to_level(0.05), AutonomyLevel::L4FullAutonomy);
    }

    #[test]
    fn test_map_to_level_high_risk() {
        let policy = default_dynamic_policy();
        assert_eq!(policy.map_to_level(0.9), AutonomyLevel::L0Frozen);
    }

    #[test]
    fn test_map_to_level_mid() {
        let policy = default_dynamic_policy();
        assert_eq!(policy.map_to_level(0.4), AutonomyLevel::L2SemiAutonomous);
    }

    #[test]
    fn test_map_to_level_boundary() {
        let policy = default_dynamic_policy();
        assert_eq!(policy.map_to_level(0.15), AutonomyLevel::L3Conditional);
    }

    #[test]
    fn test_map_to_level_above_range() {
        let policy = default_dynamic_policy();
        assert_eq!(policy.map_to_level(1.5), AutonomyLevel::L0Frozen);
    }

    #[test]
    fn test_strategy_for() {
        let policy = default_dynamic_policy();
        let s = policy.strategy_for(AutonomyLevel::L4FullAutonomy);
        assert!(matches!(s, Strategy::Allow { auto_approve: true }));

        let s = policy.strategy_for(AutonomyLevel::L0Frozen);
        assert!(matches!(s, Strategy::Block { .. }));
    }

    #[test]
    fn test_invalid_weights() {
        let mut policy = default_dynamic_policy();
        policy.dimension_weights = [0.5, 0.5, 0.5, 0.5, 0.5];
        assert!(policy.validate().is_err());
    }
}
