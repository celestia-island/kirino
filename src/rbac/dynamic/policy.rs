use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::verdict::{AutonomyLevel, Strategy};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicPolicy {
    pub dimension_weights: [f64; 5],
    pub autonomy_thresholds: BTreeMap<AutonomyLevel, (f64, f64)>,
    pub level_strategies: BTreeMap<AutonomyLevel, Strategy>,
}

impl DynamicPolicy {
    #[must_use]
    pub fn map_to_level(&self, risk: f64) -> AutonomyLevel {
        for (level, &(min, max)) in self.autonomy_thresholds.iter().rev() {
            if risk >= min && risk < max {
                return *level;
            }
        }
        AutonomyLevel::L0Frozen
    }

    #[must_use]
    pub fn strategy_for(&self, level: AutonomyLevel) -> Strategy {
        self.level_strategies
            .get(&level)
            .cloned()
            .unwrap_or(Strategy::Block {
                reason: "no-strategy-defined".to_string(),
            })
    }

    #[allow(clippy::missing_errors_doc)]
    pub fn validate(&self) -> Result<(), String> {
        let w: f64 = self.dimension_weights.iter().sum();
        if (w - 1.0).abs() > 0.05 {
            return Err(format!("dimension weights must sum to ~1.0, got {w}"));
        }

        for &w in &self.dimension_weights {
            if !(0.0..=1.0).contains(&w) {
                return Err(format!("dimension weight must be in [0, 1], got {w}"));
            }
        }

        Ok(())
    }
}

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
