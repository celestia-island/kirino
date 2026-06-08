use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};

use super::metrics::{ActionCategory, ActionRequest};

const DEFAULT_WINDOW_SIZE: usize = 20;
const BASELINE_MIN_SAMPLES: usize = 100;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyScore {
    pub value: f64,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionRecord {
    pub action: String,
    pub category: ActionCategory,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorBaseline {
    pub category_means: HashMap<ActionCategory, f64>,
    pub category_stdevs: HashMap<ActionCategory, f64>,
}

#[derive(Debug, Clone)]
pub struct AnomalyDetector {
    pub recent_actions: VecDeque<ActionRecord>,
    pub window_size: usize,
    pub category_profile: HashMap<ActionCategory, f64>,
    pub baseline: Option<BehaviorBaseline>,
    total_observed: u64,
}

impl AnomalyDetector {
    #[must_use]
    pub fn new(window_size: usize) -> Self {
        Self {
            recent_actions: VecDeque::with_capacity(window_size),
            window_size,
            category_profile: HashMap::new(),
            baseline: None,
            total_observed: 0,
        }
    }

    #[must_use]
    pub fn with_baseline(mut self, baseline: BehaviorBaseline) -> Self {
        self.baseline = Some(baseline);
        self
    }

    #[must_use]
    pub fn is_baseline_ready(&self) -> bool {
        self.total_observed >= BASELINE_MIN_SAMPLES as u64
    }

    #[must_use]
    pub fn total_observed(&self) -> u64 {
        self.total_observed
    }

    pub fn observe(&mut self, request: &ActionRequest) -> AnomalyScore {
        self.total_observed += 1;

        let record = ActionRecord {
            action: request.action.clone(),
            category: request.category,
            timestamp: request.timestamp,
        };

        if self.recent_actions.len() >= self.window_size {
            self.recent_actions.pop_front();
        }
        self.recent_actions.push_back(record);

        self.recompute_profile();

        if !self.is_baseline_ready() {
            return AnomalyScore {
                value: 0.0,
                reason: "insufficient-samples".to_string(),
            };
        }

        let deviation = self.pattern_deviation();
        if deviation > 0.7 {
            AnomalyScore {
                value: deviation,
                reason: "high-pattern-deviation".to_string(),
            }
        } else if deviation > 0.4 {
            AnomalyScore {
                value: deviation,
                reason: "moderate-pattern-deviation".to_string(),
            }
        } else {
            AnomalyScore {
                value: deviation,
                reason: "normal".to_string(),
            }
        }
    }

    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn pattern_deviation(&self) -> f64 {
        let Some(baseline) = &self.baseline else {
            return 0.0;
        };

        let mut total_deviation = 0.0;
        let mut count = 0;

        for (cat, &current_freq) in &self.category_profile {
            let mean = baseline.category_means.get(cat).copied().unwrap_or(0.0);
            let stdev = baseline.category_stdevs.get(cat).copied().unwrap_or(0.1);
            let z_score = if stdev > 0.0 {
                (current_freq - mean) / stdev
            } else if (current_freq - mean).abs() < f64::EPSILON {
                0.0
            } else {
                2.0
            };
            total_deviation += z_score.abs();
            count += 1;
        }

        for (cat, &mean) in &baseline.category_means {
            if !self.category_profile.contains_key(cat) && mean > 0.01 {
                total_deviation += 2.0;
                count += 1;
            }
        }

        if count == 0 {
            return 0.0;
        }

        let avg_deviation = total_deviation / f64::from(count);
        (avg_deviation / 3.0).min(1.0)
    }

    #[allow(clippy::cast_precision_loss)]
    pub fn build_baseline_from_history(&mut self) {
        if self.total_observed < BASELINE_MIN_SAMPLES as u64 {
            return;
        }

        let n = self.recent_actions.len() as f64;
        if n == 0.0 {
            return;
        }

        let mut counts: HashMap<ActionCategory, f64> = HashMap::new();
        for rec in &self.recent_actions {
            *counts.entry(rec.category).or_insert(0.0) += 1.0;
        }

        let category_means: HashMap<ActionCategory, f64> =
            counts.iter().map(|(&k, &c)| (k, c / n)).collect();

        let mut category_stdevs: HashMap<ActionCategory, f64> = HashMap::new();
        for rec in &self.recent_actions {
            if let Some(&mean) = category_means.get(&rec.category) {
                let diff = 1.0 - mean;
                *category_stdevs.entry(rec.category).or_insert(0.0) += diff * diff;
            }
        }
        for (cat, sum_sq) in &mut category_stdevs {
            let mean = category_means.get(cat).copied().unwrap_or(0.0);
            let variance = mean * (1.0 - mean) / n.max(1.0);
            *sum_sq = (variance + *sum_sq / n).sqrt().max(0.01);
        }

        self.baseline = Some(BehaviorBaseline {
            category_means,
            category_stdevs,
        });
    }

    #[allow(clippy::cast_precision_loss)]
    fn recompute_profile(&mut self) {
        self.category_profile.clear();
        if self.recent_actions.is_empty() {
            return;
        }
        let n = self.recent_actions.len() as f64;
        for rec in &self.recent_actions {
            *self.category_profile.entry(rec.category).or_insert(0.0) += 1.0;
        }
        for v in self.category_profile.values_mut() {
            *v /= n;
        }
    }
}

impl Default for AnomalyDetector {
    fn default() -> Self {
        Self::new(DEFAULT_WINDOW_SIZE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rbac::dynamic::delegator::Delegator;

    fn make_request(category: ActionCategory) -> ActionRequest {
        ActionRequest::simple(
            Delegator::human("test-user", "#test"),
            "test-action",
            category,
        )
    }

    #[test]
    fn test_observe_insufficient_samples() {
        let mut det = AnomalyDetector::new(20);
        let score = det.observe(&make_request(ActionCategory::ReadOnly));
        assert_eq!(score.value, 0.0);
        assert_eq!(score.reason, "insufficient-samples");
    }

    #[test]
    fn test_baseline_not_ready_initially() {
        let det = AnomalyDetector::new(20);
        assert!(!det.is_baseline_ready());
    }

    #[test]
    fn test_pattern_deviation_no_baseline() {
        let det = AnomalyDetector::new(20);
        assert_eq!(det.pattern_deviation(), 0.0);
    }

    #[test]
    fn test_pattern_deviation_with_baseline() {
        let mut det = AnomalyDetector::new(50);
        let baseline = BehaviorBaseline {
            category_means: {
                let mut m = HashMap::new();
                m.insert(ActionCategory::ReadOnly, 0.9);
                m
            },
            category_stdevs: {
                let mut s = HashMap::new();
                s.insert(ActionCategory::ReadOnly, 0.05);
                s
            },
        };
        det.baseline = Some(baseline);
        det.total_observed = 200;

        for _ in 0..20 {
            det.observe(&make_request(ActionCategory::ProcessExec));
        }

        let dev = det.pattern_deviation();
        assert!(dev > 0.0);
    }

    #[test]
    fn test_window_sliding() {
        let mut det = AnomalyDetector::new(5);
        det.total_observed = 200;
        for _ in 0..10 {
            det.observe(&make_request(ActionCategory::ReadOnly));
        }
        assert_eq!(det.recent_actions.len(), 5);
    }

    #[test]
    fn test_build_baseline_from_history() {
        let mut det = AnomalyDetector::new(200);
        det.total_observed = 200;
        for _ in 0..150 {
            det.observe(&make_request(ActionCategory::ReadOnly));
        }
        for _ in 0..50 {
            det.observe(&make_request(ActionCategory::FileWrite));
        }

        det.build_baseline_from_history();
        let baseline = det.baseline.as_ref().unwrap();

        let ro_mean = baseline
            .category_means
            .get(&ActionCategory::ReadOnly)
            .copied()
            .unwrap_or(0.0);
        assert!((ro_mean - 0.75).abs() < 0.05);

        let fw_mean = baseline
            .category_means
            .get(&ActionCategory::FileWrite)
            .copied()
            .unwrap_or(0.0);
        assert!((fw_mean - 0.25).abs() < 0.05);

        let ro_stdev = baseline
            .category_stdevs
            .get(&ActionCategory::ReadOnly)
            .copied()
            .unwrap_or(0.0);
        assert!(ro_stdev > 0.0);
    }

    #[test]
    fn test_build_baseline_insufficient_samples() {
        let mut det = AnomalyDetector::new(20);
        for _ in 0..50 {
            det.observe(&make_request(ActionCategory::ReadOnly));
        }
        assert!(!det.is_baseline_ready());
        det.build_baseline_from_history();
        assert!(det.baseline.is_none());
    }
}
