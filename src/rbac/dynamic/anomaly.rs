//! Behavioral anomaly detection: a per-delegator sliding window scored with a
//! z-score deviation against a baseline learned from the first 100 observations.
//!
//! Security notes: the baseline is driven by caller-supplied requests, is never
//! refreshed, and a cold detector never blocks (it returns a fixed low score), so
//! anomaly is the weakest risk dimension rather than a gate.
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};

use super::metrics::{ActionCategory, ActionRequest};

const DEFAULT_WINDOW_SIZE: usize = 20;
const BASELINE_MIN_SAMPLES: usize = 100;

/// Outcome of one behavioral observation: the deviation that feeds the anomaly
/// risk dimension plus a machine-readable reason label.
///
/// Not a verdict: the value is a sub-score in `[0, 1]` multiplied by the policy's
/// anomaly weight (0.10 by default), so even a maximal deviation of 1.0 adds at
/// most 0.10 of total risk and can never deny on its own. `reason` is a stable
/// label used by tests, logs and operators.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyScore {
    /// Deviation sub-score in `[0, 1]`; see `AnomalyDetector::pattern_deviation`.
    /// `0.1` is the fixed cold-start value emitted by this type; the `0.15` that
    /// the arbiter charges when its detector cap is reached is substituted by the
    /// arbiter, not produced here. A "normal" `0.0` is therefore only observable
    /// once a baseline exists.
    pub value: f64,
    /// Label describing why this value was produced: `insufficient-samples`
    /// (cold detector), `normal`, `moderate-pattern-deviation` (deviation above
    /// 0.4) or `high-pattern-deviation` (above 0.7). The two thresholds label the
    /// score only; they neither clamp nor rescale `value`, and their derivation
    /// is not recorded in the repository (basis to be confirmed with security
    /// review). Never use this field for a decision.
    pub reason: String,
}

/// One observation retained in a detector's sliding window or baseline history.
///
/// Only the action name, the category and the caller-supplied request timestamp
/// are kept: no parameters or resource paths enter behavioral state, which bounds
/// both memory growth and the amount of caller-controlled data stored. The action
/// name is retained verbatim, so it must not carry secrets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionRecord {
    /// Action name as supplied by the caller. Retained verbatim and never
    /// matched, globbed or normalized, so it does not have to agree with the
    /// category recorded next to it.
    pub action: String,
    /// Category used for the profile and baseline; the share of each category in
    /// the window is the basis of the deviation computation.
    pub category: ActionCategory,
    /// Timestamp of the *request*, not of the observation: the detector never
    /// reads the clock for records, so a caller that controls `timestamp`
    /// controls the recorded history and no ordering or freshness check is
    /// applied.
    pub timestamp: DateTime<Utc>,
}

/// Per-category reference distribution ("normal behavior") for one delegator.
///
/// Built from the first 100 observations (see
/// `AnomalyDetector::build_baseline_from_history`) and never refreshed
/// automatically afterwards, so a compromise that starts during warm-up becomes
/// the reference. Missing entries fall back to fixed defaults in
/// `AnomalyDetector::pattern_deviation` instead of failing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorBaseline {
    /// Expected share of the window per category, as frequencies over the
    /// 100-sample history; a category missing here is treated as mean 0.0, so
    /// unobserved categories are not suspicious by default.
    pub category_means: HashMap<ActionCategory, f64>,
    /// Standard deviation of those shares (Bernoulli sample variance, floored at
    /// 0.01 when built) used as the z-score denominator; a category missing here
    /// falls back to 0.1, and a supplied 0.0 is handled without dividing by zero.
    pub category_stdevs: HashMap<ActionCategory, f64>,
}

/// Per-delegator behavioral state: a sliding window of recent actions, the
/// category profile derived from it and an optional baseline.
///
/// One detector exists per delegator id inside `AuthorizationArbiter` (bounded by
/// that type's detector cap), and the state is process-local: not persisted, not
/// shared across replicas, discarded by `AuthorizationArbiter::restore`. The
/// window is driven entirely by request data, so a delegator can influence its
/// own baseline during the first 100 observations. `observe` mutates the state,
/// so call the detector exactly once per action; scoring the same request twice
/// (for example a `risk_score` call followed by `authorize`) double-counts the
/// action and skews both the window and the baseline.
#[derive(Debug, Clone)]
pub struct AnomalyDetector {
    /// Sliding window of the most recent actions, at most `window_size` entries;
    /// rebuilt on every observation and used to derive `category_profile`.
    pub recent_actions: VecDeque<ActionRecord>,
    /// Maximum window length, stored as given. The default constructor uses 20:
    /// short enough to react to a change within a few actions, long enough to
    /// smooth single outliers. Its basis is not recorded in the repository (basis
    /// to be confirmed with security review). A value of 0 is legal and keeps the
    /// window empty, so the profile stays empty and deviation is computed from
    /// the baseline side only.
    pub window_size: usize,
    /// Share of each category inside `recent_actions`, recomputed after every
    /// observation; this is what `pattern_deviation` compares with the baseline.
    pub category_profile: HashMap<ActionCategory, f64>,
    /// Reference distribution: `None` until 100 observations have been seen or a
    /// baseline is supplied through `with_baseline`. While it is `None`,
    /// `pattern_deviation` returns 0.0, so detection is effectively disabled and
    /// only the arbiter's fixed cold-start score remains.
    pub baseline: Option<BehaviorBaseline>,
    /// Monotonic count of every observation ever made; never reset and the
    /// trigger for baseline readiness. It counts requests, not distinct actions,
    /// so a caller can drive a detector to readiness with synthetic traffic.
    total_observed: u64,
    /// Retained observations used to build the baseline; cleared once the
    /// baseline exists. Bounded by the 100-observation minimum, and only
    /// populated while no baseline is installed.
    history: VecDeque<ActionRecord>,
}

impl AnomalyDetector {
    /// Creates a cold detector: empty window and profile, no baseline, zero
    /// observations. The first 100 observations each return the fixed 0.1
    /// `insufficient-samples` score rather than a deviation, so a new detector
    /// never blocks anything by itself.
    #[must_use]
    pub fn new(window_size: usize) -> Self {
        Self {
            recent_actions: VecDeque::with_capacity(window_size),
            window_size,
            category_profile: HashMap::new(),
            baseline: None,
            total_observed: 0,
            history: VecDeque::with_capacity(BASELINE_MIN_SAMPLES),
        }
    }

    /// Installs a pre-computed baseline and returns the detector (builder form),
    /// so detection does not have to wait for 100 observations to be collected.
    ///
    /// Trusting an external baseline means trusting its source: a baseline
    /// supplied by, or influenced by, the monitored delegator normalizes its own
    /// attack pattern. Note that readiness is still driven by the observation
    /// count, so an installed baseline does not take effect before the 100th
    /// observation -- until then `observe` returns the `insufficient-samples`
    /// score of 0.1, and the baseline only starts influencing scores once the
    /// count is reached.
    #[must_use]
    pub fn with_baseline(mut self, baseline: BehaviorBaseline) -> Self {
        self.baseline = Some(baseline);
        self
    }

    /// Whether at least 100 observations have been recorded: the readiness
    /// threshold that stops the fixed `insufficient-samples` score and triggers
    /// the automatic baseline build.
    ///
    /// Readiness is sticky (the count never decreases), and the threshold is a
    /// fixed constant whose derivation is not recorded in the repository (basis
    /// to be confirmed with security review). A detector is per delegator id, so
    /// a delegator that switches its id restarts the 100-observation warm-up.
    #[must_use]
    pub fn is_baseline_ready(&self) -> bool {
        self.total_observed >= BASELINE_MIN_SAMPLES as u64
    }

    /// Total number of observations ever recorded: monotonic, unaffected by
    /// window eviction, and the input to `is_baseline_ready`. Exposed for
    /// monitoring and warm-up decisions; it is not a risk value.
    #[must_use]
    pub fn total_observed(&self) -> u64 {
        self.total_observed
    }

    /// Records one request and returns its anomaly score, mutating the window,
    /// the profile and (once 100 observations exist) the baseline.
    ///
    /// Failure mode: this always returns a score, never an error, so a cold or
    /// saturated detector weakens detection instead of blocking. Until the 100th
    /// observation the fixed 0.1 `insufficient-samples` value is returned; on the
    /// 100th observation the baseline is built from the retained history and that
    /// same observation is already scored against it.
    ///
    /// Ordering and poisoning caveat: the baseline is built from the first 100
    /// observations and is never rebuilt afterwards, so activity during warm-up
    /// defines "normal" -- a delegator that spends its warm-up on benign traffic
    /// can then deviate more cheaply. Calling this more than once for the same
    /// action contaminates the window and pulls the baseline toward the repeated
    /// category.
    #[must_use]
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
        self.recent_actions.push_back(record.clone());

        // Collect all observations until baseline is built
        if self.baseline.is_none() && self.history.len() < BASELINE_MIN_SAMPLES {
            self.history.push_back(record);
        }

        self.recompute_profile();

        if self.is_baseline_ready() && self.baseline.is_none() {
            self.build_baseline_from_history();
            self.history.clear(); // no longer needed
            self.history.shrink_to_fit();
        }

        if !self.is_baseline_ready() {
            return AnomalyScore {
                value: 0.1,
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

    /// Mean absolute z-score of the current profile against the baseline,
    /// divided by 3.0 and capped at 1.0.
    ///
    /// Fail-open when the baseline is missing: returns 0.0, so a detector that
    /// never warmed up contributes no deviation and the arbiter's fixed cold
    /// score is the only behavioral signal. Categories present in the baseline
    /// with a mean above 0.01 but absent from the window count as a deviation of
    /// 2.0 (their disappearance is suspicious); a baseline entry with zero
    /// standard deviation yields 0.0 when the frequency matches and 2.0
    /// otherwise, so no division by zero is possible.
    ///
    /// The divisor 3.0 and the 0.01/0.1/2.0 fallback constants have no derivation
    /// recorded in the repository (basis to be confirmed with security review);
    /// an empty profile and an empty baseline both return 0.0. Keep this function
    /// pure: it is a read-only projection of the profile and the baseline.
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
            } else if (current_freq - mean).abs() < 1e-12 {
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

    /// Builds the baseline from the retained history, replacing any baseline that
    /// is already installed.
    ///
    /// A no-op below 100 total observations, so a detector cannot be given a
    /// baseline before it has earned one (an existing baseline is also left
    /// untouched by such a call), and a no-op when nothing is retained. Means are
    /// category frequencies over the history; deviations use the Bernoulli sample
    /// variance `p * (1 - p) * n / (n - 1)` floored at 0.01, which keeps the
    /// z-score denominator bounded away from zero for a category that was always
    /// present.
    ///
    /// There is no supported re-baselining path for a warm detector: once a
    /// baseline exists, `observe` stops retaining history, so this method finds an
    /// empty history and returns early. Re-baselining therefore requires dropping
    /// the detector, which the arbiter does in `restore`.
    #[allow(clippy::cast_precision_loss)]
    pub fn build_baseline_from_history(&mut self) {
        if self.total_observed < BASELINE_MIN_SAMPLES as u64 {
            return;
        }

        let n = self.history.len() as f64;
        if n == 0.0 {
            return;
        }

        let mut counts: HashMap<ActionCategory, f64> = HashMap::new();
        for rec in &self.history {
            *counts.entry(rec.category).or_insert(0.0) += 1.0;
        }

        let category_means: HashMap<ActionCategory, f64> =
            counts.iter().map(|(&k, &c)| (k, c / n)).collect();

        let mut category_stdevs: HashMap<ActionCategory, f64> = HashMap::new();
        for (&cat, &count) in &counts {
            let p = count / n;
            let sample_var = if n > 1.0 {
                // Correct Bernoulli sample variance: p(1-p) * n / (n-1)
                p * (1.0 - p) * n / (n - 1.0)
            } else {
                p * (1.0 - p)
            };
            category_stdevs.insert(cat, sample_var.sqrt().max(0.01));
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

/// Cold-start default: window size 20, empty profile, no baseline, no
/// observations. This is what the arbiter installs for every delegator it has not
/// seen before, so a new delegator always starts with the fixed cold-start score.
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
        assert_eq!(score.value, 0.1);
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
            let _ = det.observe(&make_request(ActionCategory::ProcessExec));
        }

        let dev = det.pattern_deviation();
        assert!(dev > 0.0);
    }

    #[test]
    fn test_window_sliding() {
        let mut det = AnomalyDetector::new(5);
        det.total_observed = 200;
        for _ in 0..10 {
            let _ = det.observe(&make_request(ActionCategory::ReadOnly));
        }
        assert_eq!(det.recent_actions.len(), 5);
    }

    #[test]
    fn test_build_baseline_from_history() {
        let mut det = AnomalyDetector::new(200);

        // Fill first 100 observations with mixed categories so auto-build
        // at 100 uses a representative baseline from the dedicated history buffer.
        for i in 0..BASELINE_MIN_SAMPLES {
            if i < 75 {
                let _ = det.observe(&make_request(ActionCategory::ReadOnly));
            } else {
                let _ = det.observe(&make_request(ActionCategory::FileWrite));
            }
        }

        // Baseline should have been auto-built at the 100th observation
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

        // Verify history was cleared after baseline build
        assert!(
            det.history.is_empty(),
            "history should be cleared after baseline build"
        );
    }

    #[test]
    fn test_baseline_auto_builds_after_min_samples() {
        let mut det = AnomalyDetector::new(100);
        assert!(det.baseline.is_none());

        for _ in 0..BASELINE_MIN_SAMPLES {
            let _ = det.observe(&make_request(ActionCategory::ReadOnly));
        }

        assert!(det.baseline.is_some());
        assert!(det.is_baseline_ready());
    }

    #[test]
    fn test_anomaly_detection_works_after_baseline_ready() {
        let mut det = AnomalyDetector::new(100);

        for _ in 0..BASELINE_MIN_SAMPLES {
            let _ = det.observe(&make_request(ActionCategory::ReadOnly));
        }

        let score = det.observe(&make_request(ActionCategory::ProcessExec));
        assert!(
            score.value > 0.0,
            "anomaly value should be >0 after baseline ready, got {}",
            score.value
        );
        assert_ne!(score.reason, "insufficient-samples");
    }

    #[test]
    fn test_build_baseline_insufficient_samples() {
        let mut det = AnomalyDetector::new(20);
        for _ in 0..50 {
            let _ = det.observe(&make_request(ActionCategory::ReadOnly));
        }
        assert!(!det.is_baseline_ready());
        det.build_baseline_from_history();
        assert!(det.baseline.is_none());
    }
}
