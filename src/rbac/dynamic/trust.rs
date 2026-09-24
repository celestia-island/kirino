//! Trust scoring: mutable per-delegator trust with evidence-based confidence,
//! linear time decay, and the store plus decay-worker plumbing around it.
//!
//! Trust is a penalty dimension, not a gate: an unknown delegator is scored as
//! zero trust (which raises risk), store failures are logged and treated
//! conservatively, and decay is what stops yesterday's trust from granting
//! permanent autonomy.
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::sync::RwLock;

use async_trait::async_trait;

/// Mutable trust record for one delegator: the accumulated evidence the dynamic
/// layer holds about its past behavior.
///
/// `value` is the accumulated trust and `confidence` the epistemic weight of that
/// value; only their product (`weighted`) is scored, so a freshly seeded or
/// low-evidence record can never act at full strength. The record is written by
/// `AuthorizationArbiter::feedback`, `lockdown` and `restore`, read on every
/// `risk_score` call, and lives in a `TrustScoreStore` that the host supplies, so
/// durability and cross-process consistency are the host's responsibility.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustScore {
    /// Trust in `[0, 1]`; higher is more trusted. An unknown delegator starts at
    /// 0.0, which yields the maximum trust penalty.
    pub value: f64,
    /// Weight of `value` in `[0, 1]`, recomputed from `evidence_count` by the
    /// behavior mutators and capped at 0.99 there, so an evidence-based record is
    /// never scored at full face value (`lockdown` and `restore` set this field
    /// directly instead). A zero confidence makes the record worthless
    /// (`weighted == 0.0`, i.e. maximum penalty) no matter how high `value` is.
    pub confidence: f64,
    /// Number of recorded compliant or violating observations; drives
    /// `confidence`. It is a counter, not proof: any caller of `feedback` can
    /// inflate it, and `lockdown` writes a sentinel value into it.
    pub evidence_count: u64,
    /// Time of the last update, used by `TrustScoreStore::sweep_stale` for
    /// retention. Every mutator overwrites it, so it is not an audit timestamp
    /// and it is not used to compute decay.
    pub last_updated: DateTime<Utc>,
    /// Trust lost per hour of inactivity, in trust units per hour (default 0.01,
    /// so a full 1.0 trust reaches zero after about 100 idle hours), applied by
    /// `degrade`. Decay is linear in the elapsed time passed by the caller, not
    /// exponential (despite the README wording); the default value has no
    /// derivation recorded in the repository (basis to be confirmed with security
    /// review).
    pub degradation_rate: f64,
}

/// Cold-start record for a delegator with no history: `value` 0.0, `confidence`
/// 0.0, no evidence, and the default 0.01/hour degradation rate.
///
/// `weighted()` is therefore 0.0, so the trust dimension charges its maximum
/// penalty: an unknown delegator is treated as untrusted rather than as neutral.
/// The `last_updated` field is stamped with the current time, so a brand-new
/// record is not immediately stale for retention purposes.
impl Default for TrustScore {
    fn default() -> Self {
        Self {
            value: 0.0,
            confidence: 0.0,
            evidence_count: 0,
            last_updated: Utc::now(),
            degradation_rate: 0.01,
        }
    }
}

impl TrustScore {
    /// Seeds a score with `initial_value`, clamped to `[0, 1]`, and a confidence
    /// of `initial_value.min(0.5)`.
    ///
    /// The confidence cap is the security-relevant part: a seeded score carries
    /// at most half its face value until real evidence accumulates, so neither
    /// configuration nor a single seed can grant high effective trust. The seed
    /// is not evidence-based (`evidence_count` is 0) and degrades at the default
    /// 0.01 per hour.
    #[must_use]
    pub fn new(initial_value: f64) -> Self {
        Self {
            value: initial_value.clamp(0.0, 1.0),
            confidence: initial_value.min(0.5),
            evidence_count: 0,
            last_updated: Utc::now(),
            degradation_rate: 0.01,
        }
    }

    /// Effective trust used for scoring: `value * confidence`, in `[0, 1]`.
    ///
    /// Must be recomputed after any mutation of `value` or `confidence` (the
    /// fields are public, so nothing enforces that); the arbiter derives the
    /// trust penalty as `(1.0 - weighted).clamp(0.0, 1.0)`. A `NaN` recorded by a
    /// host store propagates into the total risk and is then denied by the
    /// policy's unmatched-band fallback rather than being read as zero risk.
    #[must_use]
    pub fn weighted(&self) -> f64 {
        self.value * self.confidence
    }

    /// Records compliant behavior of `severity` (expected in `[0, 1]`): adds
    /// `0.01 * severity` to `value` (capped at 1.0), increments `evidence_count`
    /// and recomputes `confidence`.
    ///
    /// The asymmetry with `on_policy_violation` is deliberate and must be
    /// preserved: one full-severity success buys +0.01 while one full-severity
    /// violation costs at least -0.10, so trust is slow to earn and fast to lose.
    /// `severity` is caller-supplied and not clamped, so values above 1.0 grant
    /// more than the intended increment; the arbiter always passes 0.5.
    #[allow(clippy::cast_precision_loss)]
    pub fn on_compliant_behavior(&mut self, severity: f64) {
        let delta = 0.01 * severity;
        self.value = (self.value + delta).min(1.0);
        self.evidence_count += 1;
        self.confidence = (1.0 - (1.0 / (1.0 + self.evidence_count as f64 / 100.0))).min(0.99);
        self.last_updated = Utc::now();
    }

    /// Records a policy violation of `severity` (expected in `[0, 1]`): subtracts
    /// `0.1 * severity + 0.2 * max(severity - 0.8, 0.0)` from `value` (floored at
    /// 0.0), increments `evidence_count` and recomputes `confidence`.
    ///
    /// Invariant to preserve: the penalty must stay an order of magnitude larger
    /// than the compliant reward, and the term above 0.8 is what gives
    /// near-catastrophic violations a cliff. `severity` is used verbatim and is
    /// not clamped, so callers must pass a value in `[0, 1]`: a value above 1.0
    /// over-penalizes, and a negative value inverts the penalty into a trust
    /// gain. `ActionOutcome::Anomalous` forwards its `deviation` field straight
    /// into this function, so a negative deviation reported by a caller raises
    /// trust.
    #[allow(clippy::cast_precision_loss)]
    pub fn on_policy_violation(&mut self, severity: f64) {
        let penalty = 0.1 * severity + 0.2 * (severity - 0.8).max(0.0);
        self.value = (self.value - penalty).max(0.0);
        self.evidence_count += 1;
        self.confidence = (1.0 - (1.0 / (1.0 + self.evidence_count as f64 / 100.0))).min(0.99);
        self.last_updated = Utc::now();
    }

    /// Applies `degradation_rate * elapsed_hours` of decay to `value` and half
    /// that amount to `confidence`, flooring both at 0.0, and stamps
    /// `last_updated`.
    ///
    /// Ordering caveat: the amount depends only on the `elapsed` argument, never
    /// on `last_updated`, so the caller must supply the true elapsed time since
    /// the previous decay (both workers pass their own interval). Supplying the
    /// same span twice decays twice: double decay is fail-closed but ages every
    /// stored score faster than the configured rate, whereas skipping a call
    /// leaves trust higher than intended (fail-open).
    pub fn degrade(&mut self, elapsed: Duration) {
        let hours = elapsed.as_secs_f64() / 3600.0;
        let decay = self.degradation_rate * hours;
        self.value = (self.value - decay).max(0.0);
        self.confidence = (self.confidence - decay * 0.5).max(0.0);
        self.last_updated = Utc::now();
    }
}

/// Persistence boundary for trust records, keyed by delegator id (trust boundary
/// B3 in `docs/THREAT_MODEL.md`).
///
/// The arbiter treats store failures as a risk signal, never as an allow: a
/// `get` error during scoring is logged and scored as zero trust (maximum
/// penalty), and a `get` error during `feedback` restarts the record from
/// `TrustScore::default()`. Implementations are host-provided and trusted for
/// correctness and durability; only `InMemoryTrustScoreStore` ships here. Every
/// method takes `&self` and must be safe for concurrent use (`Send + Sync`).
#[async_trait]
pub trait TrustScoreStore: Send + Sync {
    /// Returns the stored score, or `Ok(None)` when the delegator has no record.
    ///
    /// `Ok(None)` and `Err` have the same conservative consequence at the arbiter
    /// (both are scored as zero trust), but only `Err` marks a broken store and is
    /// logged as such, so implementations should not map internal failures onto
    /// `Ok(None)`.
    async fn get(&self, delegator_id: &str) -> Result<Option<TrustScore>>;
    /// Inserts or replaces the score for `delegator_id`.
    ///
    /// Write errors are swallowed by the arbiter's callers after logging, so a
    /// store that accepts reads but fails writes leaves the previous (possibly
    /// more permissive) score in force. Implementations must make a successful
    /// write durable enough for the deployment's restart story, otherwise trust
    /// silently resets to zero on restart.
    async fn set(&self, delegator_id: &str, score: TrustScore) -> Result<()>;
    /// Removes the record, after which reads behave like an unknown delegator
    /// (zero trust, maximum penalty). Fail-closed by construction, and never
    /// called implicitly by the arbiter.
    async fn delete(&self, delegator_id: &str) -> Result<()>;
    /// Removes every record whose `last_updated` is older than `max_age` and
    /// returns the removed ids.
    ///
    /// This is the retention control for trust state and it is deliberately
    /// fail-closed: expiry resets a delegator to zero trust and never extends it.
    /// `max_age == 0` means "sweep nothing" and must return an empty vector, not
    /// "sweep everything"; the opposite reading would wipe all trust state, so
    /// implementations must keep this behavior. Nothing in the arbiter calls it
    /// automatically -- scheduling retention is the host's job.
    async fn sweep_stale(&self, max_age: Duration) -> Result<Vec<String>>;
    /// Lists every stored delegator id, with no ordering guarantee.
    ///
    /// `TrustDecayWorker` uses it to enumerate the records it decays, so an
    /// implementation that omits ids silently exempts those delegators from decay
    /// and their trust never ages out. An error here aborts the whole decay cycle.
    async fn list_ids(&self) -> Result<Vec<String>>;
}

/// Process-local `TrustScoreStore` backed by a `tokio::sync::RwLock<HashMap>`.
///
/// Volatile by design: records are lost on restart, after which every delegator
/// is treated as unknown (zero trust, maximum penalty), and the map is not shared
/// between processes, so replicas each hold their own view of trust unless the
/// host supplies a durable store. Reads take the read lock and `sweep_stale`
/// takes the write lock, so a large sweep briefly blocks scoring lookups. Intended
/// for tests and single-process deployments.
pub struct InMemoryTrustScoreStore {
    scores: RwLock<HashMap<String, TrustScore>>,
}

impl InMemoryTrustScoreStore {
    /// Creates an empty store; `Default` is equivalent. Starts with no records, so
    /// every delegator is unknown and carries the maximum trust penalty until
    /// feedback is recorded.
    #[must_use]
    pub fn new() -> Self {
        Self {
            scores: RwLock::new(HashMap::new()),
        }
    }
}

/// Default store: empty, with the same fail-closed behavior as `new` (no records
/// means every delegator is scored with the maximum trust penalty).
impl Default for InMemoryTrustScoreStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl TrustScoreStore for InMemoryTrustScoreStore {
    /// Clones the stored record out of the map; a missing id is `Ok(None)`.
    async fn get(&self, delegator_id: &str) -> Result<Option<TrustScore>> {
        let scores = self.scores.read().await;
        Ok(scores.get(delegator_id).cloned())
    }

    /// Inserts or replaces the record under the write lock; a `set` on an unknown
    /// id creates it, and trust is never validated here.
    async fn set(&self, delegator_id: &str, score: TrustScore) -> Result<()> {
        let mut scores = self.scores.write().await;
        scores.insert(delegator_id.to_string(), score);
        Ok(())
    }

    /// Removes the record; deleting an unknown id succeeds silently, and the next
    /// lookup returns `None` (zero trust).
    async fn delete(&self, delegator_id: &str) -> Result<()> {
        let mut scores = self.scores.write().await;
        scores.remove(delegator_id);
        Ok(())
    }

    /// Removes records older than `max_age` and returns their ids in map order.
    ///
    /// `max_age == 0` is a no-op returning an empty vector. A `max_age` too large
    /// for `chrono::Duration` is capped to one year with a warning rather than
    /// failing, so an absurd retention setting sweeps more than asked (fail-closed
    /// for trust) instead of leaving state forever.
    async fn sweep_stale(&self, max_age: Duration) -> Result<Vec<String>> {
        if max_age.is_zero() {
            return Ok(Vec::new());
        }
        let chrono_max_age = chrono::Duration::from_std(max_age).unwrap_or_else(|e| {
            tracing::warn!(
                target: "kirino::dynamic::trust",
                "max_age {max_age:?} out of range for chrono::Duration ({e}), capping to 1 year"
            );
            chrono::Duration::days(365)
        });
        let cutoff = Utc::now() - chrono_max_age;
        let mut scores = self.scores.write().await;
        let stale: Vec<String> = scores
            .iter()
            .filter(|(_, s)| s.last_updated < cutoff)
            .map(|(k, _)| k.clone())
            .collect();
        for id in &stale {
            scores.remove(id);
        }
        Ok(stale)
    }

    /// Returns a snapshot of the stored ids; the order is unspecified (hash map
    /// iteration order), so callers must not rely on it.
    async fn list_ids(&self) -> Result<Vec<String>> {
        let scores = self.scores.read().await;
        Ok(scores.keys().cloned().collect())
    }
}

/// RAII handle for a background trust-decay task: aborts the task when dropped.
///
/// The drop behavior is the security-relevant part. If the handle is dropped, or
/// never bound to a variable, decay stops silently and trust scores stop aging
/// toward lower autonomy, which is a fail-open drift for idle or compromised
/// delegators. Keep it alive for the life of the process (for example in a
/// long-lived struct field or a `let _handle = ...` binding) and use `abort` to
/// stop decay deliberately.
#[must_use]
pub struct TrustDecayHandle(tokio::task::JoinHandle<()>);

impl TrustDecayHandle {
    /// Wraps an already-spawned decay task. The caller is responsible for having
    /// spawned the right loop; wrapping a handle to any other task would abort
    /// that task on drop instead.
    pub fn new(handle: tokio::task::JoinHandle<()>) -> Self {
        Self(handle)
    }

    /// Aborts the decay task now; idempotent. A cycle already in progress may
    /// still complete part of its work, so trust can be left partially decayed.
    pub fn abort(&self) {
        self.0.abort();
    }
}

/// Aborting on drop is what makes the handle safe to keep as a guard; it also
/// means that dropping the handle (including by not binding it) silently removes
/// the staleness bound on trust.
impl Drop for TrustDecayHandle {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Background worker that applies trust decay to every stored score.
///
/// This is the staleness bound promised in `docs/THREAT_MODEL.md` section 2.5:
/// without it, a delegator that earned trust once keeps it forever, so a
/// compromised or idle delegator never drifts toward lower autonomy. One cycle
/// enumerates the whole store (`list_ids`) and rewrites each record, so its cost
/// grows with the number of delegators and it needs a Tokio runtime.
pub struct TrustDecayWorker {
    store: Arc<dyn TrustScoreStore>,
    interval: Duration,
    decay_elapsed: Duration,
}

impl TrustDecayWorker {
    /// Creates a worker with an explicit tick interval and an explicit amount of
    /// time to charge per cycle.
    ///
    /// Passing a `decay_elapsed` larger than `interval` ages scores faster than
    /// wall-clock time (fail-closed, but the configured rate is then a lie);
    /// passing a smaller one leaves scores staler than intended (fail-open).
    #[must_use]
    pub fn new(
        store: Arc<dyn TrustScoreStore>,
        interval: Duration,
        decay_elapsed: Duration,
    ) -> Self {
        Self {
            store,
            interval,
            decay_elapsed,
        }
    }

    /// Convenience constructor for the default rate: a 3600 s interval that
    /// charges 3600 s of decay per cycle, i.e. 0.01 of trust per hour at the
    /// default `degradation_rate`. Idle delegators therefore lose their trust in
    /// roughly 100 hours.
    #[must_use]
    pub fn hourly(store: Arc<dyn TrustScoreStore>) -> Self {
        Self::new(store, Duration::from_secs(3600), Duration::from_secs(3600))
    }

    /// Runs a single trust decay cycle, degrading all stored trust scores by
    /// `decay_elapsed` and returning how many records were rewritten.
    ///
    /// Not transactional: records are read and written one by one, and the first
    /// store error aborts the cycle mid-way, leaving the already-processed prefix
    /// decayed while the remainder keeps its old (higher) trust. Because the next
    /// cycle charges every record again, that prefix can be decayed twice per
    /// interval -- fail-closed, but it means "trust strictly decreases at the
    /// configured rate" is not an invariant under store failures.
    ///
    /// # Errors
    ///
    /// Returns an error if listing, getting, or setting trust scores fails.
    pub async fn run_once(&self) -> Result<usize> {
        let ids = self.store.list_ids().await?;
        let mut decayed = 0;
        for id in &ids {
            if let Some(mut score) = self.store.get(id).await? {
                score.degrade(self.decay_elapsed);
                self.store.set(id, score).await?;
                decayed += 1;
            }
        }
        Ok(decayed)
    }

    /// Runs the decay loop forever, logging each completed or failed cycle, and
    /// never returns (`-> !`).
    ///
    /// `tokio::time::interval` completes its first tick immediately, so the first
    /// decay cycle fires as soon as the worker starts rather than after one
    /// interval. A store error is logged and the loop continues, so a permanently
    /// broken store produces a log line per tick instead of stopping the worker;
    /// the missed decay of a failed cycle is not replayed.
    pub async fn run(self) -> ! {
        let mut interval = tokio::time::interval(self.interval);
        loop {
            interval.tick().await;
            match self.run_once().await {
                Ok(count) => {
                    tracing::debug!(target: "kirino::dynamic::trust::decay",
                        decayed_count = count,
                        "trust decay cycle completed"
                    );
                }
                Err(e) => {
                    tracing::error!(target: "kirino::dynamic::trust::decay",
                        error = %e,
                        "trust decay cycle failed"
                    );
                }
            }
        }
    }

    /// Spawns `run` on the current runtime and returns its `JoinHandle`.
    ///
    /// Requires a Tokio runtime (spawning panics outside one). Dropping a
    /// `JoinHandle` detaches rather than aborts, so the decay loop keeps running
    /// with no way to stop or await it; prefer `spawn_resilient`, whose handle
    /// aborts on drop.
    #[must_use]
    pub fn spawn(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move { self.run().await })
    }

    /// Spawns a self-healing decay loop (a failed cycle is logged and the next
    /// tick retries) and returns the handle that aborts it on drop.
    ///
    /// The returned handle must be kept alive: dropping it immediately stops
    /// decay, which silently removes the staleness bound and leaves the last
    /// scores in force. `decay_elapsed` equals `interval` here, so each successful
    /// cycle charges exactly one interval of decay and a failed interval is lost
    /// permanently (scores stay more trusted than the configured rate implies).
    pub fn spawn_resilient(
        store: Arc<dyn TrustScoreStore>,
        interval: Duration,
    ) -> TrustDecayHandle {
        let worker = Self::new(store, interval, interval);
        TrustDecayHandle(tokio::spawn(async move {
            let mut interval_tick = tokio::time::interval(interval);
            loop {
                interval_tick.tick().await;
                match worker.run_once().await {
                    Ok(count) => {
                        tracing::debug!(target: "kirino::dynamic::trust::decay",
                            decayed_count = count,
                            "trust decay cycle completed"
                        );
                    }
                    Err(e) => {
                        tracing::error!(target: "kirino::dynamic::trust::decay",
                            error = %e,
                            "trust decay cycle failed, will retry next interval"
                        );
                    }
                }
            }
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn test_trust_score_default() {
        let ts = TrustScore::default();
        assert!((ts.value - 0.0).abs() < 1e-10);
        assert!((ts.confidence - 0.0).abs() < 1e-10);
        assert_eq!(ts.evidence_count, 0);
    }

    #[test]
    fn test_trust_score_compliant_increases() {
        let mut ts = TrustScore::new(0.5);
        ts.on_compliant_behavior(1.0);
        assert!(ts.value > 0.5);
        assert_eq!(ts.evidence_count, 1);
    }

    #[test]
    fn test_trust_score_violation_decreases() {
        let mut ts = TrustScore::new(0.5);
        ts.on_policy_violation(0.5);
        assert!(ts.value < 0.5);
    }

    #[test]
    fn test_trust_score_severe_violation_cliff() {
        let mut ts = TrustScore::new(0.9);
        ts.on_policy_violation(0.9);
        let penalty_at_09: f64 = 0.1 * 0.9 + 0.2 * f64::max(0.9 - 0.8, 0.0);
        assert!((ts.value - (0.9 - penalty_at_09)).abs() < 1e-10);
        assert!(ts.value < 0.8);
    }

    #[test]
    fn test_trust_score_penalty_smoothness() {
        let mut ts_low = TrustScore::new(1.0);
        ts_low.on_policy_violation(0.79);
        let penalty_low = 0.1 * 0.79;

        let mut ts_high = TrustScore::new(1.0);
        ts_high.on_policy_violation(0.81);
        let penalty_high = 0.1 * 0.81 + 0.2 * 0.01;

        let jump = penalty_high - penalty_low;
        assert!(jump < 0.05, "penalty should be smooth, jump was {jump}");
    }

    #[test]
    fn test_trust_score_degrade() {
        let mut ts = TrustScore::new(0.8);
        ts.degrade(Duration::from_secs(3600));
        assert!(ts.value < 0.8);
    }

    #[test]
    fn test_trust_score_clamped() {
        let mut ts = TrustScore::new(1.0);
        ts.on_compliant_behavior(1.0);
        assert!(ts.value <= 1.0);

        let mut ts = TrustScore::new(0.01);
        ts.on_policy_violation(1.0);
        assert!(ts.value >= 0.0);
    }

    #[test]
    fn test_confidence_grows_with_evidence() {
        let mut ts = TrustScore::new(0.5);
        let initial = ts.confidence;
        for _ in 0..200 {
            ts.on_compliant_behavior(1.0);
        }
        assert!(ts.confidence > initial);
        assert!(ts.confidence <= 0.99);
    }

    #[tokio::test]
    async fn test_in_memory_store_crud() {
        let store = InMemoryTrustScoreStore::new();
        let id = "agent-001";

        assert!(store.get(id).await.unwrap().is_none());

        let score = TrustScore::new(0.8);
        store.set(id, score.clone()).await.unwrap();

        let got = store.get(id).await.unwrap().unwrap();
        assert!((got.value - 0.8).abs() < 1e-10);

        store.delete(id).await.unwrap();
        assert!(store.get(id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_sweep_stale() {
        let store = InMemoryTrustScoreStore::new();
        let mut old = TrustScore::new(0.5);
        old.last_updated = Utc::now() - chrono::Duration::hours(48);
        store.set("old-agent", old).await.unwrap();

        let mut recent = TrustScore::new(0.9);
        recent.last_updated = Utc::now();
        store.set("recent-agent", recent).await.unwrap();

        let swept = store
            .sweep_stale(Duration::from_secs(24 * 3600))
            .await
            .unwrap();
        assert_eq!(swept, vec!["old-agent"]);
        assert!(store.get("old-agent").await.unwrap().is_none());
        assert!(store.get("recent-agent").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn test_sweep_stale_none_expired() {
        let store = InMemoryTrustScoreStore::new();
        let score = TrustScore::new(0.8);
        store.set("fresh-agent", score).await.unwrap();

        let swept = store
            .sweep_stale(Duration::from_secs(24 * 3600))
            .await
            .unwrap();
        assert!(swept.is_empty());
        assert!(store.get("fresh-agent").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn test_sweep_stale_all_expired() {
        let store = InMemoryTrustScoreStore::new();
        let mut s1 = TrustScore::new(0.5);
        s1.last_updated = Utc::now() - chrono::Duration::hours(72);
        store.set("a1", s1).await.unwrap();

        let mut s2 = TrustScore::new(0.3);
        s2.last_updated = Utc::now() - chrono::Duration::hours(96);
        store.set("a2", s2).await.unwrap();

        let swept = store
            .sweep_stale(Duration::from_secs(24 * 3600))
            .await
            .unwrap();
        let mut swept = swept;
        swept.sort();
        assert_eq!(swept, vec!["a1", "a2"]);
        assert!(store.list_ids().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_list_ids() {
        let store = InMemoryTrustScoreStore::new();
        store.set("a1", TrustScore::new(0.5)).await.unwrap();
        store.set("a2", TrustScore::new(0.8)).await.unwrap();
        store.set("a3", TrustScore::new(0.3)).await.unwrap();

        let mut ids = store.list_ids().await.unwrap();
        ids.sort();
        assert_eq!(ids, vec!["a1", "a2", "a3"]);
    }

    #[tokio::test]
    async fn test_decay_worker_run_once() {
        let store = Arc::new(InMemoryTrustScoreStore::new());
        store.set("a1", TrustScore::new(0.8)).await.unwrap();
        store.set("a2", TrustScore::new(0.5)).await.unwrap();

        let worker = TrustDecayWorker::new(
            store.clone(),
            Duration::from_secs(3600),
            Duration::from_secs(3600),
        );

        let before_a1 = store.get("a1").await.unwrap().unwrap().value;
        let count = worker.run_once().await.unwrap();
        assert_eq!(count, 2);

        let after_a1 = store.get("a1").await.unwrap().unwrap().value;
        assert!(after_a1 < before_a1);
    }
}
