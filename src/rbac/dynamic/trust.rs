use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::sync::RwLock;

use async_trait::async_trait;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustScore {
    pub value: f64,
    pub confidence: f64,
    pub evidence_count: u64,
    pub last_updated: DateTime<Utc>,
    pub degradation_rate: f64,
}

impl Default for TrustScore {
    fn default() -> Self {
        Self {
            value: 0.5,
            confidence: 0.1,
            evidence_count: 0,
            last_updated: Utc::now(),
            degradation_rate: 0.01,
        }
    }
}

impl TrustScore {
    #[must_use]
    pub fn new(initial_value: f64) -> Self {
        Self {
            value: initial_value.clamp(0.0, 1.0),
            confidence: 0.1,
            evidence_count: 0,
            last_updated: Utc::now(),
            degradation_rate: 0.01,
        }
    }

    #[must_use]
    pub fn weighted(&self) -> f64 {
        self.value * self.confidence
    }

    #[allow(clippy::cast_precision_loss)]
    pub fn on_compliant_behavior(&mut self, severity: f64) {
        let delta = 0.01 * severity;
        self.value = (self.value + delta).min(1.0);
        self.evidence_count += 1;
        self.confidence = (1.0 - (1.0 / (1.0 + self.evidence_count as f64 / 100.0))).min(0.99);
        self.last_updated = Utc::now();
    }

    #[allow(clippy::cast_precision_loss)]
    pub fn on_policy_violation(&mut self, severity: f64) {
        let penalty = if severity > 0.8 {
            0.3 * severity
        } else {
            0.1 * severity
        };
        self.value = (self.value - penalty).max(0.0);
        self.evidence_count += 1;
        self.confidence = (1.0 - (1.0 / (1.0 + self.evidence_count as f64 / 100.0))).min(0.99);
        self.last_updated = Utc::now();
    }

    pub fn degrade(&mut self, elapsed: Duration) {
        let hours = elapsed.as_secs_f64() / 3600.0;
        let decay = self.degradation_rate * hours;
        self.value = (self.value - decay).max(0.0);
        self.confidence = (self.confidence - decay * 0.5).max(0.1);
        self.last_updated = Utc::now();
    }
}

#[async_trait]
pub trait TrustScoreStore: Send + Sync {
    async fn get(&self, delegator_id: &str) -> anyhow::Result<Option<TrustScore>>;
    async fn set(&self, delegator_id: &str, score: TrustScore) -> anyhow::Result<()>;
    async fn delete(&self, delegator_id: &str) -> anyhow::Result<()>;
    async fn sweep_stale(&self, max_age: Duration) -> anyhow::Result<Vec<String>>;
    async fn list_ids(&self) -> anyhow::Result<Vec<String>>;
}

pub struct InMemoryTrustScoreStore {
    scores: RwLock<HashMap<String, TrustScore>>,
}

impl InMemoryTrustScoreStore {
    #[must_use]
    pub fn new() -> Self {
        Self {
            scores: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryTrustScoreStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl TrustScoreStore for InMemoryTrustScoreStore {
    async fn get(&self, delegator_id: &str) -> anyhow::Result<Option<TrustScore>> {
        let scores = self.scores.read().await;
        Ok(scores.get(delegator_id).cloned())
    }

    async fn set(&self, delegator_id: &str, score: TrustScore) -> anyhow::Result<()> {
        let mut scores = self.scores.write().await;
        scores.insert(delegator_id.to_string(), score);
        Ok(())
    }

    async fn delete(&self, delegator_id: &str) -> anyhow::Result<()> {
        let mut scores = self.scores.write().await;
        scores.remove(delegator_id);
        Ok(())
    }

    async fn sweep_stale(&self, max_age: Duration) -> anyhow::Result<Vec<String>> {
        let cutoff = Utc::now() - chrono::Duration::from_std(max_age).unwrap_or_default();
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

    async fn list_ids(&self) -> anyhow::Result<Vec<String>> {
        let scores = self.scores.read().await;
        Ok(scores.keys().cloned().collect())
    }
}

pub struct TrustDecayWorker {
    store: Arc<dyn TrustScoreStore>,
    interval: Duration,
    decay_elapsed: Duration,
}

impl TrustDecayWorker {
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

    pub fn hourly(store: Arc<dyn TrustScoreStore>) -> Self {
        Self::new(store, Duration::from_hours(1), Duration::from_hours(1))
    }

    #[allow(clippy::missing_errors_doc)]
    pub async fn run_once(&self) -> anyhow::Result<usize> {
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

    #[must_use]
    pub fn spawn(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move { self.run().await })
    }

    pub fn spawn_resilient(
        store: Arc<dyn TrustScoreStore>,
        interval: Duration,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let worker = Self::new(store.clone(), interval, interval);
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
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn test_trust_score_default() {
        let ts = TrustScore::default();
        assert!((ts.value - 0.5).abs() < f64::EPSILON);
        assert!((ts.confidence - 0.1).abs() < f64::EPSILON);
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
        assert!(ts.value < 0.7);
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
        assert!((got.value - 0.8).abs() < f64::EPSILON);

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
