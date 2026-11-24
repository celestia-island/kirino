//! The in-memory reference implementation of [`ConsumableStore`].
//!
//! Correct by construction: one write lock spans lookup, expiry check and
//! removal, so the "exactly one winner" rule falls out of the borrow rather
//! than out of discipline. It is the reference the other backends are
//! measured against, and it is what a single-replica deployment should use.
//!
//! **Replica scope**: an in-memory store cannot be shared between
//! processes. A deployment that runs more than one replica (or restarts
//! mid-flow) needs [`DbConsumableStore`](crate::database::db_consumable)
//! behind the `store-db` feature; otherwise a credential parked on replica A
//! is simply unknown to replica B, which reads as
//! [`Claim::Lost`](super::Claim::Lost) — fail-closed, but a login that
//! mysteriously fails one time in *n*.

use std::collections::HashMap;

use anyhow::{bail, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use tokio::sync::RwLock;

use super::consumable::{fingerprint, Claim, ConsumableStore};

/// Default ceiling on parked credentials.
///
/// Reaching it is a capacity signal, not a security event: the entry with
/// the earliest expiry is evicted (with a `warn!`) so new logins keep
/// working. Credentials are short-lived by nature, so the evicted one was
/// the first to die anyway.
pub const DEFAULT_CAP: usize = 10_000;

struct Entry<P> {
    payload: P,
    expires_at: DateTime<Utc>,
}

/// Process-local [`ConsumableStore`]. Share one instance through an `Arc`.
pub struct MemoryConsumableStore<P> {
    entries: RwLock<HashMap<String, Entry<P>>>,
    cap: usize,
}

impl<P> Default for MemoryConsumableStore<P> {
    fn default() -> Self {
        Self::new()
    }
}

impl<P> MemoryConsumableStore<P> {
    /// An empty store with [`DEFAULT_CAP`].
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CAP)
    }

    /// An empty store with an explicit ceiling (`0` is treated as `1`, so a
    /// misconfiguration cannot wedge every login).
    #[must_use]
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            cap: cap.max(1),
        }
    }

    /// How many credentials are currently parked (tests / metrics).
    pub async fn len(&self) -> usize {
        self.entries.read().await.len()
    }

    /// Whether nothing is parked (tests / metrics).
    pub async fn is_empty(&self) -> bool {
        self.entries.read().await.is_empty()
    }
}

/// Remove the entry closest to its expiry, so an at-capacity store sheds
/// the credential that had the least life left.
fn evict_soonest<P>(entries: &mut HashMap<String, Entry<P>>) {
    let victim = entries
        .iter()
        .min_by_key(|(_, entry)| entry.expires_at)
        .map(|(key, _)| key.clone());
    if let Some(key) = victim {
        entries.remove(&key);
        tracing::warn!("consumable store at capacity: evicted the soonest-expiring credential");
    }
}

#[async_trait]
impl<P: Send + Sync + 'static> ConsumableStore<P> for MemoryConsumableStore<P> {
    async fn put(&self, token: &str, payload: P, expires_at: DateTime<Utc>) -> Result<()> {
        let key = fingerprint(token);
        let now = Utc::now();
        let mut entries = self.entries.write().await;
        // A live entry under the same fingerprint means the host reused a
        // token. Refuse: silently replacing it would let a second flow
        // steal the first flow's claim.
        if let Some(existing) = entries.get(&key) {
            if existing.expires_at > now {
                bail!(
                    "token is already parked and still live; tokens must be unique per credential"
                );
            }
            entries.remove(&key);
        }
        if entries.len() >= self.cap {
            evict_soonest(&mut entries);
        }
        entries.insert(
            key,
            Entry {
                payload,
                expires_at,
            },
        );
        Ok(())
    }

    async fn claim(&self, token: &str, now: DateTime<Utc>) -> Result<Claim<P>> {
        let key = fingerprint(token);
        // One write lock spans lookup, expiry check and removal — the
        // atomicity the trait contract requires. `MUT:naive-claim`: splitting
        // this into a `read` followed by a `write` gives two winners, and
        // `naive_read_then_delete_loses_the_guarantee` below demonstrates it.
        let mut entries = self.entries.write().await;
        let Some(entry) = entries.remove(&key) else {
            return Ok(Claim::Lost);
        };
        if entry.expires_at <= now {
            // Consumed but dead: dropped by the `remove` above, reported as
            // a loss so callers cannot tell "expired" from "never existed".
            return Ok(Claim::Lost);
        }
        Ok(Claim::Won(entry.payload))
    }

    async fn sweep(&self, now: DateTime<Utc>) -> Result<u64> {
        let mut entries = self.entries.write().await;
        let before = entries.len();
        entries.retain(|_, entry| entry.expires_at > now);
        #[allow(clippy::cast_possible_truncation)]
        let removed = (before - entries.len()) as u64;
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use chrono::Duration;

    use super::*;

    fn later(secs: i64) -> DateTime<Utc> {
        Utc::now() + Duration::seconds(secs)
    }

    #[tokio::test]
    async fn claim_hands_the_payload_to_exactly_one_of_many_racers() {
        let store: Arc<MemoryConsumableStore<&'static str>> =
            Arc::new(MemoryConsumableStore::new());
        store.put("tok", "grant", later(60)).await.expect("park");

        // 32 concurrent claimers. The contract is one winner, not "at most
        // one" and certainly not "however many got there first".
        let mut handles = Vec::new();
        for _ in 0..32 {
            let store = Arc::clone(&store);
            handles.push(tokio::spawn(
                async move { store.claim("tok", Utc::now()).await },
            ));
        }
        let mut winners = 0usize;
        for handle in handles {
            let claim = handle.await.expect("task").expect("claim");
            if let Claim::Won(payload) = claim {
                assert_eq!(payload, "grant");
                winners += 1;
            }
        }
        assert_eq!(winners, 1, "exactly one racer may consume the credential");
        assert_eq!(store.len().await, 0, "the entry is gone after the winner");
    }

    #[tokio::test]
    async fn a_second_sequential_claim_loses() {
        let store = MemoryConsumableStore::<u8>::new();
        store.put("tok", 1, later(60)).await.expect("park");
        assert_eq!(
            store.claim("tok", Utc::now()).await.expect("claim"),
            Claim::Won(1)
        );
        assert_eq!(
            store.claim("tok", Utc::now()).await.expect("claim"),
            Claim::Lost
        );
    }

    #[tokio::test]
    async fn an_expired_claim_loses_and_drops_the_entry() {
        let store = MemoryConsumableStore::<u8>::new();
        // Parked already expired: expiry is a parameter, so no sleeping.
        store.put("tok", 1, later(-1)).await.expect("park");
        assert_eq!(
            store.claim("tok", Utc::now()).await.expect("claim"),
            Claim::Lost,
            "an expired credential is never handed out"
        );
        assert!(
            store.is_empty().await,
            "and it does not linger: the claim consumed it"
        );
    }

    #[tokio::test]
    async fn putting_a_live_duplicate_is_refused() {
        let store = MemoryConsumableStore::<u8>::new();
        store.put("tok", 1, later(60)).await.expect("first park");
        let err = store
            .put("tok", 2, later(60))
            .await
            .expect_err("a live duplicate must be refused");
        assert!(
            err.to_string().contains("already parked"),
            "the refusal names the reason: {err}"
        );
        // The original payload still wins — the refused put did not clobber it.
        assert_eq!(
            store.claim("tok", Utc::now()).await.expect("claim"),
            Claim::Won(1)
        );
    }

    #[tokio::test]
    async fn an_expired_duplicate_can_be_replaced() {
        let store = MemoryConsumableStore::<u8>::new();
        store.put("tok", 1, later(-1)).await.expect("park expired");
        store
            .put("tok", 2, later(60))
            .await
            .expect("a dead entry does not block a fresh one");
        assert_eq!(
            store.claim("tok", Utc::now()).await.expect("claim"),
            Claim::Won(2)
        );
    }

    #[tokio::test]
    async fn sweep_removes_only_expired_entries() {
        let store = MemoryConsumableStore::<u8>::new();
        store.put("dead", 1, later(-5)).await.expect("park");
        store.put("live", 2, later(60)).await.expect("park");
        assert_eq!(store.sweep(Utc::now()).await.expect("sweep"), 1);
        assert_eq!(store.len().await, 1);
        assert_eq!(
            store.claim("live", Utc::now()).await.expect("claim"),
            Claim::Won(2)
        );
    }

    #[tokio::test]
    async fn the_store_keys_on_the_fingerprint_not_the_token() {
        let store = MemoryConsumableStore::<u8>::new();
        store
            .put("super-secret-token", 1, later(60))
            .await
            .expect("park");
        let entries = store.entries.read().await;
        assert_eq!(entries.len(), 1);
        assert!(
            !entries.contains_key("super-secret-token"),
            "the raw token must never be a key: a heap dump would expose a live credential"
        );
        assert!(entries.contains_key(&fingerprint("super-secret-token")));
    }

    #[tokio::test]
    async fn at_capacity_the_soonest_expiring_entry_is_evicted() {
        let store = MemoryConsumableStore::<u8>::with_capacity(2);
        store.put("a", 1, later(10)).await.expect("park");
        store.put("b", 2, later(120)).await.expect("park");
        // Over capacity: the entry with the least life left goes.
        store.put("c", 3, later(300)).await.expect("park");
        assert_eq!(store.len().await, 2);
        assert_eq!(
            store.claim("a", Utc::now()).await.expect("claim"),
            Claim::Lost,
            "the soonest-expiring credential was shed"
        );
        assert_eq!(
            store.claim("b", Utc::now()).await.expect("claim"),
            Claim::Won(2)
        );
    }

    /// The negative control for [`MemoryConsumableStore::claim`]'s
    /// `MUT:naive-claim` note: this is the shape the trait exists to forbid —
    /// read the entry, yield, then remove it. It produces **many** winners,
    /// which is exactly the bug a downstream service shipped for
    /// authorization codes. If the real implementation were ever rewritten
    /// this way, `claim_hands_the_payload_to_exactly_one_of_many_racers`
    /// would fail; this case proves that test is not vacuous.
    #[tokio::test]
    async fn naive_read_then_delete_loses_the_guarantee() {
        struct NaiveStore {
            entries: RwLock<HashMap<String, u8>>,
        }
        let store = Arc::new(NaiveStore {
            entries: RwLock::new(HashMap::from([("tok".to_string(), 1)])),
        });
        let mut handles = Vec::new();
        for _ in 0..8 {
            let store = Arc::clone(&store);
            handles.push(tokio::spawn(async move {
                // Read…
                let found = store.entries.read().await.get("tok").copied();
                // …yield (the network round-trip, in the real bug)…
                tokio::task::yield_now().await;
                // …then delete, which succeeds trivially for every caller.
                store.entries.write().await.remove("tok");
                found.is_some()
            }));
        }
        let mut naive_winners = 0usize;
        for handle in handles {
            if handle.await.expect("task") {
                naive_winners += 1;
            }
        }
        assert!(
            naive_winners > 1,
            "read-then-delete must show the defect this trait prevents (got {naive_winners})"
        );
    }
}
