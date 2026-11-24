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
//!
//! **Capacity**: at [`DEFAULT_CAP`] the store refuses *new* credentials. It
//! never evicts a live one — see the [trait contract](super::ConsumableStore)
//! rule 5. A refusal means the caller's `put` errors, which is a visible,
//! recoverable failure; silently discarding somebody's in-flight credential
//! is not.
//!
//! `chrono` is used here because the rest of this crate's time-bearing
//! public API does (`LoginAttempt`, `kirino-session`); the type has to agree
//! across the trait boundary. It is covered by the repository-wide
//! RUSTSEC-2026-0543 ignore and moves to `jiff` with that wave.

use std::collections::HashMap;

use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use tokio::sync::RwLock;

use super::consumable::{fingerprint, Claim, ConsumableStore};
use crate::error::KirinoError;

/// Default ceiling on parked credentials.
///
/// Reaching it is a capacity condition, not a security event: the store
/// refuses new `put`s (loudly) rather than evicting live ones. Size it to
/// the deployment's real concurrency, or use the DB backend, which has no
/// such ceiling.
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

#[async_trait]
impl<P: Send + Sync + 'static> ConsumableStore<P> for MemoryConsumableStore<P> {
    async fn put(
        &self,
        token: &str,
        payload: P,
        expires_at: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<()> {
        let key = fingerprint(token);
        let mut entries = self.entries.write().await;
        // A live entry under the same fingerprint means the host reused a
        // token. Refuse: silently replacing it would let a second flow
        // steal the first flow's claim.
        if let Some(existing) = entries.get(&key) {
            if existing.expires_at > now {
                return Err(KirinoError::Validation(
                    "token is already parked and still live; tokens must be unique per credential"
                        .to_string(),
                )
                .into());
            }
            // A dead entry does not block a fresh one.
            entries.remove(&key);
        }
        // Capacity: shed what is already dead, then refuse if still full.
        // Evicting a LIVE credential would turn "exactly one winner" into
        // "no winner" for a login already under way (contract rule 5).
        if entries.len() >= self.cap {
            entries.retain(|_, entry| entry.expires_at > now);
            if entries.len() >= self.cap {
                return Err(KirinoError::Validation(format!(
                    "consumable store is full ({} parked); refusing to evict a live credential",
                    entries.len()
                ))
                .into());
            }
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
        // One write lock spans lookup, expiry check and removal — the
        // atomicity the trait contract requires. `MUT:naive-claim`: splitting
        // this into a `read` followed by a `write` hands the credential to
        // several racers; the multi-thread concurrency case below catches the
        // shape even with no await in the window (the R3 review proved the
        // single-thread variant could not).
        let key = fingerprint(token);
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

    /// The contract's central claim, on a **multi-thread** runtime with
    /// real parallelism.
    ///
    /// A `current_thread` runtime makes this a weak test: tasks only
    /// interleave at await points, and the correct `claim` has none between
    /// lookup and removal — so a wrong implementation that also has no await
    /// in that window (clone the payload, ignore the delete's result) passes
    /// there while handing the credential to two racers in production. The
    /// `naive_clone_then_delete_loses_the_guarantee` case below is that
    /// exact shape and is the reason this runs with workers.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn claim_hands_the_payload_to_exactly_one_of_many_racers() {
        // Several rounds: a scheduling-dependent defect can hide on a quiet
        // run, and the negative control shows it needs more than one.
        for round in 0..8u32 {
            let token = format!("tok-{round}");
            let store: Arc<MemoryConsumableStore<u32>> = Arc::new(MemoryConsumableStore::new());
            store
                .put(&token, round, later(60), Utc::now())
                .await
                .expect("park");

            let barrier = Arc::new(tokio::sync::Barrier::new(32));
            let mut handles = Vec::new();
            for _ in 0..32 {
                let store = Arc::clone(&store);
                let token = token.clone();
                let barrier = Arc::clone(&barrier);
                handles.push(tokio::spawn(async move {
                    // Release every racer at once so the window is contended
                    // rather than serialised by spawn order.
                    barrier.wait().await;
                    store.claim(&token, Utc::now()).await
                }));
            }
            let mut winners = 0usize;
            for handle in handles {
                let claim = handle.await.expect("task").expect("claim");
                if let Claim::Won(payload) = claim {
                    assert_eq!(payload, round);
                    winners += 1;
                }
            }
            assert_eq!(winners, 1, "round {round}: exactly one racer may win");
            assert_eq!(store.len().await, 0, "the entry is gone after the winner");
        }
    }

    /// The defect shape a single-thread runtime cannot see: the reader
    /// clones the payload out under the read lock and then deletes without
    /// consulting the result — **no await between the two**, so the
    /// `yield_now`-based demonstration is not the thing being modelled.
    ///
    /// This is the R3 review's surviving mutation. It is a hand-written
    /// wrong store, kept as the negative control for the multi-thread case
    /// above: if that case were ever moved back to `current_thread`, this
    /// one would stop showing the defect (two winners) — which is exactly
    /// how the blind spot was found.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn naive_clone_then_delete_loses_the_guarantee() {
        struct NaiveStore {
            entries: RwLock<HashMap<String, u8>>,
        }
        let store = Arc::new(NaiveStore {
            entries: RwLock::new(HashMap::from([("tok".to_string(), 1u8)])),
        });
        let mut ever_two = false;
        for _ in 0..64 {
            store.entries.write().await.insert("tok".to_string(), 1);
            let barrier = Arc::new(tokio::sync::Barrier::new(8));
            let mut handles = Vec::new();
            for _ in 0..8 {
                let store = Arc::clone(&store);
                let barrier = Arc::clone(&barrier);
                handles.push(tokio::spawn(async move {
                    barrier.wait().await;
                    // Read: clone the payload out, drop the read lock.
                    let found = store.entries.read().await.get("tok").copied();
                    // Delete: result ignored — the bug.
                    let _ = store.entries.write().await.remove("tok");
                    found.is_some()
                }));
            }
            let mut winners = 0usize;
            for handle in handles {
                if handle.await.expect("task") {
                    winners += 1;
                }
            }
            if winners >= 2 {
                ever_two = true;
                break;
            }
        }
        assert!(
            ever_two,
            "clone-then-delete must hand the credential to two racers on a multi-thread runtime"
        );
    }

    #[tokio::test]
    async fn a_second_sequential_claim_loses() {
        let store = MemoryConsumableStore::<u8>::new();
        store
            .put("tok", 1, later(60), Utc::now())
            .await
            .expect("park");
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
        store
            .put("tok", 1, later(-1), Utc::now())
            .await
            .expect("park");
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
        let now = Utc::now();
        store
            .put("tok", 1, later(60), now)
            .await
            .expect("first park");
        let err = store
            .put("tok", 2, later(60), now)
            .await
            .expect_err("a live duplicate must be refused");
        // The refusal is a typed contract violation, not an opaque string —
        // hosts branch on the downcast instead of matching prose.
        assert!(
            matches!(
                err.downcast_ref::<KirinoError>(),
                Some(KirinoError::Validation(message)) if message.contains("already parked")
            ),
            "the refusal is KirinoError::Validation: {err}"
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
        let now = Utc::now();
        store
            .put("tok", 1, later(-1), now)
            .await
            .expect("park expired");
        store
            .put("tok", 2, later(60), now)
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
        let now = Utc::now();
        store.put("dead", 1, later(-5), now).await.expect("park");
        store.put("live", 2, later(60), now).await.expect("park");
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
            .put("super-secret-token", 1, later(60), Utc::now())
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

    /// At capacity the store refuses the **new** credential and keeps every
    /// live one. Evicting would be a targeted login DoS: whoever can reach
    /// `put` could flood the store (long TTLs win, short TTLs are shed) and
    /// knock out other people's in-flight logins.
    #[tokio::test]
    async fn a_full_store_refuses_new_credentials_and_keeps_live_ones() {
        let store = MemoryConsumableStore::<u8>::with_capacity(2);
        let now = Utc::now();
        store.put("a", 1, later(10), now).await.expect("park");
        store.put("b", 2, later(120), now).await.expect("park");

        let err = store
            .put("c", 3, later(300), now)
            .await
            .expect_err("a full store must refuse rather than evict");
        assert!(
            matches!(
                err.downcast_ref::<KirinoError>(),
                Some(KirinoError::Validation(message)) if message.contains("full")
            ),
            "the refusal names the capacity condition: {err}"
        );
        // Both live credentials survive, and each still resolves to exactly
        // one winner.
        assert_eq!(store.len().await, 2);
        assert_eq!(
            store.claim("a", Utc::now()).await.expect("claim"),
            Claim::Won(1),
            "the earliest-expiring credential was NOT sacrificed"
        );
        assert_eq!(
            store.claim("b", Utc::now()).await.expect("claim"),
            Claim::Won(2)
        );
    }

    /// A full store still accepts a `put` once dead entries are shed: the
    /// capacity check prunes expired keys before refusing.
    #[tokio::test]
    async fn a_full_store_makes_room_by_dropping_dead_entries() {
        let store = MemoryConsumableStore::<u8>::with_capacity(1);
        let now = Utc::now();
        store.put("dead", 1, later(-1), now).await.expect("park");
        store
            .put("fresh", 2, later(60), now)
            .await
            .expect("a dead entry does not consume capacity");
        assert_eq!(store.len().await, 1);
        assert_eq!(
            store.claim("fresh", Utc::now()).await.expect("claim"),
            Claim::Won(2)
        );
    }

    #[tokio::test]
    async fn with_capacity_zero_is_clamped_to_one() {
        let store = MemoryConsumableStore::<u8>::with_capacity(0);
        store
            .put("tok", 1, later(60), Utc::now())
            .await
            .expect("a clamp to 1 keeps the store usable");
    }

    /// Documents the defect class the trait exists to forbid: read the entry,
    /// yield, then delete it. It is a *demonstration against a hand-written
    /// naive store*, not a guard on [`MemoryConsumableStore`] — the guard on
    /// the real implementation is
    /// `claim_hands_the_payload_to_exactly_one_of_many_racers` (the R2 review
    /// rewrote the real `claim` this way and saw 32 winners out of 32
    /// racers). Kept because the shape is easier to see here than in a
    /// one-line lock argument.
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
