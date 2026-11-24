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

use anyhow::Result;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use tokio::sync::RwLock;

use async_trait::async_trait;

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

    /// A payload whose `clone` blocks for a fixed spin, so a read-then-delete
    /// window is **held open** instead of hoped for.
    ///
    /// The R3/R4 reviews measured the alternative: with a plain payload the
    /// "exactly one racer" pin caught the clone-then-delete mutation only
    /// probabilistically (17/20 filtered, 15/16 in the full suite, 0/10 on one
    /// CPU), and a negative control built on scheduling went red on the
    /// *correct* implementation one run in twenty. A window that is merely
    /// likely is not a test. Blocking inside the clone keeps the racer that
    /// holds the read lock there for a measurable time, so every other racer
    /// is guaranteed to arrive while the window is open — on any core count,
    /// in any suite order. The correct `claim` never calls `clone` at all
    /// (it moves the payload out under the write lock), so the spin costs
    /// the real implementation nothing.
    struct SlowPayload(u32);

    /// How long a read-phase `clone` spins. Long enough that 31 other racers
    /// have certainly entered `claim` on a loaded machine; short enough that
    /// a mutated run finishes in well under a second.
    const WINDOW_SPIN: std::time::Duration = std::time::Duration::from_millis(20);

    impl Clone for SlowPayload {
        fn clone(&self) -> Self {
            spin_for(WINDOW_SPIN);
            Self(self.0)
        }
    }

    fn spin_for(d: std::time::Duration) {
        let until = std::time::Instant::now() + d;
        while std::time::Instant::now() < until {
            std::hint::spin_loop();
        }
    }

    /// The contract's central claim: exactly one of many racers wins, with
    /// the window forced open by [`SlowPayload`].
    ///
    /// Under the correct `claim` the payload is moved, never cloned, so the
    /// spin never runs and 32 racers resolve in microseconds. Under the
    /// clone-then-delete mutation every racer that enters the read phase
    /// before the first delete spends 20 ms inside `clone`, which is far
    /// longer than the other 31 need to arrive — so several of them clone
    /// the payload and several win. R4 measured this shape 80/80 red on
    /// every core count including one.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn claim_hands_the_payload_to_exactly_one_of_many_racers() {
        for round in 0..8u32 {
            let store: Arc<MemoryConsumableStore<SlowPayload>> =
                Arc::new(MemoryConsumableStore::new());
            store
                .put(
                    &format!("tok-{round}"),
                    SlowPayload(round),
                    later(60),
                    Utc::now(),
                )
                .await
                .expect("park");

            let barrier = Arc::new(tokio::sync::Barrier::new(32));
            let mut handles = Vec::new();
            for _ in 0..32 {
                let store = Arc::clone(&store);
                let token = format!("tok-{round}");
                let barrier = Arc::clone(&barrier);
                handles.push(tokio::spawn(async move {
                    barrier.wait().await;
                    store.claim(&token, Utc::now()).await
                }));
            }
            let mut winners = 0usize;
            for handle in handles {
                let claim = handle.await.expect("task").expect("claim");
                if let Claim::Won(payload) = claim {
                    assert_eq!(payload.0, round, "the winner gets the right payload");
                    winners += 1;
                }
            }
            assert_eq!(winners, 1, "round {round}: exactly one racer may win");
            assert_eq!(store.len().await, 0, "the entry is gone after the winner");
        }
    }

    /// The defect shape, as a hand-written store, with the **same** forced
    /// window: the reader clones the payload under the read lock, then
    /// deletes without consulting the result.
    ///
    /// This demonstrates the defect shape on a hand-written store; it does not
    /// exercise `MemoryConsumableStore` (the pin above does). It is deterministic where a
    /// scheduling-based control was not: the spin holds the window open on
    /// every core count, and on a `current_thread` runtime it goes red
    /// (the tasks never overlap, so only one racer ever reads) — which is
    /// exactly the property the pin relies on the multi-thread flavor for.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn naive_clone_then_delete_loses_the_guarantee() {
        struct NaiveStore {
            entries: RwLock<HashMap<String, SlowPayload>>,
        }
        let store = Arc::new(NaiveStore {
            entries: RwLock::new(HashMap::from([("tok".to_string(), SlowPayload(1))])),
        });
        let barrier = Arc::new(tokio::sync::Barrier::new(8));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            handles.push(tokio::spawn(async move {
                barrier.wait().await;
                // Read: clone the payload (spins 20 ms), drop the read lock.
                let found = store.entries.read().await.get("tok").cloned();
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
        assert!(
            winners >= 2,
            "clone-then-delete must hand the credential to several racers (got {winners})"
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

    /// The `now` parameter drives every time decision — `claim`, `put` and
    /// `sweep` each — on a clock the wall clock cannot match. R4 showed all
    /// three could be swapped for `Utc::now()` with every case green; R5
    /// showed the first version of this case only pinned `claim` (its
    /// duplicate-put leg never reached the duplicate branch).
    #[tokio::test]
    async fn the_callers_clock_decides_liveness_not_the_wall_clock() {
        let park_at = Utc::now() - chrono::Duration::days(10);

        // claim: parked "ten days ago" per the wall clock, live per the
        // caller's.
        let store = MemoryConsumableStore::<u8>::new();
        store
            .put("tok", 1, park_at + chrono::Duration::seconds(60), park_at)
            .await
            .expect("park");
        let inside = park_at + chrono::Duration::seconds(30);
        assert_eq!(
            store.claim("tok", inside).await.expect("claim"),
            Claim::Won(1),
            "the caller's clock, not the wall clock, says this is live"
        );

        // put: the same token is refused as a live duplicate at `inside`,
        // and accepted as a replacement at an instant the caller says is
        // past its expiry — the branch a wall-clock `put` would take the
        // other way round.
        let store = MemoryConsumableStore::<u8>::new();
        store
            .put("dup", 1, park_at + chrono::Duration::seconds(60), park_at)
            .await
            .expect("park");
        let refused = store
            .put("dup", 2, park_at + chrono::Duration::seconds(120), inside)
            .await
            .expect_err("still live at `inside` per the caller");
        assert!(
            matches!(
                refused.downcast_ref::<KirinoError>(),
                Some(KirinoError::Validation(m)) if m.contains("already parked")
            ),
            "{refused}"
        );
        let past = park_at + chrono::Duration::seconds(61);
        store
            .put("dup", 2, past + chrono::Duration::seconds(60), past)
            .await
            .expect("dead at `past` per the caller, so the token is free");
        assert_eq!(
            store
                .claim("dup", past + chrono::Duration::seconds(1))
                .await
                .expect("claim"),
            Claim::Won(2)
        );

        // sweep: a row the wall clock expired ten days ago is NOT swept at
        // an instant the caller says is before its expiry.
        store
            .put("keep", 3, park_at + chrono::Duration::seconds(120), park_at)
            .await
            .expect("park");
        let removed = store.sweep(inside).await.expect("sweep");
        assert_eq!(removed, 0, "nothing is expired at the caller's `inside`");
        assert_eq!(store.len().await, 1);
        // …and IS swept once the caller's clock passes it.
        assert_eq!(
            store
                .sweep(park_at + chrono::Duration::seconds(121))
                .await
                .expect("sweep"),
            1
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
