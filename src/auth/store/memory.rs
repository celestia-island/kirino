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
        let key = fingerprint(token);
        // One write lock spans lookup, expiry check and removal — the
        // atomicity the trait contract requires. `MUT:naive-claim`: splitting
        // this into a `read` followed by a `write` gives many winners; the
        // concurrency case below turns red when it is done that way (proved
        // by the R2 review, which rewrote this method as read→yield→delete
        // and saw 32 winners out of 32 racers).
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
        store
            .put("tok", "grant", later(60), Utc::now())
            .await
            .expect("park");

        // 32 concurrent claimers. The contract is one winner — not "at most
        // one" (a store that answers `Lost` to everybody would strand the
        // login) and certainly not "however many got there first".
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
