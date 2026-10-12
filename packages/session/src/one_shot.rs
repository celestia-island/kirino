use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use chrono::Utc;

/// Soft ceiling on live JTIs tracked by one [`OneShotStore`].
///
/// Each entry is a small string plus a timestamp, but the map was
/// previously unbounded between cleanup passes — a deployment that mints
/// one-shot tokens faster than they expire grew it without limit. At the
/// ceiling the store first prunes expired entries; if the map is still
/// full it **denies** the fresh JTI (fail closed — a replay check that
/// cannot record its verdict must not answer "fresh"). Raise this via a
/// sized constructor only after sizing the deployment's token rate.
const DEFAULT_MAX_JTIS: usize = 1_000_000;

/// Minimum seconds between lazy prune passes.
///
/// The store used to run a dedicated OS thread per instance purely for
/// this — a thread that never exited, held the map's `Arc` forever, and
/// made every `OneShotStore` in tests and multi-instance processes leak.
/// Pruning now piggybacks on `check_and_mark`: at most one caller per
/// interval pays the O(n) sweep.
const PRUNE_INTERVAL_SECS: i64 = 60;

/// In-memory one-shot token store that tracks JTI (JWT ID) claims
/// to prevent token replay attacks.
///
/// Each token carries a unique `jti` claim.  When a token is used for
/// the first time its JTI is recorded.  Subsequent uses of the same
/// JTI are rejected until the token expires (at which point the JTI
/// is automatically purged).
///
/// # Example
/// ```ignore
/// use kirino_session::OneShotStore;
///
/// let store = OneShotStore::new();
/// let expiry = chrono::Utc::now().timestamp() + 30;
///
/// assert!(!store.check_and_mark("jti-1", expiry)); // first use: allowed
/// assert!( store.check_and_mark("jti-1", expiry)); // second use: denied
/// ```
#[derive(Clone)]
pub struct OneShotStore {
    used: Arc<Mutex<HashMap<String, i64>>>,
    /// Unix-seconds timestamp of the last lazy prune pass (`0` = never).
    last_prune: Arc<AtomicU64>,
    /// JTI ceiling for this store; see [`DEFAULT_MAX_JTIS`].
    max_jtis: usize,
}

impl OneShotStore {
    /// Create a new store with lazy expiry cleanup (at most one prune
    /// pass every [`PRUNE_INTERVAL_SECS`], performed inline by whichever
    /// caller crosses the interval — no background thread).
    pub fn new() -> Self {
        Self::with_max_jtis(DEFAULT_MAX_JTIS)
    }

    /// Create a store with a custom JTI ceiling.
    pub fn with_max_jtis(max_jtis: usize) -> Self {
        Self {
            used: Arc::new(Mutex::new(HashMap::new())),
            last_prune: Arc::new(AtomicU64::new(0)),
            max_jtis: max_jtis.max(1),
        }
    }

    /// Check whether `jti` has already been used, and mark it as used
    /// if not.  `expiry` is a Unix timestamp after which the JTI is
    /// automatically pruned.
    ///
    /// Returns `true` if the JTI was already present (replay attempt),
    /// `false` if it is fresh (allowed). The check **fails closed**: a
    /// poisoned lock or a map at its ceiling answers "replay" — the one
    /// answer that can never admit a replayed credential.
    pub fn check_and_mark(&self, jti: &str, expiry: i64) -> bool {
        let mut map = match self.used.lock() {
            Ok(map) => map,
            Err(_poisoned) => {
                // Audit R1-SESS-2: the lock is poisoned only after a
                // panicking thread held it, leaving the map in an
                // arbitrary state. Answering "fresh" would wave every
                // replay through until restart — answer "replay" instead.
                tracing::error!(
                    target: "kirino_session::one_shot",
                    "one-shot store lock poisoned; denying replay check (fail closed)"
                );
                return true;
            }
        };

        let now = Utc::now().timestamp();
        self.maybe_prune(&mut map, now);

        if map.len() >= self.max_jtis {
            // Audit R1-SESS-5: the map is not allowed to grow without
            // bound; before denying, try shedding everything already
            // expired.
            map.retain(|_, exp| *exp > now);
            if map.len() >= self.max_jtis {
                tracing::warn!(
                    target: "kirino_session::one_shot",
                    cap = self.max_jtis,
                    "one-shot store at its JTI ceiling; denying fresh tokens (fail closed)"
                );
                return true;
            }
        }

        map.insert(jti.to_string(), expiry).is_some()
    }

    /// Prune expired entries, but at most once per
    /// [`PRUNE_INTERVAL_SECS`] across all clones of the store (the CAS
    /// elects exactly one caller per interval to pay the sweep).
    fn maybe_prune(&self, map: &mut HashMap<String, i64>, now: i64) {
        let last = self.last_prune.load(Ordering::Relaxed);
        if now - (last as i64) < PRUNE_INTERVAL_SECS {
            return;
        }
        if self
            .last_prune
            .compare_exchange(last, now as u64, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return; // another caller already took this interval's sweep
        }
        map.retain(|_, exp| *exp > now);
    }

    /// Return the current number of tracked JTIs (useful for monitoring).
    pub fn len(&self) -> usize {
        self.used.lock().map(|m| m.len()).unwrap_or(0)
    }

    /// Returns `true` if the store is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for OneShotStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_use_allowed_second_denied() {
        let store = OneShotStore::new();
        let expiry = Utc::now().timestamp() + 30;
        assert!(!store.check_and_mark("abc", expiry));
        assert!(store.check_and_mark("abc", expiry));
    }

    #[test]
    fn different_jtis_independent() {
        let store = OneShotStore::new();
        let expiry = Utc::now().timestamp() + 30;
        assert!(!store.check_and_mark("a", expiry));
        assert!(!store.check_and_mark("b", expiry));
        assert!(store.check_and_mark("a", expiry));
        assert!(!store.check_and_mark("c", expiry));
    }

    #[test]
    fn expired_jti_survives_until_a_prune_interval_elapses() {
        let store = OneShotStore::new();
        let past = Utc::now().timestamp() - 10;
        store.check_and_mark("expired", past);
        assert_eq!(store.len(), 1);
        // No background thread any more: the entry goes when a later
        // check crosses the prune interval, not on a timer.
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert_eq!(store.len(), 1);
        // Force the prune interval to look elapsed, then check again.
        store.last_prune.store(0, Ordering::Relaxed);
        store.check_and_mark("other", Utc::now().timestamp() + 30);
        assert_eq!(store.len(), 1, "the expired entry must be pruned");
    }

    #[test]
    fn empty_store() {
        let store = OneShotStore::new();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn len_tracks_insertions() {
        let store = OneShotStore::new();
        let expiry = Utc::now().timestamp() + 60;
        store.check_and_mark("a", expiry);
        store.check_and_mark("b", expiry);
        assert_eq!(store.len(), 2);
        store.check_and_mark("b", expiry);
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn concurrent_access() {
        use std::sync::Arc;
        use std::thread;

        let store = Arc::new(OneShotStore::new());
        let mut handles = vec![];
        let expiry = Utc::now().timestamp() + 60;

        for i in 0..10 {
            let s = store.clone();
            handles.push(thread::spawn(move || {
                let jti = format!("jti-{}", i % 5);
                s.check_and_mark(&jti, expiry)
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(store.len(), 5);
    }

    #[test]
    fn poisoned_lock_denies_instead_of_allowing() {
        // Audit R1-SESS-2: the pre-fix behavior on a poisoned lock was
        // `unwrap_or(false)` — "fresh" — which waved every replay through
        // after a single panicking caller. The store must deny instead.
        let store = OneShotStore::new();
        let bomber = store.clone();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _guard = bomber.used.lock().unwrap();
            panic!("poison the one-shot lock");
        }));
        let expiry = Utc::now().timestamp() + 30;
        assert!(
            store.check_and_mark("fresh-jti", expiry),
            "a poisoned lock must answer replay (deny), not fresh (allow)"
        );
    }

    #[test]
    fn ceiling_denies_fresh_jtis_rather_than_growing_unbounded() {
        // Audit R1-SESS-5: at the ceiling, a genuinely fresh JTI is
        // denied (fail closed) instead of the map growing without limit.
        let store = OneShotStore::with_max_jtis(2);
        let expiry = Utc::now().timestamp() + 60;
        assert!(!store.check_and_mark("a", expiry));
        assert!(!store.check_and_mark("b", expiry));
        assert!(
            store.check_and_mark("c", expiry),
            "a store at its ceiling must deny (answer replay), not grow"
        );
        // The two live entries keep their semantics.
        assert!(store.check_and_mark("a", expiry));
    }

    #[test]
    fn ceiling_sheds_expired_entries_before_denying() {
        let store = OneShotStore::with_max_jtis(2);
        store.check_and_mark("stale", Utc::now().timestamp() - 10);
        store.check_and_mark("live", Utc::now().timestamp() + 60);
        // "stale" is expired: the ceiling pass must shed it and admit the
        // fresh JTI.
        assert!(!store.check_and_mark("fresh", Utc::now().timestamp() + 60));
        assert_eq!(store.len(), 2);
    }
}
