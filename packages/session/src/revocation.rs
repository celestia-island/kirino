//! In-memory revocation store for rotating refresh tokens.
//!
//! A refresh token issued by [`crate::manager::TokenManager`] carries a
//! session id (`sid`) that is unique per token pair. When a pair is rotated
//! with [`crate::manager::TokenManager::refresh_rotating`], the presented
//! token's `sid` is recorded here together with the revocation timestamp.
//! Any later attempt to rotate with the same `sid` is rejected while the
//! entry is inside the rejection window (`refresh TTL + verify leeway`).
//!
//! Entries only need to be retained for that window: because a `sid` is
//! unique to one token pair, every refresh token carrying a revoked `sid`
//! stops verifying at latest `revocation time + refresh TTL + verify
//! leeway`. After that point no token with that `sid` can pass
//! [`crate::manager::TokenManager::verify`] any more, so the stale entry
//! carries no security value and can be dropped. [`REVOCATION_MAX_ENTRIES`]
//! is only a safety valve that prunes already-expired entries once the map
//! grows past it — between prunes the map grows with rotation traffic, but
//! each entry is just a sid string plus one `i64` timestamp, so the
//! per-entry cost is tiny.
//!
//! The store is in-memory by design: **all refresh traffic must be funneled
//! into the single process that holds this store** — an in-memory map
//! cannot be shared across processes. Within that process, share it between
//! tasks through an `Arc`. A restart forgets pending rotations, which at
//! worst re-allows reuse of a not-yet-expired old refresh token until the
//! window elapses; callers who need stronger guarantees should persist the
//! map externally.

use std::collections::HashMap;

use tokio::sync::RwLock;

/// Upper bound on retained revocation entries before already-expired ones
/// are pruned. Matches the auto-cleanup pattern of the root crate's
/// `JwtManager` revocation map.
const REVOCATION_MAX_ENTRIES: usize = 10_000;

/// Verify-leeway grace period in seconds that
/// [`crate::manager::TokenManager::verify`] inherits from jsonwebtoken's
/// default `Validation` (`leeway = 60`): a token keeps passing signature
/// and expiry verification up to this many seconds past its `exp`. The
/// rejection window must cover that grace period — otherwise a reused
/// token that `verify()` still accepts would slip through undetected.
const VERIFY_LEEWAY_SECS: i64 = 60;

/// Tracks revoked refresh-token session ids within the rejection window
/// (refresh TTL plus verify leeway).
///
/// Key: session id (`sid`). Value: unix timestamp of the revocation.
pub struct RefreshRevocationStore {
    refresh_ttl_secs: i64,
    entries: RwLock<HashMap<String, i64>>,
}

/// Inserts a revocation record, pruning entries that already fell out of
/// the window once the map grows past [`REVOCATION_MAX_ENTRIES`]. The
/// just-inserted entry always survives.
fn record_entry(entries: &mut HashMap<String, i64>, session_id: &str, now: i64, window: i64) {
    entries.insert(session_id.to_string(), now);
    if entries.len() > REVOCATION_MAX_ENTRIES {
        let cutoff = now - window;
        entries.retain(|_, &mut ts| ts >= cutoff);
    }
}

impl RefreshRevocationStore {
    /// Creates a store for refresh tokens whose nominal lifetime is
    /// `refresh_ttl_secs`.
    ///
    /// `refresh_ttl_secs` must be greater than zero and must equal the
    /// refresh-token TTL of the issuing [`crate::manager::TokenManager`]
    /// configuration: a smaller value shrinks the rejection window below
    /// the real token lifetime, so late reuse slips through undetected; a
    /// larger value only keeps entries resident longer than any live token
    /// could. Internally the window is widened by
    /// [`VERIFY_LEEWAY_SECS`] to match what `verify()` actually accepts.
    pub fn new(refresh_ttl_secs: i64) -> Self {
        debug_assert!(
            refresh_ttl_secs > 0,
            "refresh_ttl_secs must be positive; a non-positive TTL disables reuse detection"
        );
        Self {
            refresh_ttl_secs,
            entries: RwLock::new(HashMap::new()),
        }
    }

    /// Total rejection window: nominal refresh TTL plus the verify-leeway
    /// grace period (see [`VERIFY_LEEWAY_SECS`]).
    fn window_secs(&self) -> i64 {
        self.refresh_ttl_secs + VERIFY_LEEWAY_SECS
    }

    /// Records `session_id` as revoked at unix time `now`.
    ///
    /// When the map exceeds [`REVOCATION_MAX_ENTRIES`], entries older than
    /// the rejection window (`ts < now - window`) are pruned; the
    /// just-inserted entry always survives.
    pub async fn revoke(&self, session_id: &str, now: i64) {
        let window = self.window_secs();
        let mut entries = self.entries.write().await;
        record_entry(&mut entries, session_id, now, window);
    }

    /// Atomically checks whether `session_id` was already rotated inside
    /// the rejection window and, if not, records it as revoked at `now`.
    ///
    /// Returns `true` when this is the first rotation attempt for the sid
    /// (the caller should proceed with issuing the new pair), `false` when
    /// the sid was already revoked inside the window (reuse — the caller
    /// must reject). The check and the bookkeeping share one write lock,
    /// so concurrent rotations of the same sid cannot all observe "first
    /// use": exactly one caller gets `true`.
    pub async fn check_and_revoke(&self, session_id: &str, now: i64) -> bool {
        let window = self.window_secs();
        let mut entries = self.entries.write().await;
        if let Some(&ts) = entries.get(session_id) {
            if now <= ts + window {
                return false;
            }
        }
        record_entry(&mut entries, session_id, now, window);
        true
    }

    /// Returns `true` while a revocation for `session_id` is still inside
    /// the rejection window. Read-only check — the rotation path uses
    /// [`Self::check_and_revoke`] instead, which checks and records in one
    /// atomic step. An entry past the window counts as *not* revoked:
    /// every refresh token with that `sid` has stopped verifying (verify
    /// leeway included) by then.
    pub async fn is_revoked(&self, session_id: &str, now: i64) -> bool {
        let window = self.window_secs();
        let entries = self.entries.read().await;
        match entries.get(session_id) {
            Some(&ts) => now <= ts + window,
            None => false,
        }
    }

    /// Drops entries whose rejection window has fully elapsed
    /// (`ts + refresh_ttl_secs + VERIFY_LEEWAY_SECS < now`).
    pub async fn cleanup(&self, now: i64) {
        let window = self.window_secs();
        let mut entries = self.entries.write().await;
        entries.retain(|_, &mut ts| ts + window >= now);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    const TTL: i64 = 3_600;
    /// Full rejection window: refresh TTL plus the verify-leeway grace.
    const WINDOW: i64 = TTL + 60;

    #[tokio::test]
    async fn revoke_then_is_revoked_within_window() {
        let store = RefreshRevocationStore::new(TTL);
        assert!(!store.is_revoked("sid-a", 1_000).await);
        store.revoke("sid-a", 1_000).await;
        assert!(store.is_revoked("sid-a", 1_000).await);
        assert!(store.is_revoked("sid-a", 1_000 + WINDOW).await);
        // Past the window (TTL + verify leeway) the entry is equivalent to
        // not revoked: the token can no longer pass verify() either.
        assert!(!store.is_revoked("sid-a", 1_000 + WINDOW + 1).await);
        assert!(!store.is_revoked("sid-b", 1_000).await);
    }

    #[tokio::test]
    async fn cleanup_removes_only_expired_entries() {
        let store = RefreshRevocationStore::new(TTL);
        store.revoke("sid-old", 0).await;
        store.revoke("sid-live", 500).await;
        // Expire "sid-old" (0 + WINDOW < WINDOW + 1) while "sid-live"
        // (500 + WINDOW >= WINDOW + 1) survives.
        store.cleanup(WINDOW + 1).await;
        assert!(!store.is_revoked("sid-old", WINDOW + 1).await);
        assert!(store.is_revoked("sid-live", WINDOW + 1).await);
    }

    #[tokio::test]
    async fn check_and_revoke_allows_first_use_only() {
        let store = RefreshRevocationStore::new(TTL);
        assert!(store.check_and_revoke("sid-a", 1_000).await);
        // Same sid again — inside the window — is reuse.
        assert!(!store.check_and_revoke("sid-a", 1_000).await);
        assert!(!store.check_and_revoke("sid-a", 1_500).await);
        // Other sids are unaffected.
        assert!(store.check_and_revoke("sid-b", 1_000).await);
    }

    #[tokio::test]
    async fn check_and_revoke_is_atomic_under_concurrency() {
        let store = Arc::new(RefreshRevocationStore::new(TTL));
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let store = Arc::clone(&store);
                tokio::spawn(async move { store.check_and_revoke("sid-a", 1_000).await })
            })
            .collect();
        let mut first_use = 0;
        for handle in handles {
            if handle.await.unwrap() {
                first_use += 1;
            }
        }
        // Exactly one of the concurrent rotations observes "first use".
        assert_eq!(first_use, 1);
    }
}
