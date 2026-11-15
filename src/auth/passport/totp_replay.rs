//! Replay guard for accepted TOTP time steps (RFC 6238 §5.2).
//!
//! RFC 6238 §5.2 requires a verifier to reject an OTP that was already
//! accepted for the same time step. Without that bookkeeping the ±1-step
//! clock-skew window makes a single observed code valid for up to three
//! periods (90 s at the default 30 s period) and every one of those
//! repetitions is a successful authentication.
//!
//! [`TotpVerifier`](super::dynamic_password::TotpVerifier) keeps the high-water mark for a
//! single verifier instance. That covers one process that reuses the
//! instance, but not the usual server shape — a verifier built per request
//! from a stored secret, and several replicas of them. Those deployments
//! must persist the mark itself, which is what [`TotpReplayGuard`] is for:
//!
//! - [`MemoryTotpReplayGuard`] — process-local map, single-replica
//!   semantics (the same caveat as `MemoryRevocationBackend`).
//! - `DbTotpReplayGuard` (`crate::database::db_totp_replay`, feature
//!   `rbac-db-session`) — shared `mfa_factors` table, so a step consumed on
//!   one replica is consumed on all of them.
//!
//! Both are keyed by a caller-chosen **factor id** (the row that owns the
//! TOTP secret: an MFA factor id, a user id, anything stable per secret).
//! Two different secrets must never share a factor id, and one secret must
//! always use the same factor id — otherwise the mark is either reset
//! (replay window re-opens) or wrongly shared (a legitimate factor is
//! rejected).

use std::collections::HashMap;

use tokio::sync::RwLock;

/// Durable "highest time step already accepted" per MFA factor.
///
/// Implementations must make [`accept_step`](Self::accept_step) an
/// **atomic check-and-set**: it returns `true` only for the caller that
/// advances the mark past `step`. Two concurrent submitters of the same
/// code inside the same window must therefore produce exactly one `true`,
/// which is what makes the guard a replay defence rather than a
/// best-effort log.
///
/// The method is fallible only through its return value, and it must fail
/// **closed**: a store that cannot read or write the mark (DB down, row
/// locked past the statement timeout) returns `false`, rejecting the code.
/// A code that cannot be proven unused is not a code that may
/// authenticate.
#[async_trait::async_trait]
pub trait TotpReplayGuard: Send + Sync {
    /// Records `step` for `factor_id` and returns whether this call is the
    /// one that advanced the mark.
    ///
    /// `true` means `step` was strictly greater than every step recorded
    /// for `factor_id` before (or no step was recorded at all) and the
    /// caller may authenticate. `false` means the step — or a newer one —
    /// was already accepted, so the code is a replay and must be rejected.
    ///
    /// `step` is a TOTP time-step counter (unix time / period), never
    /// negative in practice.
    async fn accept_step(&self, factor_id: &str, step: i64) -> bool;

    /// The highest step recorded for `factor_id`, or `None` when the
    /// factor has never had a step accepted (fresh enrollment, or a
    /// deployment that predates replay protection — the column is NULL
    /// there, which must keep the first verification working).
    async fn last_used_step(&self, factor_id: &str) -> Option<i64>;
}

/// Upper bound on retained [`MemoryTotpReplayGuard`] entries before
/// already-stale ones are pruned.
///
/// Mirrors the `REVOCATION_MAX_ENTRIES` safety valve in
/// `auth::credential::basic`: entries are only pruned once the map grows
/// past the cap, so steady-state behaviour is a plain map write.
pub const REPLAY_GUARD_MAX_ENTRIES: usize = 50_000;

/// Retention window (in TOTP steps) applied when pruning the in-memory
/// guard, measured from the newest step observed by the process.
///
/// Pruning a mark is safe only once the step it holds can no longer be
/// accepted by any verifier, and a verifier only accepts
/// `current - 1 ..= current + 1` (RFC 6238 §5.1 skew tolerance). 2880
/// steps is one day at the default 30 s period: five orders of magnitude
/// of slack against that ±1 window, so a pruned entry can only ever
/// describe a dead window and its replay is rejected by the window check
/// itself.
pub const REPLAY_GUARD_RETENTION_STEPS: i64 = 2880;

/// Process-local replay guard — the default, single-replica backend.
///
/// A mark recorded on one replica is invisible to the others, so a code
/// replayed against a different replica inside the ±1 window is accepted
/// there. Multi-replica deployments must install a shared guard (feature
/// `rbac-db-session`, `DbTotpReplayGuard`) instead.
#[derive(Default)]
pub struct MemoryTotpReplayGuard {
    entries: RwLock<HashMap<String, i64>>,
}

impl MemoryTotpReplayGuard {
    /// Creates an empty guard.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Drops entries that fell out of the retention window once the map
    /// grew past [`REPLAY_GUARD_MAX_ENTRIES`]. The newest entry (the step
    /// just recorded) is always inside the window, so it survives.
    fn prune(entries: &mut HashMap<String, i64>) {
        if entries.len() <= REPLAY_GUARD_MAX_ENTRIES {
            return;
        }
        let Some(&newest) = entries.values().max() else {
            return;
        };
        let cutoff = newest.saturating_sub(REPLAY_GUARD_RETENTION_STEPS);
        entries.retain(|_, &mut step| step >= cutoff);
    }
}

#[async_trait::async_trait]
impl TotpReplayGuard for MemoryTotpReplayGuard {
    async fn accept_step(&self, factor_id: &str, step: i64) -> bool {
        let mut entries = self.entries.write().await;
        match entries.get(factor_id) {
            // Replay: this step, or a newer one, was already accepted.
            Some(&previous) if step <= previous => false,
            _ => {
                entries.insert(factor_id.to_string(), step);
                Self::prune(&mut entries);
                true
            }
        }
    }

    async fn last_used_step(&self, factor_id: &str) -> Option<i64> {
        self.entries.read().await.get(factor_id).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn first_step_is_accepted() {
        let guard = MemoryTotpReplayGuard::new();
        assert!(guard.accept_step("factor-a", 100).await);
        assert_eq!(guard.last_used_step("factor-a").await, Some(100));
    }

    #[tokio::test]
    async fn same_step_is_rejected() {
        let guard = MemoryTotpReplayGuard::new();
        assert!(guard.accept_step("factor-a", 100).await);
        assert!(
            !guard.accept_step("factor-a", 100).await,
            "the same step must never be accepted twice"
        );
    }

    #[tokio::test]
    async fn older_step_is_rejected() {
        let guard = MemoryTotpReplayGuard::new();
        assert!(guard.accept_step("factor-a", 100).await);
        assert!(
            !guard.accept_step("factor-a", 99).await,
            "a step below the mark is a replay of an earlier window"
        );
        assert_eq!(guard.last_used_step("factor-a").await, Some(100));
    }

    #[tokio::test]
    async fn newer_step_is_accepted_and_advances() {
        let guard = MemoryTotpReplayGuard::new();
        assert!(guard.accept_step("factor-a", 100).await);
        assert!(guard.accept_step("factor-a", 101).await);
        assert_eq!(guard.last_used_step("factor-a").await, Some(101));
        assert!(!guard.accept_step("factor-a", 100).await);
    }

    #[tokio::test]
    async fn factors_are_independent() {
        let guard = MemoryTotpReplayGuard::new();
        assert!(guard.accept_step("factor-a", 100).await);
        assert!(
            guard.accept_step("factor-b", 100).await,
            "a different factor's mark must not block this one"
        );
        assert_eq!(guard.last_used_step("factor-b").await, Some(100));
    }

    #[tokio::test]
    async fn unknown_factor_has_no_step() {
        let guard = MemoryTotpReplayGuard::new();
        assert_eq!(guard.last_used_step("never-seen").await, None);
    }

    /// Concurrent submitters of the same code must produce exactly one
    /// winner: the write lock serialises the check-and-set.
    #[tokio::test]
    async fn concurrent_same_step_single_winner() {
        let guard = MemoryTotpReplayGuard::new();
        let (first, second) = tokio::join!(
            guard.accept_step("factor-a", 100),
            guard.accept_step("factor-a", 100),
        );
        assert!(
            first ^ second,
            "exactly one of two concurrent identical steps may win (got {first}/{second})"
        );
    }
}
