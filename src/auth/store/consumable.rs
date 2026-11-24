//! The atomic single-use primitive shared by every kirino credential.
//!
//! See the [module docs](self) for why the claim reports a winner instead
//! of returning the result of a delete.
//!
//! `chrono` is used here because the rest of this crate's time-bearing
//! public API does (`LoginAttempt`, `kirino-session`); the type has to agree
//! across the trait boundary. It is covered by the repository-wide
//! RUSTSEC-2026-0543 ignore and moves to `jiff` with that wave.

use anyhow::Result;
use chrono::{DateTime, Utc};

use async_trait::async_trait;
use sha2::Digest;

/// The outcome of [`ConsumableStore::claim`].
///
/// [`Lost`](Self::Lost) deliberately covers **every** way a claim can fail —
/// unknown token, already consumed, expired, or swept — because telling
/// those apart hands an attacker a probing oracle (`this code existed but
/// expired` vs `this code never existed`). The one distinction a caller may
/// rely on is won/lost.
///
/// `non_exhaustive`: a later slice may add a third state (a soft
/// "still-processing" reply for the device flow's `authorization_pending`),
/// and callers must not be broken by it. Match with a `_ =>` arm.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Claim<P> {
    /// This caller consumed the credential; the payload is theirs alone.
    Won(P),
    /// Somebody else consumed it, or it was never valid.
    Lost,
}

impl<P> Claim<P> {
    /// Whether this caller won the claim.
    #[must_use]
    pub const fn is_won(&self) -> bool {
        matches!(self, Self::Won(_))
    }

    /// The payload when this caller won.
    #[must_use]
    pub fn payload(self) -> Option<P> {
        match self {
            Self::Won(payload) => Some(payload),
            Self::Lost => None,
        }
    }
}

/// Storage for single-use credentials, parameterised by the parked payload.
///
/// `P` is fixed per deployment (a concrete grant, a device request, a
/// recovery-code record), which keeps the trait object-safe:
/// `Arc<dyn ConsumableStore<CodeGrant>>` is a usable field in a host's
/// state.
///
/// # Contract an implementation must honour
///
/// 1. **Atomic claim.** Among any number of concurrent `claim`s for one
///    token, exactly one sees [`Claim::Won`]. This is the whole point of
///    the trait; an implementation that earns it with a single SQL
///    statement, a single lock, or a compare-and-swap is fine — one that
///    reads and then deletes as two steps is not.
/// 2. **Consume on failure too.** A claim of an expired token must return
///    [`Claim::Lost`] *and* drop the entry: otherwise an expired credential
///    outlives its own lifetime in the store.
/// 3. **No replay window.** `put` refuses a token that is still parked; two
///    live credentials may never share a fingerprint (see
///    [`fingerprint`]).
/// 4. **Fingerprints only.** Implementations store [`fingerprint`], never
///    the raw token, so a heap dump or a database leak exposes no usable
///    credential.
/// 5. **Never destroy a live credential.** A store at capacity must refuse
///    the *new* `put`, not evict a credential that some user is still
///    holding — dropping it turns "exactly one winner" into "no winner"
///    for a login that was already under way.
///
/// # Errors
///
/// Two failure classes, and they must stay distinguishable:
///
/// - **Contract violations** (a duplicate token, a full store) are the
///   caller's bug or a capacity condition, and they are recoverable — the
///   caller generates a fresh token or sheds load. Implementations report
///   them as [`crate::error::KirinoError::Validation`] so a host can
///   `downcast_ref` instead of matching on prose.
/// - **Storage failures** (the backend is unreachable, the statement
///   errored) are NOT recoverable and are reported as whatever the backend
///   produced. They must never be collapsed into [`Claim::Lost`] — "I could
///   not reach the store" reported as "this credential is dead" silently
///   destroys live sessions.
///
/// `now` is a parameter on all three methods rather than an internal
/// `Utc::now()`, so expiry is testable without sleeping and so a caller can
/// pass one timestamp through a whole flow (park and claim agree on the
/// same clock).
#[async_trait]
pub trait ConsumableStore<P>: Send + Sync
where
    P: Send + Sync + 'static,
{
    /// Park `payload` under `token` until `expires_at`.
    ///
    /// `now` decides whether an already-parked entry under the same
    /// fingerprint is still alive: a live one is refused, a dead one may be
    /// replaced.
    ///
    /// # Errors
    ///
    /// [`crate::error::KirinoError::Validation`] when the token is still
    /// parked (the host must generate a fresh token per credential) or the
    /// store is at capacity; the backend's own error for storage failures.
    async fn put(
        &self,
        token: &str,
        payload: P,
        expires_at: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<()>;

    /// Claim `token`: exactly one racing caller wins.
    ///
    /// # Errors
    ///
    /// Implementation-specific storage failures. A storage failure is NOT
    /// [`Claim::Lost`] — "I could not reach the store" must not be reported
    /// as "this credential is dead", or a database blip would silently
    /// destroy live sessions.
    async fn claim(&self, token: &str, now: DateTime<Utc>) -> Result<Claim<P>>;

    /// Drop every entry that has expired at `now`, returning how many were
    /// removed.
    ///
    /// **Not** done automatically: neither shipped backend sweeps on claim
    /// (a claim only removes its own key/row), so a host that never calls
    /// this accumulates expired rows until the store's own bounds engage.
    /// Call it from a maintenance task.
    ///
    /// # Errors
    ///
    /// Implementation-specific storage failures.
    async fn sweep(&self, now: DateTime<Utc>) -> Result<u64> {
        let _ = now;
        Ok(0)
    }
}

/// The stored form of a token: lowercase hex SHA-256.
///
/// Tokens are high-entropy random strings, so a plain hash is the right
/// primitive (no salt, no KDF — there is nothing to brute-force). Every
/// implementation of [`ConsumableStore`] must key on this rather than on
/// the raw token; hosts that keep their own credential table should use it
/// too so one leak does not expose both.
#[must_use]
pub fn fingerprint(token: &str) -> String {
    hex::encode(sha2::Sha256::digest(token.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_claim_reports_win_and_payload_together() {
        let won: Claim<u8> = Claim::Won(7);
        assert!(won.is_won());
        assert_eq!(won.payload(), Some(7));
        // MUT:claim-outcome — a losing claim must carry no payload; a store
        // that answers `Won` on a miss would hand every caller the data.
        let lost: Claim<u8> = Claim::Lost;
        assert!(!lost.is_won());
        assert_eq!(lost.payload(), None);
    }

    #[test]
    fn fingerprints_are_stable_hex_and_do_not_leak_the_token() {
        let token = "correct-horse-battery-staple";
        let digest = fingerprint(token);
        assert_eq!(digest.len(), 64, "sha256 hex is 64 chars");
        assert!(digest.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(digest, digest.to_lowercase(), "lowercase hex");
        // Stable across calls (this is what makes it a usable primary key)…
        assert_eq!(digest, fingerprint(token));
        // …and the raw token never appears in it.
        assert!(!digest.contains(token));
        // Distinct tokens must not collide (they cannot, but a swapped-out
        // hash — say, the token itself — would show up here).
        assert_ne!(digest, fingerprint("correct-horse-battery-stapl3"));
    }
}
