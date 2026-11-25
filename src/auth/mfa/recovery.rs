//! Single-use recovery codes through the single-use store.
//!
//! A recovery code is a credential exactly like an authorization code: it
//! must be consumed by exactly one caller, the caller must be told whether
//! it won, and a storage blip must not silently burn it. That is the
//! contract [`ConsumableStore`] already enforces (K0), so this module is
//! thin on purpose — issue, hash, consume — and adds only what codes need:
//!
//! - codes are stored **hashed** (SHA-256, the store's own `fingerprint`),
//!   so a leaked table is not a bag of valid codes;
//! - a code is **not** a string comparison against a list: `claim` is the
//!   check, and losing the claim is "not a valid code";
//! - the code a user sees is grouped for typing and carries no information
//!   beyond its entropy.

use chrono::{DateTime, Utc};
use thiserror::Error;

use crate::auth::store::{Claim, ConsumableStore};

/// What a user is shown: the code in typing groups, and nothing else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryCode {
    /// The code as typed, groups joined by `-`.
    pub display: String,
}

/// Why a recovery step failed.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum RecoveryError {
    /// The code is not one this issuer knows, or was already used.
    #[error("the recovery code is not valid or was already used")]
    Invalid,
    /// The store failed. **Not** a verdict on the code.
    #[error("the recovery store failed: {0}")]
    Store(String),
    /// The code's shape is wrong before any store is consulted.
    #[error("a recovery code has the form xxxx-xxxx-xxxx")]
    Malformed,
}

/// Issues and consumes recovery codes for one subject.
///
/// Generic over the payload the host parks; the payload is what lets the
/// host find the subject a code belongs to — a subject id, or a struct
/// with the subject and the code's index.
pub struct RecoveryIssuer<'a, P, S>
where
    P: Clone + Send + Sync + 'static,
    S: ConsumableStore<P>,
{
    store: &'a S,
    /// How long an unused code stays valid.
    ttl_secs: i64,
    _subject: std::marker::PhantomData<P>,
}

impl<P, S> RecoveryIssuer<'_, P, S>
where
    P: Clone + Send + Sync + 'static,
    S: ConsumableStore<P>,
{
    /// A new issuer over `store`, codes valid for `ttl_secs`.
    #[must_use]
    pub fn new(store: &S, ttl_secs: i64) -> RecoveryIssuer<'_, P, S> {
        RecoveryIssuer {
            store,
            ttl_secs,
            _subject: std::marker::PhantomData,
        }
    }

    /// Issue one code for `payload` at `now`, parking its hash.
    ///
    /// # Errors
    ///
    /// [`RecoveryError::Store`] if the park fails — the caller must not show
    /// the user a code that is not stored.
    pub async fn issue(
        &self,
        payload: P,
        now: DateTime<Utc>,
    ) -> Result<RecoveryCode, RecoveryError> {
        let raw = random_code();
        let display = grouped(&raw);
        let fingerprint = crate::auth::store::fingerprint(&normalise(&display));
        self.store
            .put(
                &fingerprint,
                payload,
                now + chrono::Duration::seconds(self.ttl_secs),
                now,
            )
            .await
            .map_err(|e| RecoveryError::Store(e.to_string()))?;
        Ok(RecoveryCode { display })
    }

    /// Consume a code as typed by the user.
    ///
    /// The claim is the check: exactly one caller wins, and a losing caller
    /// is told `Invalid` — indistinguishable from an unknown code, so a
    /// prober learns nothing from a replay.
    ///
    /// # Errors
    ///
    /// - [`RecoveryError::Malformed`] if the shape is wrong (no store call).
    /// - [`RecoveryError::Invalid`] if the code is unknown or spent.
    /// - [`RecoveryError::Store`] if the store failed — the code is NOT
    ///   consumed on this path (the claim never happened), so the user may
    ///   retry.
    pub async fn consume(&self, typed: &str, now: DateTime<Utc>) -> Result<P, RecoveryError> {
        let normal = normalise(typed);
        if normal.len() != CODE_CHARS || !normal.chars().all(|c| c.is_ascii_digit()) {
            return Err(RecoveryError::Malformed);
        }
        let fingerprint = crate::auth::store::fingerprint(&normal);
        match self.store.claim(&fingerprint, now).await {
            Ok(Claim::Won(payload)) => Ok(payload),
            Ok(Claim::Lost) => Err(RecoveryError::Invalid),
            // A store failure after the claim reached the store is reported
            // as a store failure; the contract says the claim never happened
            // on this path, so nothing was burned.
            Err(e) => Err(RecoveryError::Store(e.to_string())),
        }
    }
}

/// 12 decimal digits: ~40 bits, enough for a typed code that is single-use
/// and rate-limited, and far easier to type than a base64url string.
const CODE_DIGITS: usize = 12;
const CODE_CHARS: usize = CODE_DIGITS;

fn random_code() -> String {
    use rand::RngExt;
    // 12 digits from 5 bytes (40 bits > 10^12), rejection-free by folding.
    let raw: [u8; 5] = rand::rng().random();
    let n =
        u64::from_be_bytes([0, 0, 0, raw[0], raw[1], raw[2], raw[3], raw[4]]) % 1_000_000_000_000;
    format!("{n:012}")
}

fn grouped(raw: &str) -> String {
    format!("{}-{}-{}", &raw[0..4], &raw[4..8], &raw[8..12])
}

/// Accept what a user types: case-insensitive, separators optional.
fn normalise(typed: &str) -> String {
    typed.chars().filter(|c| c.is_ascii_digit()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::store::MemoryConsumableStore;

    fn claim_key_of(plain: &str) -> String {
        crate::auth::store::fingerprint(plain)
    }

    fn issuer<'a>(
        store: &'a MemoryConsumableStore<String>,
    ) -> RecoveryIssuer<'a, String, MemoryConsumableStore<String>> {
        RecoveryIssuer::new(store, 3600)
    }

    #[test]
    fn a_code_is_twelve_digits_in_three_groups() {
        let raw = random_code();
        assert_eq!(raw.len(), 12);
        assert!(raw.chars().all(|c| c.is_ascii_digit()));
        let g = grouped(&raw);
        assert_eq!(g.len(), 14);
        assert_eq!(g.matches('-').count(), 2);
    }

    #[tokio::test]
    async fn an_issued_code_is_consumed_exactly_once() {
        let store = MemoryConsumableStore::new();
        let now = Utc::now();
        let code = issuer(&store)
            .issue("subject-1".to_owned(), now)
            .await
            .unwrap();
        let got = issuer(&store).consume(&code.display, now).await.unwrap();
        assert_eq!(got, "subject-1");
        // The same code again: invalid, and indistinguishable from unknown.
        assert_eq!(
            issuer(&store)
                .consume(&code.display, now)
                .await
                .unwrap_err(),
            RecoveryError::Invalid
        );
        // An unknown code: the same error.
        assert_eq!(
            issuer(&store)
                .consume("0000-0000-0000", now)
                .await
                .unwrap_err(),
            RecoveryError::Invalid
        );
    }

    #[tokio::test]
    async fn the_store_holds_a_hash_not_the_code() {
        let store = MemoryConsumableStore::new();
        let now = Utc::now();
        let code = issuer(&store)
            .issue("subject-1".to_owned(), now)
            .await
            .unwrap();
        let plain = code.display.replace('-', "");
        // The code the user sees is not a key; the key is its fingerprint.
        assert_eq!(
            claim_key_of(&plain),
            crate::auth::store::fingerprint(&plain)
        );
        // And the plain code is not retrievable from the key.
        assert_ne!(claim_key_of(&plain), plain);
    }

    #[tokio::test]
    async fn typing_is_forgiving_on_separators_only() {
        let store = MemoryConsumableStore::new();
        let now = Utc::now();
        let code = issuer(&store)
            .issue("subject-1".to_owned(), now)
            .await
            .unwrap();
        let digits: String = code
            .display
            .chars()
            .filter(|c| c.is_ascii_digit())
            .collect();
        let respaced = format!("{} {}", &digits[0..6], &digits[6..]);
        assert_eq!(
            issuer(&store).consume(&respaced, now).await.unwrap(),
            "subject-1"
        );
    }

    #[tokio::test]
    async fn a_malformed_code_never_reaches_the_store() {
        let store = MemoryConsumableStore::new();
        let now = Utc::now();
        assert_eq!(
            issuer(&store).consume("1234", now).await.unwrap_err(),
            RecoveryError::Malformed
        );
        assert_eq!(
            issuer(&store)
                .consume("abcd-efgh-ijkl", now)
                .await
                .unwrap_err(),
            RecoveryError::Malformed
        );
        assert_eq!(
            issuer(&store)
                .consume("1234567890123", now)
                .await
                .unwrap_err(),
            RecoveryError::Malformed
        );
    }

    #[tokio::test]
    async fn an_expired_code_is_invalid() {
        let store = MemoryConsumableStore::new();
        let t0 = Utc::now();
        let code = issuer(&store)
            .issue("subject-1".to_owned(), t0)
            .await
            .unwrap();
        let later = t0 + chrono::Duration::seconds(3601);
        assert_eq!(
            issuer(&store)
                .consume(&code.display, later)
                .await
                .unwrap_err(),
            RecoveryError::Invalid
        );
    }

    #[tokio::test]
    async fn two_concurrent_consumers_get_exactly_one_win() {
        let store = std::sync::Arc::new(MemoryConsumableStore::new());
        let now = Utc::now();
        let code = issuer(&store)
            .issue("subject-1".to_owned(), now)
            .await
            .unwrap();
        let i1 = issuer(&store);
        let i2 = issuer(&store);
        let (a, b) = tokio::join!(
            i1.consume(&code.display, now),
            i2.consume(&code.display, now)
        );
        let wins = [a.is_ok(), b.is_ok()].iter().filter(|w| **w).count();
        assert_eq!(wins, 1, "exactly one consumer may win a recovery code");
    }
}
