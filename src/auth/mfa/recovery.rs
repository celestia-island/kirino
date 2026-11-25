//! Single-use recovery codes through the single-use store.
//!
//! A recovery code is a credential exactly like an authorization code: it
//! must be consumed by exactly one caller, the caller must be told whether
//! it won, and a storage blip must not silently burn it. That is the
//! contract [`ConsumableStore`] already enforces (K0), so this module is
//! thin on purpose — issue, hash, consume — and adds only what codes need:
//!
//! - codes are stored **hashed through a KDF** (argon2id, then the store's
//!   fingerprint): a 12-digit code is ~40 bits, and a bare SHA-256 of 40
//!   bits is inverted offline in hours on one machine (R2 measured ~30 h
//!   for the whole space, no SHA-NI). With the KDF a leaked table of
//!   payloads is a table of argon2 outputs, not of codes;
//! - a code is **not** a string comparison against a list: `claim` is the
//!   check, and losing the claim is "not a valid code";
//! - `consume_for` is bound to the subject it was issued for: a code
//!   presented under another subject's recovery prompt is refused, not
//!   returned. The first version returned whatever payload the code
//!   carried, so one subject's live code satisfied another's prompt (R2 S1);
//! - the code a user sees is grouped for typing and carries no information
//!   beyond its entropy.

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use chrono::{DateTime, Utc};
use rand::RngExt;
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
    /// The code is not one this issuer knows, was already used, or was
    /// issued for a different subject. One error for all three: a prober
    /// learns nothing from which.
    #[error("the recovery code is not valid, was already used, or belongs to another account")]
    Invalid,
    /// The store failed. **Not** a verdict on the code — but not a promise
    /// that it is unburned either: the crate's own `DbConsumableStore`
    /// performs its `DELETE … RETURNING` as one statement, so a failure
    /// AFTER that statement reached the database has already consumed the
    /// row. Treat this as "outcome unknown": the same code may succeed or
    /// come back `Invalid` on retry — that is the store's contract, not
    /// this module's. (R2: the doc used to say "not consumed, may retry".)
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
    S: ConsumableStore<RecoveryParked<P>>,
{
    store: &'a S,
    /// How long an unused code stays valid.
    ttl_secs: i64,
    _subject: std::marker::PhantomData<P>,
}

impl<P, S> RecoveryIssuer<'_, P, S>
where
    P: Clone + Send + Sync + 'static,
    S: ConsumableStore<RecoveryParked<P>>,
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
        let normal = normalise(&display);
        // Two layers, both needed. The STORE key is a fast hash so a lookup
        // is O(1) and the store never holds the code; the PAYLOAD is the
        // same code through argon2id with a fresh salt, so a leaked table
        // of payloads is a table of KDF outputs, not of codes. (The fast
        // key alone inverted in hours — R2 S1.)
        let key = crate::auth::store::fingerprint(&normal);
        let mut salt_bytes = [0u8; 16];
        rand::rng().fill(&mut salt_bytes);
        let salt = SaltString::encode_b64(&salt_bytes)
            .map_err(|e| RecoveryError::Store(format!("salt encoding failed: {e}")))?;
        let kdf = Argon2::default()
            .hash_password(normal.as_bytes(), &salt)
            .map_err(|e| RecoveryError::Store(format!("kdf: {e}")))?
            .to_string();
        let parked = RecoveryParked { kdf, payload };
        self.store
            .put(
                &key,
                parked,
                now + chrono::Duration::seconds(self.ttl_secs),
                now,
            )
            .await
            .map_err(|e| RecoveryError::Store(e.to_string()))?;

        Ok(RecoveryCode { display })
    }

    /// Consume a code as typed by the user, **for `expected`**.
    ///
    /// The claim is the check: exactly one caller wins, and a losing caller
    /// is told `Invalid` — indistinguishable from an unknown code, from a
    /// spent one, and from one issued for another subject, so a prober
    /// learns nothing from which. The claimed payload must equal `expected`
    /// or the code is refused (and, having been claimed, spent — a subject
    /// who types someone else's code burns that code, which is the safe
    /// direction: the rightful owner re-issues).
    ///
    /// # Errors
    ///
    /// - [`RecoveryError::Malformed`] if the shape is wrong (no store call).
    /// - [`RecoveryError::Invalid`] if the code is unknown, spent, issued
    ///   for another subject, or does not match the parked KDF output.
    /// - [`RecoveryError::Store`] if the store failed — see the variant.
    pub async fn consume_for(
        &self,
        typed: &str,
        expected: &P,
        now: DateTime<Utc>,
    ) -> Result<(), RecoveryError>
    where
        P: PartialEq,
    {
        let parked = self.claim_typed(typed, now).await?;
        let Ok(parsed) = PasswordHash::new(&parked.kdf) else {
            return Err(RecoveryError::Invalid);
        };
        if Argon2::default()
            .verify_password(normalise(typed).as_bytes(), &parsed)
            .is_err()
        {
            // The store key matched but the KDF did not: a key collision or
            // a tampered row. Invalid; the row is already gone.
            return Err(RecoveryError::Invalid);
        }
        if &parked.payload != expected {
            return Err(RecoveryError::Invalid);
        }
        Ok(())
    }

    /// Consume and return the payload, for hosts whose `P` is the identity
    /// and that bind by other means. Prefer [`Self::consume_for`].
    pub async fn consume(&self, typed: &str, now: DateTime<Utc>) -> Result<P, RecoveryError> {
        let parked = self.claim_typed(typed, now).await?;
        let Ok(parsed) = PasswordHash::new(&parked.kdf) else {
            return Err(RecoveryError::Invalid);
        };
        if Argon2::default()
            .verify_password(normalise(typed).as_bytes(), &parsed)
            .is_err()
        {
            return Err(RecoveryError::Invalid);
        }
        Ok(parked.payload)
    }

    async fn claim_typed(
        &self,
        typed: &str,
        now: DateTime<Utc>,
    ) -> Result<RecoveryParked<P>, RecoveryError> {
        let normal = normalise(typed);
        if normal.len() != CODE_CHARS || !normal.chars().all(|c| c.is_ascii_digit()) {
            return Err(RecoveryError::Malformed);
        }
        let key = crate::auth::store::fingerprint(&normal);
        match self.store.claim(&key, now).await {
            Ok(Claim::Won(parked)) => Ok(parked),
            Ok(Claim::Lost) => Err(RecoveryError::Invalid),
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

    type Store = MemoryConsumableStore<RecoveryParked<String>>;

    fn issuer<'a, S: ConsumableStore<RecoveryParked<String>>>(
        store: &'a S,
    ) -> RecoveryIssuer<'a, String, S> {
        RecoveryIssuer::new(store, 3600)
    }

    fn key_of(plain: &str) -> String {
        crate::auth::store::fingerprint(plain)
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
    async fn an_issued_code_is_consumed_exactly_once_for_its_subject() {
        let store = Store::new();
        let now = Utc::now();
        let code = issuer(&store)
            .issue("subject-1".to_owned(), now)
            .await
            .unwrap();
        issuer(&store)
            .consume_for(&code.display, &"subject-1".to_owned(), now)
            .await
            .unwrap();
        // The same code again: invalid, and indistinguishable from unknown.
        assert_eq!(
            issuer(&store)
                .consume(&code.display, now)
                .await
                .unwrap_err(),
            RecoveryError::Invalid
        );
        assert_eq!(
            issuer(&store)
                .consume("0000-0000-0000", now)
                .await
                .unwrap_err(),
            RecoveryError::Invalid
        );
    }

    /// R2 S1: a code is bound to the subject it was issued for. Alice's
    /// live code under Bob's recovery prompt is refused — not returned.
    #[tokio::test]
    async fn a_code_is_refused_under_another_subjects_prompt() {
        let store = Store::new();
        let now = Utc::now();
        let alice = issuer(&store).issue("alice".to_owned(), now).await.unwrap();
        // MUT:no-subject-binding — dropping the payload comparison returns
        // Ok here and hands Bob a recovery that was Alice's.
        assert_eq!(
            issuer(&store)
                .consume_for(&alice.display, &"bob".to_owned(), now)
                .await
                .unwrap_err(),
            RecoveryError::Invalid
        );
        // And the attempt burned it: Alice's own retry is now invalid too.
        // That is the safe direction (the rightful owner re-issues).
        assert_eq!(
            issuer(&store)
                .consume_for(&alice.display, &"alice".to_owned(), now)
                .await
                .unwrap_err(),
            RecoveryError::Invalid
        );
    }

    /// R2 S2: what the store holds is a KDF output, not a fast hash of the
    /// code. The first version asserted `fingerprint(x) == fingerprint(x)`.
    #[tokio::test]
    async fn the_store_holds_a_kdf_output_not_a_hash_of_the_code() {
        let store = Store::new();
        let now = Utc::now();
        let code = issuer(&store)
            .issue("subject-1".to_owned(), now)
            .await
            .unwrap();
        let plain: String = code
            .display
            .chars()
            .filter(|c| c.is_ascii_digit())
            .collect();
        let parked = store.claim(&key_of(&plain), now).await.unwrap();
        let Claim::Won(parked) = parked else {
            panic!("parked under its key")
        };
        // The parked KDF line is an argon2 PHC string carrying a salt…
        assert!(parked.kdf.starts_with("$argon2"), "{}", parked.kdf);
        // …and is NOT derivable from the code without the KDF: it is not the
        // fast fingerprint, and it is not the code.
        assert_ne!(parked.kdf, key_of(&plain));
        assert!(!parked.kdf.contains(&plain));
        // MUT:no-kdf — parking `key_of(&plain)` (or the code) as the kdf
        // fails the `$argon2` prefix and the `!= fingerprint` checks.
    }

    #[tokio::test]
    async fn two_codes_for_the_same_subject_get_different_salts() {
        let store = Store::new();
        let now = Utc::now();
        let a = issuer(&store).issue("s".to_owned(), now).await.unwrap();
        let b = issuer(&store).issue("s".to_owned(), now).await.unwrap();
        let pa: String = a.display.chars().filter(|c| c.is_ascii_digit()).collect();
        let pb: String = b.display.chars().filter(|c| c.is_ascii_digit()).collect();
        let (Claim::Won(x), Claim::Won(y)) = (
            store.claim(&key_of(&pa), now).await.unwrap(),
            store.claim(&key_of(&pb), now).await.unwrap(),
        ) else {
            panic!("both parked")
        };
        assert_ne!(x.kdf, y.kdf, "a fresh salt per code");
    }

    #[tokio::test]
    async fn typing_is_forgiving_about_non_digits() {
        let store = Store::new();
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
        issuer(&store)
            .consume_for(&respaced, &"subject-1".to_owned(), now)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_malformed_code_never_reaches_the_store() {
        let store = Store::new();
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
        let store = Store::new();
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

    /// A store that can fail, so the two `Store` arms are real. R2 M06a/b
    /// survived because the only store in the tests could not fail.
    struct Flaky {
        inner: Store,
        fail_put: std::sync::atomic::AtomicBool,
        fail_claim: std::sync::atomic::AtomicBool,
    }
    impl Flaky {
        fn new() -> Self {
            Self {
                inner: Store::new(),
                fail_put: false.into(),
                fail_claim: false.into(),
            }
        }
    }
    #[async_trait::async_trait]
    impl ConsumableStore<RecoveryParked<String>> for Flaky {
        async fn put(
            &self,
            token: &str,
            payload: RecoveryParked<String>,
            expires_at: DateTime<Utc>,
            now: DateTime<Utc>,
        ) -> anyhow::Result<()> {
            if self.fail_put.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(anyhow::anyhow!("disk full"));
            }
            self.inner.put(token, payload, expires_at, now).await
        }
        async fn claim(
            &self,
            token: &str,
            now: DateTime<Utc>,
        ) -> anyhow::Result<Claim<RecoveryParked<String>>> {
            if self.fail_claim.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(anyhow::anyhow!("connection reset"));
            }
            self.inner.claim(token, now).await
        }
        async fn sweep(&self, now: DateTime<Utc>) -> anyhow::Result<u64> {
            self.inner.sweep(now).await
        }
    }

    /// R2 M06b: a failed park is a `Store` error, never "invalid code" —
    /// the host must not show the user a code that is not stored.
    #[tokio::test]
    async fn a_failed_park_is_a_store_error() {
        let store = Flaky::new();
        store
            .fail_put
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let now = Utc::now();
        // MUT:store-as-invalid — mapping the put error to `Invalid` turns
        // this into a verdict on a code the user never saw.
        assert!(matches!(
            issuer(&store).issue("s".to_owned(), now).await,
            Err(RecoveryError::Store(_))
        ));
    }

    /// R2 M06a: a failed claim is a `Store` error, never "invalid code".
    #[tokio::test]
    async fn a_failed_claim_is_a_store_error() {
        let store = Flaky::new();
        let now = Utc::now();
        let code = issuer(&store).issue("s".to_owned(), now).await.unwrap();
        store
            .fail_claim
            .store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(matches!(
            issuer(&store).consume(&code.display, now).await,
            Err(RecoveryError::Store(_))
        ));
    }

    /// Exactly one consumer wins a code — on a multi-thread runtime, with
    /// real racers (the first version ran both on one thread, which proved
    /// nothing about the race).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn many_concurrent_consumers_get_exactly_one_win() {
        let store = std::sync::Arc::new(Store::new());
        let now = Utc::now();
        let code = issuer(store.as_ref())
            .issue("s".to_owned(), now)
            .await
            .unwrap();
        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(8));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let store = store.clone();
            let code = code.display.clone();
            let barrier = barrier.clone();
            handles.push(tokio::spawn(async move {
                barrier.wait().await;
                issuer(store.as_ref()).consume(&code, now).await.is_ok()
            }));
        }
        let mut wins = 0;
        for h in handles {
            if h.await.unwrap() {
                wins += 1;
            }
        }
        assert_eq!(wins, 1, "exactly one consumer may win a recovery code");
    }
}

/// What is parked under a code: the KDF output (with its salt) and the
/// host's payload. Serialisable so the DB store can persist it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RecoveryParked<P> {
    kdf: String,
    payload: P,
}
