//! Single-use recovery codes through the single-use store.
//!
//! A recovery code is a credential exactly like an authorization code: it
//! must be consumed by exactly one caller, the caller must be told whether
//! it won, and a storage blip must not silently burn it. That is the
//! contract [`ConsumableStore`] already enforces (K0), so this module is
//! thin on purpose — issue, hash, consume — and adds only what codes need:
//!
//! - the STORE KEY under which a code is parked is `argon2id(code, salt)`
//!   with a salt derived from the issuer's pepper, not a fast hash: a
//!   12-digit code is ~40 bits, and a bare SHA-256 of 40 bits is inverted
//!   offline in hours on one machine (R2 measured ~30 h for the whole
//!   space). With the KDF in the key every guess costs one argon2 (~23 ms
//!   at the OWASP baseline) — the whole space is hundreds of core-years,
//!   and a leaked table is a table of KDF outputs. The key is deterministic
//!   for one issuer (fixed salt) so a claim can look it up; the pepper is
//!   the host's secret and never enters the store;
//! - a code is **not** a string comparison against a list: `claim` is the
//!   check, and losing the claim is "not a valid code";
//! - `consume_for` is bound to the subject it was issued for: a code
//!   presented under another subject's recovery prompt is refused, not
//!   returned. The first version returned whatever payload the code
//!   carried, so one subject's live code satisfied another's prompt (R2 S1);
//! - the code a user sees is grouped for typing and carries no information
//!   beyond its entropy.

use chrono::{DateTime, Utc};

use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2,
};
use thiserror::Error;

use crate::auth::store::{Claim, ConsumableStore};

/// What a user is shown: the code in typing groups, and nothing else.
///
/// `Debug` redacts the code — it is a live credential until it is consumed
/// or expires, and the crate's other one-time credentials (`MintedCode`,
/// `OneTimeCredential`) never reach a log.
#[derive(Clone, PartialEq, Eq)]
pub struct RecoveryCode {
    /// The code as typed, groups joined by `-`.
    pub display: String,
}

impl std::fmt::Debug for RecoveryCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoveryCode")
            .field("display", &"<redacted>")
            .finish()
    }
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

/// Issues and consumes recovery codes, bound to the subject they were
/// issued for.
///
/// The host picks `P`, the payload parked under a code — a subject id, or
/// a struct with the subject and the code's index. **`P` must carry the
/// subject**: `consume_for` compares the claimed payload against the
/// expected one and refuses a mismatch, so a payload that does not identify
/// its subject binds the code to nothing.
///
/// `pepper` is the host's secret for this issuer. It selects the argon2
/// salt, which is what makes the stored key slow to enumerate; it is never
/// stored and never logged. **It must be high-entropy** (32 random bytes,
/// not a passphrase): with the table, anyone holding one genuine code can
/// test a pepper guess offline, so a low-entropy pepper is cracked. The
/// salt is fixed per issuer, so a leaked pepper AND a leaked table let one
/// sweep cover every outstanding code at once — the per-code salt was
/// traded for a key a claim can look up. **Rate-limit the recovery
/// endpoint**: every claim runs one argon2 (~30 ms), and an unthrottled
/// endpoint is both a guessing surface and a CPU sink. Rotating the pepper
/// invalidates every outstanding code — the right thing for a leak.
pub struct RecoveryIssuer<'a, P, S>
where
    P: Clone + Send + Sync + 'static,
    S: ConsumableStore<P>,
{
    store: &'a S,
    /// How long an unused code stays valid.
    ttl_secs: i64,
    /// argon2id; the salt is fixed per issuer (see `key_for`).
    kdf: Argon2<'static>,
    salt: SaltString,
    _payload: std::marker::PhantomData<P>,
}

impl<'a, P, S> RecoveryIssuer<'a, P, S>
where
    P: Clone + Send + Sync + 'static,
    S: ConsumableStore<P>,
{
    /// A new issuer over `store`, codes valid for `ttl_secs`, keys derived
    /// from `pepper`.
    ///
    /// # Errors
    ///
    /// [`RecoveryError::Store`] if the pepper is empty or cannot be turned
    /// into a salt.
    pub fn new(store: &'a S, ttl_secs: i64, pepper: &[u8]) -> Result<Self, RecoveryError> {
        if pepper.is_empty() {
            return Err(RecoveryError::Store("pepper must not be empty".into()));
        }
        if !(0 < ttl_secs && ttl_secs <= 366 * 86_400) {
            return Err(RecoveryError::Store(
                "ttl must be between 1 s and 366 days".into(),
            ));
        }
        // The salt is DERIVED, not random: the key must be reproducible at
        // claim time. SHA-256(pepper) as base64 is a valid salt string and
        // keeps the pepper itself out of the PHC line.
        use sha2::Digest;
        let digest = sha2::Sha256::digest(pepper);
        let salt = SaltString::encode_b64(&digest)
            .map_err(|e| RecoveryError::Store(format!("salt encoding failed: {e}")))?;
        Ok(Self {
            store,
            ttl_secs,
            kdf: Argon2::default(),
            salt,
            _payload: std::marker::PhantomData,
        })
    }

    /// The deterministic, slow store key for a normalised code. Every call
    /// runs argon2 once, so a lookup costs what a guess costs.
    fn key_for(&self, normal: &str) -> Result<String, RecoveryError> {
        self.kdf
            .hash_password(normal.as_bytes(), &self.salt)
            .map(|h| crate::auth::store::fingerprint(&h.to_string()))
            .map_err(|e| RecoveryError::Store(format!("kdf: {e}")))
    }

    /// Issue one code for `payload` at `now`, parking it under its key.
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
        let key = self.key_for(&normalise(&display))?;
        self.store
            .put(
                &key,
                payload,
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
    /// - [`RecoveryError::Malformed`] if the shape is wrong (no store call,
    ///   no KDF).
    /// - [`RecoveryError::Invalid`] if the code is unknown, spent, or issued
    ///   for another subject.
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
        let payload = self.claim_typed(typed, now).await?;
        if &payload != expected {
            return Err(RecoveryError::Invalid);
        }
        Ok(())
    }

    /// Consume and return the payload **without** a subject check.
    ///
    /// This returns whatever the code carries. A caller that does not
    /// compare the result against the subject it is recovering leaks a
    /// takeover: Alice's live code typed under Bob's recovery prompt returns
    /// `Ok("alice")` here (R2 S1; R3 measured it). Use [`Self::consume_for`]
    /// unless the caller binds by other means, and say so where it does.
    pub async fn consume(&self, typed: &str, now: DateTime<Utc>) -> Result<P, RecoveryError> {
        self.claim_typed(typed, now).await
    }

    async fn claim_typed(&self, typed: &str, now: DateTime<Utc>) -> Result<P, RecoveryError> {
        let normal = normalise(typed);
        if normal.len() != CODE_CHARS || !normal.chars().all(|c| c.is_ascii_digit()) {
            return Err(RecoveryError::Malformed);
        }
        let key = self.key_for(&normal)?;
        match self.store.claim(&key, now).await {
            Ok(Claim::Won(payload)) => Ok(payload),
            Ok(Claim::Lost) => Err(RecoveryError::Invalid),
            Err(e) => Err(RecoveryError::Store(e.to_string())),
        }
    }
}
const CODE_DIGITS: usize = 12;
const CODE_CHARS: usize = CODE_DIGITS;

fn random_code() -> String {
    use rand::RngExt;
    // 12 digits by rejection sampling over 2^40: a plain `% 10^12` would
    // double-weight the lowest ~9.5% of the space (2^40 mod 10^12), which
    // R2/R3 measured at ~39.0 bits min-entropy; rejected draws are rare
    // (under one in twenty), so the loop is cheap and the result uniform.
    loop {
        let raw: [u8; 5] = rand::rng().random();
        let n = u64::from_be_bytes([0, 0, 0, raw[0], raw[1], raw[2], raw[3], raw[4]]);
        if n < 1_000_000_000_000 {
            return format!("{n:012}");
        }
    }
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

    type Store = MemoryConsumableStore<String>;
    const PEPPER: &[u8] = b"test-only pepper, never a real secret";

    fn issuer<'a, S: ConsumableStore<String>>(store: &'a S) -> RecoveryIssuer<'a, String, S> {
        RecoveryIssuer::new(store, 3600, PEPPER).unwrap()
    }

    /// R4 S2: the code a user is shown is a live credential; `Debug` must
    /// not carry it into a log.
    #[test]
    fn a_recovery_code_never_prints_itself() {
        let code = RecoveryCode {
            display: "1234-5678-9012".into(),
        };
        let rendered = format!("{code:?}");
        assert!(!rendered.contains("1234"), "{rendered}");
        assert!(rendered.contains("<redacted>"));
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

    /// R2/R3 S1: the STORE KEY is a KDF output, not a fast hash of the
    /// code. R2 inverted a real code from its key in minutes; R3 showed the
    /// first fix had only moved the KDF into the payload while the key
    /// stayed fast. Now the key itself is argon2(code, issuer salt).
    #[tokio::test]
    async fn the_store_key_is_a_kdf_output_not_a_fast_hash_of_the_code() {
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
        let fast = crate::auth::store::fingerprint(&plain);
        // The fast hash is NOT a key in the store: a claim under it loses.
        assert_eq!(store.claim(&fast, now).await.unwrap(), Claim::Lost);
        // The real key is what the issuer derives — one argon2 away.
        let i = issuer(&store);
        let key = i.key_for(&plain).unwrap();
        assert_ne!(key, fast);
        assert!(!key.contains(&plain));
        assert!(matches!(
            store.claim(&key, now).await.unwrap(),
            Claim::Won(_)
        ));
        // MUT:fast-key — making `key_for` return `fingerprint(code)` turns
        // the `Claim::Lost` above into `Won` and the `!=` red.
    }

    /// The key is bound to the issuer's pepper: the same code under another
    /// pepper is a different key, so a leaked table from one deployment
    /// does not transfer, and a pepper rotation invalidates outstanding codes.
    #[tokio::test]
    async fn the_key_is_bound_to_the_pepper() {
        let store = Store::new();
        let now = Utc::now();
        let code = issuer(&store)
            .issue("subject-1".to_owned(), now)
            .await
            .unwrap();
        let other = RecoveryIssuer::<String, Store>::new(&store, 3600, b"another pepper").unwrap();
        // MUT:no-pepper — a pepper-independent key lets this succeed.
        assert_eq!(
            other.consume(&code.display, now).await.unwrap_err(),
            RecoveryError::Invalid
        );
        // The right pepper still works.
        issuer(&store).consume(&code.display, now).await.unwrap();
    }

    #[tokio::test]
    async fn an_empty_pepper_is_refused() {
        assert!(matches!(
            RecoveryIssuer::<String, Store>::new(&Store::new(), 3600, b""),
            Err(RecoveryError::Store(_))
        ));
    }

    /// R3 S2: a code whose key matches but which was parked by a different
    /// code path (a collision, a tampered row) still has to carry the
    /// right payload — `consume_for` is the binding.
    #[tokio::test]
    async fn a_tampered_row_does_not_satisfy_consume_for() {
        let store = Store::new();
        let now = Utc::now();
        // Park Alice's payload under the key of a code the attacker types.
        let attacker = "1111-2222-3333";
        let i = issuer(&store);
        let key = i.key_for(&normalise(attacker)).unwrap();
        store
            .put(
                &key,
                "alice".to_owned(),
                now + chrono::Duration::seconds(60),
                now,
            )
            .await
            .unwrap();
        // Attacker claims it for themselves: the payload is Alice's, not
        // the attacker's subject, so `consume_for` refuses.
        assert_eq!(
            i.consume_for(attacker, &"mallory".to_owned(), now)
                .await
                .unwrap_err(),
            RecoveryError::Invalid
        );
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
    impl ConsumableStore<String> for Flaky {
        async fn put(
            &self,
            token: &str,
            payload: String,
            expires_at: DateTime<Utc>,
            now: DateTime<Utc>,
        ) -> anyhow::Result<()> {
            if self.fail_put.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(anyhow::anyhow!("disk full"));
            }
            self.inner.put(token, payload, expires_at, now).await
        }
        async fn claim(&self, token: &str, now: DateTime<Utc>) -> anyhow::Result<Claim<String>> {
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
