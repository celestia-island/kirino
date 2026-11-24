use anyhow::{anyhow, Result};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use zeroize::Zeroizing;

use crate::{auth::passport::totp_replay::TotpReplayGuard, utils::constant_time_eq};

type HmacSha1 = Hmac<Sha1>;

/// Time-based One-Time Password (TOTP) verifier as defined in RFC 6238.
///
/// Uses HMAC-SHA1 with configurable digit count and time period.
/// Accepts the current, previous (+1), and next (-1) time step to tolerate clock skew.
///
/// # Replay protection
///
/// RFC 6238 §5.2 requires a verifier to reject an OTP it already accepted
/// for the same time step. The ±1 window otherwise leaves one observed
/// code valid for up to three periods, so every replay inside that window
/// would be a successful authentication.
///
/// [`verify`](Self::verify) keeps a monotonic high-water mark of accepted
/// steps **for this instance**: a step that is not strictly newer than an
/// already accepted one is rejected. A verifier rebuilt per request — the
/// usual server shape, one instance per verification from a stored
/// secret — starts without a mark and therefore cannot protect the next
/// request. Those deployments must persist the mark and call
/// [`verify_with_guard`](Self::verify_with_guard) with a
/// [`TotpReplayGuard`] (`MemoryTotpReplayGuard` for a single process, the
/// `DbTotpReplayGuard` store for a shared `mfa_factors` table).
///
/// Because one instance holds one secret — and therefore one mark — a
/// single instance must serve exactly one factor. Sharing an instance
/// across factors (or users) makes every factor but the first look
/// replayed.
pub struct TotpVerifier {
    secret: Zeroizing<Vec<u8>>,
    digits: u32,
    period_secs: u32,
    /// Highest step accepted by this instance; [`LAST_STEP_UNSET`] until
    /// the first successful verification.
    last_used_step: AtomicI64,
}

/// Maximum number of digits for TOTP/HOTP codes (9) to prevent u32 overflow
const MAX_DIGITS: u32 = 9;

/// Sentinel for "this instance has not accepted a step yet". Real TOTP
/// steps are unix seconds divided by the period, so they are never
/// negative.
const LAST_STEP_UNSET: i64 = i64::MIN;

impl TotpVerifier {
    #[must_use]
    pub fn new(secret: Vec<u8>) -> Self {
        Self {
            secret: Zeroizing::new(secret),
            digits: 6,
            period_secs: 30,
            last_used_step: AtomicI64::new(LAST_STEP_UNSET),
        }
    }

    #[must_use]
    pub fn with_options(secret: Vec<u8>, digits: u32, period_secs: u32) -> Self {
        Self {
            secret: Zeroizing::new(secret),
            digits: digits.clamp(1, MAX_DIGITS),
            period_secs: period_secs.max(1),
            last_used_step: AtomicI64::new(LAST_STEP_UNSET),
        }
    }

    /// Verifies `code` against the current ±1 time-step window and consumes
    /// the matched step.
    ///
    /// Returns `true` only for a code that matches the current, previous,
    /// or next step **and** whose step is newer than every step this
    /// instance already accepted. A replay inside the same window returns
    /// `false`; see the type-level docs for the cross-request story.
    ///
    /// # Errors
    ///
    /// Returns an error if HMAC initialization fails.
    pub fn verify(&self, code: &str) -> Result<bool> {
        Ok(match self.match_step(code)? {
            Some(step) => self.claim_step_locally(step),
            None => false,
        })
    }

    /// Verifies `code` and consumes the matched step **through `guard`**,
    /// the durable replay defence for deployments that verify across
    /// requests or replicas.
    ///
    /// The guard is the single source of truth here: this method does not
    /// consult — nor advance — the process-local mark, so one verifier
    /// instance can serve several factors without their marks colliding.
    /// Do not mix the two paths on one instance, though: a code accepted
    /// here leaves the instance mark untouched, so a later
    /// [`verify`](Self::verify) on that same instance would see no mark and
    /// accept the replay. Pick one path per verifier.
    ///
    /// Returns `false` when the code does not match the window, when the
    /// guard reports the step as already accepted (replay), and when the
    /// guard cannot record the step (fail closed).
    ///
    /// # Errors
    ///
    /// Returns an error if HMAC initialization fails.
    pub async fn verify_with_guard(
        &self,
        code: &str,
        factor_id: &str,
        guard: &dyn TotpReplayGuard,
    ) -> Result<bool> {
        Ok(match self.match_step(code)? {
            Some(step) => guard.accept_step(factor_id, step_as_i64(step)).await,
            None => false,
        })
    }

    /// The step `code` matches inside the current ±1 window, or `None` when
    /// it matches none of the three candidates.
    ///
    /// Candidates are tried current, previous, next — the order the
    /// verifier has always used — so a code shared by adjacent windows
    /// resolves to the earliest candidate in that order.
    ///
    /// # Errors
    ///
    /// Returns an error if HMAC initialization fails.
    pub fn match_step(&self, code: &str) -> Result<Option<u64>> {
        self.match_step_at(code, self.current_step())
    }

    /// [`match_step`](Self::match_step) for an explicit time step, bypassing
    /// the wall clock.
    ///
    /// Exposed for the same reason as [`code_at`](Self::code_at): consumers
    /// holding their own factor row can compute the exact step to persist,
    /// and tests can assert window behaviour without racing the 30-second
    /// clock.
    ///
    /// # Errors
    ///
    /// Returns an error if HMAC initialization fails.
    pub fn match_step_at(&self, code: &str, time_step: u64) -> Result<Option<u64>> {
        for candidate in [
            time_step,
            time_step.saturating_sub(1),
            time_step.saturating_add(1),
        ] {
            if constant_time_eq(self.generate_at(candidate)?.as_bytes(), code.as_bytes()) {
                return Ok(Some(candidate));
            }
        }
        Ok(None)
    }

    /// The current time step for this verifier's period.
    #[must_use]
    pub fn current_step(&self) -> u64 {
        let now = chrono::Utc::now().timestamp();
        u64::try_from(now.max(0)).unwrap_or(0) / u64::from(self.period_secs)
    }

    /// Claims `step` against the process-local mark: succeeds only when it
    /// is strictly newer than every step already accepted here.
    ///
    /// Uses a compare-exchange loop so concurrent verifications of the same
    /// step cannot both succeed (the CAS that records the winner is the
    /// same operation that observes an existing newer mark).
    fn claim_step_locally(&self, step: u64) -> bool {
        let step = step_as_i64(step);
        let mut observed = self.last_used_step.load(Ordering::Acquire);
        loop {
            if observed != LAST_STEP_UNSET && step <= observed {
                return false;
            }
            match self.last_used_step.compare_exchange(
                observed,
                step,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(current) => observed = current,
            }
        }
    }

    pub fn generate(&self) -> Result<String> {
        self.generate_at(self.current_step())
    }

    /// Compute the code for an explicit RFC 4226 counter, bypassing the
    /// wall clock.
    ///
    /// Exposed so consumers (and this crate's own RFC test vectors) can
    /// assert deterministic codes at fixed counters instead of racing the
    /// 30-second window. Callers doing interactive authentication should
    /// prefer [`TotpVerifier::verify`], which applies the clock, the
    /// ±1-step skew window and the replay mark.
    pub fn code_at(&self, counter: u64) -> Result<String> {
        self.generate_at(counter)
    }

    fn generate_at(&self, counter: u64) -> Result<String> {
        let code = hotp_code(&self.secret, counter, self.digits)?;
        Ok(format_code(code, self.digits))
    }
}

/// HMAC-based One-Time Password (HOTP) verifier as defined in RFC 4226.
///
/// Uses HMAC-SHA1 with a monotonically increasing counter.
/// The counter advances atomically on each successful verification,
/// preventing replay attacks as required by RFC 4226.
pub struct HotpVerifier {
    secret: Zeroizing<Vec<u8>>,
    counter: AtomicU64,
}

impl HotpVerifier {
    #[must_use]
    pub fn new(secret: Vec<u8>, counter: u64) -> Self {
        Self {
            secret: Zeroizing::new(secret),
            counter: AtomicU64::new(counter),
        }
    }

    /// Maximum retry attempts for CAS contention to prevent livelock.
    const MAX_VERIFY_RETRIES: u32 = 3;

    pub fn verify(&self, code: &str) -> Result<bool> {
        let mut retries = 0;
        loop {
            let current = self.counter.load(Ordering::Acquire);
            let expected = hotp_code(&self.secret, current, 6)?;
            let formatted = format_code(expected, 6);
            if constant_time_eq(formatted.as_bytes(), code.as_bytes()) {
                match self.counter.compare_exchange(
                    current,
                    current + 1,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => return Ok(true),
                    Err(_) => {
                        retries += 1;
                        if retries >= Self::MAX_VERIFY_RETRIES {
                            return Ok(false);
                        }
                        continue;
                    }
                }
            } else {
                return Ok(false);
            }
        }
    }
}

fn hotp_code(secret: &[u8], counter: u64, digits: u32) -> Result<u32> {
    let digits = digits.clamp(1, MAX_DIGITS);
    let mut mac = HmacSha1::new_from_slice(secret).map_err(|e| anyhow!("HMAC init failed: {e}"))?;
    mac.update(&counter.to_be_bytes());
    let result = mac.finalize().into_bytes();
    let offset = (result[19] & 0x0f) as usize;
    let binary = ((u32::from(result[offset]) & 0x7f) << 24)
        | ((u32::from(result[offset + 1]) & 0xff) << 16)
        | ((u32::from(result[offset + 2]) & 0xff) << 8)
        | (u32::from(result[offset + 3]) & 0xff);
    Ok(binary % (10_u32.pow(digits)))
}

fn format_code(code: u32, digits: u32) -> String {
    format!("{:0>width$}", code, width = digits as usize)
}

/// Narrows a time step for the replay marks (`i64`).
///
/// Steps are unix seconds divided by a period, so they stay far below
/// `i64::MAX` for any representable clock; the saturating fallback only
/// keeps an absurd counter from wrapping into the "no step recorded"
/// sentinel.
fn step_as_i64(step: u64) -> i64 {
    i64::try_from(step).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_totp_generate_and_verify() {
        let secret = b"test-secret-12345".to_vec();
        let totp = TotpVerifier::new(secret);
        let code = totp.generate().unwrap();
        assert_eq!(code.len(), 6);
        assert!(totp.verify(&code).unwrap());
    }

    #[test]
    fn test_totp_wrong_code() {
        let secret = b"test-secret-12345".to_vec();
        let totp = TotpVerifier::new(secret);
        let code = totp.generate().unwrap();
        let wrong = if code == "000000" { "999999" } else { "000000" };
        assert!(!totp.verify(wrong).unwrap());
    }

    #[test]
    fn test_totp_accepts_previous_step() {
        let secret = b"test-secret-prev-step".to_vec();
        let totp = TotpVerifier::new(secret);
        let current = totp.generate().unwrap();

        let time_step = chrono::Utc::now().timestamp() as u64 / 30;
        let prev_code = {
            let code = hotp_code(&totp.secret, time_step.saturating_sub(1), 6).unwrap();
            format_code(code, 6)
        };

        // TOTP codes for consecutive 30s windows almost always differ, but in
        // the rare case where HOTP wraps to the same 6-digit string we cannot
        // distinguish "previous step accepted" from "current step accepted".
        if current == prev_code {
            assert!(
                totp.verify(&current).unwrap(),
                "TOTP must always accept its own freshly-generated current code"
            );
        } else {
            assert!(
                totp.verify(&prev_code).unwrap(),
                "TOTP must accept the previous time-step code (window tolerance ≥ 1)"
            );
        }
    }

    #[test]
    fn test_hotp_generate_and_verify() {
        let secret = b"test-secret-hotp".to_vec();
        let hotp = HotpVerifier::new(secret.clone(), 0);
        let code = hotp_code(&secret, 0, 6).unwrap();
        let formatted = format_code(code, 6);
        assert!(hotp.verify(&formatted).unwrap());
    }

    #[test]
    fn test_hotp_wrong_code() {
        let secret = b"test-secret-hotp".to_vec();
        let hotp = HotpVerifier::new(secret, 0);
        let code = hotp_code(&hotp.secret, 0, 6).unwrap();
        let formatted = format_code(code, 6);
        let wrong = if formatted == "000000" {
            "999999"
        } else {
            "000000"
        };
        assert!(!hotp.verify(wrong).unwrap());
    }

    #[test]
    fn test_hotp_different_counters() {
        let secret = b"test-secret-counters".to_vec();
        let code0 = hotp_code(&secret, 0, 6).unwrap();
        let code1 = hotp_code(&secret, 1, 6).unwrap();
        assert_ne!(format_code(code0, 6), format_code(code1, 6));
    }

    #[test]
    fn test_hotp_counter_advances() {
        let secret = b"test-counter-advance".to_vec();
        let hotp = HotpVerifier::new(secret.clone(), 0);
        let code0 = format_code(hotp_code(&secret, 0, 6).unwrap(), 6);
        let code1 = format_code(hotp_code(&secret, 1, 6).unwrap(), 6);
        assert!(hotp.verify(&code0).unwrap());
        assert!(
            !hotp.verify(&code0).unwrap(),
            "same code should not work twice"
        );
        assert!(
            hotp.verify(&code1).unwrap(),
            "next counter code should work"
        );
    }

    #[test]
    fn test_totp_custom_options() {
        let totp = TotpVerifier::with_options(b"secret".to_vec(), 8, 60);
        let code = totp.generate().unwrap();
        assert_eq!(code.len(), 8);
        assert!(totp.verify(&code).unwrap());
    }

    #[test]
    fn test_totp_digits_clamped_to_max() {
        let totp = TotpVerifier::with_options(b"secret".to_vec(), 100, 30);
        let code = totp.generate().unwrap();
        assert!(code.len() <= MAX_DIGITS as usize);
        assert!(totp.verify(&code).unwrap());
    }

    #[test]
    fn test_totp_verify_next_step() {
        let secret = b"test-secret-next-step".to_vec();
        let totp = TotpVerifier::new(secret);
        let time_step = chrono::Utc::now().timestamp() as u64 / 30;
        let next_code = {
            let code = hotp_code(&totp.secret, time_step.saturating_add(1), 6).unwrap();
            format_code(code, 6)
        };
        assert!(totp.verify(&next_code).unwrap());
    }

    #[test]
    fn test_hotp_deterministic() {
        let secret = b"deterministic-secret".to_vec();
        let code_a = hotp_code(&secret, 42, 6).unwrap();
        let code_b = hotp_code(&secret, 42, 6).unwrap();
        assert_eq!(code_a, code_b);
    }

    /// RFC 4226 Appendix D test vectors: the shared secret
    /// `12345678901234567890` (ASCII) with counters 0..=9.
    #[test]
    fn rfc4226_appendix_d_hotp_vectors() {
        let secret = b"12345678901234567890".to_vec();
        let totp = TotpVerifier::new(secret);
        let vectors = [
            (0u64, "755224"),
            (1, "287082"),
            (2, "359152"),
            (3, "969429"),
            (4, "338314"),
            (5, "254676"),
            (6, "287922"),
            (7, "162583"),
            (8, "399871"),
            (9, "520489"),
        ];
        for (counter, expected) in vectors {
            assert_eq!(
                totp.code_at(counter).unwrap(),
                expected,
                "HOTP vector at counter {counter}"
            );
        }
    }

    /// RFC 6238 Appendix B, SHA-1 line: the same shared secret at the
    /// documented T values. The RFC prints 8-digit codes; the 6-digit code
    /// is its last six digits (binary mod 10^6 == (binary mod 10^8) mod
    /// 10^6), asserted independently here.
    #[test]
    fn rfc6238_appendix_b_sha1_vectors() {
        let secret = b"12345678901234567890".to_vec();
        let totp = TotpVerifier::new(secret);
        //                        counter      expected 6-digit   (RFC 8-digit)
        let vectors = [
            (1u64, "287082"),      // T=59           → 94287082
            (37037036, "081804"),  // T=1111111109   → 07081804
            (37037037, "050471"),  // T=1111111111   → 14050471
            (41152263, "005924"),  // T=1234567890   → 89005924
            (66666666, "279037"),  // T=2000000000   → 69279037
            (666666666, "353130"), // T=20000000000  → 65353130
        ];
        for (counter, expected) in vectors {
            assert_eq!(
                totp.code_at(counter).unwrap(),
                expected,
                "RFC 6238 SHA-1 vector at counter {counter}"
            );
        }
    }

    /// A code from a counter far outside the ±1 window must be rejected by
    /// `verify` — the window is bounded, not a blanket accept.
    #[test]
    fn verify_rejects_far_window_code() {
        let secret = b"12345678901234567890".to_vec();
        let totp = TotpVerifier::new(secret);
        let time_step = chrono::Utc::now().timestamp() as u64 / 30;
        let far = totp.code_at(time_step + 1000).unwrap();
        if far != totp.code_at(time_step).unwrap() {
            assert!(
                !totp.verify(&far).unwrap(),
                "a code 1000 steps ahead must be rejected"
            );
        }
    }

    /// `code_at` must honor the configured digit count, not silently fall
    /// back to the default 6.
    #[test]
    fn code_at_honors_digit_options() {
        let totp = TotpVerifier::with_options(b"12345678901234567890".to_vec(), 8, 30);
        let code = totp.code_at(1).unwrap();
        assert_eq!(code, "94287082", "RFC 6238 T=59 full 8-digit value");
    }

    // ---------------------------------------------------------------
    // Replay protection (RFC 6238 §5.2)
    // ---------------------------------------------------------------

    /// Two adjacent windows can produce the same 6-digit string (~1 in
    /// 10^6). Such a code genuinely belongs to both steps, so a test that
    /// means "this exact string must be a replay" has nothing to assert —
    /// skip instead of flaking.
    fn collides_with_next_step(totp: &TotpVerifier, step: u64) -> bool {
        totp.code_at(step).unwrap() == totp.code_at(step.saturating_add(1)).unwrap()
    }

    /// (a) A code accepted once inside the ±1 window must not be accepted a
    /// second time — the reported gap: the window made one observed code
    /// usable repeatedly for up to three periods.
    #[test]
    fn totp_verify_rejects_replayed_code_in_same_window() {
        let totp = TotpVerifier::new(b"replay-secret".to_vec());
        let step = totp.current_step();
        let code = totp.generate().unwrap();

        assert!(
            totp.verify(&code).unwrap(),
            "the first submission of a fresh code must pass"
        );
        if collides_with_next_step(&totp, step) {
            // The same string is also the next window's code, which is a
            // legitimately newer step — no replay to assert.
            return;
        }
        assert!(
            !totp.verify(&code).unwrap(),
            "the same code must be rejected on a second verify inside the ±1 window"
        );
        assert!(
            !totp.verify(&code).unwrap(),
            "and must stay rejected for every further replay"
        );
    }

    /// (b) A code from a later window still passes: the mark blocks
    /// replays, not normal use.
    #[test]
    fn totp_verify_accepts_code_from_a_newer_window() {
        let totp = TotpVerifier::new(b"next-window-secret".to_vec());
        let step = totp.current_step();
        let current = totp.code_at(step).unwrap();
        let next = totp.code_at(step.saturating_add(1)).unwrap();

        assert!(totp.verify(&current).unwrap());
        if current == next {
            return;
        }
        assert!(
            totp.verify(&next).unwrap(),
            "a code from the next window is a new step and must be accepted"
        );
        assert!(
            !totp.verify(&current).unwrap(),
            "the older window's code is a replay once a newer step was consumed"
        );
    }

    /// The matched step is reported, and only the ±1 window matches.
    #[test]
    fn match_step_reports_the_window_and_rejects_further_steps() {
        let totp = TotpVerifier::new(b"window-map-secret".to_vec());
        let step = 1_111_111_109u64 / 30;

        // Candidates are tried current, previous, next — so when adjacent
        // windows happen to share a code the earliest candidate in that
        // order wins.
        let window = [step, step - 1, step + 1];
        for candidate in window {
            let code = totp.code_at(candidate).unwrap();
            let expected = window
                .into_iter()
                .find(|&probe| totp.code_at(probe).unwrap() == code)
                .expect("the code came from inside the window");
            assert_eq!(
                totp.match_step_at(&code, step).unwrap(),
                Some(expected),
                "step {candidate} relative to {step}"
            );
        }

        let far = totp.code_at(step + 3).unwrap();
        if far != totp.code_at(step + 1).unwrap()
            && far != totp.code_at(step).unwrap()
            && far != totp.code_at(step - 1).unwrap()
        {
            assert_eq!(
                totp.match_step_at(&far, step).unwrap(),
                None,
                "a step three windows away is outside the accepted window"
            );
        }
    }

    /// A wrong code never consumes a step — otherwise a probe would lock
    /// the legitimate user out of the current window.
    #[test]
    fn wrong_code_does_not_consume_the_step() {
        let totp = TotpVerifier::new(b"wrong-code-secret".to_vec());
        let code = totp.generate().unwrap();
        let wrong = if code == "000000" { "999999" } else { "000000" };

        assert!(!totp.verify(wrong).unwrap());
        assert!(
            totp.verify(&code).unwrap(),
            "a rejected code must not advance the replay mark"
        );
    }

    /// The `verify_with_guard` path is the one that survives a verifier
    /// rebuilt per request: two fresh instances, one guard, exactly one
    /// acceptance.
    #[tokio::test]
    async fn totp_guard_rejects_replay_across_verifier_instances() {
        use crate::auth::passport::totp_replay::MemoryTotpReplayGuard;

        let guard = MemoryTotpReplayGuard::new();
        let secret = b"per-request-secret".to_vec();
        let first = TotpVerifier::new(secret.clone());
        let step = first.current_step();
        let code = first.generate().unwrap();

        assert!(first
            .verify_with_guard(&code, "factor-1", &guard)
            .await
            .unwrap());

        let second = TotpVerifier::new(secret);
        if collides_with_next_step(&second, step) {
            return;
        }
        assert!(
            !second
                .verify_with_guard(&code, "factor-1", &guard)
                .await
                .unwrap(),
            "a replayed code must be rejected by the durable mark even though \
             the verifying instance is fresh"
        );
    }

    /// (c) A factor that never had a step accepted (the NULL column of an
    /// existing deployment) must still verify: replay protection cannot
    /// lock out enrolled users on upgrade.
    #[tokio::test]
    async fn totp_guard_accepts_first_use_of_a_fresh_factor() {
        use crate::auth::passport::totp_replay::MemoryTotpReplayGuard;

        let guard = MemoryTotpReplayGuard::new();
        assert_eq!(guard.last_used_step("upgraded-factor").await, None);

        let totp = TotpVerifier::new(b"fresh-factor-secret".to_vec());
        let code = totp.generate().unwrap();
        assert!(
            totp.verify_with_guard(&code, "upgraded-factor", &guard)
                .await
                .unwrap(),
            "a factor without a recorded step must pass its first verification"
        );
        assert!(guard.last_used_step("upgraded-factor").await.is_some());
    }

    /// The guard path never consults the instance mark, so one verifier can
    /// serve several factors (each with its own durable mark).
    #[tokio::test]
    async fn totp_guard_keys_replays_per_factor() {
        use crate::auth::passport::totp_replay::MemoryTotpReplayGuard;

        let guard = MemoryTotpReplayGuard::new();
        let totp = TotpVerifier::new(b"multi-factor-secret".to_vec());
        let code = totp.generate().unwrap();

        assert!(totp
            .verify_with_guard(&code, "factor-a", &guard)
            .await
            .unwrap());
        assert!(
            totp.verify_with_guard(&code, "factor-b", &guard)
                .await
                .unwrap(),
            "a different factor has an independent mark"
        );
    }

    /// (d) Two submitters racing on the same code: the process-local mark's
    /// compare-exchange admits exactly one.
    ///
    /// `verify` is synchronous and never awaits, so the race has to come
    /// from real threads — a single-threaded runtime would run the two
    /// calls back to back and prove nothing.
    #[test]
    fn concurrent_verifies_admit_one() {
        let totp = TotpVerifier::new(b"concurrent-secret".to_vec());
        let step = totp.current_step();
        let code = totp.generate().unwrap();
        if collides_with_next_step(&totp, step) {
            return;
        }

        let barrier = std::sync::Barrier::new(2);
        let outcomes = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..2)
                .map(|_| {
                    let code = code.clone();
                    let barrier = &barrier;
                    let totp = &totp;
                    scope.spawn(move || {
                        barrier.wait();
                        totp.verify(&code).unwrap()
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().expect("verification thread panicked"))
                .collect::<Vec<_>>()
        });

        assert!(
            outcomes[0] ^ outcomes[1],
            "exactly one concurrent verification of the same code may pass \
             (got {}/{})",
            outcomes[0],
            outcomes[1]
        );
    }
}
