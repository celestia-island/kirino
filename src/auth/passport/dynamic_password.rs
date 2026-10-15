use anyhow::{anyhow, Result};
use std::sync::atomic::{AtomicU64, Ordering};

use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use zeroize::Zeroizing;

use crate::utils::constant_time_eq;

type HmacSha1 = Hmac<Sha1>;

/// Time-based One-Time Password (TOTP) verifier as defined in RFC 6238.
///
/// Uses HMAC-SHA1 with configurable digit count and time period.
/// Accepts the current, previous (+1), and next (-1) time step to tolerate clock skew.
pub struct TotpVerifier {
    secret: Zeroizing<Vec<u8>>,
    digits: u32,
    period_secs: u32,
}

/// Maximum number of digits for TOTP/HOTP codes (9) to prevent u32 overflow
const MAX_DIGITS: u32 = 9;

impl TotpVerifier {
    #[must_use]
    pub fn new(secret: Vec<u8>) -> Self {
        Self {
            secret: Zeroizing::new(secret),
            digits: 6,
            period_secs: 30,
        }
    }

    #[must_use]
    pub fn with_options(secret: Vec<u8>, digits: u32, period_secs: u32) -> Self {
        Self {
            secret: Zeroizing::new(secret),
            digits: digits.clamp(1, MAX_DIGITS),
            period_secs: period_secs.max(1),
        }
    }

    pub fn verify(&self, code: &str) -> Result<bool> {
        let time_step = chrono::Utc::now().timestamp() as u64 / u64::from(self.period_secs);
        let generated = self.generate_at(time_step)?;
        let generated_prev = self.generate_at(time_step.saturating_sub(1))?;
        let generated_next = self.generate_at(time_step.saturating_add(1))?;
        Ok(constant_time_eq(generated.as_bytes(), code.as_bytes())
            || constant_time_eq(generated_prev.as_bytes(), code.as_bytes())
            || constant_time_eq(generated_next.as_bytes(), code.as_bytes()))
    }

    pub fn generate(&self) -> Result<String> {
        let time_step = chrono::Utc::now().timestamp() as u64 / u64::from(self.period_secs);
        self.generate_at(time_step)
    }

    /// Compute the code for an explicit RFC 4226 counter, bypassing the
    /// wall clock.
    ///
    /// Exposed so consumers (and this crate's own RFC test vectors) can
    /// assert deterministic codes at fixed counters instead of racing the
    /// 30-second window. Callers doing interactive authentication should
    /// prefer [`TotpVerifier::verify`], which applies the clock and the
    /// ±1-step skew window.
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
}
