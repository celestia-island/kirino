use anyhow::Result;
use hmac::{Hmac, Mac};
use sha1::Sha1;

use crate::utils::constant_time_eq;

type HmacSha1 = Hmac<Sha1>;

pub struct TotpVerifier {
    secret: Vec<u8>,
    digits: u32,
    period_secs: u32,
}

impl TotpVerifier {
    #[must_use]
    pub fn new(secret: Vec<u8>) -> Self {
        Self {
            secret,
            digits: 6,
            period_secs: 30,
        }
    }

    #[must_use]
    pub fn with_options(secret: Vec<u8>, digits: u32, period_secs: u32) -> Self {
        Self {
            secret,
            digits,
            period_secs,
        }
    }

    pub fn verify(&self, code: &str) -> Result<bool> {
        let time_step = chrono::Utc::now().timestamp() as u64 / self.period_secs as u64;
        let generated = self.generate_at(time_step)?;
        let generated_prev = self.generate_at(time_step.saturating_sub(1))?;
        Ok(constant_time_eq(generated.as_bytes(), code.as_bytes())
            || constant_time_eq(generated_prev.as_bytes(), code.as_bytes()))
    }

    pub fn generate(&self) -> Result<String> {
        let time_step = chrono::Utc::now().timestamp() as u64 / self.period_secs as u64;
        self.generate_at(time_step)
    }

    fn generate_at(&self, counter: u64) -> Result<String> {
        let code = hotp_code(&self.secret, counter, self.digits)?;
        Ok(format_code(code, self.digits))
    }
}

pub struct HotpVerifier {
    secret: Vec<u8>,
    counter: u64,
}

impl HotpVerifier {
    #[must_use]
    pub fn new(secret: Vec<u8>, counter: u64) -> Self {
        Self { secret, counter }
    }

    pub fn verify(&self, code: &str) -> Result<bool> {
        let expected = hotp_code(&self.secret, self.counter, 6)?;
        let formatted = format_code(expected, 6);
        Ok(constant_time_eq(formatted.as_bytes(), code.as_bytes()))
    }
}

fn hotp_code(secret: &[u8], counter: u64, digits: u32) -> Result<u32> {
    let mut mac =
        HmacSha1::new_from_slice(secret).map_err(|e| anyhow::anyhow!("HMAC init failed: {e}"))?;
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

        if current != prev_code {
            assert!(totp.verify(&prev_code).unwrap());
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
        let code = hotp_code(&hotp.secret, hotp.counter, 6).unwrap();
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
        let hotp0 = HotpVerifier::new(secret.clone(), 0);
        let hotp1 = HotpVerifier::new(secret, 1);

        let code0 = hotp_code(&hotp0.secret, 0, 6).unwrap();
        let code1 = hotp_code(&hotp1.secret, 1, 6).unwrap();
        assert_ne!(format_code(code0, 6), format_code(code1, 6));
    }

    #[test]
    fn test_totp_custom_options() {
        let totp = TotpVerifier::with_options(b"secret".to_vec(), 8, 60);
        let code = totp.generate().unwrap();
        assert_eq!(code.len(), 8);
        assert!(totp.verify(&code).unwrap());
    }

    #[test]
    fn test_hotp_deterministic() {
        let secret = b"deterministic-secret".to_vec();
        let code_a = hotp_code(&secret, 42, 6).unwrap();
        let code_b = hotp_code(&secret, 42, 6).unwrap();
        assert_eq!(code_a, code_b);
    }
}
