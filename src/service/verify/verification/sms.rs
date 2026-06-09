use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

use rand::Rng;

use crate::utils::constant_time_eq;

pub struct SmsVerifier {
    sender: String,
    codes: Arc<RwLock<HashMap<String, PendingCode>>>,
}

struct PendingCode {
    code: String,
    expires_at: std::time::Instant,
}

impl SmsVerifier {
    #[must_use]
    pub fn new(sender: String) -> Self {
        Self {
            sender,
            codes: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn send_code(&self, phone: &str, code: &str) -> Result<()> {
        let pending = PendingCode {
            code: code.to_string(),
            expires_at: std::time::Instant::now() + Duration::from_secs(300),
        };
        self.codes.write().await.insert(phone.to_string(), pending);
        tracing::debug!(
            target: "kirino::verify::sms",
            from = %self.sender,
            to = %phone,
            "SMS verification code would be sent"
        );
        Ok(())
    }

    pub async fn verify_code(&self, phone: &str, code: &str) -> Result<bool> {
        let mut codes = self.codes.write().await;
        if let Some(pending) = codes.remove(phone) {
            if std::time::Instant::now() < pending.expires_at {
                return Ok(constant_time_eq(pending.code.as_bytes(), code.as_bytes()));
            }
        }
        Ok(false)
    }

    pub fn generate_code(len: usize) -> String {
        let mut rng = rand::thread_rng();
        (0..len)
            .map(|_| rng.gen_range(b'0'..=b'9') as char)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_send_and_verify() {
        let v = SmsVerifier::new("+1234567890".to_string());
        let code = SmsVerifier::generate_code(6);
        v.send_code("+9876543210", &code).await.unwrap();
        assert!(v.verify_code("+9876543210", &code).await.unwrap());
    }

    #[tokio::test]
    async fn test_wrong_code() {
        let v = SmsVerifier::new("+1234567890".to_string());
        v.send_code("+9876543210", "654321").await.unwrap();
        assert!(!v.verify_code("+9876543210", "000000").await.unwrap());
    }

    #[tokio::test]
    async fn test_unknown_phone() {
        let v = SmsVerifier::new("+1234567890".to_string());
        assert!(!v.verify_code("+0000000000", "123456").await.unwrap());
    }

    #[test]
    fn test_generate_code_length() {
        let code = SmsVerifier::generate_code(6);
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }

    #[tokio::test]
    async fn test_code_single_use() {
        let v = SmsVerifier::new("+1234567890".to_string());
        v.send_code("+1111111111", "123456").await.unwrap();
        assert!(v.verify_code("+1111111111", "123456").await.unwrap());
        assert!(!v.verify_code("+1111111111", "123456").await.unwrap());
    }

    #[tokio::test]
    async fn test_multiple_phones() {
        let v = SmsVerifier::new("+1234567890".to_string());
        v.send_code("+111", "111111").await.unwrap();
        v.send_code("+222", "222222").await.unwrap();
        assert!(v.verify_code("+111", "111111").await.unwrap());
        assert!(v.verify_code("+222", "222222").await.unwrap());
    }
}
