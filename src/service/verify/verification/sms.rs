use anyhow::Result;
use std::time::Duration;

use super::code_store::{generate_numeric_code, VerificationCodeStore};

const DEFAULT_TTL: Duration = Duration::from_secs(300);

pub struct SmsVerifier {
    sender: String,
    store: VerificationCodeStore,
}

impl SmsVerifier {
    #[must_use]
    pub fn new(sender: String) -> Self {
        Self {
            sender,
            store: VerificationCodeStore::new(),
        }
    }

    pub async fn send_code(&self, phone: &str, code: &str) -> Result<()> {
        self.send_code_with_ttl(phone, code, DEFAULT_TTL).await
    }

    pub async fn send_code_with_ttl(&self, phone: &str, code: &str, ttl: Duration) -> Result<()> {
        self.store.store(phone, code, ttl).await;
        tracing::debug!(
            target: "kirino::verify::sms",
            from = %self.sender,
            to = %phone,
            "SMS verification code would be sent"
        );
        Ok(())
    }

    pub async fn verify_code(&self, phone: &str, code: &str) -> Result<bool> {
        self.store.verify(phone, code).await
    }

    #[must_use]
    pub fn generate_code(len: usize) -> String {
        generate_numeric_code(len)
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

    #[tokio::test]
    async fn test_expired_code_rejected() {
        let v = SmsVerifier::new("+1234567890".to_string());
        v.send_code_with_ttl("+9876543210", "123456", Duration::from_millis(1))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(!v.verify_code("+9876543210", "123456").await.unwrap());
    }

    #[tokio::test]
    async fn test_resend_replaces_old_code() {
        let v = SmsVerifier::new("+1234567890".to_string());
        v.send_code("+9876543210", "111111").await.unwrap();
        v.send_code("+9876543210", "222222").await.unwrap();
        assert!(v.verify_code("+9876543210", "222222").await.unwrap());
    }

    #[test]
    fn test_generate_code_different_each_time() {
        let codes: Vec<String> = (0..10).map(|_| SmsVerifier::generate_code(6)).collect();
        let unique: std::collections::HashSet<_> = codes.iter().collect();
        assert!(
            unique.len() > 1,
            "generated codes should not all be identical"
        );
    }
}
