use anyhow::Result;
use std::time::Duration;

use super::code_store::{generate_numeric_code, VerificationCodeStore};

const DEFAULT_TTL: Duration = Duration::from_secs(300);

pub struct EmailVerifier {
    sender: String,
    store: VerificationCodeStore,
}

impl EmailVerifier {
    #[must_use]
    pub fn new(sender: String) -> Self {
        Self {
            sender,
            store: VerificationCodeStore::new(),
        }
    }

    pub async fn send_code(&self, address: &str, code: &str) -> Result<()> {
        self.send_code_with_ttl(address, code, DEFAULT_TTL).await
    }

    pub async fn send_code_with_ttl(&self, address: &str, code: &str, ttl: Duration) -> Result<()> {
        self.store.store(address, code, ttl).await;
        tracing::debug!(
            target: "kirino::verify::email",
            from = %self.sender,
            to = %address,
            "email verification code would be sent"
        );
        Ok(())
    }

    pub async fn verify_code(&self, address: &str, code: &str) -> Result<bool> {
        self.store.verify(address, code).await
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
        let v = EmailVerifier::new("noreply@example.com".to_string());
        let code = EmailVerifier::generate_code(6);
        v.send_code("user@example.com", &code).await.unwrap();
        assert!(v.verify_code("user@example.com", &code).await.unwrap());
    }

    #[tokio::test]
    async fn test_wrong_code() {
        let v = EmailVerifier::new("noreply@example.com".to_string());
        v.send_code("user@example.com", "123456").await.unwrap();
        assert!(!v.verify_code("user@example.com", "000000").await.unwrap());
    }

    #[tokio::test]
    async fn test_unknown_address() {
        let v = EmailVerifier::new("noreply@example.com".to_string());
        assert!(!v
            .verify_code("unknown@example.com", "123456")
            .await
            .unwrap());
    }

    #[test]
    fn test_generate_code_length() {
        let code = EmailVerifier::generate_code(6);
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_generate_code_different_each_time() {
        let codes: Vec<String> = (0..10).map(|_| EmailVerifier::generate_code(6)).collect();
        let unique: std::collections::HashSet<_> = codes.iter().collect();
        assert!(
            unique.len() > 1,
            "generated codes should not all be identical"
        );
    }

    #[tokio::test]
    async fn test_code_single_use() {
        let v = EmailVerifier::new("noreply@example.com".to_string());
        v.send_code("user@example.com", "654321").await.unwrap();
        assert!(v.verify_code("user@example.com", "654321").await.unwrap());
        assert!(!v.verify_code("user@example.com", "654321").await.unwrap());
    }

    #[tokio::test]
    async fn test_multiple_addresses() {
        let v = EmailVerifier::new("noreply@example.com".to_string());
        v.send_code("a@example.com", "111111").await.unwrap();
        v.send_code("b@example.com", "222222").await.unwrap();
        assert!(v.verify_code("a@example.com", "111111").await.unwrap());
        assert!(v.verify_code("b@example.com", "222222").await.unwrap());
    }

    #[tokio::test]
    async fn test_expired_code_rejected() {
        let v = EmailVerifier::new("noreply@example.com".to_string());
        v.send_code_with_ttl("user@example.com", "123456", Duration::from_millis(1))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(!v.verify_code("user@example.com", "123456").await.unwrap());
    }

    #[tokio::test]
    async fn test_resend_replaces_old_code() {
        let v = EmailVerifier::new("noreply@example.com".to_string());
        v.send_code("user@example.com", "111111").await.unwrap();
        v.send_code("user@example.com", "222222").await.unwrap();
        assert!(v.verify_code("user@example.com", "222222").await.unwrap());
    }
}
