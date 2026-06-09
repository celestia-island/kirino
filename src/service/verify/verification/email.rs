use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

use rand::Rng;

use crate::utils::constant_time_eq;

pub struct EmailVerifier {
    sender: String,
    codes: Arc<RwLock<HashMap<String, PendingCode>>>,
}

struct PendingCode {
    code: String,
    expires_at: std::time::Instant,
}

impl EmailVerifier {
    #[must_use]
    pub fn new(sender: String) -> Self {
        Self {
            sender,
            codes: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn send_code(&self, address: &str, code: &str) -> Result<()> {
        let pending = PendingCode {
            code: code.to_string(),
            expires_at: std::time::Instant::now() + Duration::from_secs(300),
        };
        self.codes
            .write()
            .await
            .insert(address.to_string(), pending);
        tracing::debug!(
            target: "kirino::verify::email",
            from = %self.sender,
            to = %address,
            "email verification code would be sent"
        );
        Ok(())
    }

    pub async fn verify_code(&self, address: &str, code: &str) -> Result<bool> {
        let mut codes = self.codes.write().await;
        if let Some(pending) = codes.remove(address) {
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
}
