use anyhow::Result;
use rand::Rng;
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::sync::RwLock;

use crate::utils::constant_time_eq;

struct PendingCode {
    code: String,
    expires_at: std::time::Instant,
    attempts: u32,
    max_attempts: u32,
}

pub(crate) struct VerificationCodeStore {
    codes: Arc<RwLock<HashMap<String, PendingCode>>>,
}

impl VerificationCodeStore {
    pub(crate) fn new() -> Self {
        Self {
            codes: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub(crate) async fn store(&self, key: &str, code: &str, ttl: Duration) {
        self.store_with_attempts(key, code, ttl, 3).await;
    }

    pub(crate) async fn store_with_attempts(&self, key: &str, code: &str, ttl: Duration, max_attempts: u32) {
        let mut codes = self.codes.write().await;
        let now = std::time::Instant::now();
        codes.retain(|_, v| v.expires_at > now);
        let pending = PendingCode {
            code: code.to_string(),
            expires_at: now + ttl,
            attempts: 0,
            max_attempts: max_attempts.max(1),
        };
        codes.insert(key.to_string(), pending);
    }

    pub(crate) async fn verify(&self, key: &str, code: &str) -> Result<bool> {
        let mut codes = self.codes.write().await;
        if let Some(pending) = codes.get_mut(key) {
            if std::time::Instant::now() >= pending.expires_at {
                codes.remove(key);
                return Ok(false);
            }
            pending.attempts += 1;
            if pending.attempts > pending.max_attempts {
                codes.remove(key);
                return Ok(false);
            }
            let result = constant_time_eq(pending.code.as_bytes(), code.as_bytes());
            if result {
                codes.remove(key);
            }
            return Ok(result);
        }
        Ok(false)
    }
}

pub(crate) fn generate_numeric_code(len: usize) -> String {
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| rng.gen_range(b'0'..=b'9') as char)
        .collect()
}
