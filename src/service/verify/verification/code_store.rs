use anyhow::Result;
use rand::Rng;
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::sync::RwLock;

use crate::utils::constant_time_eq;

struct PendingCode {
    code: String,
    expires_at: std::time::Instant,
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
        let pending = PendingCode {
            code: code.to_string(),
            expires_at: std::time::Instant::now() + ttl,
        };
        self.codes.write().await.insert(key.to_string(), pending);
    }

    pub(crate) async fn verify(&self, key: &str, code: &str) -> Result<bool> {
        let mut codes = self.codes.write().await;
        if let Some(pending) = codes.remove(key) {
            if std::time::Instant::now() < pending.expires_at {
                let result = constant_time_eq(pending.code.as_bytes(), code.as_bytes());
                drop(codes);
                return Ok(result);
            }
        }
        drop(codes);
        Ok(false)
    }
}

pub(crate) fn generate_numeric_code(len: usize) -> String {
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| rng.gen_range(b'0'..=b'9') as char)
        .collect()
}
