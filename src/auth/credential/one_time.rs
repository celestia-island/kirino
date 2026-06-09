#![allow(missing_docs)]
#![allow(clippy::missing_errors_doc)]

use anyhow::Result;

use async_trait::async_trait;

use super::Credential;

pub struct OneTimeCredential {
    #[allow(dead_code)]
    token: String,
    #[allow(dead_code)]
    used: bool,
}

impl OneTimeCredential {
    #[must_use]
    pub fn new(token: String) -> Self {
        Self { token, used: false }
    }

    pub fn generate() -> Self {
        unimplemented!("one-time token generation")
    }

    pub fn is_used(&self) -> bool {
        self.used
    }
}

impl Credential for OneTimeCredential {
    fn verify(&self, token: &str) -> Result<bool> {
        if self.used {
            return Ok(false);
        }
        let a = self.token.as_bytes();
        let b = token.as_bytes();
        if a.len() != b.len() {
            return Ok(false);
        }
        let mut diff = 0u8;
        for (x, y) in a.iter().zip(b.iter()) {
            diff |= x ^ y;
        }
        Ok(diff == 0)
    }
}

#[async_trait]
pub trait OneTimeStore: Send + Sync {
    async fn claim(&self, token: &str) -> Result<bool>;
    async fn issue(&self, ttl_secs: u64) -> Result<String>;
}
