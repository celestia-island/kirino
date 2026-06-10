use anyhow::Result;

use hmac::{Hmac, Mac};

use super::Credential;
use crate::{error::KirinoError, utils::constant_time_eq};

type HmacSha256 = Hmac<sha2::Sha256>;

/// HMAC-SHA256 based service credential for machine-to-machine authentication.
///
/// Stores a pre-computed HMAC-SHA256 hash of the token and verifies
/// future tokens by re-computing the hash and comparing in constant time.
/// Supports reconstruction from a stored hash via [`from_hash`](Self::from_hash).
pub struct ServiceCredential {
    token_hash: String,
    key: Vec<u8>,
}

impl ServiceCredential {
    pub fn from_shared_key(key: &[u8], token: &str) -> Result<Self> {
        if key.is_empty() {
            return Err(KirinoError::Validation(
                "ServiceCredential key must not be empty".to_string(),
            )
            .into());
        }
        let hash = hmac_sha256_hex(key, token.as_bytes())?;
        Ok(Self {
            token_hash: hash,
            key: key.to_vec(),
        })
    }

    pub fn from_hash(token_hash: String, key: Vec<u8>) -> Result<Self> {
        if key.is_empty() {
            return Err(KirinoError::Validation(
                "ServiceCredential key must not be empty".to_string(),
            )
            .into());
        }
        Ok(Self { token_hash, key })
    }
}

impl Credential for ServiceCredential {
    fn verify(&self, token: &str) -> Result<bool> {
        let computed = hmac_sha256_hex(&self.key, token.as_bytes())?;
        Ok(constant_time_eq(
            self.token_hash.as_bytes(),
            computed.as_bytes(),
        ))
    }
}

fn hmac_sha256_hex(key: &[u8], data: &[u8]) -> Result<String> {
    use std::fmt::Write;
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|_| KirinoError::Validation("HMAC key must not be empty".to_string()))?;
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut hex = String::with_capacity(result.len() * 2);
    for byte in result.as_slice() {
        let _ = write!(hex, "{byte:02x}");
    }
    Ok(hex)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_shared_key_and_verify() {
        let key = b"my-service-key-that-is-long-enough";
        let cred = ServiceCredential::from_shared_key(key, "my-service-token").unwrap();
        assert!(cred.verify("my-service-token").unwrap());
        assert!(!cred.verify("wrong-token").unwrap());
    }

    #[test]
    fn test_deterministic_hash() {
        let key = b"test-key-for-determinism-check-1234";
        let c1 = ServiceCredential::from_shared_key(key, "token").unwrap();
        let c2 = ServiceCredential::from_shared_key(key, "token").unwrap();
        assert_eq!(c1.token_hash, c2.token_hash);
    }

    #[test]
    fn test_different_keys_different_hashes() {
        let c1 =
            ServiceCredential::from_shared_key(b"key-a-that-is-long-enough-aaaa", "token").unwrap();
        let c2 =
            ServiceCredential::from_shared_key(b"key-b-that-is-long-enough-bbbb", "token").unwrap();
        assert_ne!(c1.token_hash, c2.token_hash);
    }

    #[test]
    fn test_from_hash_with_known_key() {
        let key = b"key-for-from-hash-test-1234567890";
        let cred = ServiceCredential::from_shared_key(key, "token").unwrap();
        let hash = cred.token_hash.clone();

        let cred2 = ServiceCredential::from_hash(hash, key.to_vec()).unwrap();
        assert!(cred2.verify("token").unwrap());
    }

    #[test]
    fn test_empty_token() {
        let key = b"key-for-empty-token-test-1234567890";
        let cred = ServiceCredential::from_shared_key(key, "").unwrap();
        assert!(cred.verify("").unwrap());
        assert!(!cred.verify("x").unwrap());
    }

    #[test]
    fn test_constant_time_verification() {
        let key = b"key-for-timing-test-123456789012";
        let cred = ServiceCredential::from_shared_key(key, "test-token-value").unwrap();

        assert!(cred.verify("test-token-value").unwrap());
        assert!(!cred.verify("fest-token-value").unwrap());
        assert!(!cred.verify("test-token-valuf").unwrap());
        assert!(!cred.verify("completely-different").unwrap());
    }

    #[test]
    fn test_empty_key_returns_error() {
        assert!(ServiceCredential::from_shared_key(b"", "token").is_err());
    }

    #[test]
    fn test_from_hash_empty_key_returns_error() {
        assert!(ServiceCredential::from_hash("hash".to_string(), vec![]).is_err());
    }
}
