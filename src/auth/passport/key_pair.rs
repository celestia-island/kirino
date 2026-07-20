use anyhow::{anyhow, Result};
use rand::Rng;
use zeroize::Zeroizing;
use hmac::{Hmac, Mac};


use crate::utils::constant_time_eq;

type HmacSha256 = Hmac<sha2::Sha256>;

const SECRET_KEY_LENGTH: usize = 64;
const PRIVATE_KEY_LENGTH: usize = 32;

/// HMAC-based message authentication verifier.
///
/// Note: Despite the historical name "KeyPairVerifier", this implementation
/// uses symmetric HMAC-SHA256, not asymmetric public-key cryptography.
/// The "key pair" generated is derived via HMAC from a shared secret.
/// For production use cases requiring true asymmetric signatures (e.g. Ed25519),
/// replace this with a proper public-key library.
///
/// Secrets are zeroed on drop via [`Zeroizing`].
pub struct KeyPairVerifier {
    secret_key: Zeroizing<Vec<u8>>,
}

impl KeyPairVerifier {
    #[must_use]
    pub fn new() -> Self {
        let mut rng = rand::thread_rng();
        let mut key = vec![0u8; SECRET_KEY_LENGTH];
        rng.fill(&mut key[..]);
        Self {
            secret_key: Zeroizing::new(key),
        }
    }

    pub fn with_secret_key(secret_key: Vec<u8>) -> Result<Self> {
        if secret_key.is_empty() {
            return Err(anyhow!("secret key must not be empty"));
        }
        Ok(Self {
            secret_key: Zeroizing::new(secret_key),
        })
    }

    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        hmac_compute(&self.secret_key, message)
    }

    pub fn verify_signature(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        let expected = hmac_compute(&self.secret_key, message)?;
        Ok(constant_time_eq(&expected, signature))
    }

    pub fn generate_keypair(&self) -> Result<(Vec<u8>, zeroize::Zeroizing<Vec<u8>>)> {
        let mut rng = rand::thread_rng();
        let mut private_key = zeroize::Zeroizing::new(vec![0u8; PRIVATE_KEY_LENGTH]);
        rng.fill(&mut private_key[..]);
        let public_key = self.derive_public(&private_key)?;
        Ok((public_key, private_key))
    }

    fn derive_public(&self, private_key: &[u8]) -> Result<Vec<u8>> {
        hmac_compute(&self.secret_key, private_key)
    }
}

impl Default for KeyPairVerifier {
    fn default() -> Self {
        Self::new()
    }
}

fn hmac_compute(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|e| anyhow!("HMAC init failed: {e}"))?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_and_verify() {
        let verifier = KeyPairVerifier::new();
        let message = b"test message";
        let signature = verifier.sign(message).unwrap();
        assert!(verifier.verify_signature(message, &signature).unwrap());
    }

    #[test]
    fn test_wrong_message() {
        let verifier = KeyPairVerifier::new();
        let signature = verifier.sign(b"original").unwrap();
        assert!(!verifier.verify_signature(b"tampered", &signature).unwrap());
    }

    #[test]
    fn test_wrong_signature() {
        let verifier = KeyPairVerifier::new();
        assert!(!verifier
            .verify_signature(b"test", b"wrong-signature")
            .unwrap());
    }

    #[test]
    fn test_generate_keypair() {
        let verifier = KeyPairVerifier::new();
        let (public_key, private_key) = verifier.generate_keypair().unwrap();
        assert!(!public_key.is_empty());
        assert!(!private_key.is_empty());
        assert_ne!(public_key, *private_key);
    }

    #[test]
    fn test_keypairs_are_unique() {
        let verifier = KeyPairVerifier::new();
        let (pub1, priv1) = verifier.generate_keypair().unwrap();
        let (pub2, priv2) = verifier.generate_keypair().unwrap();
        assert_ne!(pub1, pub2);
        assert_ne!(priv1, priv2);
    }

    #[test]
    fn test_deterministic_signatures() {
        let verifier = KeyPairVerifier::with_secret_key(vec![42u8; 64]).unwrap();
        let msg = b"deterministic test";
        let sig1 = verifier.sign(msg).unwrap();
        let sig2 = verifier.sign(msg).unwrap();
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_verify_empty_message() {
        let verifier = KeyPairVerifier::new();
        let signature = verifier.sign(b"").unwrap();
        assert!(verifier.verify_signature(b"", &signature).unwrap());
    }

    #[test]
    fn test_verify_signature_length_mismatch() {
        let verifier = KeyPairVerifier::new();
        assert!(!verifier.verify_signature(b"test", b"short").unwrap());
    }

    #[test]
    fn test_with_secret_key() {
        let key = vec![0xAB; 64];
        let verifier = KeyPairVerifier::with_secret_key(key).unwrap();
        let signature = verifier.sign(b"message").unwrap();
        assert!(verifier.verify_signature(b"message", &signature).unwrap());
    }

    #[test]
    fn test_with_empty_secret_key_returns_error() {
        assert!(KeyPairVerifier::with_secret_key(vec![]).is_err());
    }
}
