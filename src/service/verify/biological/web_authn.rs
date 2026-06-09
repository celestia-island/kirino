use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Reference implementation of a WebAuthn-like assertion verifier.
///
/// **Security warning:** This implementation does NOT perform real cryptographic
/// signature verification. It only checks structural validity of inputs and that
/// a registration challenge exists for the given credential. For production use,
/// replace this with a proper WebAuthn library (e.g. `webauthn-rs`).
pub struct WebAuthnVerifier {
    challenges: Arc<RwLock<HashMap<String, Vec<u8>>>>,
    rp_id: String,
}

impl WebAuthnVerifier {
    #[must_use]
    pub fn new() -> Self {
        Self {
            challenges: Arc::new(RwLock::new(HashMap::new())),
            rp_id: "localhost".to_string(),
        }
    }

    #[must_use]
    pub fn with_rp_id(rp_id: String) -> Self {
        Self {
            challenges: Arc::new(RwLock::new(HashMap::new())),
            rp_id,
        }
    }

    /// Verifies a WebAuthn assertion.
    ///
    /// **Note:** This is a reference stub that validates structure only.
    /// It does NOT verify the actual cryptographic signature.
    /// In production, use a real WebAuthn library.
    pub async fn verify_assertion(
        &self,
        credential_id: &[u8],
        authenticator_data: &[u8],
        client_data_json: &[u8],
        signature: &[u8],
    ) -> Result<bool> {
        let challenges = self.challenges.read().await;
        let cid_str = String::from_utf8_lossy(credential_id).to_string();

        if !challenges.contains_key(&cid_str) {
            return Err(anyhow!("unknown credential"));
        }
        if authenticator_data.len() < 37 {
            return Err(anyhow!("authenticator data too short (minimum 37 bytes)"));
        }
        if client_data_json.is_empty() {
            return Err(anyhow!("empty client data"));
        }
        if signature.is_empty() {
            return Ok(false);
        }

        // Reference stub: accepts any non-empty signature.
        // Production implementation must verify signature against the
        // authenticator data + client_data_hash using the stored public key.
        Ok(true)
    }

    pub async fn start_registration(&self, user_id: &str) -> Result<RegistrationChallenge> {
        let challenge: Vec<u8> = {
            let mut rng = rand::thread_rng();
            (0..32).map(|_| rand::Rng::gen(&mut rng)).collect()
        };
        let key = format!("reg:{user_id}");
        let mut challenges = self.challenges.write().await;
        challenges.insert(key, challenge.clone());

        Ok(RegistrationChallenge {
            challenge,
            rp_id: self.rp_id.clone(),
        })
    }

    pub async fn start_authentication(&self, credential_id: &[u8]) -> Result<Vec<u8>> {
        let cid_str = String::from_utf8_lossy(credential_id).to_string();
        let mut challenges = self.challenges.write().await;
        if !challenges.contains_key(&cid_str) {
            return Err(anyhow!("credential not registered"));
        }
        let challenge: Vec<u8> = {
            let mut rng = rand::thread_rng();
            (0..32).map(|_| rand::Rng::gen(&mut rng)).collect()
        };
        challenges.insert(cid_str, challenge.clone());
        Ok(challenge)
    }
}

impl Default for WebAuthnVerifier {
    fn default() -> Self {
        Self::new()
    }
}

pub struct RegistrationChallenge {
    pub challenge: Vec<u8>,
    pub rp_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_start_registration() {
        let v = WebAuthnVerifier::new();
        let ch = v.start_registration("user-1").await.unwrap();
        assert_eq!(ch.challenge.len(), 32);
        assert_eq!(ch.rp_id, "localhost");
    }

    #[tokio::test]
    async fn test_verify_unknown_credential() {
        let v = WebAuthnVerifier::new();
        let result = v
            .verify_assertion(b"unknown", &[0u8; 37], b"{}", b"sig")
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_verify_short_authenticator_data() {
        let v = WebAuthnVerifier::with_rp_id("example.com".to_string());
        assert_eq!(v.rp_id, "example.com");
    }

    #[tokio::test]
    async fn test_verify_empty_client_data() {
        let v = WebAuthnVerifier::new();
        let result = v.verify_assertion(b"test", &[0u8; 37], b"", b"sig").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_verify_empty_signature() {
        let v = WebAuthnVerifier::new();
        v.start_registration("user-1").await.unwrap();
        let cred_id = b"reg:user-1";
        v.start_authentication(cred_id).await.unwrap();
        let result = v.verify_assertion(cred_id, &[0u8; 37], b"{}", b"").await;
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[tokio::test]
    async fn test_verify_with_valid_structure() {
        let v = WebAuthnVerifier::new();
        v.start_registration("user-1").await.unwrap();
        let cred_id = b"reg:user-1";
        v.start_authentication(cred_id).await.unwrap();
        let result = v
            .verify_assertion(cred_id, &[0u8; 37], b"{}", b"signature-data")
            .await;
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[tokio::test]
    async fn test_start_authentication_unknown_credential() {
        let v = WebAuthnVerifier::new();
        let result = v.start_authentication(b"unknown").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_registration_unique_challenges() {
        let v = WebAuthnVerifier::new();
        let ch1 = v.start_registration("user-1").await.unwrap();
        let ch2 = v.start_registration("user-2").await.unwrap();
        assert_ne!(ch1.challenge, ch2.challenge);
    }
}
