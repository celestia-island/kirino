//! Legacy standalone assertion verifier (ES256 signature + counter only).
//!
//! **Deprecated for new code.** This type predates the full ceremony
//! verification in [`super::assertion`] and performs a *subset* of the W3C
//! steps: it does not parse `clientDataJSON`, does not check `rpIdHash`,
//! flags or authData structure, and trusts the caller-supplied counter.
//! It is kept because it was part of kirino's published 0.6 surface; new
//! integrations should use [`super::assertion::verify_assertion`].
//!
//! Shared helpers used by the rest of the module (`key_from_cose`,
//! `validate_supported_key`) live here as well and are re-exported from
//! the module root.

use anyhow::{anyhow, Result};
use coset::{CborSerializable, KeyType};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::utils::constant_time_eq;

/// Verify a WebAuthn assertion as defined in the W3C Web Authentication Level 2 specification.
///
/// Verifies ECDSA P-256 (ES256) signatures over the `authenticatorData || clientDataHash`.
/// Also enforces the anti-cloning counter: the authenticator's `sign_count` must be strictly
/// greater than the stored counter value, or both must be zero (for authenticators that do not
/// implement a signature counter).
pub struct WebAuthnVerifier {
    credential_id: Vec<u8>,
    public_key_cose: Vec<u8>,
    sign_count: u32,
}

/// Maximum acceptable signature counter gap to prevent re-sync DOS attacks.
/// Authenticators that skip counters by more than this value will be rejected.
const MAX_SIGN_COUNT_GAP: u32 = 1024;

impl WebAuthnVerifier {
    #[must_use]
    pub fn new(credential_id: Vec<u8>, public_key_cose: Vec<u8>, sign_count: u32) -> Self {
        Self {
            credential_id,
            public_key_cose,
            sign_count,
        }
    }

    #[must_use]
    pub fn credential_id(&self) -> &[u8] {
        &self.credential_id
    }

    #[must_use]
    pub fn sign_count(&self) -> u32 {
        self.sign_count
    }

    /// Returns the new sign_count on success, or an error on verification failure.
    ///
    /// # Arguments
    ///
    /// * `credential_id` - The credential identifier from the authenticator response.
    ///   Compared against the stored value using constant-time equality.
    /// * `authenticator_data` - Raw bytes of `authenticatorData` from the assertion response.
    /// * `client_data_json` - Raw bytes of `clientDataJSON` from the assertion response.
    /// * `signature` - Raw bytes of the DER-encoded ECDSA P-256 signature.
    /// * `auth_sign_count` - The 4-byte sign count extracted from `authenticatorData` bytes 33-36.
    ///
    /// # Errors
    ///
    /// Returns an error if any verification step fails, including failed signature,
    /// credential ID mismatch, or sign_count regression.
    pub fn verify(
        &self,
        credential_id: &[u8],
        authenticator_data: &[u8],
        client_data_json: &[u8],
        signature: &[u8],
        auth_sign_count: u32,
    ) -> Result<u32> {
        if !constant_time_eq(credential_id, &self.credential_id) {
            return Err(anyhow!("credential_id mismatch"));
        }

        if auth_sign_count != 0 || self.sign_count != 0 {
            if auth_sign_count <= self.sign_count {
                return Err(anyhow!(
                    "sign_count not incremented: stored={}, auth={}",
                    self.sign_count,
                    auth_sign_count
                ));
            }
            if auth_sign_count.saturating_sub(self.sign_count) > MAX_SIGN_COUNT_GAP {
                return Err(anyhow!(
                    "sign_count gap too large: stored={}, auth={}",
                    self.sign_count,
                    auth_sign_count
                ));
            }
        }

        let verifying_key = cose_to_verifying_key(&self.public_key_cose)?;
        let client_data_hash = Sha256::digest(client_data_json);

        let mut signed_data = Vec::with_capacity(authenticator_data.len() + client_data_hash.len());
        signed_data.extend_from_slice(authenticator_data);
        signed_data.extend_from_slice(&client_data_hash);

        let sig =
            Signature::from_der(signature).map_err(|e| anyhow!("invalid DER signature: {}", e))?;

        verifying_key
            .verify(&signed_data, &sig)
            .map_err(|e| anyhow!("signature verification failed: {}", e))?;

        Ok(auth_sign_count)
    }
}

fn cose_to_verifying_key(cose_key_bytes: &[u8]) -> Result<VerifyingKey> {
    key_from_cose(cose_key_bytes)
}

/// Parse and policy-check a stored COSE public key (EC2 / ES256 / P-256
/// only). Shared with the full assertion verifier.
pub fn key_from_cose(cose_key_bytes: &[u8]) -> Result<VerifyingKey> {
    cose_to_verifying_key_impl(cose_key_bytes)
}

/// Reject COSE keys whose algorithms kirino cannot verify during a later
/// assertion. Called at registration time so bad keys never get stored.
pub fn validate_supported_key(key: &coset::CoseKey) -> Result<()> {
    let alg = key
        .alg
        .as_ref()
        .and_then(|a| match a {
            coset::Algorithm::Assigned(a) => Some(*a),
            _ => None,
        })
        .ok_or_else(|| anyhow!("missing or unassigned algorithm"))?;
    if alg != coset::iana::Algorithm::ES256 {
        return Err(anyhow!(
            "unsupported algorithm: expected ES256, got {}",
            alg as i64
        ));
    }
    Ok(())
}

fn cose_to_verifying_key_impl(cose_key_bytes: &[u8]) -> Result<VerifyingKey> {
    let cose_key = coset::CoseKey::from_slice(cose_key_bytes)
        .map_err(|e| anyhow!("invalid COSE key: {}", e))?;

    if cose_key.kty != KeyType::Assigned(coset::iana::KeyType::EC2) {
        return Err(anyhow!(
            "unsupported key type: expected EC2, got {:?}",
            cose_key.kty
        ));
    }

    let alg = cose_key
        .alg
        .and_then(|a| {
            if let coset::Algorithm::Assigned(a) = a {
                Some(a)
            } else {
                None
            }
        })
        .ok_or_else(|| anyhow!("missing or unassigned algorithm"))?;

    if alg != coset::iana::Algorithm::ES256 {
        return Err(anyhow!(
            "unsupported algorithm: expected ES256, got {}",
            alg as i64
        ));
    }

    let get_param_int = |label_int: i64| -> Option<i64> {
        let val = cose_key
            .params
            .iter()
            .find(|(l, _)| matches!(l, coset::Label::Int(v) if *v == label_int))
            .map(|(_, v)| v);
        match val.and_then(|v| v.as_integer()) {
            Some(i) => i64::try_from(i).ok(),
            None => None,
        }
    };

    let get_param_bytes = |label_int: i64| -> Option<Vec<u8>> {
        cose_key
            .params
            .iter()
            .find(|(l, _)| matches!(l, coset::Label::Int(v) if *v == label_int))
            .and_then(|(_, v)| v.as_bytes().cloned())
    };

    let crv = get_param_int(coset::iana::Ec2KeyParameter::Crv as i64)
        .ok_or_else(|| anyhow!("missing curve parameter"))?;

    if crv != coset::iana::EllipticCurve::P_256 as i64 {
        return Err(anyhow!(
            "unsupported curve: expected P-256 ({}), got {}",
            coset::iana::EllipticCurve::P_256 as i64,
            crv
        ));
    }

    let x = get_param_bytes(coset::iana::Ec2KeyParameter::X as i64)
        .ok_or_else(|| anyhow!("missing EC x-coordinate"))?;
    let y = get_param_bytes(coset::iana::Ec2KeyParameter::Y as i64)
        .ok_or_else(|| anyhow!("missing EC y-coordinate"))?;

    let mut encoded = Vec::with_capacity(1 + x.len() + y.len());
    encoded.push(0x04);
    encoded.extend_from_slice(&x);
    encoded.extend_from_slice(&y);

    VerifyingKey::from_sec1_bytes(&encoded).map_err(|e| anyhow!("invalid EC public key: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Signer, SigningKey};
    use p256::elliptic_curve::Generate;

    fn make_real_keypair() -> (SigningKey, Vec<u8>) {
        let signing_key = SigningKey::generate();
        let verifying_key_bytes = signing_key.verifying_key().to_sec1_bytes().to_vec();

        let x = &verifying_key_bytes[1..33];
        let y = &verifying_key_bytes[33..65];

        use coset::CoseKeyBuilder;
        let cose_key = CoseKeyBuilder::new_ec2_pub_key(
            coset::iana::EllipticCurve::P_256,
            x.to_vec(),
            y.to_vec(),
        )
        .algorithm(coset::iana::Algorithm::ES256)
        .build();

        (signing_key, cose_key.to_vec().unwrap())
    }

    fn make_signed_assertion(
        signing_key: &SigningKey,
        authenticator_data: &[u8],
        client_data_json: &[u8],
    ) -> Vec<u8> {
        let client_data_hash = Sha256::digest(client_data_json);
        let mut signed_data = Vec::with_capacity(authenticator_data.len() + client_data_hash.len());
        signed_data.extend_from_slice(authenticator_data);
        signed_data.extend_from_slice(&client_data_hash);
        let sig: Signature = signing_key.sign(&signed_data);
        sig.to_der().to_bytes().to_vec()
    }

    fn make_test_cose_key() -> Vec<u8> {
        use coset::CoseKeyBuilder;
        let key = CoseKeyBuilder::new_ec2_pub_key(
            coset::iana::EllipticCurve::P_256,
            vec![0xAA; 32],
            vec![0xBB; 32],
        )
        .algorithm(coset::iana::Algorithm::ES256)
        .build();
        key.to_vec().unwrap()
    }

    #[test]
    fn test_credential_id_mismatch_rejected() {
        let cose_key = make_test_cose_key();
        let verifier = WebAuthnVerifier::new(b"stored-id".to_vec(), cose_key, 0);
        let result = verifier.verify(b"wrong-id", &[0u8; 37], b"{}", &[], 0);
        assert!(result.is_err());
        assert!(format!("{}", result.unwrap_err()).contains("credential_id"));
    }

    #[test]
    fn test_sign_count_not_incremented_rejected() {
        let cose_key = make_test_cose_key();
        let verifier = WebAuthnVerifier::new(b"cred".to_vec(), cose_key, 10);
        let result = verifier.verify(b"cred", &[0u8; 37], b"{}", &[], 5);
        assert!(result.is_err());
        assert!(format!("{}", result.unwrap_err()).contains("sign_count"));
    }

    #[test]
    fn test_sign_count_zero_allows_bypass() {
        let (signing_key, cose_key) = make_real_keypair();
        let verifier = WebAuthnVerifier::new(b"cred".to_vec(), cose_key, 0);
        let auth_data = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        let client_data = b"{\"type\":\"webauthn.get\"}";
        let sig = make_signed_assertion(&signing_key, auth_data, client_data);

        let result = verifier.verify(b"cred", auth_data, client_data, &sig, 0);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
    }

    #[test]
    fn test_sign_count_equal_rejected() {
        let (signing_key, cose_key) = make_real_keypair();
        let verifier = WebAuthnVerifier::new(b"cred".to_vec(), cose_key, 5);
        let auth_data = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        let client_data = b"{\"type\":\"webauthn.get\"}";
        let sig = make_signed_assertion(&signing_key, auth_data, client_data);
        let result = verifier.verify(b"cred", auth_data, client_data, &sig, 5);
        assert!(result.is_err());
    }

    #[test]
    fn test_sign_count_zero_auth_nonzero_stored_rejected() {
        let (signing_key, cose_key) = make_real_keypair();
        let verifier = WebAuthnVerifier::new(b"cred".to_vec(), cose_key, 42);
        let auth_data = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        let client_data = b"{\"type\":\"webauthn.get\"}";
        let sig = make_signed_assertion(&signing_key, auth_data, client_data);
        let result = verifier.verify(b"cred", auth_data, client_data, &sig, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_sign_count_gap_too_large_rejected() {
        let (signing_key, cose_key) = make_real_keypair();
        let verifier = WebAuthnVerifier::new(b"cred".to_vec(), cose_key, 5);
        let auth_data = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        let client_data = b"{\"type\":\"webauthn.get\"}";
        let sig = make_signed_assertion(&signing_key, auth_data, client_data);
        let result = verifier.verify(b"cred", auth_data, client_data, &sig, 5000);
        assert!(result.is_err());
    }

    #[test]
    fn test_sign_count_gap_exactly_max_passes() {
        let (signing_key, cose_key) = make_real_keypair();
        let verifier = WebAuthnVerifier::new(b"cred".to_vec(), cose_key, 0);
        let auth_data = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        let client_data = b"{\"type\":\"webauthn.get\"}";
        let sig = make_signed_assertion(&signing_key, auth_data, client_data);

        let result = verifier.verify(b"cred", auth_data, client_data, &sig, MAX_SIGN_COUNT_GAP);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), MAX_SIGN_COUNT_GAP);
    }

    #[test]
    fn test_sign_count_gap_just_over_max_rejected() {
        let (signing_key, cose_key) = make_real_keypair();
        let verifier = WebAuthnVerifier::new(b"cred".to_vec(), cose_key, 0);
        let auth_data = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        let client_data = b"{\"type\":\"webauthn.get\"}";
        let sig = make_signed_assertion(&signing_key, auth_data, client_data);

        let result = verifier.verify(
            b"cred",
            auth_data,
            client_data,
            &sig,
            MAX_SIGN_COUNT_GAP + 1,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_successful_verification_increments_counter() {
        let (signing_key, cose_key) = make_real_keypair();
        let verifier = WebAuthnVerifier::new(b"my-credential".to_vec(), cose_key, 41);
        let auth_data = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        let client_data = b"{\"type\":\"webauthn.get\"}";
        let sig = make_signed_assertion(&signing_key, auth_data, client_data);

        let result = verifier.verify(b"my-credential", auth_data, client_data, &sig, 42);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn test_wrong_signature_fails() {
        let (signing_key, cose_key) = make_real_keypair();
        let verifier = WebAuthnVerifier::new(b"cred".to_vec(), cose_key, 0);
        let auth_data = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        let client_data = b"{\"type\":\"webauthn.get\"}";
        let sig = make_signed_assertion(&signing_key, auth_data, client_data);

        let tampered_auth = b"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        let result = verifier.verify(b"cred", tampered_auth, client_data, &sig, 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_cose_key_rejected() {
        let verifier = WebAuthnVerifier::new(b"cred".to_vec(), b"not-valid-cbor".to_vec(), 0);
        let result = verifier.verify(b"cred", &[0u8; 37], b"{}", &[], 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_algorithm_cose_key_rejected() {
        use coset::CoseKeyBuilder;
        let key = CoseKeyBuilder::new_ec2_pub_key(
            coset::iana::EllipticCurve::P_256,
            vec![0xAA; 32],
            vec![0xBB; 32],
        )
        .algorithm(coset::iana::Algorithm::ES384)
        .build();
        let verifier = WebAuthnVerifier::new(b"cred".to_vec(), key.to_vec().unwrap(), 0);
        let result = verifier.verify(b"cred", &[0u8; 37], b"{}", &[], 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_curve_cose_key_rejected() {
        use coset::CoseKeyBuilder;
        let key = CoseKeyBuilder::new_ec2_pub_key(
            coset::iana::EllipticCurve::P_384,
            vec![0xAA; 48],
            vec![0xBB; 48],
        )
        .algorithm(coset::iana::Algorithm::ES256)
        .build();
        let verifier = WebAuthnVerifier::new(b"cred".to_vec(), key.to_vec().unwrap(), 0);
        let result = verifier.verify(b"cred", &[0u8; 37], b"{}", &[], 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_key_type_cose_key_rejected() {
        use coset::CoseKeyBuilder;
        let key = CoseKeyBuilder::new_symmetric_key(vec![0xCC; 32])
            .algorithm(coset::iana::Algorithm::ES256)
            .build();
        let verifier = WebAuthnVerifier::new(b"cred".to_vec(), key.to_vec().unwrap(), 0);
        let result = verifier.verify(b"cred", &[0u8; 37], b"{}", &[], 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_missing_x_cose_key_rejected() {
        use coset::CoseKeyBuilder;
        let mut key = CoseKeyBuilder::new_ec2_pub_key(
            coset::iana::EllipticCurve::P_256,
            vec![0xAA; 32],
            vec![0xBB; 32],
        )
        .algorithm(coset::iana::Algorithm::ES256)
        .build();
        key.params.retain(|(l, _)| {
            matches!(l, coset::Label::Int(v) if *v != coset::iana::Ec2KeyParameter::X as i64)
        });
        let verifier = WebAuthnVerifier::new(b"cred".to_vec(), key.to_vec().unwrap(), 0);
        let result = verifier.verify(b"cred", &[0u8; 37], b"{}", &[], 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_successful_verification_nonzero_start() {
        let (signing_key, cose_key) = make_real_keypair();
        let verifier = WebAuthnVerifier::new(b"cred".to_vec(), cose_key, 100);
        let auth_data = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        let client_data = b"{\"type\":\"webauthn.get\"}";
        let sig = make_signed_assertion(&signing_key, auth_data, client_data);

        let result = verifier.verify(b"cred", auth_data, client_data, &sig, 101);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 101);
    }

    #[test]
    fn test_accessors() {
        let verifier = WebAuthnVerifier::new(b"id".to_vec(), vec![0x01, 0x02], 7);
        assert_eq!(verifier.credential_id(), b"id");
        assert_eq!(verifier.sign_count(), 7);
    }
}
