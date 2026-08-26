//! Full assertion (authentication) verification — W3C L2 §7.2.
//!
//! Orchestrates the three inputs the browser hands up for a login:
//!
//! * `credentialId` + raw `authenticatorData` + `signature`,
//! * `clientDataJSON` (parsed and expectation-checked),
//! * the stored COSE public key + counter from the RP's credential record.
//!
//! Every policy-relevant value is read back out of the signed bytes; nothing
//! is caller-trusted anymore (the legacy [`super::assertion_legacy`] path
//! accepted an already-extracted counter, decoupling counter policy from the
//! signed data). The RP ID binding (§7.2 step 9) is enforced *inside* this
//! module via [`AssertionExpectations::rp_id`] — callers cannot skip it.

use super::auth_data::AuthenticatorData;
use super::client_data::{ClientData, TYPE_GET};
use anyhow::{anyhow, Result};
use p256::ecdsa::signature::Verifier;
use sha2::{Digest, Sha256};

/// Policy applied to an assertion before accepting it.
#[derive(Debug, Clone)]
pub struct AssertionExpectations {
    /// RP ID whose SHA-256 must equal authData's rpIdHash (§7.2 step 9).
    /// This is the anti-phishing binding and is enforced internally —
    /// callers cannot forget it.
    pub rp_id: String,
    /// Exact base64url challenge as issued for this ceremony.
    pub challenge_b64: String,
    /// Origin allowlist (scheme + host [+ port]). Compared
    /// ASCII-case-insensitively per WebAuthn §5.8.2 serialization rules.
    pub allowed_origins: Vec<String>,
    /// Require the UV flag (step-up / biometric-mandatory deployments).
    pub require_user_verification: bool,
}

/// Result of a successful assertion verification.
#[derive(Debug, Clone)]
pub struct AssertionOutcome {
    /// The new signature counter to persist.
    pub sign_count: u32,
    /// UV flag state (for risk scoring upstream).
    pub user_verified: bool,
    /// Backup-state flag (BS) at assertion time.
    pub backup_state: bool,
}

/// Maximum acceptable signature counter gap to prevent re-sync DOS attacks
/// (same policy as the legacy verifier).
const MAX_SIGN_COUNT_GAP: u32 = 1024;

/// Verify one assertion end-to-end.
///
/// # Errors
///
/// Errors on any failed W3C step: clientData type/challenge/origin, rpIdHash
/// mismatch, missing UP/UV, credential-id mismatch, zero-length credential
/// id, signature failure or counter regression. The credential id ↔ user
/// mapping remains the caller's responsibility — always resolve the stored
/// record by looking up `response_credential_id` and pass ITS values here;
/// never verify against a userHandle-supplied record without checking that
/// it matches the credential row's owner.
#[allow(clippy::too_many_arguments)]
pub fn verify_assertion(
    stored_credential_id: &[u8],
    stored_public_key_cose: &[u8],
    stored_sign_count: u32,
    response_credential_id: &[u8],
    authenticator_data: &[u8],
    signature: &[u8],
    client_data_json: &[u8],
    expectations: &AssertionExpectations,
) -> Result<AssertionOutcome> {
    // --- clientDataJSON -------------------------------------------------
    let cd = ClientData::parse(client_data_json)?;
    cd.verify_expectations(
        TYPE_GET,
        &expectations.challenge_b64,
        &expectations.allowed_origins,
    )?;

    // --- authData structure ---------------------------------------------
    let ad = AuthenticatorData::parse(authenticator_data)?;
    if !ad.user_present() {
        return Err(anyhow!("UP flag not set"));
    }
    if expectations.require_user_verification && !ad.user_verified() {
        return Err(anyhow!("UV flag required but not set"));
    }

    // --- rpIdHash (§7.2 step 9) -----------------------------------------
    let expected_hash = Sha256::digest(expectations.rp_id.as_bytes());
    if ad.rp_id_hash() != expected_hash.as_slice() {
        return Err(anyhow!("rpIdHash mismatch for RP {:?}", expectations.rp_id));
    }

    // --- credential id ---------------------------------------------------
    if response_credential_id.is_empty() || stored_credential_id.is_empty() {
        return Err(anyhow!("credential id must not be empty"));
    }
    if !crate::utils::constant_time_eq(response_credential_id, stored_credential_id) {
        return Err(anyhow!("credential_id mismatch"));
    }

    // --- signature over authData || SHA256(clientDataJSON) ---------------
    let verifying_key = super::assertion_legacy::key_from_cose(stored_public_key_cose)?;
    let client_data_hash = Sha256::digest(client_data_json);
    let mut signed_data = Vec::with_capacity(authenticator_data.len() + 32);
    signed_data.extend_from_slice(ad.as_raw());
    signed_data.extend_from_slice(&client_data_hash);
    let sig = p256::ecdsa::Signature::from_der(signature)
        .map_err(|e| anyhow!("invalid DER signature: {e}"))?;
    verifying_key
        .verify(&signed_data, &sig)
        .map_err(|e| anyhow!("signature verification failed: {e}"))?;

    // --- counter policy ---------------------------------------------------
    let auth_count = ad.sign_count();
    let new_count = if auth_count != 0 || stored_sign_count != 0 {
        if auth_count <= stored_sign_count {
            return Err(anyhow!(
                "sign_count not incremented: stored={stored_sign_count}, auth={auth_count}"
            ));
        }
        if auth_count.saturating_sub(stored_sign_count) > MAX_SIGN_COUNT_GAP {
            return Err(anyhow!(
                "sign_count gap too large: stored={stored_sign_count}, auth={auth_count}"
            ));
        }
        auth_count
    } else {
        0
    };

    Ok(AssertionOutcome {
        sign_count: new_count,
        user_verified: ad.user_verified(),
        backup_state: ad.backup_state(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expectations(rp_id: &str) -> AssertionExpectations {
        AssertionExpectations {
            rp_id: rp_id.to_string(),
            challenge_b64: "Zm9v".to_string(),
            allowed_origins: vec![format!("https://{rp_id}")],
            require_user_verification: false,
        }
    }

    #[test]
    fn rejects_wrong_rp_id_before_signature_work() {
        // authData built for "a.example" must fail when expectations name
        // "b.example" even with otherwise-valid framing.
        use sha2::{Digest, Sha256};
        let mut auth = Sha256::digest(b"a.example").to_vec();
        auth.push(super::super::auth_data::FLAG_UP);
        auth.extend_from_slice(&1u32.to_be_bytes());
        let cd = br#"{"type":"webauthn.get","challenge":"Zm9v","origin":"https://b.example"}"#;
        let err = verify_assertion(
            b"cred",
            &[0x01], // invalid COSE → would error anyway, but rpIdHash fires first
            0,
            b"cred",
            &auth,
            &[],
            cd,
            &expectations("b.example"),
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("rpIdHash"), "{err:#}");
    }

    #[test]
    fn rejects_empty_credential_ids() {
        use sha2::{Digest, Sha256};
        let mut auth = Sha256::digest(b"a").to_vec();
        auth.push(super::super::auth_data::FLAG_UP);
        auth.extend_from_slice(&0u32.to_be_bytes());
        let err = verify_assertion(
            b"",
            &[0x01],
            0,
            b"",
            &auth,
            &[],
            br#"{"type":"webauthn.get","challenge":"Zm9v","origin":"https://a"}"#,
            &expectations("a"),
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("must not be empty"));
    }
}
