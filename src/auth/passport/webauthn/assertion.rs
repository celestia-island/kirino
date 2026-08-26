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
//! signed data).

use super::auth_data::AuthenticatorData;
use super::client_data::{ClientData, TYPE_GET};
use anyhow::{anyhow, Result};
use p256::ecdsa::signature::Verifier;
use sha2::{Digest, Sha256};

/// Policy applied to an assertion before accepting it.
#[derive(Debug, Clone)]
pub struct AssertionExpectations {
    /// Exact base64url challenge as issued for this ceremony.
    pub challenge_b64: String,
    /// Origin allowlist (scheme + host [+ port]), lowercased by convention.
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
/// mismatch, missing UP/UV, credential-id mismatch, signature failure or
/// counter regression.
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

    // --- credential id (constant-time) ----------------------------------
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
