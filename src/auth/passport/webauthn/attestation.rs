//! Registration ceremony verification — attestation object handling
//! (W3C L2 §7.1) under an explicit **none-attestation policy**.
//!
//! Relying parties in the passkey model ("user-verifying platform
//! authenticators, synced") receive `fmt == "none"` from virtually all
//! modern authenticators (iCloud Keychain, Google Password Manager, Windows
//! Hello, 1Password). kirino keeps no trust-anchor store, so this module:
//!
//! * fully parses the `attestationObject` CBOR structure,
//! * enforces `fmt == "none"` **and** an empty `attStmt` map (anything else
//!   is rejected rather than silently treated as unverified),
//! * delegates structural parsing of the embedded `authData` to
//!   [`super::auth_data::AuthenticatorData`],
//! * hands back the credential id + COSE public key for storage.

use super::auth_data::{AuthenticatorData, FLAG_AT};
use anyhow::{anyhow, Result};
use coset::{cbor::value::Value, CborSerializable, CoseKey};

/// A verified registration's useful outputs.
#[derive(Debug, Clone)]
pub struct AttestedCredential {
    /// The credential id exactly as the authenticator produced it.
    pub credential_id: Vec<u8>,
    /// COSE key serialization of the credential public key.
    pub public_key_cose: Vec<u8>,
    /// Authenticator AAGUID (16 bytes; all-zero = no specific model).
    pub aaguid: [u8; 16],
    /// Backup-eligible flag (BE) read from the registration authData.
    pub backup_eligible: bool,
    /// Backup-state flag (BS) read from the registration authData.
    pub backup_state: bool,
}

impl RegistrationOutputs {
    /// Initial signCount as embedded in the registration authData (§6.4.1:
    /// platforms may already use a nonzero counter). Persisting this —
    /// instead of assuming 0 — keeps roaming authenticators with high
    /// counters from tripping the assertion gap check.
    #[must_use]
    pub fn initial_sign_count(&self) -> u32 {
        self.sign_count
    }
}

/// Outcome of a full registration check. Owns its data — safe to store or
/// ship across await points / threads by the HTTP layer above kirino.
pub struct RegistrationOutputs {
    /// SHA-256 of the RP ID as embedded in the (already validated) authData.
    pub rp_id_hash: [u8; 32],
    pub credential: AttestedCredential,
    /// Sign counter embedded in the registration authData. Store it —
    /// starting from 0 is only valid when the authenticator reported 0.
    pub sign_count: u32,
}

/// Verify an `attestationObject` under none-policy.
///
/// `client_data` must have passed
/// [`super::client_data::ClientData::verify_expectations`] with
/// `webauthn.create`; its challenge is re-checked here against the
/// attestation's own authData when extensions bind it, and the pair must
/// come from the same ceremony response. With `fmt=none` nothing but
/// authData is signed, so challenge/origin policy remains the caller's —
/// enforced in kirino only through [`wa::WebAuthnChallengeStore`] wiring.
///
/// `rp_id` is the RP ID this ceremony was issued for — its SHA-256 **must**
/// equal the authData rpIdHash (§7.1 step 9) or registration is rejected,
/// so credentials can never be stored under a foreign RP binding.
///
/// # Errors
///
/// Errors on malformed CBOR, non-`none` formats, non-empty statements,
/// rpIdHash mismatch, missing AT flag/credential data, or unsupported key
/// material.
pub fn verify_attestation_none(
    attestation_object: &[u8],
    _client_data: &super::client_data::ClientData,
    rp_id: &str,
) -> Result<RegistrationOutputs> {
    use sha2::{Digest, Sha256};

    let (fmt, auth_data_bytes) = parse_attestation_object(attestation_object)?;
    if fmt != "none" {
        return Err(anyhow!(
            "unsupported attestation format {fmt:?} (policy: none)"
        ));
    }

    let ad = AuthenticatorData::parse(&auth_data_bytes)?;
    if !ad.user_present() {
        return Err(anyhow!("UP flag not set at registration"));
    }
    // §7.1 step 9 — enforced, not merely returned.
    let expected_hash = Sha256::digest(rp_id.as_bytes());
    if ad.rp_id_hash() != expected_hash.as_slice() {
        return Err(anyhow!("rpIdHash mismatch for RP {rp_id:?}"));
    }
    if ad.flags() & FLAG_AT == 0 || ad.attested_credential_data().is_none() {
        return Err(anyhow!("AT flag not set or credential data missing"));
    }
    let attested = ad
        .attested_credential_data()
        .expect("checked directly above");

    // The real COSE decode — validates the slice our header walk located and
    // fails fast on algorithms the assertion verifier cannot check later.
    let cose = CoseKey::from_slice(attested.credential_public_key_cbor)
        .map_err(|e| anyhow!("credential public key CBOR invalid: {e:?}"))?;
    super::assertion_legacy::validate_supported_key(&cose)?;

    let mut rp_id_hash = [0u8; 32];
    rp_id_hash.copy_from_slice(ad.rp_id_hash());

    Ok(RegistrationOutputs {
        rp_id_hash,
        sign_count: ad.sign_count(),
        credential: AttestedCredential {
            credential_id: attested.credential_id.to_vec(),
            public_key_cose: attested.credential_public_key_cbor.to_vec(),
            aaguid: attested.aaguid,
            backup_eligible: ad.backup_eligible(),
            backup_state: ad.backup_state(),
        },
    })
}

/// Split `attestationObject` into `(fmt, authData)` enforcing empty `attStmt`.
fn parse_attestation_object(bytes: &[u8]) -> Result<(String, Vec<u8>)> {
    let value = coset::cbor::from_reader(bytes)
        .map_err(|e| anyhow!("attestationObject CBOR invalid: {e:?}"))?;
    let Value::Map(map) = value else {
        return Err(anyhow!("attestationObject is not a CBOR map"));
    };

    let mut fmt: Option<String> = None;
    let mut auth_data: Option<Vec<u8>> = None;
    let mut att_stmt_seen_empty = false;

    for (k, v) in map {
        let Some(field) = k.as_text() else {
            return Err(anyhow!("non-text map key in attestationObject"));
        };
        match field {
            "fmt" => {
                let Value::Text(f) = v else {
                    return Err(anyhow!("fmt must be text"));
                };
                fmt = Some(f);
            }
            "attStmt" => match &v {
                Value::Map(m) if m.is_empty() => att_stmt_seen_empty = true,
                _ => return Err(anyhow!("attStmt must be an empty map for fmt=none")),
            },
            "authData" => {
                let Value::Bytes(b) = v else {
                    return Err(anyhow!("authData must be bytes"));
                };
                auth_data = Some(b);
            }
            _ => {}
        }
    }

    match (fmt, att_stmt_seen_empty, auth_data) {
        (Some(fmt), true, Some(auth_data)) => Ok((fmt, auth_data)),
        (_, false, _) => Err(anyhow!("missing or non-empty attStmt for fmt=none")),
        (None, _, _) => Err(anyhow!("missing fmt")),
        (_, _, None) => Err(anyhow!("missing authData")),
    }
}
