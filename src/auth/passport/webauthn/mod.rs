//! WebAuthn (passkey) ceremony support — W3C Web Authentication L2.
//!
//! Split:
//!
//! * [`auth_data`] — `authenticatorData` structural parser (rpIdHash, flags,
//!   sign counter, attested credential data);
//! * [`client_data`] — `clientDataJSON` parser + expectation checks;
//! * [`challenge`] — single-use server-side challenge store;
//! * [`attestation`] — registration verification under a strict
//!   none-attestation policy;
//! * [`assertion`] — full §7.2 login verification (the entry point new code
//!   should use);
//! * [`assertion_legacy`] — the 0.6-era verifier kept for API compatibility,
//!   plus shared COSE key helpers.
//!
//! All of this is gated behind the `auth-webauthn` feature.

pub mod assertion;
pub mod assertion_legacy;
pub mod auth_data;
pub mod challenge;
pub mod client_data;

#[cfg(feature = "auth-webauthn")]
pub mod attestation;

pub use assertion::{verify_assertion, AssertionExpectations, AssertionOutcome};
#[cfg(feature = "auth-webauthn")]
pub use assertion_legacy::{key_from_cose, validate_supported_key, WebAuthnVerifier};
#[cfg(feature = "auth-webauthn")]
pub use attestation::{verify_attestation_none, AttestedCredential, RegistrationOutputs};
pub use auth_data::AuthenticatorData;
pub use challenge::{
    base64url_decode, base64url_encode, ChallengePurpose, WebAuthnChallengeError,
    WebAuthnChallengeStore,
};
pub use client_data::ClientData;

#[cfg(test)]
mod tests {
    use super::*;

    /// End-to-end synthetic ceremony: register with a hand-built attestation
    /// object, then authenticate with an assertion over it.
    #[test]
    fn full_ceremony_roundtrip() {
        use coset::CborSerializable;
        use coset::CoseKeyBuilder;
        use p256::ecdsa::{signature::Signer, SigningKey};
        use p256::elliptic_curve::Generate;
        use sha2::{Digest, Sha256};

        let rp_id = "celestia.world";
        let origin = "https://app.celestia.world";
        let challenge = "c3RhdGljLXN0cmluZw"; // arbitrary b64url

        // --- authenticator secrets -------------------------------------
        let signing_key = SigningKey::generate();
        let vk_bytes = signing_key.verifying_key().to_sec1_bytes().to_vec();
        let (x, y) = (&vk_bytes[1..33], &vk_bytes[33..65]);
        let cose_key = CoseKeyBuilder::new_ec2_pub_key(
            coset::iana::EllipticCurve::P_256,
            x.to_vec(),
            y.to_vec(),
        )
        .algorithm(coset::iana::Algorithm::ES256)
        .build();
        let cose_bytes = cose_key.to_vec().unwrap();

        let credential_id = b"cred-0123456789".to_vec();

        // --- registration authData --------------------------------------
        let mut reg_auth = build_auth_data(rp_id, true, 0);
        // set AT flag + append attested credential data
        let last = reg_auth.len() - 5; // flags byte position
        reg_auth[last] |= auth_data::FLAG_AT;
        reg_auth.extend_from_slice(&[0u8; 16]); // AAGUID zero
        reg_auth.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
        reg_auth.extend_from_slice(&credential_id);
        reg_auth.extend_from_slice(&cose_bytes);

        let client_data_json = format!(
            r#"{{"type":"webauthn.create","challenge":"{challenge}","origin":"{origin}","crossOrigin":false}}"#
        );
        let cd_create = ClientData::parse(client_data_json.as_bytes()).unwrap();
        cd_create
            .verify_expectations(client_data::TYPE_CREATE, challenge, &[origin.to_string()])
            .unwrap();

        // Assemble attestationObject CBOR: { "fmt": "none", "attStmt": {},
        // "authData": bstr } using coset's cbor writer for exactness.
        let mut map = coset::cbor::value::Value::Map(vec![
            (
                coset::cbor::value::Value::Text("fmt".into()),
                coset::cbor::value::Value::Text("none".into()),
            ),
            (
                coset::cbor::value::Value::Text("attStmt".into()),
                coset::cbor::value::Value::Map(vec![]),
            ),
            (
                coset::cbor::value::Value::Text("authData".into()),
                coset::cbor::value::Value::Bytes(reg_auth.clone()),
            ),
        ]);
        if let coset::cbor::value::Value::Map(ref mut m) = map {
            m.reverse(); // canonical order not required by our parser
        }
        let att_obj = serialize_cbor_value(&map);

        let outputs = attestation::verify_attestation_none(&att_obj, &cd_create)
            .expect("registration verifies");
        assert_eq!(outputs.credential.credential_id, credential_id);
        assert_eq!(outputs.credential.public_key_cose, cose_bytes);
        assert_eq!(
            outputs.rp_id_hash,
            Sha256::digest(rp_id.as_bytes()).as_slice()
        );

        // --- assertion (login) ------------------------------------------
        let login_auth = build_auth_data(rp_id, false, 42); // UP only
        let cd_get_json =
            format!(r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"{origin}"}}"#);
        let sig_input: Vec<u8> = login_auth
            .iter()
            .chain(Sha256::digest(cd_get_json.as_bytes()).iter())
            .cloned()
            .collect();
        let signature: p256::ecdsa::Signature = signing_key.sign(&sig_input);

        let expectations = AssertionExpectations {
            challenge_b64: challenge.to_string(),
            allowed_origins: vec![origin.to_string()],
            require_user_verification: false,
        };
        let outcome = verify_assertion(
            &outputs.credential.credential_id,
            &outputs.credential.public_key_cose,
            0,
            &credential_id,
            &login_auth,
            &signature.to_der().to_bytes(),
            cd_get_json.as_bytes(),
            &expectations,
        )
        .expect("assertion verifies");
        assert_eq!(outcome.sign_count, 42);
        // build_auth_data sets UP|UV, so the read-back must agree.
        assert!(outcome.user_verified);

        // Tampered authData must fail (signature covers raw bytes).
        let mut tampered = login_auth.clone();
        tampered[33] ^= 0x01;
        assert!(verify_assertion(
            &outputs.credential.credential_id,
            &outputs.credential.public_key_cose,
            42,
            &credential_id,
            &tampered,
            &signature.to_der().to_bytes(),
            cd_get_json.as_bytes(),
            &expectations,
        )
        .is_err());
    }

    fn build_auth_data(rp_id: &str, include_at_placeholder: bool, count: u32) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let _ = include_at_placeholder;
        let mut v = Sha256::digest(rp_id.as_bytes()).to_vec();
        v.push(auth_data::FLAG_UP | auth_data::FLAG_UV);
        v.extend_from_slice(&count.to_be_bytes());
        v
    }

    fn serialize_cbor_value(v: &coset::cbor::value::Value) -> Vec<u8> {
        let mut buf = Vec::new();
        coset::cbor::into_writer(v, &mut buf).expect("CBOR serialization cannot fail here");
        buf
    }
}
