//! `clientDataJSON` parsing and expectation checking (W3C L2 §5.8.1).
//!
//! The verifier owns parsing: callers hand over the raw bytes handed up by
//! the browser, and receive back exactly what the ceremony contract needs —
//! type, challenge, origin. `crossOrigin` and token binding are observed but
//! not policy-enforced here beyond rejecting cross-origin ceremonies.

use anyhow::{anyhow, Result};
use serde::Deserialize;

/// The two ceremony types a relying party can receive.
pub const TYPE_CREATE: &str = "webauthn.create";
pub const TYPE_GET: &str = "webauthn.get";

/// Parsed `clientDataJSON`.
#[derive(Debug, Clone, Deserialize)]
pub struct ClientData {
    #[serde(rename = "type")]
    pub typ: String,
    pub challenge: String,
    pub origin: String,
    #[serde(default)]
    pub cross_origin: bool,
}

impl ClientData {
    /// Parse raw `clientDataJSON` bytes.
    ///
    /// # Errors
    ///
    /// Errors when the payload is not valid JSON or missing required fields.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes).map_err(|e| anyhow!("invalid clientDataJSON: {e}"))
    }

    /// Enforce ceremony expectations: exact type match, challenge equality
    /// (decoded-byte compare, padding-tolerant), same-origin (ASCII
    /// case-insensitive per RFC 6454 serialization), no cross-origin flag.
    ///
    /// # Errors
    ///
    /// Returns an error on any mismatched expectation.
    pub fn verify_expectations(
        &self,
        expected_type: &str,
        expected_challenge_b64: &str,
        allowed_origins: &[String],
    ) -> Result<()> {
        use super::challenge::base64url_decode;

        if self.typ != expected_type {
            return Err(anyhow!(
                "clientData type mismatch: expected {expected_type}, got {}",
                self.typ
            ));
        }
        // Byte-wise compare so unpadded/padded serializations of the same
        // challenge bytes both match; browsers emit unpadded per §4.2.
        let issued = base64url_decode(expected_challenge_b64)
            .map_err(|_| anyhow!("issued challenge is not valid base64url"))?;
        let presented = base64url_decode(&self.challenge)
            .map_err(|_| anyhow!("presented challenge is not valid base64url"))?;
        if !crate::utils::constant_time_eq(&issued, &presented) {
            return Err(anyhow!("clientData challenge mismatch"));
        }
        if self.cross_origin {
            return Err(anyhow!("cross_origin ceremonies are not accepted"));
        }
        // Origins serialize lowercase; normalize both sides to stay
        // forgiving of uppercase config entries (the values are public —
        // a non-constant-time compare is fine).
        let origin = self.origin.to_ascii_lowercase();
        if !allowed_origins
            .iter()
            .any(|o| o.to_ascii_lowercase() == origin)
        {
            return Err(anyhow!("origin {:?} not in allowlist", self.origin));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(challenge: &str, origin: &str) -> Vec<u8> {
        format!(
            r#"{{"type":"webauthn.create","challenge":"{challenge}","origin":"{origin}","crossOrigin":false}}"#
        )
        .into_bytes()
    }

    #[test]
    fn parses_minimal_payload() {
        let cd = ClientData::parse(&sample("abc", "https://a.example")).unwrap();
        assert_eq!(cd.typ, "webauthn.create");
        assert_eq!(cd.challenge, "abc");
        assert_eq!(cd.origin, "https://a.example");
        assert!(!cd.cross_origin);
    }

    #[test]
    fn rejects_type_mismatch() {
        let cd = ClientData::parse(&sample("abc", "https://a.example")).unwrap();
        assert!(cd
            .verify_expectations(TYPE_GET, "abc", &["https://a.example".into()])
            .is_err());
    }

    #[test]
    fn rejects_wrong_challenge() {
        let cd = ClientData::parse(&sample("abc", "https://a.example")).unwrap();
        assert!(cd
            .verify_expectations(TYPE_CREATE, "xyz", &["https://a.example".into()])
            .is_err());
    }

    #[test]
    fn rejects_unlisted_origin() {
        let cd = ClientData::parse(&sample("abc", "https://evil.example")).unwrap();
        assert!(cd
            .verify_expectations(TYPE_CREATE, "abc", &["https://a.example".into()])
            .is_err());
    }

    #[test]
    fn accepts_matching_expectations() {
        let cd = ClientData::parse(&sample("abc", "https://a.example")).unwrap();
        assert!(cd
            .verify_expectations(
                TYPE_CREATE,
                "abc",
                &["https://other.example".into(), "https://a.example".into()]
            )
            .is_ok());
    }
}
