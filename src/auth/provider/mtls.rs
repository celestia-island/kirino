//! mTLS: binding a token to a client certificate (RFC 8705).
//!
//! The mutual-TLS counterpart of DPoP. The client presents a certificate at
//! the TLS layer; the provider records its SHA-256 thumbprint in the token's
//! `cnf.x5t#S256`, and every later request must arrive over a connection
//! whose certificate hashes to the same value. No extra header, no proof
//! JWT — the transport IS the proof.
//!
//! # What can go wrong, and what is checked here
//!
//! - **Accepting any certificate.** A resource that terminates TLS accepts
//!   whatever the reverse proxy hands it; the binding is only as strong as
//!   the check that the presented certificate is the one in `cnf`.
//! - **Thumbprinting the wrong bytes.** `x5t#S256` is the SHA-256 of the
//!   **DER** certificate, base64url — not of the PEM text, not of the
//!   subject, not of the public key. Getting this wrong makes every token
//!   unbound and the failure looks like "mTLS is broken", so hosts turn it
//!   off.
//! - **Believing a forwarded header.** A proxy that sets
//!   `X-Client-Cert` and a service that trusts it without verifying the
//!   proxy is no better than a bearer token. This module takes the
//!   ALREADY-EXTRACTED certificate and says so in the type
//!   ([`PresentedCertificate`] carries the DER it was given); whether the
//!   reverse proxy's header can be trusted is the host's decision, and it is
//!   a decision about the proxy, not about this code.
//! - **Self-signed or unvalidated chains.** `x5t#S256` binds to a
//!   certificate, and a certificate is only an identity if someone vouched
//!   for it. [`CertificateBinding::bind`] takes a flag for "the chain was
//!   validated" and refuses to bind otherwise.
//!
//! # What this module does not do
//!
//! It does no X.509 parsing beyond hashing: the host's TLS stack has already
//! parsed the certificate and decided what it means. Here the certificate is
//! bytes, and the only fact taken from it is its thumbprint.

use base64::Engine;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The `cnf` member mTLS-bound tokens carry (RFC 8705 §3.1).
pub const X5T_S256: &str = "x5t#S256";

/// A certificate the transport presented, as DER bytes.
///
/// Constructed only from DER so the thumbprint cannot be taken over PEM
/// text by mistake — that mistake makes every binding fail in a way that
/// looks like "mTLS does not work".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresentedCertificate {
    der: Vec<u8>,
}

impl PresentedCertificate {
    /// Wrap DER bytes.
    #[must_use]
    pub fn from_der(der: impl Into<Vec<u8>>) -> Self {
        Self { der: der.into() }
    }

    /// The DER bytes.
    #[must_use]
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    /// `x5t#S256`: base64url(SHA-256(DER)), as RFC 8705 defines it.
    #[must_use]
    pub fn thumbprint(&self) -> String {
        use sha2::Digest;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(&self.der))
    }
}

/// Why a certificate could not be bound or checked.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum MtlsError {
    /// No certificate on a connection that must carry one.
    #[error("the request presented no client certificate")]
    NoCertificate,
    /// The chain was not validated: an unvouched certificate is not an
    /// identity, and binding to it would bind to an attacker's key.
    #[error("the client certificate's chain was not validated")]
    UnvalidatedChain,
    /// The token carries no `x5t#S256`, so it is a bearer token.
    #[error("the access token carries no mTLS binding")]
    NotBound,
    /// The presented certificate is not the one the token is bound to.
    #[error("the client certificate is not the one this token is bound to")]
    WrongCertificate,
    /// The thumbprint in the token is malformed (not 32 bytes base64url).
    #[error("the token's x5t#S256 is malformed")]
    MalformedThumbprint,
}

/// A validated binding: the certificate the token was issued to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateBinding {
    thumbprint: String,
}

impl CertificateBinding {
    /// Bind a token to `certificate`, refusing an unvalidated chain.
    ///
    /// # Errors
    ///
    /// [`MtlsError::UnvalidatedChain`] when `chain_validated` is false — the
    /// caller must have established that the certificate is who it claims,
    /// which this module cannot do.
    pub fn bind(
        certificate: &PresentedCertificate,
        chain_validated: bool,
    ) -> Result<Self, MtlsError> {
        if !chain_validated {
            return Err(MtlsError::UnvalidatedChain);
        }
        Ok(Self {
            thumbprint: certificate.thumbprint(),
        })
    }

    /// The `x5t#S256` value to put in the token's `cnf`.
    #[must_use]
    pub fn thumbprint(&self) -> &str {
        &self.thumbprint
    }
}

/// Check a token's `cnf.x5t#S256` against the certificate on THIS connection.
///
/// # Errors
///
/// - [`MtlsError::NoCertificate`] when `presented` is `None` — a token
///   bound to a certificate cannot be used over a connection without one;
/// - [`MtlsError::NotBound`] when the token has no `x5t#S256` (a bearer
///   token at an mTLS-only resource);
/// - [`MtlsError::MalformedThumbprint`] when the claim is not 32 bytes of
///   base64url;
/// - [`MtlsError::WrongCertificate`] when it is a different certificate.
pub fn check_binding(
    token_thumbprint: Option<&str>,
    presented: Option<&PresentedCertificate>,
) -> Result<(), MtlsError> {
    let Some(bound) = token_thumbprint else {
        // A bearer token at an mTLS resource: refusing is the whole point.
        return Err(MtlsError::NotBound);
    };
    // The claim has to look like a thumbprint before it is compared, so a
    // hand-edited token cannot match by accident.
    if !is_thumbprint_shaped(bound) {
        return Err(MtlsError::MalformedThumbprint);
    }
    let Some(cert) = presented else {
        return Err(MtlsError::NoCertificate);
    };
    if cert.thumbprint() != bound {
        return Err(MtlsError::WrongCertificate);
    }
    Ok(())
}

fn is_thumbprint_shaped(value: &str) -> bool {
    // 32 bytes base64url without padding is 43 characters, and the alphabet
    // excludes `+`, `/` and `=`. Checking the length alone would accept
    // "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".
    value.len() == 43
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// The `cnf` claim an mTLS-bound token carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateConfirmation {
    /// `x5t#S256`: base64url(SHA-256(DER certificate)).
    #[serde(rename = "x5t#S256")]
    pub x5t_s256: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cert(seed: u8) -> PresentedCertificate {
        // Not a real certificate — the module only ever hashes the bytes, so
        // any DER-shaped blob exercises the same path.
        PresentedCertificate::from_der(vec![0x30, 0x82, seed, 0x01, seed, seed])
    }

    #[test]
    fn the_thumbprint_is_base64url_of_the_der_hash() {
        let c = cert(1);
        let t = c.thumbprint();
        assert_eq!(t.len(), 43, "32 bytes base64url");
        assert!(!t.contains('=') && !t.contains('+') && !t.contains('/'));
        assert_ne!(t, cert(2).thumbprint());
        // The DER, not the PEM text: hashing the same bytes must repeat.
        assert_eq!(
            t,
            PresentedCertificate::from_der(c.der().to_vec()).thumbprint()
        );
    }

    #[test]
    fn an_unvalidated_chain_cannot_be_bound() {
        // MUT:bind-unvalidated — dropping this check binds a token to
        // whatever certificate an attacker presents.
        assert_eq!(
            CertificateBinding::bind(&cert(1), false).unwrap_err(),
            MtlsError::UnvalidatedChain
        );
        let b = CertificateBinding::bind(&cert(1), true).unwrap();
        assert_eq!(b.thumbprint(), cert(1).thumbprint());
    }

    #[test]
    fn a_bearer_token_is_refused_at_an_mtls_resource() {
        // MUT:not-bound-accepted — returning Ok lets a stolen bearer token
        // through an mTLS-only resource.
        assert_eq!(
            check_binding(None, Some(&cert(1))).unwrap_err(),
            MtlsError::NotBound
        );
    }

    #[test]
    fn no_certificate_means_no_service() {
        let bound = cert(1).thumbprint();
        // MUT:no-cert-accepted — a token bound to a certificate must not work
        // over a connection without one.
        assert_eq!(
            check_binding(Some(&bound), None).unwrap_err(),
            MtlsError::NoCertificate
        );
    }

    #[test]
    fn a_different_certificate_is_refused() {
        let bound = cert(1).thumbprint();
        assert_eq!(
            check_binding(Some(&bound), Some(&cert(2))).unwrap_err(),
            MtlsError::WrongCertificate
        );
    }

    #[test]
    fn a_malformed_thumbprint_is_refused_before_it_is_compared() {
        for bad in [
            "",
            "short",
            &"a".repeat(44),
            &"a".repeat(42),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa+a",
        ] {
            assert_eq!(
                check_binding(Some(bad), Some(&cert(1))).unwrap_err(),
                MtlsError::MalformedThumbprint,
                "{bad:?}"
            );
        }
    }

    #[test]
    fn the_happy_path_binds_certificate_to_token() {
        let binding = CertificateBinding::bind(&cert(7), true).unwrap();
        check_binding(Some(binding.thumbprint()), Some(&cert(7))).expect("same certificate");
    }
}
