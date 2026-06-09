#![allow(missing_docs)]
#![allow(clippy::missing_errors_doc)]

use anyhow::Result;

pub struct CertificateAuthorityVerifier;

impl CertificateAuthorityVerifier {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    pub fn verify_certificate(&self, _cert_pem: &str) -> Result<CertificateInfo> {
        unimplemented!("X.509 certificate verification")
    }
}

impl Default for CertificateAuthorityVerifier {
    fn default() -> Self {
        Self::new()
    }
}

pub struct CertificateInfo {
    pub subject: String,
    pub issuer: String,
    pub is_valid: bool,
}
