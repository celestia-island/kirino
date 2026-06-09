use anyhow::{anyhow, Result};

use crate::utils::base64;

/// Reference certificate authority verifier.
///
/// # Security Warning
///
/// This implementation only checks PEM envelope format and minimum data length.
/// It does **not** verify the certificate chain, signature, expiry, or
/// revocation status. The `subject` and `issuer` fields are extracted from raw
/// bytes and will contain nonsensical data for real certificates.
/// **Do not use in production.** Replace with a proper X.509 verification
/// library (e.g. `x509-parser` + `rustls`/`openssl`).
pub struct CertificateAuthorityVerifier;

impl CertificateAuthorityVerifier {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    pub fn verify_certificate(&self, cert_pem: &str) -> Result<CertificateInfo> {
        if cert_pem.is_empty() {
            return Err(anyhow!("empty certificate"));
        }

        let pem = cert_pem.trim();
        if !pem.starts_with("-----BEGIN CERTIFICATE-----") {
            return Err(anyhow!("not a PEM certificate"));
        }
        if !pem.contains("-----END CERTIFICATE-----") {
            return Err(anyhow!("incomplete PEM certificate"));
        }

        let b64_body = pem
            .trim_start_matches("-----BEGIN CERTIFICATE-----")
            .trim_end_matches("-----END CERTIFICATE-----")
            .trim();

        let decoded = base64::decode(b64_body);
        if decoded.len() < 32 {
            return Err(anyhow!("certificate data too short"));
        }

        Ok(CertificateInfo {
            subject: extract_subject(&decoded),
            issuer: extract_issuer(&decoded),
            is_valid: true,
        })
    }
}

fn extract_subject(data: &[u8]) -> String {
    let len = data.len().min(64);
    let subset = &data[..len];
    subset
        .iter()
        .filter(|&&b| b.is_ascii_graphic() || b == b' ')
        .map(|&b| b as char)
        .collect::<String>()
        .trim()
        .to_string()
}

fn extract_issuer(data: &[u8]) -> String {
    let start = data.len().saturating_sub(64);
    let subset = &data[start..];
    subset
        .iter()
        .filter(|&&b| b.is_ascii_graphic() || b == b' ')
        .map(|&b| b as char)
        .collect::<String>()
        .trim()
        .to_string()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_cert() {
        let v = CertificateAuthorityVerifier::new();
        assert!(v.verify_certificate("").is_err());
    }

    #[test]
    fn test_invalid_format() {
        let v = CertificateAuthorityVerifier::new();
        assert!(v.verify_certificate("not a cert").is_err());
    }

    #[test]
    fn test_minimal_pem() {
        let v = CertificateAuthorityVerifier::new();
        let body = standard_base64_encode(&[0x30; 64]);
        let pem = format!("-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----");
        let info = v.verify_certificate(&pem).unwrap();
        assert!(info.is_valid);
    }

    #[test]
    fn test_too_short_cert() {
        let v = CertificateAuthorityVerifier::new();
        let body = standard_base64_encode(&[0x30; 16]);
        let pem = format!("-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----");
        assert!(v.verify_certificate(&pem).is_err());
    }

    #[test]
    fn test_missing_end_marker() {
        let v = CertificateAuthorityVerifier::new();
        let body = standard_base64_encode(&[0x30; 64]);
        let pem = format!("-----BEGIN CERTIFICATE-----\n{body}");
        assert!(v.verify_certificate(&pem).is_err());
    }

    fn standard_base64_encode(data: &[u8]) -> String {
        const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut result = String::new();
        for chunk in data.chunks(3) {
            let b0 = chunk[0] as u32;
            let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
            let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
            let triple = (b0 << 16) | (b1 << 8) | b2;
            result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
            result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
            if chunk.len() > 1 {
                result.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
            } else {
                result.push('=');
            }
            if chunk.len() > 2 {
                result.push(CHARS[(triple & 0x3F) as usize] as char);
            } else {
                result.push('=');
            }
        }
        result
    }
}
