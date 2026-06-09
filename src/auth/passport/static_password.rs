use anyhow::{anyhow, Result};
use rand::rngs::OsRng;
use std::sync::OnceLock;

use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, Params, Version,
};

const ARGON2_M_COST: u32 = 19456;
const ARGON2_T_COST: u32 = 2;
const ARGON2_P_COST: u32 = 1;

fn argon2_instance() -> &'static Argon2<'static> {
    static INSTANCE: OnceLock<Argon2<'static>> = OnceLock::new();
    INSTANCE.get_or_init(|| {
        let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, None)
            .expect("hardcoded Argon2 parameters are valid by construction");
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
    })
}

/// Hashes a password using Argon2id.
///
/// # Errors
///
/// Returns an error if the Argon2 hashing fails (e.g. password exceeds
/// Argon2's internal limits, which is unlikely in practice).
pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = argon2_instance()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow!("password hash failed: {e}"))?;
    Ok(hash.to_string())
}

/// Verifies a password against an Argon2id hash string.
///
/// # Errors
///
/// Returns an error if `hash` is not a valid PHC hash string.
pub fn verify_password(password: &str, hash: &str) -> Result<bool> {
    let parsed = PasswordHash::new(hash).map_err(|e| anyhow!("invalid hash format: {e}"))?;
    Ok(argon2_instance()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_and_verify() {
        let hash = hash_password("test123").unwrap();
        assert!(verify_password("test123", &hash).unwrap());
        assert!(!verify_password("wrong", &hash).unwrap());
    }

    #[test]
    fn test_hash_uniqueness() {
        let h1 = hash_password("same-password").unwrap();
        let h2 = hash_password("same-password").unwrap();
        assert_ne!(h1, h2, "same password should produce different hashes");
        assert!(verify_password("same-password", &h1).unwrap());
        assert!(verify_password("same-password", &h2).unwrap());
    }

    #[test]
    fn test_invalid_hash_format() {
        assert!(verify_password("anything", "not-a-valid-phc-hash").is_err());
        assert!(verify_password("anything", "").is_err());
    }

    #[test]
    fn test_empty_password() {
        let hash = hash_password("").unwrap();
        assert!(verify_password("", &hash).unwrap());
        assert!(!verify_password("x", &hash).unwrap());
    }

    #[test]
    fn test_unicode_password() {
        let hash = hash_password("密码🔑安全123!aA").unwrap();
        assert!(verify_password("密码🔑安全123!aA", &hash).unwrap());
        assert!(!verify_password("密码🔑安全123!aB", &hash).unwrap());
    }
}
