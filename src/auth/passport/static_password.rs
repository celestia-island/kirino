use anyhow::{anyhow, Result};
use rand::rngs::OsRng;

use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, Params, Version,
};

const ARGON2_M_COST: u32 = 19456;
const ARGON2_T_COST: u32 = 2;
const ARGON2_P_COST: u32 = 1;

fn argon2_instance() -> Argon2<'static> {
    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, None)
        .expect("hardcoded Argon2 parameters are valid by construction");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
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
}
