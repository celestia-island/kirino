use anyhow::{anyhow, Result};
use rand::RngExt;
use std::sync::OnceLock;

use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, Params, Version,
};

const ARGON2_M_COST: u32 = 19456;
const ARGON2_T_COST: u32 = 2;
const ARGON2_P_COST: u32 = 1;

/// Length, in characters, of a password minted by [`generate_temporary_password`].
///
/// A bootstrap password is printed to the operator's terminal and travels by eye and
/// clipboard, so it is sized to stay unguessable (4 character classes over 20 slots, never
/// below one character per class) rather than to be memorable.
pub const TEMPORARY_PASSWORD_LEN: usize = 20;

// Bootstrap character pools. Ambiguous glyphs (`I/l/1`, `O/0`) are left out because the
// password is transcribed by hand, and the symbol pool keeps only characters an operator can
// paste without escaping anywhere: no POSIX-shell quoting or expansion ($, backtick, ", ', \, !,
// ~), no globbing (*, ?, [, ]), no redirection or separators (|, &, ;, <, >, (, )), no comment
// introducer (#), no percent escape (%) and no whitespace — and, in URL terms, only unreserved
// (-, _, .) and query-safe sub-delims (=, ,), i.e. neither the userinfo delimiters (:, @) nor
// the form-encoded space (+). The tests in this module pin that invariant down.
const TEMP_UPPER: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ";
const TEMP_LOWER: &[u8] = b"abcdefghijkmnopqrstuvwxyz";
const TEMP_DIGIT: &[u8] = b"23456789";
const TEMP_SYMBOL: &[u8] = b"-_.=,";

/// Generates a random temporary password for a first-run bootstrap.
///
/// The value is drawn from the OS-backed thread RNG on every call — it is never a fixed
/// literal and never derived from a seed the caller could reproduce — and by construction
/// contains at least one uppercase letter, one lowercase letter, one digit and one symbol,
/// so it always satisfies the kernel's password-strength rules
/// ([`validate_password`](crate::service::login::validate_password)).
///
/// Pair it with [`bootstrap_credential`](crate::rbac::policy::bootstrap_credential), which
/// adds the initial-password account state and the one-time operator log line.
#[must_use]
pub fn generate_temporary_password() -> String {
    let mut rng = rand::rng();
    let pools = [TEMP_UPPER, TEMP_LOWER, TEMP_DIGIT, TEMP_SYMBOL];
    let mut chars: Vec<char> = Vec::with_capacity(TEMPORARY_PASSWORD_LEN);

    // One character from every pool first, so each class is guaranteed to be present.
    for pool in pools {
        chars.push(char::from(pool[rng.random_range(0..pool.len())]));
    }

    let all: Vec<u8> = pools.concat();
    while chars.len() < TEMPORARY_PASSWORD_LEN {
        chars.push(char::from(all[rng.random_range(0..all.len())]));
    }

    // Fisher-Yates, so the guaranteed characters are not always in the first four slots.
    for i in (1..chars.len()).rev() {
        let j = rng.random_range(0..=i);
        chars.swap(i, j);
    }

    chars.into_iter().collect()
}

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
    let mut salt_bytes = [0u8; 16];
    rand::rng().fill(&mut salt_bytes);
    let salt =
        SaltString::encode_b64(&salt_bytes).map_err(|e| anyhow!("salt encoding failed: {e}"))?;
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

    /// Characters that make a pasted bootstrap password dangerous or ambiguous in a shell, a
    /// URL or a config file: quoting/expansion, globbing, redirection, command separators,
    /// comments, percent-encoding and whitespace.
    const HOSTILE: &str = "$`\"'\\|&;<>()[]{}*?!~#% \t\n";

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

    #[test]
    fn test_generate_temporary_password_shape() {
        let password = generate_temporary_password();
        assert_eq!(password.chars().count(), TEMPORARY_PASSWORD_LEN);
        assert!(password.chars().any(|c| c.is_ascii_uppercase()));
        assert!(password.chars().any(|c| c.is_ascii_lowercase()));
        assert!(password.chars().any(|c| c.is_ascii_digit()));
        assert!(password.chars().any(|c| c.is_ascii_punctuation()));
    }

    #[test]
    fn test_generate_temporary_password_is_random() {
        let a = generate_temporary_password();
        let b = generate_temporary_password();
        assert_ne!(a, b, "a bootstrap password must never be a fixed literal");
    }

    #[test]
    fn test_generate_temporary_password_stays_pasteable() {
        for _ in 0..64 {
            let password = generate_temporary_password();
            assert!(
                !password.chars().any(|c| HOSTILE.contains(c)),
                "shell/URL metacharacters must not appear in a pasted bootstrap password"
            );
        }
    }

    /// The pools themselves must stay free of paste-hostile characters, so a future edit cannot
    /// reintroduce one that the sampling test above would only catch by luck.
    #[test]
    fn test_generate_temporary_password_pools_are_paste_safe() {
        for pool in [TEMP_UPPER, TEMP_LOWER, TEMP_DIGIT, TEMP_SYMBOL] {
            for &byte in pool {
                assert!(
                    !HOSTILE.contains(char::from(byte)),
                    "character pool contains a paste-hostile character: {:?}",
                    char::from(byte)
                );
            }
        }
    }

    #[test]
    fn test_generate_temporary_password_satisfies_strength_rules() {
        for _ in 0..64 {
            let password = generate_temporary_password();
            assert!(
                crate::service::login::validate_password(&password).is_ok(),
                "generated bootstrap passwords must pass the kernel's strength rules"
            );
        }
    }
}
