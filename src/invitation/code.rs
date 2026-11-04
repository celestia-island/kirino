//! Unambiguous human-typed invitation codes (Crockford Base32 subset).
//!
//! Invitation links already carry a 256-bit secret token
//! ([`generate_token`](crate::invitation::generate_token)); an invite code is
//! a SECOND, human-handled factor: the admin reads it aloud / prints it and
//! the invitee types it back at accept time. That role demands a very
//! different alphabet from machine tokens:
//!
//! - **32 characters = 2^5**, so indexing with `byte & 31` is exactly
//!   unbiased (any other alphabet size would need rejection sampling);
//! - the visually confusable pairs are excluded outright (`I` `L` `O` `U`)
//!   and their hand-typed look-alikes normalize INTO the alphabet
//!   (`i`/`l` → `1`, `o` → `0`, `u` → `v`) instead of failing;
//! - separators (spaces, `-`, `_`) are stripped, so a code copied out of a
//!   grouped rendering (`ABCD-2345`) verifies unchanged.
//!
//! Eight characters ≈ 32^8 ≈ 1.1e12 candidates — meaningless against the
//! token but ample for a rate-limited secondary check, which is the intended
//! shape: the acceptance endpoint still requires the link's token, the code
//! only gates it.
//!
//! The alphabet is the Crockford Base32 set
//! (`0123456789ABCDEFGHJKMNPQRSTVWXYZ`); [`normalize_code`] implements the
//! classic Crockford confusable mapping so printed and hand-typed forms of
//! the same code agree.

use crate::utils::constant_time_eq;

/// The Crockford Base32 alphabet — 32 characters, no `I`/`L`/`O`/`U`.
pub const CODE_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Generate a random code of `len` characters from [`CODE_ALPHABET`].
///
/// Drawn from the OS-backed thread RNG via an unbiased `& 31` index (the
/// alphabet size is a power of two, so no rejection sampling is needed).
/// Callers should use `len >= 8`; shorter codes are linearly weaker and
/// `len == 0` yields the empty string.
#[must_use]
pub fn generate_code(len: usize) -> String {
    let mut bytes = vec![0u8; len];
    rand::RngExt::fill(&mut rand::rng(), &mut bytes);
    bytes
        .iter()
        .map(|b| CODE_ALPHABET[(b & 31) as usize] as char)
        .collect()
}

/// Normalize a hand-typed code into its canonical stored form.
///
/// Strips whitespace and `-`/`_` separators, uppercases, and applies the
/// Crockford confusable mapping (`i`/`l` → `1`, `o` → `0`, `u` → `v`).
/// Non-ASCII input passes through unchanged and simply never matches.
#[must_use]
pub fn normalize_code(raw: &str) -> String {
    raw.chars()
        .filter(|c| !c.is_whitespace() && *c != '-' && *c != '_')
        .map(|c| match c {
            'i' | 'I' | 'l' | 'L' => '1',
            'o' | 'O' => '0',
            'u' | 'U' => 'V',
            other => other.to_ascii_uppercase(),
        })
        .collect()
}

/// Check a hand-typed code against its canonical stored form.
///
/// Normalizes `raw` first, so `abcd-2345`, `ABCD 2345` and `ABCD2345` all
/// verify against the same expected value. Comparison is constant time
/// ([`constant_time_eq`](crate::utils::constant_time_eq)) — the code rides
/// alongside a secret token and must not become a length/prefix oracle.
#[must_use]
pub fn verify_code(raw: &str, expected: &str) -> bool {
    let candidate = normalize_code(raw);
    constant_time_eq(candidate.as_bytes(), expected.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn generated_codes_stay_inside_the_alphabet() {
        // Coverage assertion: with 2000 codes × 8 chars each, a 32-character
        // alphabet has probability (31/32)^16000 ≈ e^-500 of missing some
        // char — so this ALSO kills an index-truncation mutation (& 7 would
        // light up only the first 8 alphabet chars and fail here).
        let mut seen = [false; 32];
        for _ in 0..2000 {
            let code = generate_code(8);
            assert_eq!(code.len(), 8);
            for ch in code.chars() {
                assert!(
                    CODE_ALPHABET.contains(&(ch as u8)),
                    "char {ch} escaped the alphabet"
                );
                seen[CODE_ALPHABET
                    .iter()
                    .position(|&a| a == ch as u8)
                    .expect("in alphabet")] = true;
            }
        }
        assert!(
            seen.iter().all(|s| *s),
            "2000 codes must cover every alphabet char: {:?}",
            CODE_ALPHABET
                .iter()
                .zip(seen)
                .filter(|(_, s)| !s)
                .map(|(a, _)| *a as char)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn ten_thousand_eight_char_codes_are_all_distinct() {
        let seen: HashSet<String> = (0..10_000).map(|_| generate_code(8)).collect();
        assert_eq!(seen.len(), 10_000);
    }

    #[test]
    fn zero_length_yields_the_empty_string() {
        assert_eq!(generate_code(0), "");
    }

    #[test]
    fn normalization_strips_separators_and_maps_confusables() {
        assert_eq!(normalize_code("ab cd-12"), "ABCD12");
        assert_eq!(normalize_code("iLlO"), "1110");
        assert_eq!(normalize_code("uU"), "VV");
        assert_eq!(normalize_code("a_b-c"), "ABC");
        assert_eq!(normalize_code(""), "");
    }

    #[test]
    fn verification_accepts_hand_typed_variants_of_the_same_code() {
        let code = generate_code(8);
        assert!(verify_code(&code, &code));
        assert!(verify_code(&code.to_lowercase(), &code));
        let spaced: String = code
            .chars()
            .enumerate()
            .flat_map(|(i, c)| if i == 4 { vec!['-', c] } else { vec![c] })
            .collect();
        assert!(verify_code(&spaced, &code));
    }

    #[test]
    fn verification_refuses_wrong_or_empty_codes() {
        let code = generate_code(8);
        let mut tampered = code.clone();
        tampered.replace_range(0..1, "Z");
        assert!(!verify_code(&tampered, &code));
        assert!(!verify_code("", &code));
        assert!(!verify_code(&code, ""));
    }

    #[test]
    fn roundtrip_generation_to_verification() {
        for _ in 0..100 {
            let code = generate_code(8);
            // normalize must be the identity on generated (already
            // canonical) codes — anything else would break the
            // verify_code(generate_code(n), n) contract.
            assert_eq!(normalize_code(&code), code);
            assert!(verify_code(&code, &normalize_code(&code)));
        }
    }
}
