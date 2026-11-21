//! Real-name verification primitives shared by chest and erp.
//!
//! **Design (P-3 decision — minimal storage)**: a verified profile stores
//! only WHAT was verified and WHEN — the provider id, a verification
//! digest over the subject identifier keyed by the instance key, the tier
//! it granted and its timestamp. Raw identifiers exist transiently in the
//! challenge/verify exchange and nowhere else.
//!
//! This module is PURE: no database, no I/O, no feature gates. Each
//! service keeps its own storage/routing (chest: the `realname_providers`
//! catalog; erp: the `realname_profiles` adjudication surface).

use serde::{Deserialize, Serialize};
use sha2::Digest;

// ── shapes ──────────────────────────────────────────────────────────────

/// Instance-wide gates: the master switch and the feature list that
/// requires a verified profile. A missing file = disabled (the
/// conservative default for an identity surface).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct RealnameInstanceConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Feature gates that demand a verified profile before use.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_for: Vec<String>,
}

/// One provider's configuration as stored in the catalog. `settings`
/// carries `${VAR}` references only — resolution happens in memory at
/// read time, so a secret never rests resolved in the database.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct RealnameProviderConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Verification tier a successful run grants ("basic"/"advanced").
    #[serde(default = "default_level")]
    pub level: String,
    /// Provider-specific settings (`${VAR}` references only — SR-05).
    #[serde(default)]
    pub settings: std::collections::BTreeMap<String, String>,
}

fn default_true() -> bool {
    true
}

fn default_level() -> String {
    "basic".to_string()
}

// ── primitives ──────────────────────────────────────────────────────────

/// Domain-separated digest of a raw identifier under the instance key:
/// `SHA256("realname.v1" ‖ instance_key ‖ identifier)` hex. The domain
/// prefix keeps digests from colliding across surfaces that share a key,
/// and the raw identifier is never stored.
pub fn digest_subject(instance_key: &[u8; 32], identifier: &str) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"realname.v1");
    hasher.update(instance_key);
    hasher.update(identifier.as_bytes());
    hex::encode(hasher.finalize())
}

/// A display hint that keeps the informative tail and never hands back a
/// large fraction of the value:
/// * ≥ 11 chars — head 3 + masked middle + tail 4 (an 18-digit ID keeps
///   `310***…****1234`);
/// * 8–10 chars — masked head + tail 4;
/// * 5–7 chars — masked head + tail 2 (a 6-char value must not hand back
///   two thirds of itself);
/// * ≤ 4 chars — all stars.
///
/// Never the raw value.
pub fn mask_identifier(identifier: &str) -> String {
    let chars: Vec<char> = identifier.chars().collect();
    let n = chars.len();
    if n >= 11 {
        let head: String = chars.iter().take(3).collect();
        let tail: String = chars.iter().skip(n - 4).collect();
        format!("{head}{}{tail}", "*".repeat(n - 7))
    } else if n > 4 {
        let tail_len = if n <= 7 { 2 } else { 4 };
        let tail: String = chars.iter().skip(n - tail_len).collect();
        format!("{}{tail}", "*".repeat(n - tail_len))
    } else {
        "*".repeat(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_is_domain_separated_and_keyed() {
        let key = [7u8; 32];
        let d = digest_subject(&key, "310110199001011234");
        assert_eq!(d.len(), 64);
        // Same key + same identifier = same digest (deterministic).
        assert_eq!(d, digest_subject(&key, "310110199001011234"));
        // A different key changes the digest.
        assert_ne!(d, digest_subject(&[8u8; 32], "310110199001011234"));
        // A different identifier changes the digest.
        assert_ne!(d, digest_subject(&key, "310110199001015678"));
    }

    #[test]
    fn digest_matches_the_chest_shape() {
        // chest's `digest_subject` is this exact construction; the golden
        // value is computed here (not hardcoded) but the SHAPE is pinned:
        // domain prefix first, then the key, then the identifier.
        let key = [0u8; 32];
        let mut hasher = sha2::Sha256::new();
        hasher.update(b"realname.v1");
        hasher.update(key);
        hasher.update(b"abc");
        assert_eq!(digest_subject(&key, "abc"), hex::encode(hasher.finalize()));
    }

    #[test]
    fn mask_keeps_the_tail_for_long_values() {
        // An 18-digit ID: head 3 + stars + tail 4.
        let m = mask_identifier("310110199001011234");
        assert!(m.starts_with("310"));
        assert!(m.ends_with("1234"));
        assert!(m.contains('*'));
        assert_eq!(m.chars().count(), 18);
    }

    #[test]
    fn mask_shrinks_the_tail_for_short_values() {
        // 6 chars: tail 2 only (4/6 revealed was the R2 measurement).
        let m = mask_identifier("abcdef");
        assert!(m.starts_with("****"));
        assert!(m.ends_with("ef"));
        // 5 chars: tail 2.
        assert_eq!(mask_identifier("abcde"), "***de");
        // ≤ 4 chars: all stars.
        assert_eq!(mask_identifier("abcd"), "****");
        assert_eq!(mask_identifier("ab"), "**");
    }

    #[test]
    fn instance_config_defaults_to_disabled() {
        let cfg = RealnameInstanceConfig::default();
        assert!(!cfg.enabled);
        assert!(cfg.required_for.is_empty());
    }

    #[test]
    fn provider_config_parses_the_shape() {
        let cfg: RealnameProviderConfig = serde_json::from_str(
            r#"{"enabled": true, "level": "advanced", "settings": {"APP_ID": "${APP_ID}"}}"#,
        )
        .expect("parse");
        assert!(cfg.enabled);
        assert_eq!(cfg.level, "advanced");
        assert_eq!(
            cfg.settings.get("APP_ID").map(String::as_str),
            Some("${APP_ID}")
        );
    }
}
