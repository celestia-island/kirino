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
///
/// Field semantics follow chest's catalog (the only consumer with a
/// panel today): `enabled` gates issuing, `display_name` is republished
/// to browsers (validated non-empty / ≤ 128 chars at chest's admin
/// boundary), `level` is the tier a successful run grants. A new
/// consumer MUST re-derive the validation gates — this type carries
/// data, not policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RealnameProviderConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Display name shown in the panel. chest's catalog requires it
    /// (no serde default there); the `serde(default)` here keeps a
    /// consumer without a panel parsing the same rows.
    #[serde(default)]
    pub display_name: String,
    /// Verification tier a successful run grants ("basic"/"advanced").
    #[serde(default = "default_level")]
    pub level: String,
    /// Provider-specific settings (`${VAR}` references only — SR-05).
    /// The convention is NOT enforced by this type.
    #[serde(default)]
    pub settings: std::collections::BTreeMap<String, String>,
}

/// `Default` agrees with the serde defaults ON PURPOSE: the derived
/// impl answered `enabled=false, level=""` while parsing `{}` answered
/// `enabled=true, level="basic"` — an identity master switch must not
/// flip between those two paths.
impl Default for RealnameProviderConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            display_name: String::new(),
            level: default_level(),
            settings: Default::default(),
        }
    }
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
///
/// CONTRACT — this is a keyed HASH, not a MAC: the plain concatenation
/// has no length-extension resistance, so it must not be presented (or
/// depended on) as authenticating. chest's stored digests are exactly
/// this construction (byte-compat is mandatory — do not "upgrade" to
/// HMAC without a row migration). Key notes for consumers: the key is a
/// fixed 32 bytes so the key/identifier boundary is unambiguous — and it
/// must be SECRET and full-entropy: a low-entropy key lets an attacker
/// who knows the construction offline-enumerate low-entropy identifiers
/// (a phone number is ~1e10).
///
/// erp NOTE: erp's current digest is a DIFFERENT construction (HMAC over
/// the raw env string, no prefix, key not 32 bytes) and no bridge exists
/// yet — adopting this module means erp must derive the SAME 32 bytes
/// its rows will live with and accept that old rows keep the HMAC
/// values (nothing reads a digest back on either side today).
pub fn digest_subject(instance_key: &[u8; 32], identifier: &str) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"realname.v1");
    hasher.update(instance_key);
    hasher.update(identifier.as_bytes());
    hex::encode(hasher.finalize())
}

/// A display hint that keeps the informative tail. The ≥11 band reveals
/// the phone-conventional head-3+tail-4 (about two thirds of the value —
/// head 3 is the operator prefix, not subscriber data); the shorter bands
/// hand back at most half:
/// * ≥ 11 chars — head 3 + masked middle + tail 4 (an 18-digit ID keeps
///   `310***********1234`);
/// * 8–10 chars — masked head + tail 4;
/// * 5–7 chars — masked head + tail 2 (a 6-char value must not hand back
///   two thirds of itself);
/// * ≤ 4 chars — all stars.
///
/// Never the raw value; the empty input returns the empty string.
///
/// NOTE the disclosure is deliberately NON-monotonic at the 11-char
/// edge (10 chars reveal 4, 11 reveal 7): the ≥11 band is the PHONE
/// shape, where `138****8000` is the conventional rendering and the
/// head-3 prefix is the operator prefix, not subscriber data. chest's
/// chest keeps its own independent `mask_phone` (it is the STORED hint
/// format; this function is not a wrapper over it).
///
/// Mask bands are a contract: every edge above has a test.
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
        // chest's `digest_subject` is this exact construction, pinned to
        // GOLDEN HEX values computed independently in Python:
        //   sha256(b"realname.v1" + bytes(32) + b"abc")
        //   sha256(b"realname.v1" + bytes([7])*32 + b"310110199001011234")
        // A coordinated edit of the literals cannot pass, and a
        // cross-check against a locally rebuilt hasher would agree by
        // construction.
        let key = [0u8; 32];
        assert_eq!(
            digest_subject(&key, "abc"),
            "7fe694483360d4d90fb532502a1d204828d25a42b9a4739b85af27e976d399e3"
        );
        let key7 = [7u8; 32];
        assert_eq!(
            digest_subject(&key7, "310110199001011234"),
            "408bc2fdf75fa845c91813aff50b90a23eca8205bc5acf61fea7f8f282553c2e"
        );
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
    fn mask_band_edges_are_exact() {
        // Every documented edge, computed by hand (R3 M2/M3 survived
        // without these).
        assert_eq!(mask_identifier("abcd"), "****"); // n=4: all stars
        assert_eq!(mask_identifier("abcde"), "***de"); // n=5: tail 2
        assert_eq!(mask_identifier("abcdef"), "****ef"); // n=6: tail 2
        assert_eq!(mask_identifier("abcdefg"), "*****fg"); // n=7: tail 2
        assert_eq!(mask_identifier("abcdefgh"), "****efgh"); // n=8: tail 4
        assert_eq!(mask_identifier("abcdefghi"), "*****fghi"); // n=9: tail 4
        assert_eq!(mask_identifier("abcdefghij"), "******ghij"); // n=10: tail 4
        assert_eq!(
            mask_identifier("abcdefghijk"),
            "abc****hijk" // n=11: head 3 + tail 4
        );
        // Non-ASCII counts by chars, not bytes.
        assert_eq!(mask_identifier("张三李四王五"), "****王五");
    }

    #[test]
    fn mask_of_the_empty_input_is_empty() {
        assert_eq!(mask_identifier(""), "");
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
    fn instance_config_serde_defaults_match_the_contract() {
        // R4-delta M4 survived: dropping `#[serde(default)]` on `enabled`
        // kept every test green, so the documented "a missing file =
        // disabled" contract had no guard. Both shapes pinned:
        // an EMPTY object is the missing-file analogue…
        let empty: RealnameInstanceConfig = serde_json::from_str("{}").expect("parse");
        assert!(!empty.enabled, "missing enabled = disabled (the contract)");
        assert!(empty.required_for.is_empty());
        // …and a present object parses its fields.
        let full: RealnameInstanceConfig =
            serde_json::from_str(r#"{"enabled": true, "required_for": ["topup"]}"#).expect("parse");
        assert!(full.enabled);
        assert_eq!(full.required_for, vec!["topup".to_string()]);
    }

    #[test]
    fn provider_default_agrees_with_the_serde_defaults() {
        // R3 S2: the derived Default answered `enabled=false, level=""`
        // while `{}` parsed to `enabled=true, level="basic"` — a master
        // switch flipping between the two paths is a footgun. The manual
        // impl removed `derive(Default)`; this pin holds both paths
        // equal.
        let derived = RealnameProviderConfig::default();
        let parsed: RealnameProviderConfig = serde_json::from_str("{}").expect("parse");
        assert_eq!(derived, parsed);
        assert!(derived.enabled, "the default provider is enabled");
        assert_eq!(derived.level, "basic");
    }

    #[test]
    fn provider_config_keeps_display_name_through_the_union() {
        // chest's admin boundary parses its payload into this type: a
        // field silently dropped here would silently drop the panel
        // label there (R3 S1).
        let cfg: RealnameProviderConfig =
            serde_json::from_str(r#"{"display_name": "支付宝实名", "level": "advanced"}"#)
                .expect("parse");
        assert_eq!(cfg.display_name, "支付宝实名");
        // And the default keeps a panel-less consumer parsing old rows.
        let bare: RealnameProviderConfig =
            serde_json::from_str(r#"{"level": "basic"}"#).expect("parse");
        assert_eq!(bare.display_name, "");
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
