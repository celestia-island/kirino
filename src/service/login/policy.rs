//! Whether the local password credential may be used to sign in at all.
//!
//! # Third-party-only deployments
//!
//! Some deployments do not want password login: every human identity arrives
//! through a third-party provider (OAuth / SSO) and the local username +
//! password pair is never issued. The first family adopter is the ERP
//! (`easy-hydro-erp`), which keeps Feishu sign-in only; services that keep
//! passwords (for example `shittim-chest`) stay on
//! [`PasswordLoginPolicy::Enabled`] and see no change at all.
//!
//! The switch lives here - the family's auth-primitives layer (kirino) -
//! rather than as a per-service boolean, so every consumer gets one typed
//! value, one parsing contract and one set of integration points instead of
//! hand-rolled `if password_login_enabled` checks that drift apart. Adopters
//! configure it from their own settings and pass it to
//! [`AuthService::with_password_login_policy`](super::AuthService::with_password_login_policy).
//!
//! # What `Disabled` turns off
//!
//! [`AuthService`](super::AuthService) refuses the password login entry
//! points ([`login`](super::AuthService::login) and
//! [`login_with_session`](super::AuthService::login_with_session)) before any
//! credential is looked up, hashed or compared, and a
//! [`LoginRateLimiter`](super::LoginRateLimiter) configured with the policy
//! skips its bookkeeping: a deployment with no password attempts must not
//! accumulate lockout state, and a key that is never counted can never lock a
//! real account out of the sign-in paths that remain.
//!
//! The boundary is deliberate: `Disabled` is about the *method*, not the
//! stored data. Password hashes stay where they are,
//! [`change_password`](super::AuthService::change_password) keeps its
//! semantics for accounts that still hold a credential, and third-party
//! issuance - which lives in the consuming service, not in this crate - is
//! untouched.
//!
//! # Parsing and the fail-closed contract
//!
//! [`PasswordLoginPolicy::parse`](PasswordLoginPolicy::parse) reads a
//! configuration value (environment variable, settings field):
//! case-insensitive `enabled`/`on`/`1`/`true` and `disabled`/`off`/`0`/
//! `false`, with surrounding whitespace tolerated. Anything else - the empty
//! string included - returns `None`, and the caller must treat that as a
//! configuration error at load time rather than silently picking a state: a
//! typo that quietly re-enables password login is exactly the failure this
//! enum exists to prevent.
//!
//! # Relationship to `rbac::policy::PasswordPolicy`
//!
//! The names are close but the questions differ.
//! [`rbac::policy::PasswordPolicy`](crate::rbac::policy::PasswordPolicy)
//! asks whether a *stored* credential is still acceptable (bootstrap
//! rotation, maximum age); this type asks whether the password *method* is
//! offered at all. A deployment may disable the method while the age policy
//! still governs the hashes that remain on disk.
//!
//! ```
//! use kirino::service::login::policy::PasswordLoginPolicy;
//!
//! // A settings value, read the way a service would read it.
//! let raw = "DISABLED";
//! let policy =
//!     PasswordLoginPolicy::parse(raw).expect("configuration value must be valid");
//! assert!(!policy.is_enabled());
//! assert_eq!(policy.as_str(), "disabled");
//!
//! // Unrecognized values are `None` so config loading fails closed.
//! assert_eq!(PasswordLoginPolicy::parse("sometimes"), None);
//! assert_eq!(PasswordLoginPolicy::parse(""), None);
//!
//! // `as_str` round-trips through `parse`.
//! for policy in [PasswordLoginPolicy::Enabled, PasswordLoginPolicy::Disabled] {
//!     assert_eq!(PasswordLoginPolicy::parse(policy.as_str()), Some(policy));
//! }
//! ```

/// Whether the password sign-in method is offered by a deployment.
///
/// A `Copy` value type. [`Enabled`](Self::Enabled) is the historical
/// behaviour and every pre-existing constructor keeps it, so consumers that
/// never mention the policy are unaffected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordLoginPolicy {
    /// Password login is offered; the historical behaviour.
    Enabled,
    /// Password login is refused; only third-party (OAuth) sign-in remains.
    Disabled,
}

impl PasswordLoginPolicy {
    /// Parse a configuration value into a policy.
    ///
    /// Accepts, case-insensitively and after trimming surrounding whitespace,
    /// `enabled`/`on`/`1`/`true` and `disabled`/`off`/`0`/`false`. Every
    /// other value - the empty string included - yields `None`; treat that as
    /// a configuration error rather than a default, see the module docs for
    /// the fail-closed contract.
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "enabled" | "on" | "1" | "true" => Some(Self::Enabled),
            "disabled" | "off" | "0" | "false" => Some(Self::Disabled),
            _ => None,
        }
    }

    /// Whether password login is offered.
    #[must_use]
    pub fn is_enabled(self) -> bool {
        matches!(self, Self::Enabled)
    }

    /// The canonical spelling, for logs, config echo and round-tripping
    /// through [`parse`](Self::parse).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Enabled => "enabled",
            Self::Disabled => "disabled",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::PasswordLoginPolicy;

    #[test]
    fn test_parse_accepts_enabled_spellings() {
        for raw in ["enabled", "ENABLED", "Enabled", "eNaBlEd"] {
            assert_eq!(
                PasswordLoginPolicy::parse(raw),
                Some(PasswordLoginPolicy::Enabled),
                "expected {raw:?} to parse as Enabled"
            );
        }
    }

    #[test]
    fn test_parse_accepts_disabled_spellings() {
        for raw in ["disabled", "DISABLED", "Disabled", "dIsAbLeD"] {
            assert_eq!(
                PasswordLoginPolicy::parse(raw),
                Some(PasswordLoginPolicy::Disabled),
                "expected {raw:?} to parse as Disabled"
            );
        }
    }

    #[test]
    fn test_parse_accepts_on_off_numerics_and_booleans() {
        for raw in ["on", "ON", "1", "true", "TRUE", "True"] {
            assert_eq!(
                PasswordLoginPolicy::parse(raw),
                Some(PasswordLoginPolicy::Enabled),
                "expected {raw:?} to parse as Enabled"
            );
        }
        for raw in ["off", "OFF", "0", "false", "FALSE", "False"] {
            assert_eq!(
                PasswordLoginPolicy::parse(raw),
                Some(PasswordLoginPolicy::Disabled),
                "expected {raw:?} to parse as Disabled"
            );
        }
    }

    #[test]
    fn test_parse_trims_surrounding_whitespace() {
        assert_eq!(
            PasswordLoginPolicy::parse("  enabled\t"),
            Some(PasswordLoginPolicy::Enabled)
        );
        assert_eq!(
            PasswordLoginPolicy::parse("\toff\n"),
            Some(PasswordLoginPolicy::Disabled)
        );
    }

    #[test]
    fn test_parse_rejects_unrecognized_values() {
        for raw in [
            "",
            " ",
            "yes",
            "no",
            "maybe",
            "2",
            "10",
            "-1",
            "enabled=true",
            "enabled disabled",
            "enalbed",
            "disabeld",
            "是",
            "ｅｎａｂｌｅｄ",
        ] {
            assert_eq!(
                PasswordLoginPolicy::parse(raw),
                None,
                "expected {raw:?} to be rejected"
            );
        }
    }

    #[test]
    fn test_parse_rejects_inner_separators_and_compound_values() {
        for raw in ["en abled", "on//1", "true,false", "enabled=1"] {
            assert_eq!(
                PasswordLoginPolicy::parse(raw),
                None,
                "expected {raw:?} to be rejected"
            );
        }
    }

    #[test]
    fn test_as_str_spellings() {
        assert_eq!(PasswordLoginPolicy::Enabled.as_str(), "enabled");
        assert_eq!(PasswordLoginPolicy::Disabled.as_str(), "disabled");
    }

    #[test]
    fn test_as_str_round_trips_through_parse() {
        for policy in [PasswordLoginPolicy::Enabled, PasswordLoginPolicy::Disabled] {
            assert_eq!(PasswordLoginPolicy::parse(policy.as_str()), Some(policy));
        }
    }

    #[test]
    fn test_is_enabled() {
        assert!(PasswordLoginPolicy::Enabled.is_enabled());
        assert!(!PasswordLoginPolicy::Disabled.is_enabled());
    }

    #[test]
    fn test_policy_is_copy_and_comparable() {
        let policy = PasswordLoginPolicy::Disabled;
        let copy = policy;
        assert_eq!(policy, copy);
        assert_ne!(policy, PasswordLoginPolicy::Enabled);
        let _debug = format!("{policy:?}");
    }
}
