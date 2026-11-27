use zeroize::Zeroizing;

use crate::SessionError;

/// Minimum accepted shared-secret length for [`SessionConfig::try_new`].
///
/// HS256 security rests entirely on this secret's entropy; the OWASP
/// guidance for symmetric signing keys starts at 256 bits (32 bytes).
pub const MIN_SECRET_BYTES: usize = 32;

/// Configuration for JWT session management.
///
/// Three key profiles exist. The historical one is a **shared secret**
/// (HS256): every service holding the secret can both mint and verify
/// tokens, so a leak in any one of them forges credentials for all of
/// them. The asymmetric profiles are **Ed25519** and, behind the
/// default-off `mldsa` feature, **ML-DSA-65** (FIPS 204 / RFC 9964):
/// the issuer service holds the private key and every verifier
/// distributes only public keys, so a verifier compromise cannot mint
/// anything. Configure an asymmetric profile by adding at least one of
/// its public verifying keys; the shared secret is then ignored (remove
/// it — see [`SessionConfig::add_ed25519_verifying_key`] and
/// [`SessionConfig::add_mldsa65_verifying_key`]). The two asymmetric
/// profiles are mutually exclusive: configuring key material for both
/// leaves the manager unusable (a
/// [`SessionError::Keys`](crate::SessionError::Keys) on every sign and
/// verify) rather than guessing which trust path was meant.
///
/// The two lifetimes may be read from the environment via
/// [`SessionTtlEnv::from_env`] (the `CELESTIA_` spellings, with one
/// release of legacy fallback); the host can still override whatever that
/// read produced by assigning the fields directly or calling
/// [`SessionConfig::with_ttl`].
#[derive(Clone, Default)]
pub(crate) struct Ed25519Keys {
    /// Private key PEM (issuer side). `None` on verify-only services such
    /// as a gateway that must never mint tokens.
    pub signing_pem: Option<Zeroizing<String>>,
    /// Public key PEMs accepted for verification, in try-order. More than
    /// one entry enables key rotation: tokens signed by any listed public
    /// key verify, so a new key can be rolled out before the old one
    /// retires.
    pub verifying_pems: Vec<Zeroizing<String>>,
}

/// ML-DSA-65 (FIPS 204 / RFC 9964) key material.
///
/// Structurally the same role as [`Ed25519Keys`] but byte-oriented:
/// ML-DSA has no PEM wrapping here — the 32-byte seed **is** the private
/// key, and the 1952-byte encoded public key (FIPS 204 `pkEncode`
/// output) is the trust anchor. Holding plain bytes keeps this struct
/// usable without the `mldsa` feature: a config that declares ML-DSA
/// keys on a build without the feature resolves to a `Broken` keyset
/// (see [`TokenManager`](crate::TokenManager)) instead of silently
/// falling back to the HS256 shared secret.
#[derive(Clone, Default)]
pub(crate) struct MlDsa65Keys {
    /// 32-byte signing seed (issuer side). `None` on verify-only
    /// services.
    pub signing_seed: Option<Zeroizing<[u8; 32]>>,
    /// Encoded public keys (1952 bytes each, FIPS 204 `pkEncode`
    /// output) accepted for verification, in try-order — the same
    /// rotation semantics as [`Ed25519Keys::verifying_pems`]. Any
    /// 1952-byte array is structurally admissible (FIPS 204 has no cheap
    /// pk syntax check); a junk key simply fails every signature it is
    /// tried against.
    pub verifying: Vec<[u8; 1952]>,
}

#[derive(Clone)]
pub struct SessionConfig {
    /// Shared secret for JWT signing (HS256). Only used when no Ed25519
    /// or ML-DSA-65 verifying key is configured.
    pub(crate) secret: Zeroizing<String>,
    /// Ed25519 key material; `verifying_pems` non-empty selects the
    /// Ed25519 profile.
    pub(crate) ed25519: Ed25519Keys,
    /// ML-DSA-65 key material; `verifying` non-empty selects the
    /// ML-DSA-65 profile (requires the `mldsa` feature at build time).
    pub(crate) mldsa65: MlDsa65Keys,
    /// Access token lifetime in seconds (default: 900 = 15 min).
    pub access_ttl_secs: u64,
    /// Refresh token lifetime in seconds (default: 604800 = 7 days).
    pub refresh_ttl_secs: u64,
    /// Token issuer claim.
    pub issuer: String,
    /// Optional audience validation. If set, tokens must have this audience.
    pub audience: Option<String>,
    /// Optional key id (`kid`): stamped into the JOSE header on mint and
    /// published by [`TokenManager::jwks`](crate::TokenManager::jwks) on
    /// the Ed25519 and ML-DSA-65 profiles. The legacy HS256 profile does
    /// not stamp `kid` — its byte format stays frozen.
    pub(crate) kid: Option<String>,
}

/// The two session lifetimes a deployment may pin, read under the family's
/// `CELESTIA_` spellings with a one-release fallback to the historical
/// unprefixed names (`JWT_EXPIRATION_SECONDS` /
/// `JWT_REFRESH_EXPIRATION_SECONDS`).
///
/// This is the ONE resolution entry point for the session TTLs — hosts
/// (erp, chest) previously each re-implemented the same unprefixed read;
/// the name and the parse now live here only. The resolved values are
/// suggestions, not overrides: a host that knows better may still pin
/// [`SessionConfig::access_ttl_secs`] / [`SessionConfig::refresh_ttl_secs`]
/// (or [`SessionConfig::with_ttl`]) after reading.
///
/// Parse rules, byte-for-byte the behavior the hosts shipped:
///
/// | access source | refresh source | result |
/// |---|---|---|
/// | new name, parses | new name, parses | both new values |
/// | new name, unparsable | (any) | default — NOT the legacy value |
/// | absent | legacy name, parses | legacy value |
/// | absent | absent | [`Self::DEFAULT_ACCESS_SECS`] / [`Self::DEFAULT_REFRESH_SECS`] |
///
/// The one deliberate deviation from a naive "try every name in order"
/// chain: when the new name is set but unparsable, the legacy name is NOT
/// consulted. An explicit misconfiguration must stay visible — falling
/// back would let a typo'd `CELESTIA_SESSION_TTL_SECONDS` silently serve
/// the old variable's value, pinning a lifetime the operator believes they
/// overrode. Missing (absent) and broken (unparsable) are different states;
/// only the first falls through. Both names set parses to the new value
/// silently — that is the intended migration shape, not an error.
pub struct SessionTtlEnv {
    /// Access-token lifetime in seconds
    /// ([`SessionConfig::access_ttl_secs`]).
    pub access_secs: u64,
    /// Refresh-token lifetime in seconds
    /// ([`SessionConfig::refresh_ttl_secs`]).
    pub refresh_secs: u64,
}

impl SessionTtlEnv {
    /// 15 minutes — the lifetime [`SessionConfig`] ships when nothing says
    /// otherwise.
    pub const DEFAULT_ACCESS_SECS: u64 = 900;
    /// 7 days — the refresh lifetime [`SessionConfig`] ships when nothing
    /// says otherwise.
    pub const DEFAULT_REFRESH_SECS: u64 = 604_800;

    /// New spellings first; the unprefixed historical names survive one
    /// release (the rename wave's compatibility window) and warn once per
    /// variable per process when they serve.
    pub const ACCESS_NEW: &str = "CELESTIA_SESSION_TTL_SECONDS";
    /// Legacy unprefixed access-lifetime name, warned on use — see
    /// [`Self::ACCESS_NEW`].
    pub const ACCESS_LEGACY: &str = "JWT_EXPIRATION_SECONDS";
    /// New spelling of the refresh lifetime — see [`Self::ACCESS_NEW`].
    pub const REFRESH_NEW: &str = "CELESTIA_SESSION_REFRESH_TTL_SECONDS";
    /// Legacy unprefixed refresh-lifetime name, warned on use — see
    /// [`Self::ACCESS_NEW`].
    pub const REFRESH_LEGACY: &str = "JWT_REFRESH_EXPIRATION_SECONDS";

    /// Read both lifetimes from the process environment. Never panics and
    /// never blocks: a missing or unparsable value degrades to the default,
    /// exactly the behavior the hosts shipped before this entry point
    /// existed.
    pub fn from_env() -> Self {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    /// The pure core of [`Self::from_env`] — the lookup is injected, so the
    /// parse rules (including the no-fallthrough-on-unparsable-new-name
    /// rule) are testable and usable over custom channels (a config file,
    /// a service shim) without touching the process environment.
    /// [`Self::from_lookup`] with an EXPLICIT warn-once state: the tests use
    /// it so the "exactly one line for two reads" assertion is independent
    /// of what any other test read first (R2's S1: the shared process set
    /// made that test pass only in isolation).
    #[cfg(test)]
    fn from_lookup_with(lookup: impl Fn(&str) -> Option<String>, warner: &LegacyWarner) -> Self {
        Self {
            access_secs: resolve_secs(
                Self::ACCESS_NEW,
                Self::ACCESS_LEGACY,
                Self::DEFAULT_ACCESS_SECS,
                &lookup,
                warner,
            ),
            refresh_secs: resolve_secs(
                Self::REFRESH_NEW,
                Self::REFRESH_LEGACY,
                Self::DEFAULT_REFRESH_SECS,
                &lookup,
                warner,
            ),
        }
    }

    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Self {
        let warner = global_warner();
        let access_secs = resolve_secs(
            Self::ACCESS_NEW,
            Self::ACCESS_LEGACY,
            Self::DEFAULT_ACCESS_SECS,
            &lookup,
            warner,
        );
        let refresh_secs = resolve_secs(
            Self::REFRESH_NEW,
            Self::REFRESH_LEGACY,
            Self::DEFAULT_REFRESH_SECS,
            &lookup,
            warner,
        );
        Self {
            access_secs,
            refresh_secs,
        }
    }
}

/// One variable's resolution under the two-name compatibility window: the
/// new name wins outright (parses or not), the legacy name serves with
/// exactly one deprecation warning per variable per process (the name,
/// never the value — a legacy value can be an operator secret and the
/// journal is a wider audience than the shell that set it).
fn resolve_secs(
    new_name: &str,
    legacy_name: &str,
    default: u64,
    lookup: &impl Fn(&str) -> Option<String>,
    warner: &LegacyWarner,
) -> u64 {
    if let Some(raw) = lookup(new_name) {
        // MUT:ttl-no-fallthrough — an unparsable NEW name must NOT fall
        // through to the legacy variable: explicit misconfiguration has to
        // stay visible, and a fallback would pin the old variable's value
        // under a typo'd new name. See `SessionTtlEnv`'s table.
        return raw.parse().unwrap_or(default);
    }
    if let Some(raw) = lookup(legacy_name) {
        warner.warn_once(legacy_name);
        return raw.parse().unwrap_or(default);
    }
    default
}

/// The "warn once per variable" state, as an OBJECT rather than a process
/// singleton.
///
/// The production path uses [`GLOBAL_WARNER`] (one line per variable per
/// process: a startup read may re-run per worker or per reload, and the
/// journal does not need the same deprecation a dozen times). Keeping the
/// set in a value is what makes the rule TESTABLE: a test constructs its
/// own warner and asserts "exactly one line for two reads" without
/// depending on which other test in the binary read a legacy name first —
/// the order-dependence R2 caught in the previous cut, where the global set
/// was shared by four tests and the warn-count test passed only when run
/// alone.
pub(crate) struct LegacyWarner {
    seen: std::sync::Mutex<std::collections::HashSet<String>>,
}

impl LegacyWarner {
    fn new() -> Self {
        Self {
            seen: std::sync::Mutex::new(std::collections::HashSet::new()),
        }
    }

    /// The names warned about so far (test/inspection only): the dedupe
    /// rule is observable state, not just log output.
    #[cfg(test)]
    fn warned_names(&self) -> Vec<String> {
        let seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        let mut names: Vec<String> = seen.iter().cloned().collect();
        names.sort();
        names
    }

    fn warn_once(&self, name: &str) {
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        if seen.insert(name.to_string()) {
            tracing::warn!(
                target: "kirino_session::config",
                variable = name,
                "{}",
                legacy_warn_message(name)
            );
        }
    }
}

/// The one rendering of the deprecation line.
///
/// Its input is the VARIABLE NAME and nothing else, which is what keeps the
/// served value out of the journal by construction rather than by reviewer
/// diligence: a legacy value can be an operator secret, and journald reaches
/// a wider audience than the shell that set it.
fn legacy_warn_message(name: &str) -> String {
    format!(
        "legacy unprefixed session-lifetime variable {name} served; rename to the CELESTIA_ spelling (support ends next release)"
    )
}

/// The process-wide warner the environment path uses.
fn global_warner() -> &'static LegacyWarner {
    static GLOBAL: std::sync::OnceLock<LegacyWarner> = std::sync::OnceLock::new();
    GLOBAL.get_or_init(LegacyWarner::new)
}

impl SessionConfig {
    /// Build a configuration around a shared secret (HS256 profile).
    ///
    /// Infallible on purpose: existing deployments and tests construct
    /// here. A secret that is empty or shorter than [`MIN_SECRET_BYTES`]
    /// leaves a `tracing` warning behind (audit R1-SESS-7 — a weak HS256
    /// key is a standing, logged risk, not a silent one); the strict
    /// constructor is [`SessionConfig::try_new`].
    pub fn new(secret: impl Into<String>) -> Self {
        Self::from_secret(secret.into())
    }

    /// Strict constructor: refuses an empty shared secret outright and
    /// any secret shorter than [`MIN_SECRET_BYTES`] — exactly the keys an
    /// HS256 brute forcer hopes for.
    ///
    /// # Errors
    ///
    /// [`SessionError::Other`] describing the rejected secret.
    pub fn try_new(secret: impl Into<String>) -> Result<Self, SessionError> {
        let secret = secret.into();
        if secret.is_empty() {
            return Err(SessionError::Other(
                "shared secret is empty; refusing to configure HS256 without a key".into(),
            ));
        }
        if secret.len() < MIN_SECRET_BYTES {
            return Err(SessionError::Other(format!(
                "shared secret is {len} bytes; HS256 needs at least {MIN_SECRET_BYTES}",
                len = secret.len()
            )));
        }
        Ok(Self::from_secret(secret))
    }

    fn from_secret(secret: String) -> Self {
        if secret.len() < MIN_SECRET_BYTES {
            tracing::warn!(
                target: "kirino_session::config",
                len = secret.len(),
                "weak HS256 shared secret (empty or under 32 bytes); \
                 SessionConfig::try_new refuses it at construction"
            );
        }
        Self {
            secret: Zeroizing::new(secret),
            ed25519: Ed25519Keys::default(),
            mldsa65: MlDsa65Keys::default(),
            access_ttl_secs: 900,
            refresh_ttl_secs: 604_800,
            issuer: "kirino".into(),
            audience: None,
            kid: None,
        }
    }

    pub fn with_ttl(mut self, access_secs: u64, refresh_secs: u64) -> Self {
        self.access_ttl_secs = access_secs;
        self.refresh_ttl_secs = refresh_secs;
        self
    }

    pub fn with_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = issuer.into();
        self
    }

    pub fn with_audience(mut self, aud: impl Into<String>) -> Self {
        self.audience = Some(aud.into());
        self
    }

    /// Configure the Ed25519 **signing** (private) key. The manager becomes
    /// able to mint tokens; verification still needs at least one public
    /// key via [`Self::add_ed25519_verifying_key`].
    ///
    /// Issuer services (the ones users log into) set this; verify-only
    /// services (gateways, sibling APIs) must not — a missing signing key
    /// makes every minting call fail with
    /// [`SessionError::SigningUnavailable`](crate::SessionError::SigningUnavailable)
    /// instead of silently working.
    pub fn with_ed25519_signing_key(mut self, pem: impl Into<String>) -> Self {
        self.ed25519.signing_pem = Some(Zeroizing::new(pem.into()));
        self
    }

    /// Add an Ed25519 **verifying** (public) key. Adding the first one
    /// switches the profile from HS256 to Ed25519; the shared secret is
    /// then ignored entirely — an HS256 token is rejected because the
    /// accepted algorithm set no longer contains it, so a leftover secret
    /// cannot quietly keep the old trust path alive.
    pub fn add_ed25519_verifying_key(mut self, pem: impl Into<String>) -> Self {
        self.ed25519.verifying_pems.push(Zeroizing::new(pem.into()));
        self
    }

    /// Set the key id (`kid`) for the asymmetric profiles.
    ///
    /// On mint the `kid` is written into the JOSE header of Ed25519 and
    /// ML-DSA-65 tokens; on verify (ML-DSA-65 profile) a token whose
    /// header `kid` differs from the configured one is rejected outright,
    /// while a token without a `kid` falls back to trying every verifying
    /// key in order. The same `kid` is published in
    /// [`TokenManager::jwks`](crate::TokenManager::jwks). The legacy
    /// HS256 profile ignores it to keep its token bytes frozen.
    pub fn with_kid(mut self, kid: impl Into<String>) -> Self {
        self.kid = Some(kid.into());
        self
    }

    /// Configure the ML-DSA-65 **signing seed** (32 bytes, FIPS 204
    /// `xi`). The manager becomes able to mint tokens; verification
    /// still needs at least one public key via
    /// [`Self::add_mldsa65_verifying_key`] — a seed without any
    /// verifying key leaves the manager unusable (loudly, mirroring the
    /// Ed25519 wrong-direction guard) because it would otherwise be a
    /// silent invitation to fall back to the shared secret.
    ///
    /// Issuer services set this; verify-only services must not — a
    /// missing seed makes every minting call fail with
    /// [`SessionError::SigningUnavailable`](crate::SessionError::SigningUnavailable)
    /// instead of silently working. Enabling ML-DSA-65 requires the
    /// `mldsa` feature at build time (toolchain ≥ 1.87 per the ml-dsa
    /// MSRV).
    pub fn with_mldsa65_signing_seed(mut self, seed: &[u8; 32]) -> Self {
        self.mldsa65.signing_seed = Some(Zeroizing::new(*seed));
        self
    }

    /// Add an ML-DSA-65 **verifying** (public) key — the 1952-byte FIPS
    /// 204 `pkEncode` output, exactly as
    /// [`TokenManager::jwks`](crate::TokenManager::jwks) publishes it in
    /// the `pub` field (base64url of the same bytes). Adding the first
    /// one switches the profile from HS256 to ML-DSA-65; the shared
    /// secret is then ignored entirely, and Ed25519 key material must
    /// not be configured on the same config (the two asymmetric profiles
    /// are mutually exclusive — mixing them leaves the manager unusable
    /// rather than ambiguous).
    pub fn add_mldsa65_verifying_key(mut self, key: &[u8; 1952]) -> Self {
        self.mldsa65.verifying.push(*key);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_new_refuses_empty_and_short_secrets() {
        assert!(SessionConfig::try_new("").is_err());
        assert!(SessionConfig::try_new("short").is_err());
        assert!(SessionConfig::try_new("a".repeat(MIN_SECRET_BYTES - 1)).is_err());
    }

    #[test]
    fn try_new_accepts_a_full_length_secret() {
        let secret = "a".repeat(MIN_SECRET_BYTES);
        assert!(SessionConfig::try_new(secret).is_ok());
    }

    #[test]
    fn new_stays_infallible_for_legacy_callers() {
        // The historical constructor must keep working (scepter/arona
        // construct through it) — weakness is logged, not refused.
        let _ = SessionConfig::new("test-secret");
    }

    // All TTL-resolution tests go through `from_lookup` — the pure core —
    // so no test touches the process environment and none needs a mutex
    // against `set_var` races.

    fn lookup_from<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |name| {
            pairs
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, v)| v.to_string())
        }
    }

    #[test]
    fn ttl_new_name_wins_when_present() {
        let env = SessionTtlEnv::from_lookup(lookup_from(&[
            ("CELESTIA_SESSION_TTL_SECONDS", "1800"),
            ("JWT_EXPIRATION_SECONDS", "999"),
            ("CELESTIA_SESSION_REFRESH_TTL_SECONDS", "10"),
            ("JWT_REFRESH_EXPIRATION_SECONDS", "999"),
        ]));
        assert_eq!(env.access_secs, 1800);
        assert_eq!(env.refresh_secs, 10);
    }

    #[test]
    fn ttl_legacy_name_serves_the_same_value() {
        let env = SessionTtlEnv::from_lookup(lookup_from(&[
            ("JWT_EXPIRATION_SECONDS", "3600"),
            ("JWT_REFRESH_EXPIRATION_SECONDS", "42"),
        ]));
        assert_eq!(env.access_secs, 3600);
        assert_eq!(env.refresh_secs, 42);
    }

    #[test]
    fn ttl_missing_names_take_the_defaults() {
        let env = SessionTtlEnv::from_lookup(lookup_from(&[]));
        assert_eq!(env.access_secs, SessionTtlEnv::DEFAULT_ACCESS_SECS);
        assert_eq!(env.refresh_secs, SessionTtlEnv::DEFAULT_REFRESH_SECS);
    }

    #[test]
    fn ttl_unparsable_new_name_takes_default_not_legacy() {
        // MUT:ttl-test-no-fallthrough — pins the visible-misconfiguration
        // rule: the broken new name must yield the DEFAULT, never the
        // legacy variable's value; a fallback here would silently serve a
        // lifetime the operator believes they overrode.
        let env = SessionTtlEnv::from_lookup(lookup_from(&[
            ("CELESTIA_SESSION_TTL_SECONDS", "not-a-number"),
            ("JWT_EXPIRATION_SECONDS", "3600"),
            ("CELESTIA_SESSION_REFRESH_TTL_SECONDS", ""),
            ("JWT_REFRESH_EXPIRATION_SECONDS", "42"),
        ]));
        assert_eq!(env.access_secs, SessionTtlEnv::DEFAULT_ACCESS_SECS);
        assert_eq!(env.refresh_secs, SessionTtlEnv::DEFAULT_REFRESH_SECS);
    }

    #[test]
    fn ttl_unparsable_legacy_name_also_takes_default() {
        // Same strictness applies on the legacy path — the hosts shipped
        // `parse().ok().unwrap_or(default)`, so a broken value degrades to
        // the default, not to a panic.
        let env = SessionTtlEnv::from_lookup(lookup_from(&[
            ("JWT_EXPIRATION_SECONDS", "tomorrow"),
            ("JWT_REFRESH_EXPIRATION_SECONDS", "NaN"),
        ]));
        assert_eq!(env.access_secs, SessionTtlEnv::DEFAULT_ACCESS_SECS);
        assert_eq!(env.refresh_secs, SessionTtlEnv::DEFAULT_REFRESH_SECS);
    }

    #[test]
    fn ttl_legacy_warn_fires_exactly_once_per_variable() {
        // Repeated legacy reads through a FRESH warner: the first warns, the
        // rest must be silent. A private warner is what makes this assertion
        // independent of test order — with the process-wide set, another test
        // that read a legacy name first made the count 0 or 2 depending on
        // which test ran first (R2's S1).
        let warner = super::LegacyWarner::new();
        let first = SessionTtlEnv::from_lookup_with(
            lookup_from(&[("JWT_EXPIRATION_SECONDS", "60")]),
            &warner,
        );
        let second = SessionTtlEnv::from_lookup_with(
            lookup_from(&[("JWT_EXPIRATION_SECONDS", "60")]),
            &warner,
        );
        assert_eq!(first.access_secs, 60);
        assert_eq!(second.access_secs, 60);
        assert_eq!(
            warner.warned_names(),
            vec!["JWT_EXPIRATION_SECONDS".to_string()],
            "two legacy reads of one variable record exactly one warning"
        );
        // A SECOND legacy variable is its own warning, and defaults do not warn.
        let third = SessionTtlEnv::from_lookup_with(
            lookup_from(&[("JWT_REFRESH_EXPIRATION_SECONDS", "120")]),
            &warner,
        );
        assert_eq!(third.refresh_secs, 120);
        assert_eq!(
            warner.warned_names(),
            vec![
                "JWT_EXPIRATION_SECONDS".to_string(),
                "JWT_REFRESH_EXPIRATION_SECONDS".to_string()
            ],
            "the once-per-variable rule is per variable, not per process"
        );
    }

    /// MUT:ttl-warn-leaks-the-value — the deprecation line is built from the
    /// variable NAME alone (see `legacy_warn_message`'s signature), so no
    /// served value can reach the journal. The assertion below is the
    /// observable half of that: the rendered line carries the name and the
    /// CELESTIA_ spelling, and carries no value-shaped interpolation.
    #[test]
    fn ttl_legacy_warn_line_names_the_variable_and_nothing_else() {
        let line = super::legacy_warn_message("JWT_EXPIRATION_SECONDS");
        assert!(line.contains("JWT_EXPIRATION_SECONDS"), "{line}");
        assert!(line.contains("CELESTIA_"), "{line}");
        assert!(
            !line.contains("60"),
            "a served value must never appear: {line}"
        );
        assert!(
            !line.contains("="),
            "the line interpolates no field: {line}"
        );
    }
}
