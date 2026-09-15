//! Password policy: the credential-age and bootstrap-rotation rules of the RBAC surface.
//!
//! # Where this sits relative to [`Permission`](crate::rbac::permission::Permission) and
//! [`RbacEngine`](crate::rbac::engine::RbacEngine)
//!
//! A [`Permission`](crate::rbac::permission::Permission) answers *"may this subject perform
//! this action on this resource?"* — the RBAC0/1/2 catalog that
//! [`RbacEngine`](crate::rbac::engine::RbacEngine) evaluates for a subject/role assignment.
//!
//! A password policy answers a different and earlier question: *"is this subject's credential
//! state still acceptable at all?"* It is deliberately **not** an entry in the
//! `hierarchical_permission!` catalog: there is no resource to name, and no role can
//! meaningfully be granted "keep using an expired password". It is nonetheless part of access
//! control, so it lives in the same layer and the same surface (`rbac::`), not in per-service
//! configuration: every service that already consults kirino for authorization gets one
//! implementation, one set of semantics and one set of tests for the bootstrap/rotation rules.
//!
//! The rules themselves are pure: [`PasswordPolicy::change_requirement`] takes the injected
//! clock value, so callers control time (tests, replay, skewed nodes) and the kernel never
//! reads a clock behind their back.
//!
//! # How a service uses it
//!
//! 1. **Bootstrap** (first install, debug runs): [`bootstrap_credential`] mints a random
//!    temporary password together with the [`PasswordState::initial`] state for it; the service
//!    creates the account with that password, persists [`BootstrapCredential::state`] next to
//!    it and prints [`BootstrapCredential::log_line`] once, on the terminal that ran the
//!    bootstrap.
//! 2. **Login**: read the state back with [`PasswordStateStore::get`] and ask the policy —
//!    `policy.change_requirement(&state, Utc::now())`. `Some(reason)` means the account may do
//!    nothing except change its password (report the reason to the client, e.g.
//!    [`PasswordChangeReason::as_str`]); `None` means continue normally.
//! 3. **Change password**: once the new hash is stored, write [`PasswordState::rotated`]`(now)`
//!    back through [`PasswordStateStore::put`].
//! 4. **Accounts that predate the tracking** (`Ok(None)` from the store) are the service's
//!    call, see [`PasswordStateStore`] — adopt them either as already rotated at their creation
//!    time or as an initial password for a one-off forced rotation.
//!
//! ```
//! use chrono::{Duration, Utc};
//! use kirino::rbac::policy::{
//!     PasswordChangeReason, PasswordPolicy, PasswordState,
//! };
//!
//! let policy = PasswordPolicy::new(true, Some(90));
//! let now = Utc::now();
//!
//! // A bootstrap password that was never rotated must be changed on first login.
//! let minted = PasswordState::initial(now);
//! assert_eq!(
//!     policy.change_requirement(&minted, now),
//!     Some(PasswordChangeReason::InitialPassword),
//! );
//!
//! // A user-chosen password is fine until it reaches the maximum age.
//! let chosen = PasswordState::rotated(now);
//! assert_eq!(policy.change_requirement(&chosen, now), None);
//! assert!(policy
//!     .change_requirement(&chosen, now + Duration::days(90))
//!     .is_some());
//! ```

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;
use uuid::Uuid;

use async_trait::async_trait;

use crate::error::KirinoError;

/// Why an account is required to change its password.
///
/// Callers get a reason rather than a boolean so the two cases can be told apart in an API
/// response (a bootstrap password is a one-time operator secret, an expired password is a
/// routine rotation), in audit records and in operator-facing messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PasswordChangeReason {
    /// The account still carries the temporary password minted at bootstrap; the switch
    /// `force_change_on_first_login` of the policy makes it unusable for anything else.
    InitialPassword,
    /// The password has reached (or passed) the configured maximum age.
    Expired {
        /// Whole days elapsed since the password was last changed.
        age_days: u32,
        /// The configured maximum age that was reached.
        max_age_days: u32,
    },
}

impl PasswordChangeReason {
    /// Stable machine-readable code for API responses and audit records.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InitialPassword => "initial_password",
            Self::Expired { .. } => "expired",
        }
    }
}

impl std::fmt::Display for PasswordChangeReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InitialPassword => f.write_str(self.as_str()),
            Self::Expired {
                age_days,
                max_age_days,
            } => write!(f, "{}({age_days}/{max_age_days}d)", self.as_str()),
        }
    }
}

/// The password policy of one deployment.
///
/// It carries the two rules the product owner asked for — "the bootstrap password must be
/// changed on first login" and "a password must be changed after N days" — behind a master
/// `enabled` switch, so an operator can turn the whole surface off without losing the
/// configured rule values (a kill switch, not a config rewrite).
///
/// Construct it from configuration with [`PasswordPolicy::from_config`] (which rejects the
/// degenerate `max_age_days = 0`), or field-by-field in code with [`PasswordPolicy::new`] and
/// the `with_*` builders. [`Default`] is the product default: the bootstrap rule is **on** and
/// no expiry rule is configured, so a service that wires the policy up but configures nothing
/// still cannot leave a machine-generated password in place. Use [`PasswordPolicy::disabled`]
/// to switch the surface off entirely.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PasswordPolicy {
    enabled: bool,
    force_change_on_first_login: bool,
    max_age_days: Option<u32>,
}

impl PasswordPolicy {
    /// Builds the policy directly: `force_change_on_first_login` is the bootstrap rule,
    /// `max_age_days` the optional expiry rule (`None` = passwords never expire).
    ///
    /// The master switch is on; use [`PasswordPolicy::with_enabled`] or
    /// [`PasswordPolicy::disabled`] to change that.
    ///
    /// `Some(0)` is a degenerate maximum age — every password, including one just set, is
    /// instantly stale — so build from configuration through [`PasswordPolicy::from_config`],
    /// which rejects it.
    #[must_use]
    pub const fn new(force_change_on_first_login: bool, max_age_days: Option<u32>) -> Self {
        Self {
            enabled: true,
            force_change_on_first_login,
            max_age_days,
        }
    }

    /// The kill switch: no rule of this policy is ever applied.
    ///
    /// Every rule is off here rather than merely switched off, because there is nothing to keep.
    /// To suspend an already-configured policy and restore it later, use
    /// [`PasswordPolicy::with_enabled`], which leaves the rule values untouched.
    #[must_use]
    pub const fn disabled() -> Self {
        Self {
            enabled: false,
            force_change_on_first_login: false,
            max_age_days: None,
        }
    }

    /// Builds the policy from configuration values (env vars, CLI flags, config file).
    ///
    /// # Errors
    ///
    /// Returns [`KirinoError::Validation`] when `max_age_days` is `Some(0)`: a zero-day
    /// maximum age would mark every password — including one just set — as expired and trap
    /// the account in a change loop. Omit the value (`None`) to disable the expiry rule.
    pub fn from_config(
        enabled: bool,
        force_change_on_first_login: bool,
        max_age_days: Option<u32>,
    ) -> Result<Self> {
        if max_age_days == Some(0) {
            return Err(KirinoError::Validation(
                "password policy max_age_days must be at least 1 day; omit it to disable expiration"
                    .to_string(),
            )
            .into());
        }
        Ok(Self {
            enabled,
            force_change_on_first_login,
            max_age_days,
        })
    }

    /// Turns the whole policy on or off without touching the configured rule values.
    #[must_use]
    pub const fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Sets the bootstrap rule ("change the machine-generated password on first login").
    #[must_use]
    pub const fn with_force_change_on_first_login(mut self, force: bool) -> Self {
        self.force_change_on_first_login = force;
        self
    }

    /// Sets the expiry rule ("change the password after `days` days").
    ///
    /// `0` is degenerate (instant expiry) and is only meaningful in tests; configure through
    /// [`PasswordPolicy::from_config`] to have it rejected.
    #[must_use]
    pub const fn with_max_age_days(mut self, days: u32) -> Self {
        self.max_age_days = Some(days);
        self
    }

    /// Whether the policy applies at all (the master switch).
    #[must_use]
    pub const fn is_enabled(self) -> bool {
        self.enabled
    }

    /// Whether the bootstrap rule is on.
    #[must_use]
    pub const fn force_change_on_first_login(self) -> bool {
        self.force_change_on_first_login
    }

    /// The configured maximum password age, if the expiry rule is on.
    #[must_use]
    pub const fn max_age_days(self) -> Option<u32> {
        self.max_age_days
    }

    /// Decides whether `state` needs a password change at `now`, and why.
    ///
    /// Pure: the caller injects the clock, so the decision is deterministic and replayable.
    /// Precedence is bootstrap first, then expiry — an unrotated bootstrap password is
    /// reported as [`PasswordChangeReason::InitialPassword`] even when it is also old, because
    /// "this is still the operator's one-time secret" is the actionable fact.
    ///
    /// Boundary: the expiry rule is inclusive, i.e. a password that has reached **exactly**
    /// `max_age_days` (whole days elapsed) is already stale — `age_days >= max_age_days`
    /// requires a change, there is no extra grace day. Partial days are truncated, so the rule
    /// fires on the `max_age_days`-th day after the change. Timestamps in the future (clock
    /// skew) are treated as age zero, never as expired.
    #[must_use]
    pub fn change_requirement(
        &self,
        state: &PasswordState,
        now: DateTime<Utc>,
    ) -> Option<PasswordChangeReason> {
        if !self.enabled {
            return None;
        }
        if self.force_change_on_first_login && state.is_initial() {
            return Some(PasswordChangeReason::InitialPassword);
        }
        if let Some(max_age_days) = self.max_age_days {
            let age_days = state.age_days(now);
            if age_days >= max_age_days {
                return Some(PasswordChangeReason::Expired {
                    age_days,
                    max_age_days,
                });
            }
        }
        None
    }
}

impl Default for PasswordPolicy {
    /// Product default: bootstrap passwords must be changed on first login, no expiry rule.
    fn default() -> Self {
        Self::new(true, None)
    }
}

/// The recorded password state of one account.
///
/// A consumer persists both facts next to the account (`UserRecord` in
/// [`crate::service::login`] does not carry them yet, see [`PasswordStateStore`]): whether the
/// stored hash is still the bootstrap/temporary password, and when the password was last set.
/// Services that do not persist it cannot enforce either rule, because neither fact can be
/// derived from a password hash or from `UserRecord::updated_at` (which any profile edit
/// moves).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasswordState {
    is_initial: bool,
    changed_at: DateTime<Utc>,
}

impl PasswordState {
    /// State of an account whose current password was minted by the bootstrap (temporary).
    #[must_use]
    pub const fn initial(changed_at: DateTime<Utc>) -> Self {
        Self {
            is_initial: true,
            changed_at,
        }
    }

    /// State of an account whose current password was chosen by the user.
    #[must_use]
    pub const fn rotated(changed_at: DateTime<Utc>) -> Self {
        Self {
            is_initial: false,
            changed_at,
        }
    }

    /// Rehydrates a state read back from storage.
    #[must_use]
    pub const fn from_parts(changed_at: DateTime<Utc>, is_initial: bool) -> Self {
        Self {
            is_initial,
            changed_at,
        }
    }

    /// Whether the stored hash is still the bootstrap/temporary password.
    #[must_use]
    pub const fn is_initial(self) -> bool {
        self.is_initial
    }

    /// When the password was last set.
    #[must_use]
    pub const fn changed_at(self) -> DateTime<Utc> {
        self.changed_at
    }

    /// Whole days since the password was last set, saturating at zero for future timestamps.
    #[must_use]
    pub fn age_days(self, now: DateTime<Utc>) -> u32 {
        let elapsed = now.signed_duration_since(self.changed_at);
        u32::try_from(elapsed.num_days().max(0)).unwrap_or(u32::MAX)
    }
}

/// Persistence surface for [`PasswordState`].
///
/// Kirino keeps no schema of its own (`PasswordState` is a plain serializable value and the
/// in-memory implementation below is the reference), so a consuming service stores the pair in
/// whatever it already uses for auth state — typically two columns (`password_is_initial`,
/// `password_changed_at`) on its user table, next to the password hash.
///
/// `get` returning `Ok(None)` means the account has no recorded password state: a row that
/// predates this feature, or an account created outside kirino. The kernel does not guess —
/// a deployment that wants no mass lockout adopts such accounts with the password age it can
/// already justify, e.g. `PasswordState::rotated(user.created_at)`, and a deployment that
/// wants a one-off forced rotation adopts them as `PasswordState::initial(now)`.
#[async_trait]
pub trait PasswordStateStore: Send + Sync {
    /// Returns the recorded state, or `None` when the account has none yet.
    async fn get(&self, account: &Uuid) -> Result<Option<PasswordState>>;

    /// Records (or replaces) the state of one account.
    async fn put(&self, account: &Uuid, state: PasswordState) -> Result<()>;
}

/// In-memory [`PasswordStateStore`], the reference implementation for tests and single-node
/// deployments; mirror it with a table-backed store in production like kirino's other stores.
#[derive(Clone, Default)]
pub struct InMemoryPasswordStateStore {
    states: Arc<RwLock<HashMap<Uuid, PasswordState>>>,
}

impl InMemoryPasswordStateStore {
    /// Creates an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl PasswordStateStore for InMemoryPasswordStateStore {
    async fn get(&self, account: &Uuid) -> Result<Option<PasswordState>> {
        Ok(self.states.read().await.get(account).copied())
    }

    async fn put(&self, account: &Uuid, state: PasswordState) -> Result<()> {
        self.states.write().await.insert(*account, state);
        Ok(())
    }
}

/// A first-run bootstrap credential: the temporary password plus the [`PasswordState`] the
/// account must be created with.
///
/// The password is random on every call (never a fixed literal) and is meant to be shown once,
/// to the operator, on the terminal that ran the bootstrap.
#[derive(Clone)]
pub struct BootstrapCredential {
    username: String,
    password: String,
    state: PasswordState,
}

impl BootstrapCredential {
    /// The account name the password was minted for.
    #[must_use]
    pub fn username(&self) -> &str {
        &self.username
    }

    /// The temporary password, for the one-time operator hand-off.
    #[must_use]
    pub fn password(&self) -> &str {
        &self.password
    }

    /// The state to persist with the account: an unrotated bootstrap password.
    #[must_use]
    pub const fn state(&self) -> PasswordState {
        self.state
    }

    /// The operator-facing log line, for a CLI that prints to stdout/stderr without `tracing`.
    ///
    /// It contains the temporary password on purpose — that is the only hand-off channel for a
    /// machine-generated first-run secret. Print it once, on the bootstrap run only; a service
    /// must never persist it to a tracked file or re-emit it on later starts.
    #[must_use]
    pub fn log_line(&self) -> String {
        format!(
            "temporary password for '{}': {} — change it on first login",
            self.username, self.password
        )
    }

    /// Emits [`BootstrapCredential::log_line`] through `tracing` at warn level.
    ///
    /// Warn (not info) so it survives a shutdown quieting of the log level, and so an operator
    /// cannot miss a credential the install is waiting on.
    pub fn emit_log(&self) {
        tracing::warn!(
            target: "kirino::rbac::policy",
            username = %self.username,
            temporary_password = %self.password,
            "bootstrap temporary password issued; the account must change it on first login"
        );
    }
}

impl std::fmt::Debug for BootstrapCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BootstrapCredential")
            .field("username", &self.username)
            .field("password", &"[redacted]")
            .field("state", &self.state)
            .finish()
    }
}

/// Mints the first-run bootstrap credential for `username`.
///
/// Generates a random temporary password (see
/// [`generate_temporary_password`](crate::auth::passport::static_password::generate_temporary_password))
/// and marks it as an initial password, so that a policy built with
/// `force_change_on_first_login` — the [`PasswordPolicy::default`] — forces the change on the
/// account's first login. The caller creates the account with this password and persists
/// [`BootstrapCredential::state`] alongside it.
///
/// This is the whole bootstrap contract for a CLI: mint, store the state, print the line once.
///
/// ```text
/// // First install (no user in the database yet):
/// let credential = bootstrap_credential("admin", Utc::now());
/// db.create_user(&UserRecord { password_hash: hash_password(credential.password())?, .. });
/// store.put(&user_id, credential.state()).await?;
/// credential.emit_log(); // prints the temporary password exactly once
/// ```
#[cfg(feature = "auth-password")]
#[must_use]
pub fn bootstrap_credential(username: &str, now: DateTime<Utc>) -> BootstrapCredential {
    BootstrapCredential {
        username: username.to_string(),
        password: crate::auth::passport::static_password::generate_temporary_password(),
        state: PasswordState::initial(now),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn at() -> PasswordPolicy {
        PasswordPolicy::new(true, Some(90))
    }

    #[test]
    fn test_initial_password_requires_change() {
        let now = Utc::now();
        let policy = at();
        assert_eq!(
            policy.change_requirement(&PasswordState::initial(now), now),
            Some(PasswordChangeReason::InitialPassword)
        );
    }

    #[test]
    fn test_initial_password_with_switch_off_is_accepted() {
        let now = Utc::now();
        let policy = PasswordPolicy::new(false, None);
        assert_eq!(
            policy.change_requirement(&PasswordState::initial(now), now),
            None
        );
    }

    #[test]
    fn test_disabled_policy_never_requires_change() {
        let now = Utc::now();
        let policy = PasswordPolicy::new(true, Some(30)).with_enabled(false);
        assert!(!policy.is_enabled());
        assert_eq!(
            policy.change_requirement(&PasswordState::initial(now), now),
            None
        );
        assert_eq!(
            policy.change_requirement(&PasswordState::rotated(now - Duration::days(3650)), now),
            None
        );
        assert_eq!(
            PasswordPolicy::disabled().change_requirement(&PasswordState::initial(now), now),
            None
        );
    }

    #[test]
    fn test_rotated_password_not_required_when_fresh() {
        let now = Utc::now();
        let policy = at();
        assert_eq!(
            policy.change_requirement(&PasswordState::rotated(now), now),
            None
        );
        assert_eq!(
            policy.change_requirement(&PasswordState::rotated(now - Duration::days(89)), now),
            None
        );
    }

    #[test]
    fn test_expiry_boundary_at_exact_limit_is_stale() {
        let now = Utc::now();
        let policy = PasswordPolicy::new(false, Some(90));
        let state = PasswordState::rotated(now - Duration::days(90));
        assert_eq!(
            policy.change_requirement(&state, now),
            Some(PasswordChangeReason::Expired {
                age_days: 90,
                max_age_days: 90
            })
        );
    }

    #[test]
    fn test_expiry_boundary_one_second_before_limit_is_fresh() {
        let now = Utc::now();
        let policy = PasswordPolicy::new(false, Some(90));
        let state = PasswordState::rotated(now - Duration::days(90) + Duration::seconds(1));
        assert_eq!(policy.change_requirement(&state, now), None);
        assert_eq!(state.age_days(now), 89);
    }

    #[test]
    fn test_expiry_truncates_partial_days() {
        let now = Utc::now();
        let policy = PasswordPolicy::new(false, Some(7));
        // 6 days 23 hours: still day 6, not yet stale.
        let state = PasswordState::rotated(now - Duration::days(6) - Duration::hours(23));
        assert_eq!(state.age_days(now), 6);
        assert_eq!(policy.change_requirement(&state, now), None);
        // 7 days 0 hours: stale (inclusive boundary).
        let state = PasswordState::rotated(now - Duration::days(7));
        assert!(policy.change_requirement(&state, now).is_some());
    }

    #[test]
    fn test_future_timestamp_is_age_zero_never_expired() {
        let now = Utc::now();
        let policy = PasswordPolicy::new(false, Some(1));
        let state = PasswordState::rotated(now + Duration::days(30));
        assert_eq!(state.age_days(now), 0);
        assert_eq!(policy.change_requirement(&state, now), None);
    }

    #[test]
    fn test_initial_reason_wins_over_expiry() {
        let now = Utc::now();
        let policy = at();
        let state = PasswordState::initial(now - Duration::days(400));
        assert_eq!(
            policy.change_requirement(&state, now),
            Some(PasswordChangeReason::InitialPassword)
        );
    }

    #[test]
    fn test_default_policy_forces_bootstrap_change_only() {
        let now = Utc::now();
        let policy = PasswordPolicy::default();
        assert!(policy.is_enabled());
        assert!(policy.force_change_on_first_login());
        assert_eq!(policy.max_age_days(), None);
        assert_eq!(
            policy.change_requirement(&PasswordState::initial(now), now),
            Some(PasswordChangeReason::InitialPassword)
        );
        // No expiry rule: an ancient user-chosen password is left alone.
        assert_eq!(
            policy.change_requirement(&PasswordState::rotated(now - Duration::days(3650)), now),
            None
        );
    }

    #[test]
    fn test_from_config_round_trip() {
        let policy = PasswordPolicy::from_config(true, true, Some(45)).unwrap();
        assert!(policy.is_enabled());
        assert!(policy.force_change_on_first_login());
        assert_eq!(policy.max_age_days(), Some(45));

        let off = PasswordPolicy::from_config(false, true, Some(45)).unwrap();
        assert!(!off.is_enabled());
        assert_eq!(off.max_age_days(), Some(45));

        let no_expiry = PasswordPolicy::from_config(true, false, None).unwrap();
        assert_eq!(no_expiry.max_age_days(), None);
    }

    #[test]
    fn test_from_config_rejects_zero_max_age() {
        let err = PasswordPolicy::from_config(true, true, Some(0)).unwrap_err();
        assert!(err
            .downcast_ref::<KirinoError>()
            .is_some_and(|e| matches!(e, KirinoError::Validation(_))));
    }

    #[test]
    fn test_serde_defaults_fill_missing_config_keys() {
        let bare: PasswordPolicy = serde_json::from_str("{}").unwrap();
        assert_eq!(bare, PasswordPolicy::default());

        let configured: PasswordPolicy =
            serde_json::from_str(r#"{"enabled":false,"max_age_days":30}"#).unwrap();
        assert!(!configured.is_enabled());
        assert!(configured.force_change_on_first_login());
        assert_eq!(configured.max_age_days(), Some(30));

        let round_trip: PasswordPolicy =
            serde_json::from_str(&serde_json::to_string(&configured).unwrap()).unwrap();
        assert_eq!(round_trip, configured);
    }

    #[test]
    fn test_state_serde_round_trip() {
        let now = Utc::now();
        let state = PasswordState::from_parts(now, true);
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(serde_json::from_str::<PasswordState>(&json).unwrap(), state);
        assert!(state.is_initial());
        assert_eq!(state.changed_at(), now);
    }

    #[test]
    fn test_reason_codes() {
        assert_eq!(
            PasswordChangeReason::InitialPassword.as_str(),
            "initial_password"
        );
        assert_eq!(
            PasswordChangeReason::Expired {
                age_days: 91,
                max_age_days: 90
            }
            .as_str(),
            "expired"
        );
        assert_eq!(
            PasswordChangeReason::InitialPassword.to_string(),
            "initial_password"
        );
        assert_eq!(
            PasswordChangeReason::Expired {
                age_days: 91,
                max_age_days: 90
            }
            .to_string(),
            "expired(91/90d)"
        );
    }

    #[tokio::test]
    async fn test_store_round_trip() {
        let store = InMemoryPasswordStateStore::new();
        let account = Uuid::now_v7();
        let now = Utc::now();

        assert_eq!(store.get(&account).await.unwrap(), None);

        let state = PasswordState::initial(now);
        store.put(&account, state).await.unwrap();
        assert_eq!(store.get(&account).await.unwrap(), Some(state));

        let rotated = PasswordState::rotated(now);
        store.put(&account, rotated).await.unwrap();
        assert_eq!(store.get(&account).await.unwrap(), Some(rotated));

        assert_eq!(store.get(&Uuid::now_v7()).await.unwrap(), None);
    }

    #[cfg(feature = "auth-password")]
    mod bootstrap {
        use super::*;
        use crate::auth::passport::static_password::TEMPORARY_PASSWORD_LEN;
        use crate::service::login::validate_password;

        #[test]
        fn test_bootstrap_credential_is_initial_and_valid() {
            let now = Utc::now();
            let credential = bootstrap_credential("admin", now);

            assert_eq!(credential.username(), "admin");
            assert_eq!(credential.state(), PasswordState::initial(now));
            assert_eq!(
                credential.password().chars().count(),
                TEMPORARY_PASSWORD_LEN
            );
            validate_password(credential.password()).unwrap();
        }

        #[test]
        fn test_bootstrap_credential_is_random() {
            let a = bootstrap_credential("admin", Utc::now());
            let b = bootstrap_credential("admin", Utc::now());
            assert_ne!(
                a.password(),
                b.password(),
                "a generated temporary password must never be a fixed literal"
            );
        }

        #[test]
        fn test_bootstrap_credential_forces_change_under_default_policy() {
            let now = Utc::now();
            let credential = bootstrap_credential("admin", now);
            assert_eq!(
                PasswordPolicy::default().change_requirement(&credential.state(), now),
                Some(PasswordChangeReason::InitialPassword)
            );
        }

        #[test]
        fn test_bootstrap_debug_redacts_password_and_log_line_carries_it() {
            let credential = bootstrap_credential("admin", Utc::now());
            let debug = format!("{credential:?}");
            assert!(debug.contains("[redacted]"));
            assert!(!debug.contains(credential.password()));
            assert!(credential.log_line().contains(credential.password()));
            assert!(credential.log_line().contains("admin"));
        }
    }
}
