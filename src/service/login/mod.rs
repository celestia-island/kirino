use anyhow::Result;
use chrono::Utc;
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Instant,
};
use tokio::sync::RwLock;
use uuid::Uuid;

#[cfg(feature = "auth-jwt")]
use crate::auth::credential::basic::JwtManager;
#[cfg(feature = "auth-password")]
use crate::auth::passport::static_password::{hash_password, verify_password};
#[cfg(feature = "rbac-dynamic")]
use crate::rbac::dynamic::arbiter::AuthorizationArbiter;
#[cfg(all(feature = "auth-password", feature = "auth-jwt"))]
use crate::rbac::traits::AssignmentStore;
use crate::{
    error::KirinoError,
    models::identity::Identity,
    rbac::{
        engine::RbacEngine,
        shared::Shared,
        store::{
            memory::InMemoryAssignmentStore,
            registry::{SimpleRole, StaticPermissionRegistry, StaticRoleRegistry},
        },
        subject::StringSubject,
        traits::Permission,
    },
};

#[derive(Debug, Clone)]
struct RateLimitEntry {
    attempts: u32,
    window_start: Instant,
}

/// Fixed-window rate limiter keyed by an opaque string (a username).
///
/// A key accumulates failures; after `max_attempts` failures within
/// `window_secs` the key stays blocked until `window_secs + lockout_secs` have
/// elapsed since the window opened. Two properties shape the threat model:
///
/// - It is per key, not per source address. It slows guessing against one account,
///   but does not by itself stop a spray across many usernames, and anyone who
///   knows a victim's username can use it to keep that account locked out.
/// - State is in-process and unshared. N replicas allow N times the attempts, and a
///   restart clears every lockout, so a deployment that needs a hard guarantee must
///   put a shared limiter (or per-IP limiting) in front of this one.
///
/// The limiter is also not an existence oracle: it counts attempts for any key,
/// whether or not the account exists, and its error carries no account state.
pub struct LoginRateLimiter {
    max_attempts: u32,
    window_secs: u64,
    lockout_secs: u64,
    entries: Arc<RwLock<HashMap<String, RateLimitEntry>>>,
}

/// Minimum password length in bytes, enforced by [`validate_password`].
///
/// 8 is the NIST SP 800-63B minimum password length; the length floor, not the
/// character-class rule below, is the control that actually raises guessing cost.
const MIN_PASSWORD_LEN: usize = 8;
/// Maximum password length in bytes.
///
/// Bounds how much attacker-controlled input reaches the Argon2id work function.
/// The 19 MiB memory cost is fixed, so a huge password cannot amplify memory much,
/// but it would still be hashed on every attempt; 128 keeps that cost flat and is
/// generous for both a passphrase and a password-manager value.
const MAX_PASSWORD_LEN: usize = 128;
/// Minimum username length in bytes; a local policy choice (shortest meaningful
/// operator-chosen name), not a security control - basis to be confirmed with
/// security review if any downstream treats it as one.
const MIN_USERNAME_LEN: usize = 2;
/// Maximum username length in bytes.
///
/// Bounds the size of every derived identifier: rate-limiter bucket key (see
/// [`RATE_LIMITER_MAX_ENTRIES`]), audit subject id, store rows and log lines.
const MAX_USERNAME_LEN: usize = 64;

/// Normalize and validate a username, returning the trimmed canonical form.
///
/// Accepts 2..=64 bytes of `[A-Za-z0-9._-]` after trimming, which keeps path
/// separators, whitespace, quotes and shell metacharacters out of every
/// downstream store, log line and file name. The caller must use the returned
/// value - not the input - as the identity, otherwise the rate limiter and the
/// user table can disagree on what the "same" username is.
///
/// # Errors
///
/// [`KirinoError::Validation`] when the trimmed value is empty or too short, too
/// long, or contains a character outside the allowed set.
pub fn validate_username(username: &str) -> Result<String> {
    let trimmed = username.trim();
    if trimmed.is_empty() || trimmed.len() < MIN_USERNAME_LEN {
        return Err(KirinoError::Validation(format!(
            "username must be at least {MIN_USERNAME_LEN} characters"
        ))
        .into());
    }
    if trimmed.len() > MAX_USERNAME_LEN {
        return Err(KirinoError::Validation(format!(
            "username must be at most {MAX_USERNAME_LEN} characters"
        ))
        .into());
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
    {
        return Err(KirinoError::Validation(
            "username may only contain alphanumeric characters, underscores, hyphens, and dots"
                .to_string(),
        )
        .into());
    }
    Ok(trimmed.to_string())
}

/// Enforce the password policy: 8..=128 bytes and at least 3 of the 4 character
/// classes (uppercase, lowercase, digit, non-alphanumeric).
///
/// Lengths are counted in bytes, not characters, so a non-ASCII passphrase can
/// clear the floor with fewer than eight characters. The composition rule is a
/// local policy choice - NIST SP 800-63B prefers length and breach checks over
/// composition - and its basis is to be confirmed with security review. This
/// function only checks shape: it cannot tell whether a password is breached,
/// reused or otherwise known.
///
/// # Errors
///
/// [`KirinoError::Validation`] when the length or the class count is out of
/// policy.
pub fn validate_password(password: &str) -> Result<()> {
    if password.len() < MIN_PASSWORD_LEN {
        return Err(KirinoError::Validation(format!(
            "password must be at least {MIN_PASSWORD_LEN} characters"
        ))
        .into());
    }
    if password.len() > MAX_PASSWORD_LEN {
        return Err(KirinoError::Validation(format!(
            "password must be at most {MAX_PASSWORD_LEN} characters"
        ))
        .into());
    }

    let has_uppercase = password.chars().any(|c| c.is_uppercase());
    let has_lowercase = password.chars().any(|c| c.is_lowercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_special = password.chars().any(|c| !c.is_alphanumeric());

    let categories = [has_uppercase, has_lowercase, has_digit, has_special]
        .iter()
        .filter(|&&x| x)
        .count();

    if categories < 3 {
        return Err(KirinoError::Validation(
            "password must contain at least 3 of: uppercase, lowercase, digit, special character"
                .to_string(),
        )
        .into());
    }

    Ok(())
}

/// Soft cap on how many rate-limit buckets a [`LoginRateLimiter`] tracks.
///
/// At the cap the limiter first drops buckets whose window has fully elapsed and
/// then inserts the new key unconditionally, so this is a memory-hygiene bound,
/// not a hard ceiling: a burst of distinct usernames (credential stuffing, or a
/// scanner walking the namespace) keeps every live bucket and can push the map
/// past 10k. Keys are attacker-supplied and, on the login path, only trimmed -
/// the number of distinct keys is not bounded by the user table, and neither is
/// key length, so both are unbounded inputs and the real ceiling is process
/// memory. Because only elapsed buckets are pruned, the cap can never shorten an
/// active lockout: the failure mode it permits is memory growth, not a weakened
/// block. 10k matches the in-memory audit sink and TTL permission cache
/// defaults, so one process's in-memory security state has a single predictable
/// ceiling; the number itself has no recorded derivation and is to be confirmed
/// with security review before being treated as a DoS control.
const RATE_LIMITER_MAX_ENTRIES: usize = 10_000;

impl LoginRateLimiter {
    /// Create a limiter allowing `max_attempts` failures per `window_secs`, then
    /// blocking the key for `lockout_secs`.
    ///
    /// The three numbers are policy, not derived constants: size them from the
    /// legitimate retry rate (a human mistyping a password) against the online
    /// guessing budget the deployment accepts, and record the reasoning here when
    /// changing them. [`AuthService::new`] constructs the login and registration
    /// limiters with the crate's defaults.
    #[must_use]
    pub fn new(max_attempts: u32, window_secs: u64, lockout_secs: u64) -> Self {
        Self {
            max_attempts,
            window_secs,
            lockout_secs,
            entries: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Record one failed attempt for `key`, failing while the key is blocked.
    ///
    /// The window is fixed, not sliding: it opens on the first counted failure and is
    /// reset once `window_secs + lockout_secs` have elapsed, or once the window has
    /// passed with fewer than `max_attempts` failures. The counter only advances on
    /// this path, so a successful authentication must call
    /// [`LoginRateLimiter::reset`] (the [`AuthService`] login path does); otherwise
    /// earlier failures keep counting against the key until the window rolls over.
    ///
    /// # Errors
    ///
    /// [`KirinoError::Validation`] while the key is inside its lockout window. The
    /// message states only how long to wait - it never reveals account state and
    /// must stay that way, since callers surface it to unauthenticated clients.
    pub async fn check_and_record_failure(&self, key: &str) -> Result<()> {
        let mut entries = self.entries.write().await;
        let now = Instant::now();

        if entries.len() >= RATE_LIMITER_MAX_ENTRIES {
            let total_window = std::time::Duration::from_secs(self.window_secs + self.lockout_secs);
            entries.retain(|_, entry| now.duration_since(entry.window_start) <= total_window);
        }

        let entry = entries.entry(key.to_string()).or_insert(RateLimitEntry {
            attempts: 0,
            window_start: now,
        });

        let elapsed = now.duration_since(entry.window_start);
        let total_window = std::time::Duration::from_secs(self.window_secs + self.lockout_secs);
        let window_duration = std::time::Duration::from_secs(self.window_secs);

        let should_reset = elapsed > total_window
            || (elapsed > window_duration && entry.attempts < self.max_attempts);

        if should_reset {
            entry.attempts = 0;
            entry.window_start = now;
        }

        if entry.attempts >= self.max_attempts {
            let remaining = total_window.saturating_sub(elapsed);
            if remaining > std::time::Duration::ZERO {
                return Err(KirinoError::Validation(format!(
                    "too many login attempts, try again in {} seconds",
                    remaining.as_secs()
                ))
                .into());
            }
            entry.attempts = 0;
            entry.window_start = now;
        }

        entry.attempts += 1;
        Ok(())
    }

    /// Forget `key`'s failures, clearing any active lockout.
    ///
    /// Call it only after the identity has actually been proven (a successful login
    /// or registration). Resetting on an unverified request would let an attacker
    /// clear the counter at will.
    pub async fn reset(&self, key: &str) {
        let mut entries = self.entries.write().await;
        entries.remove(key);
    }
}

#[derive(Clone)]
pub struct UserRecord {
    pub id: Uuid,
    pub username: String,
    pub(crate) password_hash: String,
    pub display_name: Option<String>,
    pub is_active: bool,
    pub identity: Identity,
    pub created_at: chrono::DateTime<Utc>,
    pub updated_at: chrono::DateTime<Utc>,
}

impl std::fmt::Debug for UserRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserRecord")
            .field("id", &self.id)
            .field("username", &self.username)
            .field("password_hash", &"[redacted]")
            .field("display_name", &self.display_name)
            .field("is_active", &self.is_active)
            .field("identity", &self.identity)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

impl UserRecord {
    #[must_use]
    pub fn to_public(&self) -> UserInfo {
        UserInfo {
            id: self.id,
            username: self.username.clone(),
            display_name: self.display_name.clone(),
            is_active: self.is_active,
            identity: self.identity.clone(),
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

#[derive(Debug, Clone)]
pub struct UserInfo {
    pub id: Uuid,
    pub username: String,
    pub display_name: Option<String>,
    pub is_active: bool,
    pub identity: Identity,
    pub created_at: chrono::DateTime<Utc>,
    pub updated_at: chrono::DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct LoginResult {
    pub token: String,
    pub user_id: String,
    pub username: String,
    pub display_name: Option<String>,
    pub roles: Vec<String>,
    #[cfg(feature = "auth-jwt")]
    pub session_id: Option<uuid::Uuid>,
}

/// Authentication service: registration, login, JWT issuance and password change.
///
/// # First user and the invitation-only model
///
/// The deployment model is invitation-only: accounts are created by an administrator who
/// already holds `rbac.manage`, so a fresh install normally has nobody who can administer it.
/// The **first** account is therefore a deliberate, narrow exemption from that model — it is
/// created without an invitation and it must be able to administer the install, otherwise the
/// install cannot be operated at all. This is an exemption, not a change of the model: the
/// second and every later account goes through the normal invitation path.
///
/// The exemption is opt-in, because the kernel cannot know whether an install bootstraps
/// itself or is seeded by an operator out of band:
///
/// * [`AuthService::new`] starts with the exemption **off** (`auto_admin_first_user = false`),
///   so the first account gets `default_role`.
/// * [`AuthService::with_auto_admin_first_user(true)`](AuthService::with_auto_admin_first_user)
///   turns it on: the first account that is registered against an empty user table receives
///   `first_user_role` (conventionally `"admin"`) instead of `default_role`.
///
/// A consumer that wants the forced behaviour must therefore set the switch explicitly; the
/// opt-in is visible in `examples/auth_service.rs` of this repository and in the workspace
/// services. The grant is guarded by both an in-process latch and an empty-table check, so it
/// can only ever hand out one first-user role, and it is applied to registration only: logging
/// in never changes a role.
#[cfg(all(feature = "auth-password", feature = "auth-jwt"))]
pub struct AuthService<DB, P, A>
where
    P: Permission,
    A: AssignmentStore<StringSubject, P>,
{
    db: DB,
    jwt: JwtManager,
    engine: Shared<RbacEngine<StringSubject, P, A>>,
    #[cfg(feature = "rbac-dynamic")]
    arbiter: Option<Shared<AuthorizationArbiter>>,
    rate_limiter: LoginRateLimiter,
    register_rate_limiter: LoginRateLimiter,
    first_user_role: String,
    default_role: String,
    auto_admin_first_user: bool,
    has_first_user: std::sync::atomic::AtomicBool,
}

#[cfg(all(feature = "auth-password", feature = "auth-jwt"))]
impl<DB, P, A> AuthService<DB, P, A>
where
    DB: UserDatabase,
    P: Permission,
    A: AssignmentStore<StringSubject, P>,
{
    pub fn new(
        db: DB,
        jwt_secret: &str,
        jwt_expiration_hours: i64,
        engine: Shared<RbacEngine<StringSubject, P, A>>,
        first_user_role: &str,
        default_role: &str,
    ) -> Result<Self> {
        Ok(Self {
            db,
            jwt: JwtManager::new(jwt_secret, jwt_expiration_hours)?,
            engine,
            #[cfg(feature = "rbac-dynamic")]
            arbiter: None,
            // Login: 5 failures per 300 s window, then a 900 s lockout. Rationale:
            // five covers a human mistyping a password a few times, while staying far
            // below what an online guessing session would need; the lockout is 3x the
            // window so the block outlives the observation period instead of expiring
            // with it. The exact numbers have no recorded derivation - treat them as
            // tunable policy defaults pending confirmation with security review.
            rate_limiter: LoginRateLimiter::new(5, 300, 900),
            // Registration: 3 failures per 300 s window, then a 1800 s lockout.
            // Stricter than login because account creation is not a repeated human
            // action and is the more attractive automation target (mass registration,
            // name squatting). A rejected duplicate name also counts as a failure,
            // since only a successful registration resets the key. Same caveat as
            // above: defaults without a recorded derivation, pending security review.
            register_rate_limiter: LoginRateLimiter::new(3, 300, 1800),
            first_user_role: first_user_role.to_string(),
            default_role: default_role.to_string(),
            auto_admin_first_user: false,
            has_first_user: std::sync::atomic::AtomicBool::new(false),
        })
    }

    #[must_use]
    pub fn with_rate_limiter(mut self, limiter: LoginRateLimiter) -> Self {
        self.rate_limiter = limiter;
        self
    }

    /// Enables the first-user exemption from the invitation-only model.
    ///
    /// With `enabled = true`, the first account registered against an empty user table is
    /// assigned `first_user_role` (conventionally `"admin"`) instead of `default_role`, so a
    /// fresh install has an administrator without an invitation. This is the only exemption:
    /// every later account goes through the normal invitation path. The default is `false`
    /// (opt-in), see the [`AuthService`] type docs for the rationale.
    #[must_use]
    pub fn with_auto_admin_first_user(mut self, enabled: bool) -> Self {
        self.auto_admin_first_user = enabled;
        self
    }

    #[must_use]
    #[cfg(feature = "rbac-dynamic")]
    pub fn with_arbiter(mut self, arbiter: AuthorizationArbiter) -> Self {
        self.arbiter = Some(Shared::new(arbiter));
        self
    }

    #[cfg(feature = "rbac-dynamic")]
    #[must_use]
    pub fn arbiter(&self) -> Option<Shared<AuthorizationArbiter>> {
        self.arbiter.clone()
    }

    #[must_use]
    pub fn jwt_manager(&self) -> &JwtManager {
        &self.jwt
    }

    #[must_use]
    pub fn engine(&self) -> Shared<RbacEngine<StringSubject, P, A>> {
        self.engine.clone()
    }

    pub async fn register(
        &self,
        username: &str,
        password: &str,
        display_name: Option<&str>,
    ) -> Result<UserInfo> {
        let username = validate_username(username)?;
        validate_password(password)?;

        self.register_rate_limiter
            .check_and_record_failure(&username)
            .await?;

        let result = self.register_impl(&username, password, display_name).await;

        if result.is_ok() {
            self.register_rate_limiter.reset(&username).await;
        }
        result
    }

    async fn register_impl(
        &self,
        username: &str,
        password: &str,
        display_name: Option<&str>,
    ) -> Result<UserInfo> {
        if self.db.find_by_username(username).await?.is_some() {
            return Err(KirinoError::Validation("username already exists".to_string()).into());
        }

        let password_hash = hash_password(password)?;
        let user_id = Uuid::now_v7();
        let now = Utc::now();
        let identity = Identity::Basic {
            id: user_id,
            created_at: now,
        };

        let user = UserRecord {
            id: user_id,
            username: username.to_string(),
            password_hash,
            display_name: display_name.map(ToString::to_string),
            is_active: true,
            identity,
            created_at: now,
            updated_at: now,
        };

        let is_first = self.auto_admin_first_user
            && !self
                .has_first_user
                .swap(true, std::sync::atomic::Ordering::SeqCst)
            && self.db.count_users().await? == 0;

        self.db.create_user(&user).await?;

        let role_name = if is_first {
            &self.first_user_role
        } else {
            &self.default_role
        };

        let subject = StringSubject::new(user_id.to_string());
        self.engine
            .assignment_store()
            .assign_role(&subject, role_name)
            .await?;

        Ok(user.to_public())
    }

    // A well-formed Argon2id hash with an all-zero salt, verified against when the
    // username does not exist so that path pays the same hashing cost as a real
    // wrong-password check (see `authenticate_user`). Its m/t/p must match
    // `static_password::ARGON2_*` or the unknown-user path becomes measurably
    // cheaper than the known-user one, restoring the enumeration oracle. Removing
    // the verification would do the same.
    const DUMMY_HASH: &str =
        "$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    async fn authenticate_user(&self, username: &str, password: &str) -> Result<UserRecord> {
        let Some(user) = self.db.find_by_username(username).await? else {
            if let Err(e) = verify_password(password, Self::DUMMY_HASH) {
                tracing::error!(target: "kirino::service::login",
                    error = %e,
                    "dummy hash verification failed"
                );
            }
            return Err(KirinoError::AuthenticationFailed.into());
        };

        if !user.is_active {
            // Timing equalization, not authentication: the deactivated-account path
            // must pay the same Argon2id cost as a wrong password on an active
            // account, otherwise response time becomes an account-state oracle
            // (the unknown-user branch above does the equivalent with DUMMY_HASH).
            // The result is intentionally discarded, and the cost is only paid if
            // `password_hash` is a valid PHC string - which `hash_password`
            // guarantees for anything stored through this crate. Do not remove this
            // call or turn it into an early return.
            let _ = verify_password(password, &user.password_hash);
            return Err(KirinoError::AuthenticationFailed.into());
        }

        if !verify_password(password, &user.password_hash)? {
            return Err(KirinoError::AuthenticationFailed.into());
        }

        self.rate_limiter.reset(username).await;
        Ok(user)
    }

    async fn fetch_user_roles_and_perms(
        &self,
        user_id: &str,
    ) -> Result<(Vec<String>, Vec<String>)> {
        let subject = StringSubject::new(user_id);
        let roles = self
            .engine
            .assignment_store()
            .roles_of(&subject)
            .await
            .map_err(|e| {
                tracing::warn!("failed to fetch roles for user {user_id}: {e}");
                KirinoError::AuthorizationDenied("store unavailable".into())
            })?;

        let perm_names: Vec<String> = self
            .engine
            .effective_permissions(&subject)
            .await
            .map_err(|e| {
                tracing::warn!("failed to fetch effective permissions: {e}");
                KirinoError::AuthorizationDenied("store unavailable".into())
            })?
            .into_iter()
            .map(|p| p.name().to_string())
            .collect();

        Ok((roles, perm_names))
    }

    pub async fn login(&self, username: &str, password: &str) -> Result<LoginResult> {
        let username = username.trim();
        self.rate_limiter.check_and_record_failure(username).await?;

        let user = self.authenticate_user(username, password).await?;
        let user_id = user.id.to_string();
        let (roles, perm_names) = self.fetch_user_roles_and_perms(&user_id).await?;

        let token = self.jwt.issue_with_options(
            &user_id,
            &user.username,
            roles.clone(),
            perm_names,
            None,
        )?;

        Ok(LoginResult {
            token,
            user_id,
            username: user.username.clone(),
            display_name: user.display_name.clone(),
            roles,
            session_id: None,
        })
    }

    pub async fn verify_token(
        &self,
        token: &str,
    ) -> Result<crate::auth::credential::basic::Claims> {
        self.jwt.verify_with_revocation(token).await
    }

    #[must_use]
    pub async fn check_permission(&self, user_id: &str, permission: &P) -> bool {
        let subject = StringSubject::new(user_id);
        self.engine.check(&subject, permission).await
    }

    #[cfg(feature = "rbac-dynamic")]
    #[must_use]
    pub async fn check_static_and_dynamic(
        &self,
        user_id: &str,
        permission: &P,
        action_request: &crate::rbac::dynamic::metrics::ActionRequest,
    ) -> bool {
        let subject = StringSubject::new(user_id);
        if !self.engine.check(&subject, permission).await {
            return false;
        }
        if let Some(ref arbiter) = self.arbiter {
            let verdict = arbiter.authorize(action_request).await;
            return verdict.allowed;
        }
        true
    }

    pub async fn change_password(
        &self,
        user_id: &str,
        old_password: &str,
        new_password: &str,
    ) -> Result<()> {
        let uid = Uuid::parse_str(user_id)
            .map_err(|_| KirinoError::Validation("invalid user_id".to_string()))?;

        let user = self
            .db
            .find_by_id(&uid)
            .await?
            .ok_or_else(|| KirinoError::NotFound("user not found".to_string()))?;

        if !verify_password(old_password, &user.password_hash)? {
            return Err(KirinoError::AuthenticationFailed.into());
        }

        validate_password(new_password)?;

        let new_hash = hash_password(new_password)?;
        self.jwt.revoke_all_for_user(user_id).await;
        self.db.update_password(&uid, &new_hash).await
    }

    pub async fn list_users(&self) -> Result<Vec<UserInfo>> {
        let users = self.db.list_users().await?;
        Ok(users.iter().map(UserRecord::to_public).collect())
    }

    pub async fn delete_user(&self, user_id: &str) -> Result<bool> {
        let uid = Uuid::parse_str(user_id)
            .map_err(|_| KirinoError::Validation("invalid user_id".to_string()))?;
        self.jwt.revoke_all_for_user(user_id).await;
        self.db.delete_user(&uid).await
    }

    pub async fn login_with_session<SM>(
        &self,
        username: &str,
        password: &str,
        session_mgr: &SM,
        session_ttl: chrono::Duration,
    ) -> Result<(LoginResult, crate::rbac::session::Session<StringSubject>)>
    where
        SM: crate::rbac::session::SessionManager<StringSubject>,
    {
        let username_trimmed = username.trim();
        self.rate_limiter
            .check_and_record_failure(username_trimmed)
            .await?;

        let user = self.authenticate_user(username_trimmed, password).await?;

        let user_id = user.id.to_string();
        let (roles, perm_names) = self.fetch_user_roles_and_perms(&user_id).await?;

        let active_roles: HashSet<String> = roles.iter().cloned().collect();
        let subject = StringSubject::new(&user_id);
        let session = session_mgr
            .create_session(&subject, active_roles, session_ttl)
            .await?;

        let token = self.jwt.issue_with_options(
            &user_id,
            &user.username,
            roles.clone(),
            perm_names,
            Some(session.id.to_string()),
        )?;

        Ok((
            LoginResult {
                token,
                user_id,
                username: user.username.clone(),
                display_name: user.display_name.clone(),
                roles,
                session_id: Some(session.id),
            },
            session,
        ))
    }

    pub async fn logout<SM>(&self, _user_id: &str, session_id: Uuid, session_mgr: &SM) -> Result<()>
    where
        SM: crate::rbac::session::SessionManager<StringSubject>,
    {
        self.jwt.revoke_session(&session_id.to_string()).await;
        session_mgr.destroy_session(session_id).await
    }
}

/// Build an RBAC engine using the hierarchical `Permission` enum.
#[must_use]
pub fn build_default_engine() -> Shared<
    RbacEngine<
        StringSubject,
        crate::rbac::permission::Permission,
        InMemoryAssignmentStore<StringSubject, crate::rbac::permission::Permission>,
    >,
> {
    use crate::rbac::permission::Permission;

    let mut role_reg = StaticRoleRegistry::new();
    role_reg.register(SimpleRole::new(
        "admin",
        Permission::all().into_iter().collect(),
    ));
    role_reg.register(SimpleRole::new(
        "operator",
        Permission::all()
            .into_iter()
            .filter(|p: &Permission| p.domain() != "system" && p.domain() != "rbac")
            .collect(),
    ));
    role_reg.register(SimpleRole::new(
        "member",
        Permission::all()
            .into_iter()
            .filter(|p: &Permission| {
                matches!(
                    p.name(),
                    "provider.list"
                        | "provider.use"
                        | "mcp.list"
                        | "mcp.use"
                        | "agent.list"
                        | "agent.use"
                        | "channel.list"
                        | "channel.use"
                        | "workspace.list"
                        | "workspace.create"
                        | "device.list"
                        | "device.connect"
                )
            })
            .collect(),
    ));
    role_reg.register(SimpleRole::new(
        "viewer",
        Permission::all()
            .into_iter()
            .filter(|p| p.name().ends_with(".list") || p.name() == "deploy.read")
            .collect(),
    ));

    let perm_reg = StaticPermissionRegistry::new(Permission::all().into_iter().collect());
    let store = InMemoryAssignmentStore::new();

    Shared::new(RbacEngine::new(role_reg, perm_reg, store))
}

#[async_trait::async_trait]
pub trait UserDatabase: Send + Sync + Clone + 'static {
    async fn create_user(&self, user: &UserRecord) -> Result<()>;
    async fn find_by_username(&self, username: &str) -> Result<Option<UserRecord>>;
    async fn find_by_id(&self, id: &Uuid) -> Result<Option<UserRecord>>;
    async fn update_password(&self, id: &Uuid, new_hash: &str) -> Result<()>;
    async fn delete_user(&self, id: &Uuid) -> Result<bool>;
    async fn list_users(&self) -> Result<Vec<UserRecord>>;
    async fn count_users(&self) -> Result<u64>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_username_valid() {
        assert_eq!(validate_username("alice").unwrap(), "alice");
        assert_eq!(validate_username("bob_123").unwrap(), "bob_123");
        assert_eq!(validate_username("user.name").unwrap(), "user.name");
        assert_eq!(validate_username("a-b").unwrap(), "a-b");
    }

    #[test]
    fn test_validate_username_too_short() {
        assert!(validate_username("a").is_err());
        assert!(validate_username("").is_err());
    }

    #[test]
    fn test_validate_username_too_long() {
        let long = "a".repeat(65);
        assert!(validate_username(&long).is_err());
    }

    #[test]
    fn test_validate_username_exactly_max_length() {
        let max = "a".repeat(64);
        assert!(validate_username(&max).is_ok());
    }

    #[test]
    fn test_validate_username_invalid_chars() {
        assert!(validate_username("alice bob").is_err());
        assert!(validate_username("alice@domain").is_err());
        assert!(validate_username("用户").is_err());
        assert!(validate_username("user!name").is_err());
    }

    #[test]
    fn test_validate_username_whitespace_only() {
        assert!(validate_username("  ").is_err());
    }

    #[test]
    fn test_validate_username_trimmed() {
        assert_eq!(validate_username("  ab  ").unwrap(), "ab");
    }

    #[test]
    fn test_validate_password_valid() {
        assert!(validate_password("Password1!").is_ok());
        assert!(validate_password("Abcdefg1").is_ok());
        assert!(validate_password("HELLOworld123!").is_ok());
    }

    #[test]
    fn test_validate_password_too_short() {
        assert!(validate_password("Ab1!").is_err());
    }

    #[test]
    fn test_validate_password_exactly_8() {
        assert!(validate_password("Abcd123!").is_ok());
    }

    #[test]
    fn test_validate_password_too_long() {
        let long = "Aa1!".repeat(33);
        assert!(validate_password(&long).is_err());
    }

    #[test]
    fn test_validate_password_exactly_max() {
        let max = "A".repeat(96) + "a1!";
        assert!(validate_password(&max).is_ok());
    }

    #[test]
    fn test_validate_password_only_two_categories() {
        assert!(validate_password("abcdefgh").is_err());
        assert!(validate_password("ABCDEFGH").is_err());
        assert!(validate_password("12345678").is_err());
        assert!(validate_password("abcdABCD").is_err());
        assert!(validate_password("abcd1234").is_err());
        assert!(validate_password("ABCD1234").is_err());
    }

    #[test]
    fn test_validate_password_exactly_three_categories() {
        assert!(validate_password("ABCDefgh1").is_ok());
        assert!(validate_password("Abcd1234").is_ok());
        assert!(validate_password("abcd123!").is_ok());
    }

    #[test]
    fn test_validate_password_unicode_uppercase_lowercase() {
        assert!(
            validate_password("Élève1!").is_ok(),
            "French accented chars should work"
        );
        assert!(
            validate_password("ÜberCafé1!").is_ok(),
            "German umlauts should work"
        );
        assert!(
            validate_password("Niño123!").is_ok(),
            "Spanish tilde should work"
        );
        assert!(
            validate_password("中文密码A1!").is_ok(),
            "CJK + ascii uppercase + digit + special"
        );
    }

    #[test]
    fn test_validate_password_unicode_all_one_category() {
        assert!(
            validate_password("abcdefgh").is_err(),
            "only lowercase fails"
        );
        assert!(
            validate_password("ÉÉÉÉÉÉÉÉ").is_err(),
            "only unicode uppercase fails"
        );
        assert!(
            validate_password("汉字汉字汉字汉字").is_err(),
            "only CJK fails"
        );
    }

    #[test]
    fn test_validate_password_unicode_with_special() {
        assert!(
            validate_password("Passエンド1!").is_ok(),
            "mixed ascii + CJK + special"
        );
    }

    #[tokio::test]
    async fn test_rate_limiter_allows_under_max() {
        let limiter = LoginRateLimiter::new(3, 300, 900);
        assert!(limiter.check_and_record_failure("user").await.is_ok());
        assert!(limiter.check_and_record_failure("user").await.is_ok());
        assert!(limiter.check_and_record_failure("user").await.is_ok());
    }

    #[tokio::test]
    async fn test_rate_limiter_blocks_at_max() {
        let limiter = LoginRateLimiter::new(3, 300, 900);
        limiter.check_and_record_failure("user").await.unwrap();
        limiter.check_and_record_failure("user").await.unwrap();
        limiter.check_and_record_failure("user").await.unwrap();
        assert!(limiter.check_and_record_failure("user").await.is_err());
    }

    #[tokio::test]
    async fn test_rate_limiter_independent_keys() {
        let limiter = LoginRateLimiter::new(2, 300, 900);
        limiter.check_and_record_failure("user-a").await.unwrap();
        limiter.check_and_record_failure("user-a").await.unwrap();
        assert!(limiter.check_and_record_failure("user-a").await.is_err());
        assert!(limiter.check_and_record_failure("user-b").await.is_ok());
    }

    #[tokio::test]
    async fn test_rate_limiter_reset() {
        let limiter = LoginRateLimiter::new(2, 300, 900);
        limiter.check_and_record_failure("user").await.unwrap();
        limiter.check_and_record_failure("user").await.unwrap();
        limiter.reset("user").await;
        assert!(limiter.check_and_record_failure("user").await.is_ok());
        assert!(limiter.check_and_record_failure("user").await.is_ok());
        assert!(limiter.check_and_record_failure("user").await.is_err());
    }

    #[tokio::test]
    async fn test_rate_limiter_reset_nonexistent_key() {
        let limiter = LoginRateLimiter::new(2, 300, 900);
        limiter.reset("nonexistent").await;
        assert!(limiter
            .check_and_record_failure("nonexistent")
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn test_rate_limiter_window_reset_below_max() {
        let limiter = LoginRateLimiter::new(5, 1, 60);
        limiter.check_and_record_failure("user").await.unwrap();
        limiter.check_and_record_failure("user").await.unwrap();
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        assert!(limiter.check_and_record_failure("user").await.is_ok());
    }

    #[tokio::test]
    async fn test_rate_limiter_lockout_persists_during_window() {
        let limiter = LoginRateLimiter::new(2, 60, 60);
        limiter.check_and_record_failure("user").await.unwrap();
        limiter.check_and_record_failure("user").await.unwrap();
        assert!(limiter.check_and_record_failure("user").await.is_err());
    }

    #[test]
    fn test_build_default_engine_roles() {
        let engine = build_default_engine();
        let reg = engine.role_registry();
        assert!(reg.get_role_permissions("admin").is_some());
        assert!(reg.get_role_permissions("operator").is_some());
        assert!(reg.get_role_permissions("viewer").is_some());
        assert!(reg.get_role_permissions("member").is_some());
        assert!(reg.get_role_permissions("nonexistent").is_none());
    }

    #[test]
    fn test_build_default_engine_admin_has_all_perms() {
        let engine = build_default_engine();
        let admin = engine
            .role_registry()
            .get_role_permissions("admin")
            .unwrap();
        assert_eq!(
            admin.len(),
            crate::rbac::permission::Permission::all().len()
        );
    }

    #[test]
    fn test_build_default_engine_viewer_is_list_read_only() {
        let engine = build_default_engine();
        let viewer = engine
            .role_registry()
            .get_role_permissions("viewer")
            .unwrap();
        for perm in &viewer {
            let n = perm.name();
            assert!(
                n.ends_with(".list") || n == "deploy.read",
                "viewer should only have .list or deploy.read, got {}",
                n
            );
        }
    }

    #[test]
    fn test_permission_all_count() {
        assert_eq!(crate::rbac::permission::Permission::all().len(), 37);
    }

    #[test]
    fn test_permission_domains() {
        use crate::rbac::permission::Permission;
        let p = Permission::from_path("agent.read").unwrap();
        assert_eq!(p.domain(), "agent");
        let p = Permission::from_path("config.write").unwrap();
        assert_eq!(p.domain(), "config");
        let p = Permission::from_path("system.read").unwrap();
        assert_eq!(p.domain(), "system");
        let p = Permission::from_path("deploy.execute").unwrap();
        assert_eq!(p.domain(), "deploy");
    }

    #[test]
    fn test_user_record_to_public() {
        let id = Uuid::now_v7();
        let now = Utc::now();
        let record = UserRecord {
            id,
            username: "alice".to_string(),
            password_hash: "hash".to_string(),
            display_name: Some("Alice".to_string()),
            is_active: true,
            identity: Identity::Basic {
                id,
                created_at: now,
            },
            created_at: now,
            updated_at: now,
        };
        let info = record.to_public();
        assert_eq!(info.id, id);
        assert_eq!(info.username, "alice");
        assert_eq!(info.display_name, Some("Alice".to_string()));
        assert!(info.is_active);
    }
}
