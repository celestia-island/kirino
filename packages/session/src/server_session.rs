//! Server-side sessions for browser-facing hosts: an opaque id in a
//! host-only cookie, the real state on the server.
//!
//! This is the "BFF" / token-handler shape, and the reason it exists is the
//! alternative: a browser holding an access token in `localStorage` is an
//! XSS away from handing it to whoever injected the script, and a token
//! in a URL is in every log between the user and the server. Here the
//! browser only ever holds a random identifier bound to one host; the
//! provider's tokens never leave the process that exchanged the code.
//!
//! Two pieces:
//!
//! - [`ServerSession`] / [`ServerSessionStore`] — the session record and
//!   the host-backed storage (idle + absolute TTL, rotation on privilege
//!   change, revoke).
//! - [`CookiePolicy`] — the attributes a session cookie must carry to be
//!   accepted by [`CookiePolicy::check`]: `Secure`, `HttpOnly`, no
//!   `Domain` (host-only), `SameSite=Lax` or stricter, `Path=/`. A cookie
//!   with a `Domain` attribute is refused outright: that is the shape that
//!   lets every subdomain of a parent receive the session, and the whole
//!   point of the migration is to stop doing that.
//!
//! No HTTP here: the host parses `Cookie` / builds `Set-Cookie` and runs
//! the bytes through [`CookiePolicy`].

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::SessionError;

/// Default idle timeout: a session unused for this long dies.
pub const DEFAULT_IDLE_SECS: i64 = 30 * 60;
/// Default absolute lifetime: a session cannot outlive this regardless of
/// activity, so a stolen id has a bounded window.
pub const DEFAULT_ABSOLUTE_SECS: i64 = 12 * 3600;

/// What the server remembers about one browser session.
///
/// The provider's tokens live in here (or in a vault the record points at),
/// never in the cookie. `generation` is the privilege epoch: it changes
/// whenever the subject's authority changes, and a request carrying an id
/// whose stored generation has moved on is refused.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerSession {
    /// The opaque id. Random, ≥128 bits, never derived from anything.
    /// Redacted by the hand-written `Debug` — it is the live credential.
    pub id: String,
    /// Who is signed in, as the host sees them (the OP's `sub`).
    pub subject: String,
    /// Creation time; `created_at + absolute` is the hard stop.
    pub created_at: DateTime<Utc>,
    /// Last activity; `last_seen + idle` is the soft stop.
    pub last_seen: DateTime<Utc>,
    /// Privilege epoch. Bump it when the subject's roles/permissions change
    /// and every outstanding session for them is refused until re-issued.
    pub generation: u64,
    /// The OP's tokens for this session, if the host keeps them here.
    /// `Debug` is redacted.
    pub tokens: Option<SessionTokens>,
}

impl ServerSession {
    /// Whether the session is past either TTL at `now` — the storage-side
    /// mirror of [`ServerSession::check`], for stores that evict.
    #[must_use]
    pub fn is_dead(&self, now: DateTime<Utc>, idle_secs: i64, absolute_secs: i64) -> bool {
        // The SAME verdict `check` gives, minus the generation (a store
        // evicts on time alone; the generation is the host's business).
        matches!(
            self.check(now, idle_secs, absolute_secs, self.generation),
            SessionCheck::Refused(SessionRefusal::Idle | SessionRefusal::Absolute)
        )
    }
}

impl std::fmt::Debug for ServerSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerSession")
            .field("id", &"<redacted>")
            .field("subject", &self.subject)
            .field("created_at", &self.created_at)
            .field("last_seen", &self.last_seen)
            .field("generation", &self.generation)
            .field("tokens", &self.tokens)
            .finish()
    }
}

/// The tokens a host parks with a session. Redacted in `Debug`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionTokens {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
    pub expires_at: DateTime<Utc>,
}

impl std::fmt::Debug for SessionTokens {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionTokens")
            .field("access_token", &"<redacted>")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "<redacted>"),
            )
            .field("id_token", &self.id_token.as_ref().map(|_| "<redacted>"))
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Why a presented session id was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SessionRefusal {
    /// Unknown id, or revoked.
    #[error("session is unknown or revoked")]
    Unknown,
    /// Idle timeout elapsed.
    #[error("session has been idle too long")]
    Idle,
    /// Absolute lifetime elapsed.
    #[error("session has reached its absolute lifetime")]
    Absolute,
    /// The stored privilege epoch moved on.
    #[error("session was issued under an earlier privilege epoch")]
    StaleGeneration,
}

/// The verdict on a presented id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionCheck {
    /// Live: the record, with `last_seen` advanced by the host.
    Live(ServerSession),
    /// Refused.
    Refused(SessionRefusal),
}

impl ServerSession {
    /// Whether the session is live at `now`, and why not if it is not.
    ///
    /// Idle is judged against `now`, absolute against creation; either
    /// expiring is a refusal.
    #[must_use]
    pub fn check(
        &self,
        now: DateTime<Utc>,
        idle_secs: i64,
        absolute_secs: i64,
        current_generation: u64,
    ) -> SessionCheck {
        if self.generation != current_generation {
            return SessionCheck::Refused(SessionRefusal::StaleGeneration);
        }
        if now > self.created_at + chrono::Duration::seconds(absolute_secs) {
            return SessionCheck::Refused(SessionRefusal::Absolute);
        }
        if now > self.last_seen + chrono::Duration::seconds(idle_secs) {
            return SessionCheck::Refused(SessionRefusal::Idle);
        }
        let mut next = self.clone();
        next.last_seen = now;
        SessionCheck::Live(next)
    }
}

/// Host-backed session storage.
///
/// Every mutation is by id. `revoke_all_for_subject` is what a password
/// change / role change / logout-everywhere calls; `bump_generation` is the
/// cheaper variant that keeps the records but makes them all stale at once.
#[async_trait::async_trait]
pub trait ServerSessionStore: Send + Sync {
    /// Insert or replace a session.
    ///
    /// # Errors
    /// Storage failures.
    async fn put(&self, session: &ServerSession) -> Result<(), SessionError>;
    /// Fetch by id.
    ///
    /// # Errors
    ///
    /// Storage failures. An unreachable store must be an `Err`, never
    /// `Ok(None)`: an outage must not read as "signed out".
    async fn get(&self, id: &str) -> Result<Option<ServerSession>, SessionError>;
    /// Drop every session that has expired under the two TTLs. Returns how
    /// many were removed.
    ///
    /// The default does nothing: a store with its own expiry (TTL rows, a
    /// cache) needs no sweep. The in-memory reference implements it,
    /// because without it an abandoned session stays in the map forever
    /// (R5: 1000 expired sessions, `len()` still 1000, and no API to shrink
    /// it). **Eviction is the host's call**: the store never drops a row on
    /// its own, so a host with TTLs different from the defaults is the only
    /// thing that decides what "expired" means.
    ///
    /// # Errors
    ///
    /// Storage failures.
    async fn sweep(
        &self,
        now: DateTime<Utc>,
        idle_secs: i64,
        absolute_secs: i64,
    ) -> Result<u64, SessionError> {
        let _ = (now, idle_secs, absolute_secs);
        Ok(0)
    }
    /// Remove one session.
    ///
    /// # Errors
    /// Storage failures.
    async fn revoke(&self, id: &str) -> Result<(), SessionError>;
    /// Remove every session of a subject (logout everywhere, account
    /// disabled). Returns how many were removed.
    ///
    /// # Errors
    /// Storage failures.
    async fn revoke_all_for_subject(&self, subject: &str) -> Result<u64, SessionError>;
    /// The current privilege epoch for a subject (0 when none is stored).
    ///
    /// # Errors
    /// Storage failures.
    async fn generation(&self, subject: &str) -> Result<u64, SessionError>;
    /// Advance the privilege epoch for a subject. Every session of theirs
    /// is stale from this point until re-issued.
    ///
    /// # Errors
    /// Storage failures.
    async fn bump_generation(&self, subject: &str) -> Result<u64, SessionError>;
}

/// In-memory [`ServerSessionStore`]: the reference implementation, right for
/// a single replica; the host sweeps it. The map key is the SHA-256 of the id so the key set
/// alone reveals nothing — but the **record still holds the id in the
/// clear** (the host needs it back to build the cookie), so this is not a
/// protection against a heap dump of the values, only of the keys.
#[derive(Debug, Default)]
pub struct InMemoryServerSessionStore {
    sessions: tokio::sync::RwLock<std::collections::HashMap<String, ServerSession>>,
    generations: tokio::sync::RwLock<std::collections::HashMap<String, u64>>,
}

impl InMemoryServerSessionStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// How many sessions are stored (tests / metrics).
    pub async fn len(&self) -> usize {
        self.sessions.read().await.len()
    }

    /// Whether nothing is stored (tests / metrics).
    pub async fn is_empty(&self) -> bool {
        self.sessions.read().await.is_empty()
    }
}

fn key(id: &str) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(id.as_bytes()))
}

#[async_trait::async_trait]
impl ServerSessionStore for InMemoryServerSessionStore {
    async fn put(&self, session: &ServerSession) -> Result<(), SessionError> {
        // Insert or replace, unconditionally — that is the trait's contract.
        // R6 caught the first version evicting on the wall clock with the
        // DEFAULT TTLs: a host with a longer policy had live sessions
        // dropped, and `ctx.now` more than 30 min behind the wall made
        // `complete` hand out a cookie for a session that was never stored.
        // Eviction is the host's call, through `sweep` with its own TTLs.
        self.sessions
            .write()
            .await
            .insert(key(&session.id), session.clone());
        Ok(())
    }
    async fn sweep(
        &self,
        now: DateTime<Utc>,
        idle_secs: i64,
        absolute_secs: i64,
    ) -> Result<u64, SessionError> {
        let mut sessions = self.sessions.write().await;
        let before = sessions.len();
        sessions.retain(|_, s| !s.is_dead(now, idle_secs, absolute_secs));
        Ok((before - sessions.len()) as u64)
    }

    async fn get(&self, id: &str) -> Result<Option<ServerSession>, SessionError> {
        Ok(self.sessions.read().await.get(&key(id)).cloned())
    }

    async fn revoke(&self, id: &str) -> Result<(), SessionError> {
        self.sessions.write().await.remove(&key(id));
        Ok(())
    }

    async fn revoke_all_for_subject(&self, subject: &str) -> Result<u64, SessionError> {
        let mut sessions = self.sessions.write().await;
        let before = sessions.len();
        sessions.retain(|_, s| s.subject != subject);
        Ok((before - sessions.len()) as u64)
    }

    async fn generation(&self, subject: &str) -> Result<u64, SessionError> {
        Ok(self
            .generations
            .read()
            .await
            .get(subject)
            .copied()
            .unwrap_or(0))
    }

    async fn bump_generation(&self, subject: &str) -> Result<u64, SessionError> {
        let mut generations = self.generations.write().await;
        let next = generations.entry(subject.to_owned()).or_insert(0);
        *next = next.wrapping_add(1).max(1);
        Ok(*next)
    }
}

/// The attributes a session cookie must carry. Parsed by the host, judged
/// by [`CookiePolicy::check`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionCookie {
    pub name: String,
    /// Whether the `Secure` attribute was present.
    pub secure: bool,
    /// Whether the `HttpOnly` attribute was present.
    pub http_only: bool,
    /// The `Domain` attribute, if any. **Any** value is a refusal.
    pub domain: Option<String>,
    /// The `Path` attribute as parsed.
    pub path: Option<String>,
    /// The `SameSite` attribute as parsed (`None`, `Lax`, `Strict`).
    pub same_site: Option<String>,
    /// Whether the `__Host-` prefix was on the name.
    pub host_prefix: bool,
}

/// The session-cookie policy. Construct with [`CookiePolicy::strict`] for
/// the migration's shape. The fields are public — a host may narrow them,
/// and `set_cookie_value` emits a value its own `check` accepts for every
/// narrowing — but nothing stops a host from loosening them, so treat a
/// hand-built policy as the host's own decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CookiePolicy {
    /// Require the `__Host-` prefix (which implies Secure, no Domain, Path=/).
    pub require_host_prefix: bool,
    /// Require `HttpOnly`.
    pub require_http_only: bool,
    /// Acceptable `SameSite` values.
    pub allowed_same_site: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CookieRefusal {
    #[error("the cookie name must carry the __Host- prefix")]
    NotHostPrefixed,
    #[error("the cookie must be Secure")]
    NotSecure,
    #[error("the cookie must be HttpOnly")]
    NotHttpOnly,
    #[error("a session cookie must be host-only; a Domain attribute ({0:?}) shares it with every subdomain")]
    HasDomain(String),
    #[error("Path must be / (got {0:?})")]
    BadPath(String),
    #[error("SameSite must be one of {expected:?} (got {got:?})")]
    BadSameSite {
        expected: Vec<String>,
        got: Option<String>,
    },
}

impl CookiePolicy {
    /// The migration's shape: `__Host-` prefix, `HttpOnly`, `Lax` or
    /// `Strict`. Nothing here is negotiable by construction — a cookie that
    /// fails any clause is a cookie that would leak the session across
    /// hosts or to script.
    #[must_use]
    pub fn strict() -> Self {
        Self {
            require_host_prefix: true,
            require_http_only: true,
            allowed_same_site: vec!["Lax".into(), "Strict".into()],
        }
    }

    /// Judge a parsed cookie. `__Host-` already implies `Secure`, no
    /// `Domain`, `Path=/` per RFC 6265bis, but those are checked explicitly
    /// too: the prefix is a browser-enforced promise, and this policy does
    /// not trust that the UA kept it.
    ///
    /// # Errors
    ///
    /// The first [`CookieRefusal`] that applies.
    pub fn check(&self, cookie: &SessionCookie) -> Result<(), CookieRefusal> {
        if self.require_host_prefix && !cookie.host_prefix {
            return Err(CookieRefusal::NotHostPrefixed);
        }
        if !cookie.secure {
            return Err(CookieRefusal::NotSecure);
        }
        if self.require_http_only && !cookie.http_only {
            return Err(CookieRefusal::NotHttpOnly);
        }
        if let Some(domain) = &cookie.domain {
            return Err(CookieRefusal::HasDomain(domain.clone()));
        }
        match cookie.path.as_deref() {
            Some("/") => {}
            other => return Err(CookieRefusal::BadPath(other.unwrap_or("").to_owned())),
        }
        if !self
            .allowed_same_site
            .iter()
            .any(|s| cookie.same_site.as_deref() == Some(s.as_str()))
        {
            return Err(CookieRefusal::BadSameSite {
                expected: self.allowed_same_site.clone(),
                got: cookie.same_site.clone(),
            });
        }
        Ok(())
    }

    /// The `SameSite` this policy emits: `Lax` unless the policy allows
    /// ONLY `Strict`, in which case `Strict`. Either way it is a value the
    /// policy's own `check` accepts (R4: emit was hard-coded `Lax`, so a
    /// `Strict`-only policy produced values it immediately refused — a
    /// silent "signed in but the next request is anonymous"). A policy that
    /// permits both gets `Lax`: it has not asked for the tighter one.
    fn emitted_same_site(&self) -> &str {
        // `Lax` unless the policy allows ONLY `Strict`: Lax is the default
        // the migration wants, and a host that permits both has not asked
        // for the tighter one.
        if self.allowed_same_site.iter().all(|s| s == "Strict") {
            "Strict"
        } else {
            "Lax"
        }
    }

    /// Build the `Set-Cookie` value for a session id under this policy.
    ///
    /// `__Host-` carries the three structural promises in the name; the
    /// explicit attributes are written anyway so a UA that ignores the
    /// prefix still sees them.
    #[must_use]
    pub fn set_cookie_value(&self, id: &str, cookie_name: &str) -> String {
        let name = if cookie_name.starts_with("__Host-") {
            cookie_name.to_owned()
        } else {
            format!("__Host-{cookie_name}")
        };
        format!(
            "{name}={id}; Path=/; Secure; HttpOnly; SameSite={}",
            self.emitted_same_site()
        )
    }

    /// The `Set-Cookie` that clears a session under this policy: same
    /// name, same attributes, `Max-Age=0` (RFC 6265 §5.3 — a mismatched
    /// clear leaves the old cookie alive).
    #[must_use]
    pub fn clear_cookie_value(&self, cookie_name: &str) -> String {
        let name = if cookie_name.starts_with("__Host-") {
            cookie_name.to_owned()
        } else {
            format!("__Host-{cookie_name}")
        };
        format!(
            "{name}=; Path=/; Secure; HttpOnly; SameSite={}; Max-Age=0",
            self.emitted_same_site()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: i64) -> DateTime<Utc> {
        Utc::now() + chrono::Duration::seconds(secs)
    }

    fn session() -> ServerSession {
        ServerSession {
            id: "s-1".into(),
            subject: "user-1".into(),
            created_at: Utc::now(),
            last_seen: Utc::now(),
            generation: 0,
            tokens: None,
        }
    }

    #[test]
    fn a_live_session_advances_last_seen() {
        let s = session();
        let later = at(60);
        let SessionCheck::Live(next) = s.check(later, DEFAULT_IDLE_SECS, DEFAULT_ABSOLUTE_SECS, 0)
        else {
            panic!("expected live");
        };
        assert_eq!(next.last_seen, later);
        assert_eq!(next.created_at, s.created_at, "creation never moves");
    }

    #[test]
    fn idle_and_absolute_are_both_refusals() {
        let s = session();
        assert_eq!(
            s.check(
                at(DEFAULT_IDLE_SECS + 1),
                DEFAULT_IDLE_SECS,
                DEFAULT_ABSOLUTE_SECS,
                0
            ),
            SessionCheck::Refused(SessionRefusal::Idle)
        );
        assert_eq!(
            s.check(
                at(DEFAULT_ABSOLUTE_SECS + 1),
                DEFAULT_IDLE_SECS,
                DEFAULT_ABSOLUTE_SECS,
                0
            ),
            SessionCheck::Refused(SessionRefusal::Absolute)
        );
    }

    /// The privilege epoch: a session issued before a role change is
    /// refused even when it is otherwise fresh.
    #[test]
    fn a_stale_generation_is_refused() {
        let s = session();
        assert!(matches!(
            s.check(Utc::now(), DEFAULT_IDLE_SECS, DEFAULT_ABSOLUTE_SECS, 1),
            SessionCheck::Refused(SessionRefusal::StaleGeneration)
        ));
        // And a matching one is live.
        assert!(matches!(
            s.check(Utc::now(), DEFAULT_IDLE_SECS, DEFAULT_ABSOLUTE_SECS, 0),
            SessionCheck::Live(_)
        ));
    }

    #[tokio::test]
    async fn the_store_revokes_by_id_and_by_subject_and_bumps_generations() {
        let store = InMemoryServerSessionStore::new();
        let mut a = session();
        a.id = "a".into();
        let mut b = session();
        b.id = "b".into();
        let mut c = session();
        c.id = "c".into();
        c.subject = "user-2".into();
        for s in [&a, &b, &c] {
            store.put(s).await.unwrap();
        }
        assert_eq!(store.revoke_all_for_subject("user-1").await.unwrap(), 2);
        assert!(store.get("a").await.unwrap().is_none());
        assert!(store.get("c").await.unwrap().is_some());
        assert_eq!(store.generation("user-2").await.unwrap(), 0);
        assert_eq!(store.bump_generation("user-2").await.unwrap(), 1);
        assert_eq!(store.generation("user-2").await.unwrap(), 1);
        store.revoke("c").await.unwrap();
        assert!(store.get("c").await.unwrap().is_none());
    }

    /// The store keys on the hash, never the id.
    #[tokio::test]
    async fn the_store_never_holds_the_raw_id_as_a_key() {
        let store = InMemoryServerSessionStore::new();
        store.put(&session()).await.unwrap();
        assert!(!store.sessions.read().await.contains_key("s-1"));
        assert!(store.sessions.read().await.contains_key(&key("s-1")));
    }

    fn good() -> SessionCookie {
        SessionCookie {
            name: "__Host-sid".into(),
            secure: true,
            http_only: true,
            domain: None,
            path: Some("/".into()),
            same_site: Some("Lax".into()),
            host_prefix: true,
        }
    }

    #[test]
    fn the_strict_policy_accepts_exactly_the_migration_shape() {
        CookiePolicy::strict().check(&good()).unwrap();
        let mut lax = good();
        lax.same_site = Some("Strict".into());
        CookiePolicy::strict().check(&lax).unwrap();
    }

    /// Every clause is a refusal on its own — these are the shapes that
    /// leak a session across hosts or to script.
    #[test]
    fn every_relaxation_is_refused() {
        let p = CookiePolicy::strict();
        // MUT:cookie-domain — a parent-domain cookie is what the migration
        // retires; accepting any Domain attribute reintroduces it.
        let mut c = good();
        c.domain = Some(".celestia.ac.cn".into());
        assert!(matches!(p.check(&c), Err(CookieRefusal::HasDomain(_))));
        let mut c = good();
        c.secure = false;
        assert_eq!(p.check(&c), Err(CookieRefusal::NotSecure));
        let mut c = good();
        c.http_only = false;
        assert_eq!(p.check(&c), Err(CookieRefusal::NotHttpOnly));
        let mut c = good();
        c.host_prefix = false;
        assert_eq!(p.check(&c), Err(CookieRefusal::NotHostPrefixed));
        let mut c = good();
        c.path = Some("/app".into());
        assert!(matches!(p.check(&c), Err(CookieRefusal::BadPath(_))));
        let mut c = good();
        c.same_site = Some("None".into());
        assert!(matches!(
            p.check(&c),
            Err(CookieRefusal::BadSameSite { .. })
        ));
        let mut c = good();
        c.same_site = None;
        assert!(matches!(
            p.check(&c),
            Err(CookieRefusal::BadSameSite { .. })
        ));
    }

    /// R4 S3: a missing or empty `Path` is refused. The `__Host-` prefix
    /// forces `Path=/` in a conforming UA and a missing default-path only
    /// narrows the cookie, so this is hygiene — but nothing pinned it.
    #[test]
    fn a_missing_or_empty_path_is_refused() {
        let p = CookiePolicy::strict();
        let mut c = good();
        c.path = None;
        assert!(matches!(p.check(&c), Err(CookieRefusal::BadPath(_))));
        let mut c = good();
        c.path = Some(String::new());
        assert!(matches!(p.check(&c), Err(CookieRefusal::BadPath(_))));
    }

    /// R4 S3: the `__Host-` prefix is added exactly once, and both spellings
    /// produce the same name (a doubled prefix is rejected by every UA).
    #[test]
    fn the_host_prefix_is_added_exactly_once() {
        let p = CookiePolicy::strict();
        assert_eq!(
            p.set_cookie_value("abc", "sid"),
            p.set_cookie_value("abc", "__Host-sid")
        );
        assert!(!p.set_cookie_value("abc", "sid").contains("__Host-__Host-"));
        assert_eq!(
            p.clear_cookie_value("sid"),
            p.clear_cookie_value("__Host-sid")
        );
    }

    /// R4 S2: what the policy emits passes its own `check`, **whatever the
    /// host narrows it to** — otherwise "sign-in succeeded" and "the next
    /// request is anonymous" are the same event.
    #[test]
    fn the_policy_accepts_what_it_emits() {
        for policy in [
            CookiePolicy::strict(),
            CookiePolicy {
                allowed_same_site: vec!["Strict".into()],
                ..CookiePolicy::strict()
            },
        ] {
            let value = policy.set_cookie_value("abc", "sid");
            let same_site = value
                .split(';')
                .find_map(|a| a.trim().strip_prefix("SameSite=").map(str::to_owned));
            let parsed = SessionCookie {
                name: "__Host-sid".into(),
                secure: value.contains("Secure"),
                http_only: value.contains("HttpOnly"),
                domain: None,
                path: Some("/".into()),
                same_site,
                host_prefix: true,
            };
            policy
                .check(&parsed)
                .unwrap_or_else(|e| panic!("the policy refused its own emission {value:?}: {e}"));
        }
    }

    /// R5 S2: the in-memory store evicts. Without a sweep, 1000 abandoned
    /// sessions stayed in the map forever with no API to shrink it.
    #[tokio::test]
    async fn the_memory_store_evicts_expired_sessions() {
        let store = InMemoryServerSessionStore::new();
        let t0 = Utc::now();
        for i in 0..100 {
            store
                .put(&ServerSession {
                    id: format!("s-{i}"),
                    subject: "sub".into(),
                    created_at: t0,
                    last_seen: t0,
                    generation: 0,
                    tokens: None,
                })
                .await
                .unwrap();
        }
        assert_eq!(store.len().await, 100);
        // Long after both TTLs: sweep removes every one.
        let later = t0 + chrono::Duration::seconds(DEFAULT_ABSOLUTE_SECS + 60);
        assert_eq!(
            store
                .sweep(later, DEFAULT_IDLE_SECS, DEFAULT_ABSOLUTE_SECS)
                .await
                .unwrap(),
            100
        );
        assert_eq!(store.len().await, 0);
        // The Idle arm on its own: a session seen recently enough on the
        // absolute clock but past the idle window is dead. (R6: every
        // eviction case so far hit Absolute first, so an `is_dead` that only
        // kept the Absolute arm survived.)
        let store = InMemoryServerSessionStore::new();
        let t = Utc::now();
        let idle_dead = ServerSession {
            id: "idle".into(),
            subject: "sub".into(),
            created_at: t,
            last_seen: t - chrono::Duration::seconds(DEFAULT_IDLE_SECS + 10),
            generation: 0,
            tokens: None,
        };
        store.put(&idle_dead).await.unwrap();
        assert_eq!(
            store
                .sweep(t, DEFAULT_IDLE_SECS, DEFAULT_ABSOLUTE_SECS)
                .await
                .unwrap(),
            1
        );
        assert_eq!(store.len().await, 0);
        // MUT:idle-arm-dropped — an `is_dead` that only tests Absolute
        // leaves this row in and the count at 0.
    }

    /// The host's TTLs decide, not the defaults: a session dead by the
    /// defaults but live under a longer policy is kept by `put`, judged
    /// `Live` by `check`, and kept by a `sweep` called with the host's TTLs.
    #[tokio::test]
    async fn the_hosts_ttls_decide_not_the_defaults() {
        let t = Utc::now();
        let host_idle = DEFAULT_IDLE_SECS + 3600;
        let mut stale_by_default = session();
        stale_by_default.id = "long".into();
        stale_by_default.created_at = t - chrono::Duration::seconds(DEFAULT_IDLE_SECS + 60);
        stale_by_default.last_seen = t - chrono::Duration::seconds(DEFAULT_IDLE_SECS + 60);
        assert_eq!(
            stale_by_default.check(t, DEFAULT_IDLE_SECS, DEFAULT_ABSOLUTE_SECS, 0),
            SessionCheck::Refused(SessionRefusal::Idle)
        );
        assert!(matches!(
            stale_by_default.check(t, host_idle, DEFAULT_ABSOLUTE_SECS, 0),
            SessionCheck::Live(_)
        ));
        assert_eq!(
            stale_by_default.check(t, host_idle, DEFAULT_IDLE_SECS, 0),
            SessionCheck::Refused(SessionRefusal::Absolute)
        );
        let store = InMemoryServerSessionStore::new();
        store.put(&stale_by_default).await.unwrap();
        store.put(&session()).await.unwrap();
        assert_eq!(store.len().await, 2, "a put must not evict another row");
        let mut touched = stale_by_default.clone();
        touched.last_seen = t;
        store.put(&touched).await.unwrap();
        assert_eq!(
            store.len().await,
            2,
            "a replaced session is not a second row"
        );
        assert_eq!(
            store.get("long").await.unwrap().expect("stored").last_seen,
            t,
            "the stored record is the newer one"
        );
        let later = t + chrono::Duration::seconds(DEFAULT_IDLE_SECS + 60);
        assert_eq!(
            store
                .sweep(later, host_idle, DEFAULT_ABSOLUTE_SECS)
                .await
                .unwrap(),
            0,
            "the host's sweep keeps what its policy calls live"
        );
        assert_eq!(
            store
                .sweep(later, DEFAULT_IDLE_SECS, DEFAULT_ABSOLUTE_SECS)
                .await
                .unwrap(),
            2
        );
        assert_eq!(store.len().await, 0);
    }

    #[test]
    fn set_and_clear_cookies_carry_the_same_name_and_attributes() {
        let p = CookiePolicy::strict();
        let set = p.set_cookie_value("abc", "sid");
        assert!(set.starts_with("__Host-sid=abc;"));
        for attr in ["Path=/", "Secure", "HttpOnly", "SameSite=Lax"] {
            assert!(set.contains(attr), "{set}");
        }
        assert!(
            !set.contains("Domain="),
            "host-only: never a Domain attribute"
        );
        let clear = p.clear_cookie_value("sid");
        assert!(clear.starts_with("__Host-sid=;"));
        assert!(clear.ends_with("Max-Age=0"));
        // Same name, same attributes apart from the value and Max-Age.
        fn strip(s: &str) -> Vec<String> {
            s.split(';')
                .skip(1)
                .map(str::trim)
                .filter(|a| *a != "Max-Age=0")
                .map(str::to_owned)
                .collect()
        }
        assert_eq!(strip(&set), strip(&clear));
    }

    #[test]
    fn session_tokens_never_print() {
        let t = SessionTokens {
            access_token: "ACCESS-SECRET".into(),
            refresh_token: Some("REFRESH-SECRET".into()),
            id_token: Some("ID-SECRET".into()),
            expires_at: Utc::now(),
        };
        let rendered = format!("{t:?}");
        assert!(rendered.contains("<redacted>"));
        for secret in ["ACCESS-SECRET", "REFRESH-SECRET", "ID-SECRET"] {
            assert!(!rendered.contains(secret), "{rendered}");
        }
    }
}
