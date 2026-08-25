//! Accurate online-presence counting for live connections.
//!
//! The problem this module solves: services that derive "online users" from
//! persistent session rows (refresh tokens, workspace registrations) keep
//! counting windows that were closed long ago, because those rows outlive the
//! connection by hours or days. The only truthful signal for "online right
//! now" is the set of live server-side connections.
//!
//! [`PresenceRegistry`] tracks exactly that, keyed by connection. The
//! intended lifecycle:
//!
//! 1. When a socket (or SSE stream) is accepted and authenticated, call
//!    [`PresenceRegistry::connect`] and keep the returned [`PresenceLease`]
//!    alive for the whole connection task.
//! 2. Refresh activity with [`PresenceRegistry::touch`] (or
//!    [`PresenceLease::touch`]) on every inbound frame — cheap, and it feeds
//!    the idle sweeper.
//! 3. When the connection task ends — *however* it ends: clean close, protocol
//!    error, idle timeout, task abort — the lease is dropped and the entry
//!    disappears immediately. RAII does the bookkeeping; there is no
//!    "on disconnect" callback to forget.
//!
//! As a belt-and-braces guard against leaked leases (a task that never
//! terminates, a future that forgets to drop), every query lazily sweeps
//! entries whose last activity is older than the configured idle timeout.
//!
//! The registry is process-local by design: connections die with the process
//! that owns them, so per-process counting is exact. Services that shard
//! across processes should aggregate the per-process numbers.
//!
//! # Example
//!
//! ```
//! use std::sync::Arc;
//! use kirino_session::presence::PresenceRegistry;
//!
//! let registry = Arc::new(PresenceRegistry::new());
//! let lease = registry.connect(Some("user-1"), None::<String>);
//! registry.touch(lease.id()); // inbound frame
//!
//! assert_eq!(registry.connection_count(), 1);
//! assert_eq!(registry.user_count(), 1);
//!
//! drop(lease); // socket task ended
//! assert_eq!(registry.connection_count(), 0);
//! assert_eq!(registry.user_count(), 0);
//! ```

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Default idle timeout: a connection whose last activity is older than this
/// is treated as gone even if its lease was not dropped. Generous enough to
/// sit above typical heartbeat/idle-close intervals (e.g. a 60 s
/// server-side idle close), tight enough to heal a leak within minutes.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(90);

/// Connection bookkeeping entry. Internal; queries return [`PresenceRecord`].
#[derive(Debug, Clone)]
struct Entry {
    user: Option<String>,
    scope: Option<String>,
    connected_at: DateTime<Utc>,
    last_activity: Instant,
}

/// A live connection's handle into a [`PresenceRegistry`].
///
/// Dropping the lease removes the connection from the registry — this is the
/// mechanism that makes closed windows stop counting. Keep it alive for the
/// entire lifetime of the connection task.
#[derive(Debug)]
pub struct PresenceLease {
    registry: Arc<PresenceRegistry>,
    id: Uuid,
}

impl PresenceLease {
    /// The connection id this lease owns.
    pub fn id(&self) -> Uuid {
        self.id
    }

    /// Mark the connection as active (call on inbound frames).
    pub fn touch(&self) {
        self.registry.touch(self.id);
    }
}

impl Drop for PresenceLease {
    fn drop(&mut self) {
        self.registry.remove(self.id);
    }
}

/// One live connection, as returned by [`PresenceRegistry::snapshot`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresenceRecord {
    /// Connection id (the lease id).
    pub id: Uuid,
    /// Authenticated user id, if the connection carried one.
    pub user: Option<String>,
    /// Optional grouping label (e.g. a workspace id).
    pub scope: Option<String>,
    /// Wall-clock connect time.
    pub connected_at: DateTime<Utc>,
    /// Wall-clock last-activity time.
    pub last_seen_at: DateTime<Utc>,
}

/// Registry of live connections with idle sweeping and RAII disconnect.
///
/// See the [module documentation](self) for the contract; the short version:
/// `connect` on accept, `touch` on activity, drop the lease on disconnect.
#[derive(Debug)]
pub struct PresenceRegistry {
    entries: Mutex<HashMap<Uuid, Entry>>,
    idle_timeout: Duration,
}

impl Default for PresenceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl PresenceRegistry {
    /// Create a registry with the default idle timeout
    /// ([`DEFAULT_IDLE_TIMEOUT`]).
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
        }
    }

    /// Create a registry with a custom idle timeout (the sweep horizon).
    pub fn with_idle_timeout(idle_timeout: Duration) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            idle_timeout: idle_timeout.max(Duration::from_millis(1)),
        }
    }

    /// Register a live connection and return its RAII lease.
    ///
    /// `user` is the authenticated user id when known (`None` for anonymous
    /// connections — they are counted, but separately from named users).
    /// `scope` is an optional grouping label such as a workspace id, queryable
    /// via [`PresenceRegistry::scope_ids`].
    pub fn connect(
        self: &Arc<Self>,
        user: Option<impl Into<String>>,
        scope: Option<impl Into<String>>,
    ) -> PresenceLease {
        let id = Uuid::now_v7();
        let now = Instant::now();
        self.entries.lock().unwrap().insert(
            id,
            Entry {
                user: user.map(Into::into),
                scope: scope.map(Into::into),
                connected_at: Utc::now(),
                last_activity: now,
            },
        );
        PresenceLease {
            registry: Arc::clone(self),
            id,
        }
    }

    /// Mark a connection as active. Returns `true` if the connection was
    /// still registered. Only the connection's own handler calls this, so a
    /// touch is itself proof the connection is alive: a stale-but-not-yet-
    /// swept entry is revived (the socket is still open, just quiet), while
    /// an id already physically removed by [`PresenceRegistry::sweep`]
    /// cannot be resurrected (returns `false`).
    pub fn touch(&self, id: Uuid) -> bool {
        let mut entries = self.entries.lock().unwrap();
        match entries.get_mut(&id) {
            Some(entry) => {
                entry.last_activity = Instant::now();
                true
            }
            None => false,
        }
    }

    /// Remove a connection (called by [`PresenceLease::drop`]; idempotent).
    pub fn remove(&self, id: Uuid) {
        self.entries.lock().unwrap().remove(&id);
    }

    /// Drop entries idle for longer than the configured timeout. Returns the
    /// number of entries removed. Queries call this lazily; it is also safe
    /// to call directly (e.g. from a maintenance loop).
    pub fn sweep(&self) -> usize {
        let cutoff = Instant::now()
            .checked_sub(self.idle_timeout)
            .unwrap_or_else(Instant::now);
        let mut entries = self.entries.lock().unwrap();
        let before = entries.len();
        entries.retain(|_, entry| entry.last_activity > cutoff);
        before - entries.len()
    }

    /// Number of live connections (named and anonymous), after an idle sweep.
    pub fn connection_count(&self) -> usize {
        let cutoff = self.idle_cutoff();
        self.entries
            .lock()
            .unwrap()
            .values()
            .filter(|e| e.last_activity > cutoff)
            .count()
    }

    /// Number of *distinct* authenticated users currently online. Multiple
    /// tabs of one user count once; anonymous connections do not count.
    pub fn user_count(&self) -> usize {
        let cutoff = self.idle_cutoff();
        self.entries
            .lock()
            .unwrap()
            .values()
            .filter(|e| e.last_activity > cutoff)
            .filter_map(|e| e.user.as_deref())
            .collect::<HashSet<_>>()
            .len()
    }

    /// Number of live anonymous connections (no user identity attached).
    pub fn anonymous_count(&self) -> usize {
        let cutoff = self.idle_cutoff();
        self.entries
            .lock()
            .unwrap()
            .values()
            .filter(|e| e.last_activity > cutoff)
            .filter(|e| e.user.is_none())
            .count()
    }

    /// Live connection count per authenticated user. Users with zero live
    /// connections do not appear.
    pub fn per_user_counts(&self) -> HashMap<String, usize> {
        let cutoff = self.idle_cutoff();
        let mut counts: HashMap<String, usize> = HashMap::new();
        for entry in self.entries.lock().unwrap().values() {
            if entry.last_activity <= cutoff {
                continue;
            }
            if let Some(user) = entry.user.as_deref() {
                *counts.entry(user.to_owned()).or_default() += 1;
            }
        }
        counts
    }

    /// The set of scopes (e.g. workspace ids) that currently have at least
    /// one live connection.
    pub fn scope_ids(&self) -> HashSet<String> {
        let cutoff = self.idle_cutoff();
        self.entries
            .lock()
            .unwrap()
            .values()
            .filter(|e| e.last_activity > cutoff)
            .filter_map(|e| e.scope.clone())
            .collect()
    }

    /// Whether a given scope has at least one live connection.
    pub fn scope_online(&self, scope: &str) -> bool {
        let cutoff = self.idle_cutoff();
        self.entries
            .lock()
            .unwrap()
            .values()
            .any(|e| e.last_activity > cutoff && e.scope.as_deref() == Some(scope))
    }

    /// Snapshot of all live connections, oldest connection first.
    pub fn snapshot(&self) -> Vec<PresenceRecord> {
        let cutoff = self.idle_cutoff();
        let now = Utc::now();
        let mut records: Vec<PresenceRecord> = self
            .entries
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, e)| e.last_activity > cutoff)
            .map(|(id, e)| PresenceRecord {
                id: *id,
                user: e.user.clone(),
                scope: e.scope.clone(),
                connected_at: e.connected_at,
                last_seen_at: now,
            })
            .collect();
        records.sort_by_key(|a| a.connected_at);
        records
    }

    fn idle_cutoff(&self) -> Instant {
        Instant::now()
            .checked_sub(self.idle_timeout)
            .unwrap_or_else(Instant::now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lease_drop_removes_the_connection() {
        let registry = Arc::new(PresenceRegistry::new());
        assert_eq!(registry.connection_count(), 0);

        let lease = registry.connect(Some("u1"), None::<String>);
        assert_eq!(registry.connection_count(), 1);
        assert_eq!(registry.user_count(), 1);

        drop(lease);
        assert_eq!(
            registry.connection_count(),
            0,
            "closed window must stop counting"
        );
        assert_eq!(registry.user_count(), 0);
    }

    #[test]
    fn two_tabs_of_one_user_count_as_one_user() {
        let registry = Arc::new(PresenceRegistry::new());
        let a = registry.connect(Some("u1"), None::<String>);
        let b = registry.connect(Some("u1"), None::<String>);
        assert_eq!(registry.connection_count(), 2);
        assert_eq!(registry.user_count(), 1);

        drop(a);
        assert_eq!(
            registry.connection_count(),
            1,
            "second tab keeps the user online"
        );
        assert_eq!(registry.user_count(), 1);

        drop(b);
        assert_eq!(registry.user_count(), 0);
    }

    #[test]
    fn anonymous_connections_are_counted_separately() {
        let registry = Arc::new(PresenceRegistry::new());
        let anon = registry.connect(None::<String>, None::<String>);
        let named = registry.connect(Some("u1"), None::<String>);
        assert_eq!(registry.connection_count(), 2);
        assert_eq!(registry.user_count(), 1);
        assert_eq!(registry.anonymous_count(), 1);

        drop(named);
        assert_eq!(registry.user_count(), 0);
        assert_eq!(registry.anonymous_count(), 1);
        drop(anon);
        assert_eq!(registry.anonymous_count(), 0);
    }

    #[test]
    fn idle_entries_are_swept_from_queries() {
        let registry = Arc::new(PresenceRegistry::with_idle_timeout(Duration::from_millis(
            20,
        )));
        let lease = registry.connect(Some("u1"), Some("ws-a"));
        std::thread::sleep(Duration::from_millis(80));

        // Lazy queries filter stale entries out of every count.
        assert_eq!(registry.connection_count(), 0, "stale entry must not count");
        assert_eq!(registry.user_count(), 0);
        assert!(!registry.scope_online("ws-a"));

        // An explicit sweep physically removes the entry; after that the id
        // is gone for good — a late touch cannot resurrect it.
        assert_eq!(registry.sweep(), 1);
        assert!(!registry.touch(lease.id()));
        assert_eq!(registry.connection_count(), 0);
        drop(lease); // idempotent remove of an already-swept id
    }

    #[test]
    fn touch_keeps_a_connection_alive_past_the_timeout() {
        let registry = Arc::new(PresenceRegistry::with_idle_timeout(Duration::from_millis(
            60,
        )));
        let lease = registry.connect(Some("u1"), None::<String>);
        for _ in 0..4 {
            std::thread::sleep(Duration::from_millis(30));
            lease.touch();
        }
        assert_eq!(
            registry.connection_count(),
            1,
            "touched connection stays live"
        );
        assert_eq!(registry.user_count(), 1);
        drop(lease);
    }

    #[test]
    fn per_user_counts_and_scopes_track_live_connections() {
        let registry = Arc::new(PresenceRegistry::new());
        let a = registry.connect(Some("u1"), Some("ws-a"));
        let b = registry.connect(Some("u1"), Some("ws-b"));
        let _c = registry.connect(Some("u2"), Some("ws-a"));

        let counts = registry.per_user_counts();
        assert_eq!(counts.get("u1"), Some(&2));
        assert_eq!(counts.get("u2"), Some(&1));

        let mut scopes: Vec<String> = registry.scope_ids().into_iter().collect();
        scopes.sort();
        assert_eq!(scopes, vec!["ws-a".to_string(), "ws-b".to_string()]);
        assert!(registry.scope_online("ws-a"));
        assert!(registry.scope_online("ws-b"));

        drop(a);
        drop(b);
        assert!(registry.scope_online("ws-a"), "u2 still holds ws-a");
        assert!(!registry.scope_online("ws-b"));
        assert_eq!(registry.per_user_counts().get("u1"), None);
    }

    #[test]
    fn snapshot_lists_live_connections_oldest_first() {
        let registry = Arc::new(PresenceRegistry::new());
        let first = registry.connect(Some("u1"), Some("ws-a"));
        std::thread::sleep(Duration::from_millis(5));
        let second = registry.connect(None::<String>, None::<String>);

        let snap = registry.snapshot();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[0].user.as_deref(), Some("u1"));
        assert_eq!(snap[0].scope.as_deref(), Some("ws-a"));
        assert_eq!(snap[1].user, None);
        assert!(snap[0].connected_at <= snap[1].connected_at);

        drop(first);
        drop(second);
        assert!(registry.snapshot().is_empty());
    }

    #[test]
    fn explicit_sweep_reports_removed_count() {
        let registry = Arc::new(PresenceRegistry::with_idle_timeout(Duration::from_millis(
            20,
        )));
        let stale = registry.connect(Some("u1"), None::<String>);
        let live = registry.connect(Some("u2"), None::<String>);
        std::thread::sleep(Duration::from_millis(80));
        // Refresh only u2 so the sweep has exactly one victim.
        registry.touch(live.id());

        assert_eq!(registry.sweep(), 1);
        assert_eq!(registry.connection_count(), 1);
        drop(stale);
        drop(live);
    }
}
