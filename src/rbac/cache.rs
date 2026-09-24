use std::{
    collections::{BinaryHeap, HashMap},
    marker::PhantomData,
    time::{Duration, Instant},
};
use tokio::sync::RwLock;

use async_trait::async_trait;

use super::traits::{Permission, Subject};

/// Upper bound on memoized decisions before the cache starts evicting.
/// It is a memory guard, not an authority limit: see
/// [`TtlPermissionCache::with_max_entries`].
const DEFAULT_MAX_CACHE_ENTRIES: usize = 10_000;

/// Short-lived memo of permission decisions, keyed by subject id and
/// permission name.
///
/// Security semantics: a cache hit is an authority decision made earlier and
/// replayed without consulting the stores, so every entry is a bounded
/// staleness window during which a revoked grant can still be honoured. The
/// engine closes that window by calling
/// [`invalidate_subject`](PermissionCache::invalidate_subject) after a write;
/// anything that mutates assignments without invalidating leaves the subject
/// with its previous answer until the entry expires.
///
/// `get` returning `None` means "no cached answer": the caller must ask the
/// authoritative stores and treat the result as unknown, never as denied. A
/// store error occurring inside the TTL window is not observable here at all -
/// the earlier answer wins until it expires, which is why the TTL must stay
/// short relative to the revocation requirement.
///
/// Contract for implementors: a miss (`None`) is "unknown" and must never be
/// reported as `Some(false)`, because that would turn an unavailable store
/// into a decision; a stale entry must likewise be reported as a miss rather
/// than served. An error from the underlying storage has no representation
/// here, so implementations must fail closed by returning `None` (letting the
/// engine re-query) instead of guessing an answer.
#[async_trait]
pub trait PermissionCache<S, P>: Send + Sync
where
    S: Subject,
    P: Permission,
{
    /// Cached decision for this pair, or `None` when there is no entry or the
    /// entry has expired. `None` means "unknown": the caller must resolve the
    /// permission against the stores and must not treat it as a denial.
    async fn get(&self, subject: &S, permission: &P) -> Option<bool>;
    /// Records a decision. This is authority state with a lifetime, not a
    /// hint: a wrong `granted` value is replayed verbatim until the entry
    /// expires or is invalidated, and it outlives the request that produced
    /// it. `invalidate_subject` after every write is what keeps revocation
    /// effective.
    async fn set(&self, subject: &S, permission: &P, granted: bool);
    /// Drops every cached decision for one subject. Must be called after any
    /// change to that subject's roles, extra permissions or denies, otherwise
    /// the older answer is served until its TTL elapses.
    async fn invalidate_subject(&self, subject: &S);
    /// Drops all entries, for changes that affect many subjects at once (role
    /// definition edits, bulk migrations). Cheap but blunt: it forces a full
    /// re-query load on the stores.
    async fn invalidate_all(&self);
}

struct CacheEntry {
    granted: bool,
    expires_at: Instant,
}

/// TTL-based permission cache using an in-memory `HashMap`.
///
/// Entries expire after the configured TTL duration. When the cache exceeds
/// `max_entries`, expired entries are evicted on the next write. Thread-safe
/// via [`tokio::sync::RwLock`].
///
/// Security semantics: the TTL is the revocation window - a subject keeps its
/// last-known answer for at most `ttl` after a change, unless the writer calls
/// invalidate. Expiry is enforced on read (an expired entry reads as a miss)
/// but the entry is only removed on a later write, so memory can exceed the
/// intended cap until the next write; exceeding `max_entries` therefore
/// degrades by evicting entries with the soonest expiry date rather than by
/// rejecting writes, i.e. it costs extra store queries, never correctness of a
/// decision.
pub struct TtlPermissionCache<S, P>
where
    S: Subject,
    P: Permission,
{
    cache: RwLock<HashMap<(String, String), CacheEntry>>,
    max_entries: usize,

    ttl: Duration,
    _phantom: PhantomData<(S, P)>,
}

impl<S, P> TtlPermissionCache<S, P>
where
    S: Subject,
    P: Permission,
{
    /// Builds an empty cache whose entries live for `ttl`.
    ///
    /// Security semantics: `ttl` is the worst-case staleness of a granted
    /// decision, so it is a revocation deadline, not a performance knob. A
    /// short TTL narrows the window in which a revoked role still passes but
    /// multiplies store queries and audit-log noise; a long TTL does the
    /// reverse and keeps a wrong answer live longer.
    /// [`RbacEngine`](crate::rbac::engine::RbacEngine::new) constructs this
    /// cache with a `300` s TTL: five minutes bounds the revocation window for
    /// a check-heavy workload whose stores are not queried on every request.
    /// The value matches the login rate-limit window used elsewhere in the
    /// crate, but no in-code measurement or security review record justifies
    /// it - basis to be confirmed with security review.
    #[must_use]
    pub fn new(ttl: Duration) -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            max_entries: DEFAULT_MAX_CACHE_ENTRIES,
            ttl,
            _phantom: PhantomData,
        }
    }

    /// Overrides the entry cap (the default is `DEFAULT_MAX_CACHE_ENTRIES`,
    /// 10_000).
    ///
    /// Security semantics: the cap bounds memory, not authority - it is never
    /// enforced by refusing to cache a fresh decision, only by evicting the
    /// entries closest to expiry. A smaller cap therefore means more misses
    /// and more authoritative lookups (safer but slower); a larger cap keeps
    /// decisions cached for the full TTL, which lengthens the effective
    /// revocation window for any subject whose entry survives. The 10_000
    /// default is a memory bound sized for the observed subject population;
    /// basis to be confirmed with security review.
    #[must_use]
    pub fn with_max_entries(mut self, max_entries: usize) -> Self {
        self.max_entries = max_entries;
        self
    }
}

#[async_trait]
impl<S, P> PermissionCache<S, P> for TtlPermissionCache<S, P>
where
    S: Subject,
    P: Permission,
{
    /// Reads the memoized decision for this subject/permission pair.
    ///
    /// Returns `None` on a miss, on an expired entry (expiry is evaluated
    /// here) and for an unknown key alike: the three are deliberately
    /// indistinguishable, because "unknown" is the only safe thing a cache may
    /// report. `Some(false)` is an actual recorded denial, so implementations
    /// must never synthesize it to mean "not cached". A hit is served without
    /// touching the stores, which is exactly the staleness the TTL bounds.
    async fn get(&self, subject: &S, permission: &P) -> Option<bool> {
        let key = (
            subject.subject_id().to_string(),
            permission.name().to_string(),
        );
        let cache = self.cache.read().await;
        cache.get(&key).and_then(|entry| {
            if Instant::now() < entry.expires_at {
                Some(entry.granted)
            } else {
                None
            }
        })
    }

    /// Stores a decision under the pair's key, replacing any previous entry
    /// (including one that had already expired) and starting a fresh TTL.
    ///
    /// Security semantics: the caller is asserting an authoritative answer, so
    /// this must only be called with the result of an actual store check.
    /// Caching a `false` produced by a failed lookup would remember the
    /// failure as a denial; caching a `true` that is not backed by a grant
    /// would remember an escalation. The write is last-write-wins per key, and
    /// a decision cached here survives its originating request - invalidate
    /// after any authority change.
    async fn set(&self, subject: &S, permission: &P, granted: bool) {
        let key = (
            subject.subject_id().to_string(),
            permission.name().to_string(),
        );
        let mut cache = self.cache.write().await;
        if let Some(existing) = cache.get(&key) {
            if Instant::now() >= existing.expires_at {
                cache.remove(&key);
            }
        }
        cache.insert(
            key,
            CacheEntry {
                granted,
                expires_at: Instant::now() + self.ttl,
            },
        );
        if cache.len() > self.max_entries {
            let now = Instant::now();
            cache.retain(|_, entry| now < entry.expires_at);
            if cache.len() > self.max_entries {
                let excess = cache.len() - self.max_entries;
                let mut heap: BinaryHeap<(Instant, (String, String))> =
                    BinaryHeap::with_capacity(excess + 1);
                for (key, entry) in cache.iter() {
                    heap.push((entry.expires_at, key.clone()));
                    if heap.len() > excess {
                        heap.pop();
                    }
                }
                for (_, key) in heap {
                    cache.remove(&key);
                }
            }
        }
    }

    /// Drops every entry of one subject, across all permissions.
    ///
    /// Security semantics: this is the revocation primitive - call it after
    /// changing a subject's roles, extra permissions or denies, otherwise the
    /// subject keeps its earlier answers until they expire. It is idempotent
    /// and succeeds for a subject with no entries, so callers may invalidate
    /// defensively without checking first.
    async fn invalidate_subject(&self, subject: &S) {
        let sid = subject.subject_id().to_string();
        let mut cache = self.cache.write().await;
        cache.retain(|(s, _), _| s != &sid);
    }

    /// Drops every entry for every subject.
    ///
    /// Security semantics: use for changes with system-wide effect (role
    /// definitions, bulk migrations); it is the only safe response to a write
    /// whose affected subjects are not known. It forces the next check of
    /// every subject to consult the stores, so it temporarily removes the
    /// cache's staleness window at the cost of a query burst.
    async fn invalidate_all(&self) {
        let mut cache = self.cache.write().await;
        cache.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{TestPerm, TestSubject};
    use std::sync::Arc;

    #[tokio::test]
    async fn test_cache_set_and_get() {
        let cache = TtlPermissionCache::new(Duration::from_secs(300));
        let subject = TestSubject("user1".to_string());
        let perm = TestPerm::Read;

        assert_eq!(cache.get(&subject, &perm).await, None);

        cache.set(&subject, &perm, true).await;
        assert_eq!(cache.get(&subject, &perm).await, Some(true));
    }

    #[tokio::test]
    async fn test_cache_ttl_expiry() {
        let cache = TtlPermissionCache::new(Duration::from_millis(100));
        let subject = TestSubject("user1".to_string());
        let perm = TestPerm::Read;

        cache.set(&subject, &perm, true).await;
        assert_eq!(cache.get(&subject, &perm).await, Some(true));

        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(cache.get(&subject, &perm).await, None);
    }

    #[tokio::test]
    async fn test_cache_invalidate_subject() {
        let cache = TtlPermissionCache::new(Duration::from_secs(300));
        let subject1 = TestSubject("user1".to_string());
        let subject2 = TestSubject("user2".to_string());
        let perm = TestPerm::Read;

        cache.set(&subject1, &perm, true).await;
        cache.set(&subject2, &perm, false).await;

        cache.invalidate_subject(&subject1).await;
        assert_eq!(cache.get(&subject1, &perm).await, None);
        assert_eq!(cache.get(&subject2, &perm).await, Some(false));
    }

    #[tokio::test]
    async fn test_cache_invalidate_all() {
        let cache = TtlPermissionCache::new(Duration::from_secs(300));
        let subject = TestSubject("user1".to_string());
        let perm1 = TestPerm::Read;
        let perm2 = TestPerm::Write;

        cache.set(&subject, &perm1, true).await;
        cache.set(&subject, &perm2, false).await;
        cache.invalidate_all().await;
        assert_eq!(cache.get(&subject, &perm1).await, None);
        assert_eq!(cache.get(&subject, &perm2).await, None);
    }

    #[tokio::test]
    async fn test_cache_overwrite() {
        let cache = TtlPermissionCache::new(Duration::from_secs(300));
        let subject = TestSubject("user1".to_string());
        let perm = TestPerm::Read;

        cache.set(&subject, &perm, true).await;
        assert_eq!(cache.get(&subject, &perm).await, Some(true));

        cache.set(&subject, &perm, false).await;
        assert_eq!(cache.get(&subject, &perm).await, Some(false));
    }

    #[tokio::test]
    async fn test_cache_multiple_permissions() {
        let cache = TtlPermissionCache::new(Duration::from_secs(300));
        let subject = TestSubject("user1".to_string());
        let read_perm = TestPerm::Read;
        let write_perm = TestPerm::Write;

        cache.set(&subject, &read_perm, true).await;
        cache.set(&subject, &write_perm, false).await;

        assert_eq!(cache.get(&subject, &read_perm).await, Some(true));
        assert_eq!(cache.get(&subject, &write_perm).await, Some(false));
    }

    #[tokio::test]
    async fn test_cache_different_subjects_isolated() {
        let cache = TtlPermissionCache::new(Duration::from_secs(300));
        let s1 = TestSubject("user1".into());
        let s2 = TestSubject("user2".into());
        let perm = TestPerm::Read;

        cache.set(&s1, &perm, true).await;
        cache.set(&s2, &perm, false).await;

        assert_eq!(cache.get(&s1, &perm).await, Some(true));
        assert_eq!(cache.get(&s2, &perm).await, Some(false));
    }

    #[tokio::test]
    async fn test_cache_invalidate_one_subject_preserves_others() {
        let cache = TtlPermissionCache::new(Duration::from_secs(300));
        let s1 = TestSubject("u1".into());
        let s2 = TestSubject("u2".into());
        let s3 = TestSubject("u3".into());
        let perm = TestPerm::Read;

        cache.set(&s1, &perm, true).await;
        cache.set(&s2, &perm, false).await;
        cache.set(&s3, &perm, true).await;

        cache.invalidate_subject(&s2).await;

        assert_eq!(cache.get(&s1, &perm).await, Some(true));
        assert_eq!(cache.get(&s2, &perm).await, None);
        assert_eq!(cache.get(&s3, &perm).await, Some(true));
    }

    #[tokio::test]
    async fn test_cache_get_nonexistent_perm() {
        let cache = TtlPermissionCache::new(Duration::from_secs(300));
        let subject = TestSubject("user1".into());
        let perm = TestPerm::Read;

        assert_eq!(cache.get(&subject, &perm).await, None);
    }

    #[tokio::test]
    async fn test_cache_invalidate_all_drops_everything() {
        let cache = TtlPermissionCache::new(Duration::from_secs(300));
        let s1 = TestSubject("u1".into());
        let s2 = TestSubject("u2".into());
        let p1 = TestPerm::Read;
        let p2 = TestPerm::Write;

        cache.set(&s1, &p1, true).await;
        cache.set(&s1, &p2, false).await;
        cache.set(&s2, &p1, true).await;

        cache.invalidate_all().await;

        assert_eq!(cache.get(&s1, &p1).await, None);
        assert_eq!(cache.get(&s1, &p2).await, None);
        assert_eq!(cache.get(&s2, &p1).await, None);
    }

    #[tokio::test]
    async fn test_cache_concurrent_access_no_deadlock() {
        let cache = Arc::new(TtlPermissionCache::new(Duration::from_secs(300)));
        let subject = Arc::new(TestSubject("user1".to_string()));
        let perm = Arc::new(TestPerm::Read);

        let mut handles = Vec::new();
        for i in 0..10 {
            let c = Arc::clone(&cache);
            let s = Arc::clone(&subject);
            let p = Arc::clone(&perm);
            handles.push(tokio::spawn(async move {
                for _ in 0..100 {
                    c.set(&*s, &*p, true).await;
                    let _ = c.get(&*s, &*p).await;
                }
                format!("thread-{i} done")
            }));
        }

        for h in handles {
            h.await.expect("task panicked");
        }

        assert_eq!(cache.get(&*subject, &*perm).await, Some(true));
    }

    #[tokio::test]
    async fn test_cache_invalidate_nonexistent_subject_is_noop() {
        let cache = TtlPermissionCache::new(Duration::from_secs(300));
        let s1 = TestSubject("u1".into());
        let s2 = TestSubject("u2".into());
        let perm = TestPerm::Read;

        cache.set(&s1, &perm, true).await;
        cache.invalidate_subject(&s2).await;

        assert_eq!(cache.get(&s1, &perm).await, Some(true));
    }
}
