use std::{
    collections::{BinaryHeap, HashMap},
    marker::PhantomData,
    time::{Duration, Instant},
};
use tokio::sync::RwLock;

use async_trait::async_trait;

use super::traits::{Permission, Subject};

const DEFAULT_MAX_CACHE_ENTRIES: usize = 10_000;

#[async_trait]
pub trait PermissionCache<S, P>: Send + Sync
where
    S: Subject,
    P: Permission,
{
    #[must_use]
    async fn get(&self, subject: &S, permission: &P) -> Option<bool>;
    async fn set(&self, subject: &S, permission: &P, granted: bool);
    async fn invalidate_subject(&self, subject: &S);
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
    #[must_use]
    pub fn new(ttl: Duration) -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            max_entries: DEFAULT_MAX_CACHE_ENTRIES,
            ttl,
            _phantom: PhantomData,
        }
    }

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

    async fn invalidate_subject(&self, subject: &S) {
        let sid = subject.subject_id().to_string();
        let mut cache = self.cache.write().await;
        cache.retain(|(s, _), _| s != &sid);
    }

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
