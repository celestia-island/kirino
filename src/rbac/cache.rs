use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use super::traits::{Permission, Subject};

pub trait PermissionCache<S, P>: Send + Sync
where
    S: Subject,
    P: Permission,
{
    fn get(&self, subject: &S, permission: &P) -> Option<bool>;
    fn set(&self, subject: &S, permission: &P, granted: bool);
    fn invalidate_subject(&self, subject: &S);
    fn invalidate_all(&self);
}

struct CacheEntry {
    granted: bool,
    expires_at: Instant,
}

pub struct TtlPermissionCache<S, P>
where
    S: Subject,
    P: Permission,
{
    cache: RwLock<HashMap<(String, String), CacheEntry>>,
    ttl: Duration,
    _phantom: PhantomData<(S, P)>,
}

impl<S, P> TtlPermissionCache<S, P>
where
    S: Subject,
    P: Permission,
{
    pub fn new(ttl: Duration) -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            ttl,
            _phantom: PhantomData,
        }
    }
}

impl<S, P> PermissionCache<S, P> for TtlPermissionCache<S, P>
where
    S: Subject,
    P: Permission,
{
    fn get(&self, subject: &S, permission: &P) -> Option<bool> {
        let key = (
            subject.subject_id().to_string(),
            permission.name().to_string(),
        );
        let cache = self.cache.read().unwrap();
        cache.get(&key).and_then(|entry| {
            if Instant::now() < entry.expires_at {
                Some(entry.granted)
            } else {
                None
            }
        })
    }

    fn set(&self, subject: &S, permission: &P, granted: bool) {
        let key = (
            subject.subject_id().to_string(),
            permission.name().to_string(),
        );
        let mut cache = self.cache.write().unwrap();
        cache.insert(
            key,
            CacheEntry {
                granted,
                expires_at: Instant::now() + self.ttl,
            },
        );
    }

    fn invalidate_subject(&self, subject: &S) {
        let sid = subject.subject_id().to_string();
        let mut cache = self.cache.write().unwrap();
        cache.retain(|(s, _), _| s != &sid);
    }

    fn invalidate_all(&self) {
        let mut cache = self.cache.write().unwrap();
        cache.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    struct TestPerm(&'static str);

    impl Permission for TestPerm {
        fn name(&self) -> &str {
            self.0
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    struct TestSubject(String);

    impl Subject for TestSubject {
        fn subject_id(&self) -> &str {
            &self.0
        }
    }

    #[test]
    fn test_cache_set_and_get() {
        let cache = TtlPermissionCache::<TestSubject, TestPerm>::new(Duration::from_secs(60));
        let subj = TestSubject("user1".to_string());
        let perm = TestPerm("read");

        assert!(cache.get(&subj, &perm).is_none());
        cache.set(&subj, &perm, true);
        assert_eq!(cache.get(&subj, &perm), Some(true));
    }

    #[test]
    fn test_cache_ttl_expiry() {
        let cache = TtlPermissionCache::<TestSubject, TestPerm>::new(Duration::from_millis(1));
        let subj = TestSubject("user1".to_string());
        let perm = TestPerm("read");

        cache.set(&subj, &perm, true);
        std::thread::sleep(Duration::from_millis(5));
        assert!(cache.get(&subj, &perm).is_none());
    }

    #[test]
    fn test_cache_invalidate_subject() {
        let cache = TtlPermissionCache::<TestSubject, TestPerm>::new(Duration::from_secs(60));
        let u1 = TestSubject("user1".to_string());
        let u2 = TestSubject("user2".to_string());
        let perm = TestPerm("read");

        cache.set(&u1, &perm, true);
        cache.set(&u2, &perm, false);
        cache.invalidate_subject(&u1);
        assert!(cache.get(&u1, &perm).is_none());
        assert_eq!(cache.get(&u2, &perm), Some(false));
    }

    #[test]
    fn test_cache_invalidate_all() {
        let cache = TtlPermissionCache::<TestSubject, TestPerm>::new(Duration::from_secs(60));
        let subj = TestSubject("user1".to_string());
        let perm = TestPerm("read");

        cache.set(&subj, &perm, true);
        cache.invalidate_all();
        assert!(cache.get(&subj, &perm).is_none());
    }
}
