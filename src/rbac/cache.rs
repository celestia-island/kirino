use std::{
    collections::HashMap,
    marker::PhantomData,
    time::{Duration, Instant},
};

use tokio::sync::RwLock;

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
    #[must_use]
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
        let cache = self.cache.try_read();
        match cache {
            Ok(cache) => cache.get(&key).and_then(|entry| {
                if Instant::now() < entry.expires_at {
                    Some(entry.granted)
                } else {
                    None
                }
            }),
            Err(_) => None,
        }
    }

    fn set(&self, subject: &S, permission: &P, granted: bool) {
        let key = (
            subject.subject_id().to_string(),
            permission.name().to_string(),
        );
        if let Ok(mut cache) = self.cache.try_write() {
            cache.insert(
                key,
                CacheEntry {
                    granted,
                    expires_at: Instant::now() + self.ttl,
                },
            );
        }
    }

    fn invalidate_subject(&self, subject: &S) {
        let sid = subject.subject_id().to_string();
        if let Ok(mut cache) = self.cache.try_write() {
            cache.retain(|(s, _), _| s != &sid);
        }
    }

    fn invalidate_all(&self) {
        if let Ok(mut cache) = self.cache.try_write() {
            cache.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    struct TestPerm {
        name: String,
    }

    impl Permission for TestPerm {
        fn name(&self) -> &str {
            &self.name
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    struct TestSubject {
        id: String,
    }

    impl Subject for TestSubject {
        fn subject_id(&self) -> &str {
            &self.id
        }
    }

    #[test]
    fn test_cache_set_and_get() {
        let cache = TtlPermissionCache::new(Duration::from_secs(300));
        let subject = TestSubject {
            id: "user1".to_string(),
        };
        let perm = TestPerm {
            name: "read".to_string(),
        };

        assert_eq!(cache.get(&subject, &perm), None);

        cache.set(&subject, &perm, true);
        assert_eq!(cache.get(&subject, &perm), Some(true));
    }

    #[test]
    fn test_cache_ttl_expiry() {
        let cache = TtlPermissionCache::new(Duration::from_millis(10));
        let subject = TestSubject {
            id: "user1".to_string(),
        };
        let perm = TestPerm {
            name: "read".to_string(),
        };

        cache.set(&subject, &perm, true);
        assert_eq!(cache.get(&subject, &perm), Some(true));

        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(cache.get(&subject, &perm), None);
    }

    #[test]
    fn test_cache_invalidate_subject() {
        let cache = TtlPermissionCache::new(Duration::from_secs(300));
        let subject1 = TestSubject {
            id: "user1".to_string(),
        };
        let subject2 = TestSubject {
            id: "user2".to_string(),
        };
        let perm = TestPerm {
            name: "read".to_string(),
        };

        cache.set(&subject1, &perm, true);
        cache.set(&subject2, &perm, false);

        cache.invalidate_subject(&subject1);
        assert_eq!(cache.get(&subject1, &perm), None);
        assert_eq!(cache.get(&subject2, &perm), Some(false));
    }

    #[test]
    fn test_cache_invalidate_all() {
        let cache = TtlPermissionCache::new(Duration::from_secs(300));
        let subject = TestSubject {
            id: "user1".to_string(),
        };
        let perm1 = TestPerm {
            name: "read".to_string(),
        };
        let perm2 = TestPerm {
            name: "write".to_string(),
        };

        cache.set(&subject, &perm1, true);
        cache.set(&subject, &perm2, false);
        cache.invalidate_all();
        assert_eq!(cache.get(&subject, &perm1), None);
        assert_eq!(cache.get(&subject, &perm2), None);
    }

    #[test]
    fn test_cache_overwrite() {
        let cache = TtlPermissionCache::new(Duration::from_secs(300));
        let subject = TestSubject {
            id: "user1".to_string(),
        };
        let perm = TestPerm {
            name: "read".to_string(),
        };

        cache.set(&subject, &perm, true);
        assert_eq!(cache.get(&subject, &perm), Some(true));

        cache.set(&subject, &perm, false);
        assert_eq!(cache.get(&subject, &perm), Some(false));
    }

    #[test]
    fn test_cache_multiple_permissions() {
        let cache = TtlPermissionCache::new(Duration::from_secs(300));
        let subject = TestSubject {
            id: "user1".to_string(),
        };
        let read_perm = TestPerm {
            name: "read".to_string(),
        };
        let write_perm = TestPerm {
            name: "write".to_string(),
        };

        cache.set(&subject, &read_perm, true);
        cache.set(&subject, &write_perm, false);

        assert_eq!(cache.get(&subject, &read_perm), Some(true));
        assert_eq!(cache.get(&subject, &write_perm), Some(false));
    }

    #[test]
    fn test_cache_different_subjects_isolated() {
        let cache = TtlPermissionCache::new(Duration::from_secs(300));
        let s1 = TestSubject { id: "user1".into() };
        let s2 = TestSubject { id: "user2".into() };
        let perm = TestPerm {
            name: "read".into(),
        };

        cache.set(&s1, &perm, true);
        cache.set(&s2, &perm, false);

        assert_eq!(cache.get(&s1, &perm), Some(true));
        assert_eq!(cache.get(&s2, &perm), Some(false));
    }

    #[test]
    fn test_cache_invalidate_one_subject_preserves_others() {
        let cache = TtlPermissionCache::new(Duration::from_secs(300));
        let s1 = TestSubject { id: "u1".into() };
        let s2 = TestSubject { id: "u2".into() };
        let s3 = TestSubject { id: "u3".into() };
        let perm = TestPerm {
            name: "read".into(),
        };

        cache.set(&s1, &perm, true);
        cache.set(&s2, &perm, false);
        cache.set(&s3, &perm, true);

        cache.invalidate_subject(&s2);

        assert_eq!(cache.get(&s1, &perm), Some(true));
        assert_eq!(cache.get(&s2, &perm), None);
        assert_eq!(cache.get(&s3, &perm), Some(true));
    }

    #[test]
    fn test_cache_get_nonexistent_perm() {
        let cache = TtlPermissionCache::new(Duration::from_secs(300));
        let subject = TestSubject { id: "user1".into() };
        let perm = TestPerm {
            name: "read".into(),
        };

        assert_eq!(cache.get(&subject, &perm), None);
    }

    #[test]
    fn test_cache_invalidate_all_drops_everything() {
        let cache = TtlPermissionCache::new(Duration::from_secs(300));
        let s1 = TestSubject { id: "u1".into() };
        let s2 = TestSubject { id: "u2".into() };
        let p1 = TestPerm {
            name: "read".into(),
        };
        let p2 = TestPerm {
            name: "write".into(),
        };

        cache.set(&s1, &p1, true);
        cache.set(&s1, &p2, false);
        cache.set(&s2, &p1, true);

        cache.invalidate_all();

        assert_eq!(cache.get(&s1, &p1), None);
        assert_eq!(cache.get(&s1, &p2), None);
        assert_eq!(cache.get(&s2, &p1), None);
    }

    #[test]
    fn test_cache_invalidate_nonexistent_subject_is_noop() {
        let cache = TtlPermissionCache::new(Duration::from_secs(300));
        let s1 = TestSubject { id: "u1".into() };
        let s2 = TestSubject { id: "u2".into() };
        let perm = TestPerm {
            name: "read".into(),
        };

        cache.set(&s1, &perm, true);
        cache.invalidate_subject(&s2);

        assert_eq!(cache.get(&s1, &perm), Some(true));
    }
}
