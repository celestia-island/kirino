use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use chrono::Utc;

/// In-memory one-shot token store that tracks JTI (JWT ID) claims
/// to prevent token replay attacks.
///
/// Each token carries a unique `jti` claim.  When a token is used for
/// the first time its JTI is recorded.  Subsequent uses of the same
/// JTI are rejected until the token expires (at which point the JTI
/// is automatically purged).
///
/// # Example
/// ```ignore
/// use kirino_session::OneShotStore;
///
/// let store = OneShotStore::new();
/// let expiry = chrono::Utc::now().timestamp() + 30;
///
/// assert!(!store.check_and_mark("jti-1", expiry)); // first use: allowed
/// assert!( store.check_and_mark("jti-1", expiry)); // second use: denied
/// ```
#[derive(Clone)]
pub struct OneShotStore {
    used: Arc<Mutex<HashMap<String, i64>>>,
}

impl OneShotStore {
    /// Create a new store with automatic expiry cleanup every 60 seconds.
    pub fn new() -> Self {
        let store = Self {
            used: Arc::new(Mutex::new(HashMap::new())),
        };
        let used = store.used.clone();
        thread::spawn(move || loop {
            thread::sleep(Duration::from_secs(60));
            let now = Utc::now().timestamp();
            if let Ok(mut map) = used.lock() {
                map.retain(|_, exp| *exp > now);
            }
        });
        store
    }

    /// Check whether `jti` has already been used, and mark it as used
    /// if not.  `expiry` is a Unix timestamp after which the JTI is
    /// automatically pruned.
    ///
    /// Returns `true` if the JTI was already present (replay attempt),
    /// `false` if it is fresh (allowed).
    pub fn check_and_mark(&self, jti: &str, expiry: i64) -> bool {
        self.used
            .lock()
            .map(|mut map| map.insert(jti.to_string(), expiry).is_some())
            .unwrap_or(false)
    }

    /// Return the current number of tracked JTIs (useful for monitoring).
    pub fn len(&self) -> usize {
        self.used.lock().map(|m| m.len()).unwrap_or(0)
    }

    /// Returns `true` if the store is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for OneShotStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_use_allowed_second_denied() {
        let store = OneShotStore::new();
        let expiry = Utc::now().timestamp() + 30;
        assert!(!store.check_and_mark("abc", expiry));
        assert!(store.check_and_mark("abc", expiry));
    }

    #[test]
    fn different_jtis_independent() {
        let store = OneShotStore::new();
        let expiry = Utc::now().timestamp() + 30;
        assert!(!store.check_and_mark("a", expiry));
        assert!(!store.check_and_mark("b", expiry));
        assert!(store.check_and_mark("a", expiry));
        assert!(!store.check_and_mark("c", expiry));
    }

    #[test]
    fn expired_jti_purged() {
        let store = OneShotStore::new();
        let past = Utc::now().timestamp() - 10;
        store.check_and_mark("expired", past);
        assert_eq!(store.len(), 1);
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn empty_store() {
        let store = OneShotStore::new();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn len_tracks_insertions() {
        let store = OneShotStore::new();
        let expiry = Utc::now().timestamp() + 60;
        store.check_and_mark("a", expiry);
        store.check_and_mark("b", expiry);
        assert_eq!(store.len(), 2);
        store.check_and_mark("b", expiry);
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn concurrent_access() {
        use std::sync::Arc;
        use std::thread;

        let store = Arc::new(OneShotStore::new());
        let mut handles = vec![];
        let expiry = Utc::now().timestamp() + 60;

        for i in 0..10 {
            let s = store.clone();
            handles.push(thread::spawn(move || {
                let jti = format!("jti-{}", i % 5);
                s.check_and_mark(&jti, expiry)
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(store.len(), 5);
    }
}
