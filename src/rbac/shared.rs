use std::{ops::Deref, sync::Arc};

#[derive(Debug)]
pub struct Shared<T: ?Sized>(Arc<T>);

impl<T: ?Sized> Clone for Shared<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T> Shared<T> {
    pub fn new(value: T) -> Self {
        Self(Arc::new(value))
    }

    pub fn from_arc(arc: Arc<T>) -> Self {
        Self(arc)
    }

    #[must_use]
    pub fn into_arc(self) -> Arc<T> {
        self.0
    }
}

impl<T: ?Sized> Shared<T> {
    pub fn from_arc_unsized(arc: Arc<T>) -> Self {
        Self(arc)
    }

    #[must_use]
    pub fn strong_count(&self) -> usize {
        Arc::strong_count(&self.0)
    }

    #[must_use]
    pub fn ptr_eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }

    #[must_use]
    pub fn clone_arc(&self) -> Arc<T> {
        Arc::clone(&self.0)
    }
}

impl<T: ?Sized> Deref for Shared<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> Default for Shared<T>
where
    T: Default,
{
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T: ?Sized> PartialEq for Shared<T> {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl<T: ?Sized> Eq for Shared<T> {}

impl<T: ?Sized> std::hash::Hash for Shared<T> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let ptr = Arc::as_ptr(&self.0);
        let thin = ptr.cast::<()>();
        std::ptr::hash(thin, state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn test_clone_semantics() {
        let s = Shared::new(42);
        let s2 = s.clone();
        let s3 = s2.clone();
        assert_eq!(*s, 42);
        assert_eq!(*s2, 42);
        assert_eq!(*s3, 42);
        assert!(s.ptr_eq(&s2));
        assert_eq!(s.strong_count(), 3);
    }

    #[test]
    fn test_deref() {
        let s = Shared::new(vec![1, 2, 3]);
        assert_eq!(s.len(), 3);
        assert_eq!(s[0], 1);
    }

    #[test]
    fn test_default() {
        let s: Shared<Vec<i32>> = Shared::default();
        assert!(s.is_empty());
    }

    #[test]
    fn test_from_arc() {
        let arc = Arc::new(99);
        let s = Shared::from_arc(arc);
        assert_eq!(*s, 99);
    }

    #[test]
    fn test_into_arc() {
        let s = Shared::new(String::from("world"));
        let arc: Arc<String> = s.into_arc();
        assert_eq!(*arc, "world");
    }

    #[test]
    fn test_drop_decrements() {
        static COUNT: AtomicUsize = AtomicUsize::new(0);

        struct Tracked;
        impl Tracked {
            fn new() -> Self {
                COUNT.fetch_add(1, Ordering::SeqCst);
                Self
            }
        }
        impl Drop for Tracked {
            fn drop(&mut self) {
                COUNT.fetch_sub(1, Ordering::SeqCst);
            }
        }

        COUNT.store(0, Ordering::SeqCst);
        let s1 = Shared::new(Tracked::new());
        let s2 = s1.clone();
        assert_eq!(COUNT.load(Ordering::SeqCst), 1);
        drop(s1);
        assert_eq!(COUNT.load(Ordering::SeqCst), 1);
        drop(s2);
        assert_eq!(COUNT.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_equality_and_hash() {
        use std::collections::HashSet;

        let s1 = Shared::new(42);
        let s2 = s1.clone();
        assert_eq!(s1, s2);

        let s3 = Shared::new(42);
        assert_ne!(s1, s3);

        let mut set = HashSet::new();
        set.insert(s1);
        set.insert(s2);
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn test_not_clone_inner() {
        #[derive(Debug)]
        struct NotClone(i32);

        let s = Shared::new(NotClone(10));
        let s2 = s.clone();
        assert_eq!((*s).0, 10);
        assert_eq!((*s2).0, 10);
    }

    #[test]
    fn test_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Shared<i32>>();
        assert_send_sync::<Shared<String>>();
    }

    #[test]
    fn test_trait_object() {
        trait Greet {
            fn greet(&self) -> &str;
        }
        struct Hello;
        impl Greet for Hello {
            fn greet(&self) -> &'static str {
                "hello"
            }
        }

        let s: Shared<dyn Greet> = Shared::from_arc_unsized(Arc::new(Hello));
        assert_eq!(s.greet(), "hello");
        let s2 = s.clone();
        assert!(s.ptr_eq(&s2));
    }

    #[test]
    fn test_clone_arc() {
        let s = Shared::new(42);
        let arc = s.clone_arc();
        assert_eq!(*arc, 42);
        let ptr = Arc::as_ptr(&arc);
        assert_eq!(unsafe { *ptr }, 42);
    }
}
