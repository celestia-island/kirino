use std::hash::{Hash, Hasher};

use crate::{models::identity::Identity, rbac::traits::Subject};

pub trait Delegatable: Subject {
    fn can_delegate_to<S: Subject>(&self, delegate: &S) -> bool;
}

#[derive(Debug, Clone)]
pub struct IdentitySubject {
    identity: Identity,
    id_str: String,
    type_str: &'static str,
}

impl IdentitySubject {
    #[must_use]
    pub fn new(identity: Identity) -> Self {
        let type_str = match &identity {
            Identity::Anonymous { .. } => "anonymous",
            Identity::Basic { .. } => "user",
            Identity::Temporary { .. } => "temporary",
            Identity::Service { .. } => "service",
        };
        let id_str = match &identity {
            Identity::Anonymous { id, .. }
            | Identity::Basic { id }
            | Identity::Temporary { id, .. }
            | Identity::Service { id, .. } => id.to_string(),
        };
        Self {
            identity,
            id_str,
            type_str,
        }
    }

    #[must_use]
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    #[must_use]
    pub fn into_inner(self) -> Identity {
        self.identity
    }

    #[must_use]
    pub fn is_expired(&self) -> bool {
        match &self.identity {
            Identity::Temporary { expires_at, .. } => *expires_at < chrono::Utc::now(),
            _ => false,
        }
    }
}

impl PartialEq for IdentitySubject {
    fn eq(&self, other: &Self) -> bool {
        self.id_str == other.id_str
    }
}

impl Eq for IdentitySubject {}

impl Hash for IdentitySubject {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id_str.hash(state);
    }
}

impl Subject for IdentitySubject {
    fn subject_id(&self) -> &str {
        &self.id_str
    }

    fn subject_type(&self) -> &'static str {
        self.type_str
    }
}

impl Delegatable for IdentitySubject {
    fn can_delegate_to<S: Subject>(&self, delegate: &S) -> bool {
        match &self.identity {
            Identity::Service { caller, .. } => {
                delegate.subject_id() == caller.to_string() && delegate.subject_type() == "user"
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn test_basic_subject() {
        let id = Uuid::now_v7();
        let identity = Identity::Basic { id };
        let subject = IdentitySubject::new(identity);

        assert_eq!(subject.subject_id(), id.to_string());
        assert_eq!(subject.subject_type(), "user");
    }

    #[test]
    fn test_anonymous_subject() {
        let id = Uuid::now_v7();
        let identity = Identity::Anonymous {
            id,
            created_at: chrono::Utc::now(),
        };
        let subject = IdentitySubject::new(identity);

        assert_eq!(subject.subject_id(), id.to_string());
        assert_eq!(subject.subject_type(), "anonymous");
    }

    #[test]
    fn test_temporary_subject_not_expired() {
        let id = Uuid::now_v7();
        let identity = Identity::Temporary {
            id,
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
        };
        let subject = IdentitySubject::new(identity);

        assert_eq!(subject.subject_type(), "temporary");
        assert!(!subject.is_expired());
    }

    #[test]
    fn test_temporary_subject_expired() {
        let id = Uuid::now_v7();
        let identity = Identity::Temporary {
            id,
            expires_at: chrono::Utc::now() - chrono::Duration::hours(1),
        };
        let subject = IdentitySubject::new(identity);
        assert!(subject.is_expired());
    }

    #[test]
    fn test_service_subject() {
        let id = Uuid::now_v7();
        let caller = Uuid::now_v7();
        let identity = Identity::Service {
            id,
            caller,
            created_at: chrono::Utc::now(),
        };
        let subject = IdentitySubject::new(identity);

        assert_eq!(subject.subject_id(), id.to_string());
        assert_eq!(subject.subject_type(), "service");
    }

    #[test]
    fn test_subject_equality() {
        let id = Uuid::now_v7();
        let s1 = IdentitySubject::new(Identity::Basic { id });
        let s2 = IdentitySubject::new(Identity::Basic { id });
        assert_eq!(s1, s2);
    }

    #[test]
    fn test_subject_inequality() {
        let s1 = IdentitySubject::new(Identity::Basic { id: Uuid::now_v7() });
        let s2 = IdentitySubject::new(Identity::Basic { id: Uuid::now_v7() });
        assert_ne!(s1, s2);
    }

    #[test]
    fn test_service_delegation() {
        let caller_id = Uuid::now_v7();
        let service_id = Uuid::now_v7();
        let service = IdentitySubject::new(Identity::Service {
            id: service_id,
            caller: caller_id,
            created_at: chrono::Utc::now(),
        });
        let caller = IdentitySubject::new(Identity::Basic { id: caller_id });
        let stranger = IdentitySubject::new(Identity::Basic { id: Uuid::now_v7() });

        assert!(service.can_delegate_to(&caller));
        assert!(!service.can_delegate_to(&stranger));
    }

    #[test]
    fn test_basic_cannot_delegate() {
        let user = IdentitySubject::new(Identity::Basic { id: Uuid::now_v7() });
        let other = IdentitySubject::new(Identity::Basic { id: Uuid::now_v7() });
        assert!(!user.can_delegate_to(&other));
    }
}
