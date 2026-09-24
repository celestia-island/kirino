use std::hash::{Hash, Hasher};

use anyhow::Result;
use chrono::Utc;

use crate::{models::identity::Identity, rbac::traits::Subject};

/// A subject that may act on behalf of another one.
///
/// Security semantics: delegation is the one place where authority is
/// transferred without a grant, so an implementation must be deny-by-default -
/// a subject type that returns `true` for an unrelated delegate lets it act
/// with the caller's permissions. Only the delegate check itself is modelled
/// here; nothing in this trait records or audits the delegation.
pub trait Delegatable: Subject {
    /// Check if this subject can delegate to the given subject.
    ///
    /// Only [`Identity::Service`] can delegate, and only to the `caller`
    /// whose UUID matches `delegate.subject_id()`. The delegate is expected
    /// to be an [`IdentitySubject`] (or another type whose `subject_id()`
    /// returns a UUID string).
    ///
    /// Deny-by-default: any identity that is not a service identity returns
    /// `false`, and the check also requires the delegate to report subject
    /// type `"user"` - a service identity cannot chain delegation to another
    /// service. The comparison is a plain string comparison of id strings, not
    /// a constant-time comparison; that is acceptable only because the ids are
    /// not secrets.
    fn can_delegate_to<S: Subject>(&self, delegate: &S) -> bool;
}

/// A subject built from an [`Identity`], the principal type used across the
/// auth service.
///
/// Security semantics: the subject id is the identity's UUID rendered as a
/// string, and the subject type is derived from the identity variant
/// (`anonymous`, `user`, `temporary`, `service`). Equality and hashing use the
/// (id, type) pair, so the same UUID with a different identity kind is a
/// DIFFERENT principal - an anonymous identity can never inherit the
/// assignments of the user with the same UUID. `is_expired` is a check, not a
/// gate: nothing in this type prevents an expired temporary identity from
/// being constructed or used, so callers must enforce expiry explicitly.
#[derive(Debug, Clone)]
pub struct IdentitySubject {
    identity: Identity,
    id_str: String,
    type_str: &'static str,
}

impl IdentitySubject {
    /// Derives the id and type strings once from the identity variant.
    ///
    /// Security semantics: the derived type string is what delegation checks
    /// compare against `"user"`, and the derived id string is what stores and
    /// the permission cache key on, so a wrong derivation would widen
    /// authority rather than merely mislabel it.
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
            | Identity::Basic { id, .. }
            | Identity::Temporary { id, .. }
            | Identity::Service { id, .. } => id.to_string(),
        };
        Self {
            identity,
            id_str,
            type_str,
        }
    }

    /// Borrows the underlying identity for callers that need the full
    /// credential detail (expiry, service caller) beyond the subject id and
    /// type.
    #[must_use]
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// Consumes the subject and returns the identity it was built from; the
    /// derived id/type strings are dropped and recomputed if it is wrapped
    /// again.
    #[must_use]
    pub fn into_inner(self) -> Identity {
        self.identity
    }

    /// Builds a `Basic` (user) subject from a user id string.
    ///
    /// Returns `Err` when the id is not a valid UUID - this is the
    /// error-preserving constructor, so a malformed id from a request or a
    /// stored row surfaces as an error instead of becoming an anonymous
    /// principal. The `created_at` timestamp is set to now and is metadata
    /// only; it does not affect authorization.
    pub fn user(id: &str) -> Result<Self> {
        let uuid = uuid::Uuid::parse_str(id)
            .map_err(|e| anyhow::anyhow!("invalid user UUID '{}': {}", id, e))?;
        Ok(Self::new(Identity::Basic {
            id: uuid,
            created_at: Utc::now(),
        }))
    }

    /// Whether this is a `Temporary` identity whose `expires_at` is in the
    /// past. Always `false` for anonymous, basic and service identities, which
    /// have no expiry of their own (their lifetime is bounded by the session
    /// and token layer instead).
    ///
    /// Security semantics: this reports the state but does not act on it, and
    /// it is not consulted by the permission engine - a caller that accepts an
    /// expired temporary subject without checking this would keep honouring
    /// assignments attached to it. The boundary is exclusive: an identity is
    /// expired only once `now` has passed `expires_at`.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        match &self.identity {
            Identity::Temporary { expires_at, .. } => *expires_at < chrono::Utc::now(),
            _ => false,
        }
    }
}

impl PartialEq for IdentitySubject {
    /// Identity equality on (subject id, subject type): the same UUID with a
    /// different identity kind is not the same principal, so assignments
    /// cannot leak across identity kinds.
    fn eq(&self, other: &Self) -> bool {
        self.id_str == other.id_str && self.type_str == other.type_str
    }
}

impl Eq for IdentitySubject {}

impl Hash for IdentitySubject {
    /// Hashes exactly the (id, type) pair used by
    /// [`eq`](IdentitySubject::eq); hashing anything else would break the
    /// `Eq`/`Hash` contract that store and cache keying relies on.
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id_str.hash(state);
        self.type_str.hash(state);
    }
}

impl Subject for IdentitySubject {
    /// The UUID string of the identity; identical for every identity kind that
    /// carries the same UUID, which is why the type string is part of equality.
    fn subject_id(&self) -> &str {
        &self.id_str
    }

    /// One of `anonymous`, `user`, `temporary`, `service`, derived at
    /// construction. Delegation requires `"user"`, so this value decides
    /// whether the subject can be delegated to.
    fn subject_type(&self) -> &'static str {
        self.type_str
    }

    /// Infallible conversion used when rehydrating a stored id.
    ///
    /// Error contract as implemented: a non-UUID id is logged at error level
    /// and silently downgraded to an ANONYMOUS identity with the nil UUID -
    /// this never panics and never returns an error. The returned anonymous
    /// principal has no assignments and cannot delegate, so a malformed or
    /// tampered id cannot escalate; the danger is the opposite one, that a
    /// caller mistakes the anonymous fallback for the principal it asked for.
    /// Use [`try_from_subject_id`](Subject::try_from_subject_id) whenever the
    /// id comes from untrusted input or must not be replaced silently.
    fn from_subject_id(id: &str) -> Self {
        Self::try_from_subject_id(id).unwrap_or_else(|e| {
            tracing::error!(
                target: "kirino::rbac::identity_subject",
                "from_subject_id called with invalid UUID '{}': {} — \
                 use try_from_subject_id to handle this error gracefully. \
                 Falling back to anonymous identity.",
                id, e
            );
            Self::new(Identity::Anonymous {
                id: uuid::Uuid::nil(),
                created_at: chrono::Utc::now(),
            })
        })
    }

    /// Fallible conversion: parses a UUID and builds a `Basic` (user) subject,
    /// or returns `Err` when the id is not a valid UUID.
    ///
    /// Error contract as implemented: the error is produced for exactly the
    /// same input that [`from_subject_id`](Subject::from_subject_id) would
    /// downgrade to anonymous, which is what lets session loading turn a
    /// corrupt row into a failed load (fail-closed) instead of an unprivileged
    /// but successful login. Note the type string is always `"user"` here: a
    /// service or temporary identity cannot be reconstructed from an id alone
    /// and must be built through [`IdentitySubject::new`].
    fn try_from_subject_id(id: &str) -> Result<Self> {
        let uuid = uuid::Uuid::parse_str(id)
            .map_err(|e| anyhow::anyhow!("invalid subject UUID '{}': {}", id, e))?;
        Ok(Self::new(Identity::Basic {
            id: uuid,
            created_at: Utc::now(),
        }))
    }
}

impl Delegatable for IdentitySubject {
    /// True only for a `Service` identity delegating to the user named as its
    /// `caller`: the delegate's subject id must equal the caller UUID and the
    /// delegate must report type `"user"`. Everything else - a service
    /// delegating to another service, a user or anonymous subject delegating
    /// at all - is `false` by default. The ids are compared as strings (not in
    /// constant time); they are identifiers, not secrets.
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

    fn basic_id(id: Uuid) -> Identity {
        Identity::Basic {
            id,
            created_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn test_basic_subject() {
        let id = Uuid::now_v7();
        let subject = IdentitySubject::new(basic_id(id));

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
        let s1 = IdentitySubject::new(basic_id(id));
        let s2 = IdentitySubject::new(basic_id(id));
        assert_eq!(s1, s2);
    }

    #[test]
    fn test_subject_inequality() {
        let s1 = IdentitySubject::new(basic_id(Uuid::now_v7()));
        let s2 = IdentitySubject::new(basic_id(Uuid::now_v7()));
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
        let caller = IdentitySubject::new(basic_id(caller_id));
        let stranger = IdentitySubject::new(basic_id(Uuid::now_v7()));

        assert!(service.can_delegate_to(&caller));
        assert!(!service.can_delegate_to(&stranger));
    }

    #[test]
    fn test_basic_cannot_delegate() {
        let user = IdentitySubject::new(basic_id(Uuid::now_v7()));
        let other = IdentitySubject::new(basic_id(Uuid::now_v7()));
        assert!(!user.can_delegate_to(&other));
    }
}
