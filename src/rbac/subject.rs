use crate::rbac::traits::Subject;

/// A subject whose identity is an arbitrary string, for services that key
/// accounts by a non-UUID id (usernames, tenant-scoped ids).
///
/// Security semantics: the id is used verbatim as the assignment, deny and
/// cache key, with no validation, normalization or case folding. Two ids that
/// differ only by case, surrounding whitespace or Unicode normalization are
/// therefore different principals here, so any caller that accepts untrusted
/// text must canonicalize it before constructing this type - otherwise the
/// same human can end up with two sets of assignments. Equality and hashing
/// follow the exact string.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StringSubject(String);

impl StringSubject {
    /// Wraps an id that the caller has already validated. Nothing is checked
    /// or trimmed here: an empty string is accepted and becomes a valid
    /// principal, so reject empty ids at the boundary where they are read.
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

impl Subject for StringSubject {
    /// The wrapped id unchanged; this is the key every store and cache lookup
    /// uses.
    fn subject_id(&self) -> &str {
        &self.0
    }

    /// Accepts the stored id as-is: rehydration never fails for this type, so
    /// a corrupt or attacker-chosen id in a row becomes a usable principal
    /// rather than a load error. Prefer a validating subject type when the id
    /// is not fully trusted.
    fn from_subject_id(id: &str) -> Self {
        Self::new(id)
    }

    /// Always `Ok`, with the same no-validation behaviour as
    /// [`from_subject_id`](Subject::from_subject_id). The error path exists
    /// for validating subject types; it is never taken here.
    fn try_from_subject_id(id: &str) -> anyhow::Result<Self> {
        Ok(Self::new(id))
    }
}

impl std::fmt::Display for StringSubject {
    /// Renders the raw id for logs and audit rows. It is the same value that
    /// keys the stores, so do not print it where the id itself is sensitive.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
