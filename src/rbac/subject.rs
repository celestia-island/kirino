use crate::rbac::traits::Subject;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StringSubject(String);

impl StringSubject {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

impl Subject for StringSubject {
    fn subject_id(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for StringSubject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
