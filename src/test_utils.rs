use crate::rbac::traits::{Permission, Subject};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TestSubject(pub String);

impl Subject for TestSubject {
    fn subject_id(&self) -> &str {
        &self.0
    }

    fn from_subject_id(id: &str) -> Self {
        Self(id.to_string())
    }

    fn try_from_subject_id(id: &str) -> anyhow::Result<Self> {
        Ok(Self(id.to_string()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TestPerm {
    Read,
    Write,
    Delete,
    Admin,
}

impl Permission for TestPerm {
    fn name(&self) -> &str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Delete => "delete",
            Self::Admin => "admin",
        }
    }

    fn domain(&self) -> &'static str {
        "test"
    }
}
