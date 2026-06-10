use crate::rbac::traits::{Permission, Subject};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TestSubject(pub String);

impl Subject for TestSubject {
    fn subject_id(&self) -> &str {
        &self.0
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
        _ = self;
        "test"
    }
}
