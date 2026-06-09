use std::fmt;

#[derive(Debug)]
pub enum KirinoError {
    Store(String),
    NotFound(String),
    Validation(String),
    AuthenticationFailed,
    AuthorizationDenied(String),
    SessionExpired,
    SessionNotFound,
    ConstraintViolation(String),
    Internal(String),
}

impl fmt::Display for KirinoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KirinoError::Store(msg) => write!(f, "store error: {msg}"),
            KirinoError::NotFound(msg) => write!(f, "not found: {msg}"),
            KirinoError::Validation(msg) => write!(f, "validation error: {msg}"),
            KirinoError::AuthenticationFailed => write!(f, "authentication failed"),
            KirinoError::AuthorizationDenied(msg) => write!(f, "authorization denied: {msg}"),
            KirinoError::SessionExpired => write!(f, "session expired"),
            KirinoError::SessionNotFound => write!(f, "session not found"),
            KirinoError::ConstraintViolation(msg) => write!(f, "constraint violation: {msg}"),
            KirinoError::Internal(msg) => write!(f, "internal error: {msg}"),
        }
    }
}

impl std::error::Error for KirinoError {}

impl From<anyhow::Error> for KirinoError {
    fn from(e: anyhow::Error) -> Self {
        KirinoError::Internal(e.to_string())
    }
}

pub type KirinoResult<T> = Result<T, KirinoError>;
