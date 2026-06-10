use thiserror::Error;

#[derive(Debug, Clone, Error)]
pub enum KirinoError {
    #[error("not found: {0}")]
    NotFound(String),

    #[error("validation error: {0}")]
    Validation(String),

    #[error("authentication failed")]
    AuthenticationFailed,

    #[error("authorization denied: {0}")]
    AuthorizationDenied(String),

    #[error("session expired")]
    SessionExpired,

    #[error("session not found")]
    SessionNotFound,

    #[error("constraint violation: {0}")]
    ConstraintViolation(String),

    #[error("internal error: {0}")]
    Internal(String),
}
