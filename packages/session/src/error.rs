use thiserror::Error;

#[derive(Error, Debug)]
pub enum SessionError {
    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
    #[error("invalid token: {0}")]
    InvalidToken(String),
    #[error("token expired at {0}")]
    Expired(chrono::DateTime<chrono::Utc>),
    #[error("token revoked")]
    Revoked,
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[cfg(feature = "postgres")]
    #[error("database error: {0}")]
    Db(#[from] sea_orm::DbErr),
    #[error("{0}")]
    Other(String),
}

pub type SessionResult<T> = Result<T, SessionError>;
