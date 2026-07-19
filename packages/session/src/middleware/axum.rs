use axum::{
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Response},
};
use std::sync::Arc;

use crate::{SessionError, TokenClaims, TokenManager};

/// Extractor that validates a JWT from the Authorization header.
pub struct JwtClaims {
    pub claims: TokenClaims,
}

#[axum::async_trait]
impl<S> FromRequestParts<S> for JwtClaims
where
    S: Send + Sync,
{
    type Rejection = AuthRejection;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let manager = parts
            .extensions
            .get::<Arc<TokenManager>>()
            .cloned()
            .ok_or(AuthRejection::MissingManager)?;

        let header = parts
            .headers
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .ok_or(AuthRejection::MissingHeader)?;

        let token = header
            .strip_prefix("Bearer ")
            .ok_or(AuthRejection::InvalidFormat)?;

        let claims = manager.verify(token).map_err(|e| match e {
            SessionError::Expired(_) => AuthRejection::Expired,
            _ => AuthRejection::Invalid,
        })?;

        Ok(JwtClaims { claims })
    }
}

#[derive(Debug)]
pub enum AuthRejection {
    MissingHeader,
    InvalidFormat,
    Invalid,
    Expired,
    MissingManager,
}

impl IntoResponse for AuthRejection {
    fn into_response(self) -> Response {
        let (status, msg) = match self {
            AuthRejection::MissingHeader => (StatusCode::UNAUTHORIZED, "missing Authorization header"),
            AuthRejection::InvalidFormat => (StatusCode::UNAUTHORIZED, "invalid Authorization format"),
            AuthRejection::Invalid => (StatusCode::UNAUTHORIZED, "invalid token"),
            AuthRejection::Expired => (StatusCode::UNAUTHORIZED, "token expired"),
            AuthRejection::MissingManager => (StatusCode::INTERNAL_SERVER_ERROR, "auth not configured"),
        };
        (status, msg).into_response()
    }
}

/// Put `Arc<TokenManager>` into axum extensions for `JwtClaims` to find.
pub fn layer(manager: TokenManager) -> Arc<TokenManager> {
    Arc::new(manager)
}
