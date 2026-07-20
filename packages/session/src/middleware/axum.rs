use axum::{
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Response},
};
use std::sync::Arc;

use crate::{SessionError, TokenClaims, TokenManager};

// ── Simple extractor (Bearer header, backward-compat) ──────────────

/// JWT claims extractor — reads `Authorization: Bearer <token>`.
pub struct JwtClaims {
    pub claims: TokenClaims,
}

impl<S> FromRequestParts<S> for JwtClaims
where
    S: Send + Sync,
{
    type Rejection = AuthRejection;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let Extension(manager): Extension<Arc<TokenManager>> =
            Extension::from_request_parts(parts, _state)
                .await
                .map_err(|_| AuthRejection::MissingManager)?;

        let token = parts
            .headers
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or(AuthRejection::MissingHeader)?;

        let claims = manager.verify(token).map_err(|e| match e {
            SessionError::Expired(_) => AuthRejection::Expired,
            _ => AuthRejection::Invalid,
        })?;

        Ok(JwtClaims { claims })
    }
}

// ── Multi-source extractor ─────────────────────────────────────────

/// Token source for [`MultiJwt`].
#[derive(Clone)]
pub enum AuthSource {
    /// `Authorization: Bearer <token>` header.
    Bearer,
    /// Cookie value of the named cookie.
    Cookie(String),
    /// Query parameter value of the named param.
    Query(String),
}

/// Configuration for [`MultiJwt`].  Inject with
/// `axum::Extension(MultiJwtConfig { ... })`.
#[derive(Clone)]
pub struct MultiJwtConfig {
    /// Sources tried in declaration order.  The first source that yields
    /// a non-empty token string wins.
    pub sources: Vec<AuthSource>,
}

/// Multi-source JWT claims extractor.
///
/// ```ignore
/// let app = Router::new()
///     .route("/api", get(handler))
///     .layer(Extension(Arc::new(TokenManager::new(config))))
///     .layer(Extension(MultiJwtConfig {
///         sources: vec![
///             AuthSource::Bearer,
///             AuthSource::Cookie("wsat".into()),
///             AuthSource::Query("token".into()),
///         ],
///     }));
///
/// async fn handler(claims: MultiJwt) -> String {
///     format!("Hello, {}", claims.claims.username)
/// }
/// ```
pub struct MultiJwt {
    pub claims: TokenClaims,
}

impl<S> FromRequestParts<S> for MultiJwt
where
    S: Send + Sync,
{
    type Rejection = AuthRejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let Extension(manager): Extension<Arc<TokenManager>> =
            Extension::from_request_parts(parts, state)
                .await
                .map_err(|_| AuthRejection::MissingManager)?;

        let Extension(config): Extension<MultiJwtConfig> =
            Extension::from_request_parts(parts, state)
                .await
                .map_err(|_| AuthRejection::MissingManager)?;

        let token = config
            .sources
            .iter()
            .find_map(|s| extract_token(s, parts))
            .ok_or(AuthRejection::MissingHeader)?;

        let claims = manager.verify(&token).map_err(|e| match e {
            SessionError::Expired(_) => AuthRejection::Expired,
            _ => AuthRejection::Invalid,
        })?;

        Ok(MultiJwt { claims })
    }
}

fn extract_token(source: &AuthSource, parts: &Parts) -> Option<String> {
    match source {
        AuthSource::Bearer => parts
            .headers
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(|s| s.to_string()),
        AuthSource::Cookie(name) => parts
            .headers
            .get("Cookie")
            .and_then(|v| v.to_str().ok())
            .and_then(|raw| {
                raw.split(';')
                    .map(str::trim)
                    .filter_map(|pair| pair.strip_prefix(&format!("{name}=")))
                    .next()
            })
            .map(|s| s.to_string()),
        AuthSource::Query(name) => parts.uri.query().and_then(|query| {
            query
                .split('&')
                .filter_map(|pair| pair.split_once('='))
                .find(|(k, _)| *k == *name)
                .map(|(_, v)| v.to_string())
        }),
    }
}

use axum::Extension;

// ── Layer helpers ──────────────────────────────────────────────────

/// Put `Arc<TokenManager>` into request extensions.
/// Equivalent to `.layer(Extension(Arc::new(manager)))`.
pub fn layer(manager: TokenManager) -> Arc<TokenManager> {
    Arc::new(manager)
}

// ── Rejection ──────────────────────────────────────────────────────

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
            Self::MissingHeader => {
                (StatusCode::UNAUTHORIZED, "missing credentials")
            },
            Self::InvalidFormat => {
                (StatusCode::UNAUTHORIZED, "invalid credential format")
            },
            Self::Invalid => (StatusCode::UNAUTHORIZED, "invalid token"),
            Self::Expired => (StatusCode::UNAUTHORIZED, "token expired"),
            Self::MissingManager => {
                (StatusCode::INTERNAL_SERVER_ERROR, "auth not configured")
            },
        };
        (status, msg).into_response()
    }
}
