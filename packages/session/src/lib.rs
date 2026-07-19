//! Distributed JWT session management for kirino.
//!
//! Provides:
//! - JWT token signing and verification with shared secret
//! - Session persistence via PostgreSQL (optional `postgres` feature)
//! - Token refresh mechanism
//! - Revocation list support
//!
//! # Example
//! ```ignore
//! use kirino_session::{TokenManager, SessionConfig};
//!
//! let config = SessionConfig::new("my-secret-key");
//! let manager = TokenManager::new(config);
//!
//! let token = manager.sign(&claims)?;
//! let verified = manager.verify(&token)?;
//! ```

mod config;
mod error;
mod manager;
pub mod middleware;
mod token;

#[cfg(feature = "postgres")]
mod store;

pub use config::SessionConfig;
pub use error::{SessionError, SessionResult};
pub use manager::TokenManager;
pub use token::{TokenClaims, TokenPair, TokenType};

/// Session management for distributed deployments.
///
/// Uses JWT with shared secret (all instances share the same `JWT_SECRET`),
/// so tokens survive server restarts and work across load-balanced nodes.
/// Optional PostgreSQL backend enables session revocation and blacklisting.
///
/// # Quick Start
///
/// ```no_run
/// use kirino_session::{TokenManager, SessionConfig};
///
/// let config = SessionConfig::new(std::env::var("JWT_SECRET").unwrap());
/// let manager = TokenManager::new(config);
///
/// // Issue tokens after login
/// let pair = manager.issue_pair(user_id, "alice".into(), vec!["admin".into()])?;
///
/// // Verify on each request
/// let claims = manager.verify(&pair.access_token)?;
/// ```
///
/// # Axum Integration
///
/// ```no_run
/// use kirino_session::middleware::axum::{self, JwtClaims};
/// use axum::{routing::get, Router};
///
/// let manager = axum::layer(TokenManager::new(config));
/// let app = Router::new()
///     .route("/api/me", get(|claims: JwtClaims| async {
///         format!("Hello, {}!", claims.claims.username)
///     }))
///     .layer(axum::Extension(manager));
/// ```
///
/// # Features
///
/// | Flag | Description |
/// |------|-------------|
/// | `axum` (default) | `JwtClaims` extractor for axum 0.8 |
/// | `actix` | `JwtMiddleware` for actix-web 4 |
/// | `postgres` | `SessionStore` backed by sea-orm/PostgreSQL |
