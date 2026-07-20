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
//! use kirino-session::{TokenManager, SessionConfig};
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
mod one_shot;
mod token;

#[cfg(feature = "postgres")]
mod store;

pub use config::SessionConfig;
pub use error::{SessionError, SessionResult};
pub use manager::TokenManager;
pub use one_shot::OneShotStore;
pub use token::{TokenClaims, TokenPair, TokenType};

