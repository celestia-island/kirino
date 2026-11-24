#[cfg(feature = "auth-jwt")]
pub mod basic;
pub mod one_time;
pub mod service;

use anyhow::Result;

#[cfg(feature = "auth-jwt")]
pub use basic::RevocationBackend;

pub trait Credential {
    /// Verifies the given token against the stored credential.
    ///
    /// # Errors
    ///
    /// Returns an error if verification fails due to an internal error.
    fn verify(&self, token: &str) -> Result<bool>;
}
