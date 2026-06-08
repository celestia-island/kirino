pub mod basic;
pub mod one_time;
pub mod service;

use anyhow::Result;

pub trait Credential {
    #[allow(clippy::missing_errors_doc)]
    fn verify(&self, token: &str) -> Result<bool>;
}
