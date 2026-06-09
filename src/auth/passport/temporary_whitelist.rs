#![allow(missing_docs)]
#![allow(clippy::missing_errors_doc)]

use anyhow::Result;
use std::{net::IpAddr, time::Instant};

pub struct WhitelistEntry {
    pub source: ClientSource,
    pub expires_at: Option<Instant>,
}

#[derive(Debug, Clone)]
pub enum ClientSource {
    Ip(IpAddr),
    Mac(String),
}

pub struct WhitelistVerifier {
    #[allow(dead_code)]
    entries: Vec<WhitelistEntry>,
}

impl WhitelistVerifier {
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn is_whitelisted(&self, source: &ClientSource) -> Result<bool> {
        let _ = source;
        unimplemented!("whitelist checking with expiry")
    }

    pub fn add(&mut self, source: ClientSource, ttl: Option<std::time::Duration>) {
        let _ = (source, ttl);
        unimplemented!("whitelist entry addition")
    }
}

impl Default for WhitelistVerifier {
    fn default() -> Self {
        Self::new()
    }
}
