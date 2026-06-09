#![allow(missing_docs)]
#![allow(clippy::missing_errors_doc)]

use anyhow::Result;
use std::net::IpAddr;

pub struct NetworkSourceVerifier {
    #[allow(dead_code)]
    allowed_networks: Vec<String>,
}

impl NetworkSourceVerifier {
    #[must_use]
    pub fn new(allowed_networks: Vec<String>) -> Self {
        Self { allowed_networks }
    }

    pub fn is_allowed(&self, _source_ip: IpAddr) -> Result<bool> {
        unimplemented!("network source IP whitelist verification")
    }
}
