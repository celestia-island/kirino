use anyhow::Result;
use std::{net::IpAddr, time::Instant};

pub struct WhitelistEntry {
    pub source: ClientSource,
    pub expires_at: Option<Instant>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ClientSource {
    Ip(IpAddr),
    Mac(String),
}

pub struct WhitelistVerifier {
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
        let now = Instant::now();
        for entry in &self.entries {
            if &entry.source == source {
                if let Some(expires) = entry.expires_at {
                    if now < expires {
                        return Ok(true);
                    }
                } else {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    pub fn add(&mut self, source: ClientSource, ttl: Option<std::time::Duration>) {
        let expires_at = ttl.map(|d| Instant::now() + d);
        self.entries.retain(|e| e.source != source);
        self.entries.push(WhitelistEntry { source, expires_at });
    }

    pub fn remove(&mut self, source: &ClientSource) {
        self.entries.retain(|e| &e.source != source);
    }

    pub fn cleanup_expired(&mut self) -> usize {
        let before = self.entries.len();
        let now = Instant::now();
        self.entries
            .retain(|e| e.expires_at.map_or(true, |exp| now < exp));
        before - self.entries.len()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for WhitelistVerifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::time::Duration;

    #[test]
    fn test_add_and_check_ip() {
        let mut wl = WhitelistVerifier::new();
        let ip = ClientSource::Ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        wl.add(ip.clone(), None);
        assert!(wl.is_whitelisted(&ip).unwrap());
    }

    #[test]
    fn test_not_whitelisted() {
        let wl = WhitelistVerifier::new();
        let ip = ClientSource::Ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(!wl.is_whitelisted(&ip).unwrap());
    }

    #[test]
    fn test_ttl_expiry() {
        let mut wl = WhitelistVerifier::new();
        let ip = ClientSource::Ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        wl.add(ip.clone(), Some(Duration::from_millis(1)));
        std::thread::sleep(Duration::from_millis(5));
        assert!(!wl.is_whitelisted(&ip).unwrap());
    }

    #[test]
    fn test_remove() {
        let mut wl = WhitelistVerifier::new();
        let ip = ClientSource::Ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        wl.add(ip.clone(), None);
        assert_eq!(wl.len(), 1);
        wl.remove(&ip);
        assert!(!wl.is_whitelisted(&ip).unwrap());
        assert!(wl.is_empty());
    }

    #[test]
    fn test_mac_address() {
        let mut wl = WhitelistVerifier::new();
        let mac = ClientSource::Mac("AA:BB:CC:DD:EE:FF".to_string());
        wl.add(mac.clone(), None);
        assert!(wl.is_whitelisted(&mac).unwrap());
    }

    #[test]
    fn test_remove_nonexistent() {
        let mut wl = WhitelistVerifier::new();
        let ip = ClientSource::Ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        wl.remove(&ip);
        assert!(wl.is_empty());
    }

    #[test]
    fn test_multiple_entries() {
        let mut wl = WhitelistVerifier::new();
        let ip1 = ClientSource::Ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        let ip2 = ClientSource::Ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        let mac = ClientSource::Mac("AA:BB:CC:DD:EE:FF".to_string());
        wl.add(ip1.clone(), None);
        wl.add(ip2.clone(), None);
        wl.add(mac.clone(), None);
        assert_eq!(wl.len(), 3);
        assert!(wl.is_whitelisted(&ip1).unwrap());
        assert!(wl.is_whitelisted(&ip2).unwrap());
        assert!(wl.is_whitelisted(&mac).unwrap());
    }

    #[test]
    fn test_ipv6_whitelist() {
        let mut wl = WhitelistVerifier::new();
        let ip = ClientSource::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST));
        wl.add(ip.clone(), None);
        assert!(wl.is_whitelisted(&ip).unwrap());
    }

    #[test]
    fn test_cleanup_expired() {
        let mut wl = WhitelistVerifier::new();
        let ip1 = ClientSource::Ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        let ip2 = ClientSource::Ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        wl.add(ip1.clone(), Some(Duration::from_millis(1)));
        wl.add(ip2.clone(), None);
        assert_eq!(wl.len(), 2);

        std::thread::sleep(Duration::from_millis(5));
        let cleaned = wl.cleanup_expired();
        assert_eq!(cleaned, 1);
        assert_eq!(wl.len(), 1);
        assert!(!wl.is_whitelisted(&ip1).unwrap());
        assert!(wl.is_whitelisted(&ip2).unwrap());
    }

    #[test]
    fn test_cleanup_no_expired() {
        let mut wl = WhitelistVerifier::new();
        let ip = ClientSource::Ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        wl.add(ip.clone(), None);
        assert_eq!(wl.cleanup_expired(), 0);
        assert_eq!(wl.len(), 1);
    }

    #[test]
    fn test_re_add_replaces() {
        let mut wl = WhitelistVerifier::new();
        let ip = ClientSource::Ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        wl.add(ip.clone(), None);
        wl.add(ip.clone(), None);
        assert_eq!(wl.len(), 1);
    }

    #[test]
    fn test_empty_verifier() {
        let wl = WhitelistVerifier::new();
        assert!(wl.is_empty());
        assert_eq!(wl.len(), 0);
    }
}
