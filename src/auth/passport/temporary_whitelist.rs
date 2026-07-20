use anyhow::Result;
use std::{net::IpAddr, time::Instant};
use tokio::sync::RwLock;

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
    entries: RwLock<Vec<WhitelistEntry>>,
}

impl WhitelistVerifier {
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(Vec::new()),
        }
    }

    pub async fn is_whitelisted(&self, source: &ClientSource) -> Result<bool> {
        let now = Instant::now();
        let entries = self.entries.read().await;
        for entry in entries.iter() {
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

    pub async fn add(&self, source: ClientSource, ttl: Option<std::time::Duration>) {
        let expires_at = ttl.map(|d| Instant::now() + d);
        let mut entries = self.entries.write().await;
        let now = Instant::now();
        entries.retain(|e| e.expires_at.map_or(true, |exp| now < exp));

        let mut entries = self.entries.write().await;
        let expires_at = ttl.map(|d| Instant::now() + d);

        entries.retain(|e| e.source != source);
        entries.push(WhitelistEntry { source, expires_at });
    }

    pub async fn remove(&self, source: &ClientSource) {
        let mut entries = self.entries.write().await;
        entries.retain(|e| &e.source != source);
    }

    #[must_use]
    pub async fn cleanup_expired(&self) -> usize {
        let mut entries = self.entries.write().await;
        let before = entries.len();
        if before == 0 {
            return 0;
        }
        let now = Instant::now();
        entries.retain(|e| e.expires_at.map_or(true, |exp| now < exp));
        before - entries.len()
    }

    #[must_use]
    pub async fn len(&self) -> usize {
        let entries = self.entries.read().await;
        entries.len()
    }

    #[must_use]
    pub async fn is_empty(&self) -> bool {
        let entries = self.entries.read().await;
        entries.is_empty()
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

    #[tokio::test]
    async fn test_add_and_check_ip() {
        let wl = WhitelistVerifier::new();
        let ip = ClientSource::Ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        wl.add(ip.clone(), None).await;
        assert!(wl.is_whitelisted(&ip).await.unwrap());
    }

    #[tokio::test]
    async fn test_not_whitelisted() {
        let wl = WhitelistVerifier::new();
        let ip = ClientSource::Ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(!wl.is_whitelisted(&ip).await.unwrap());
    }

    #[tokio::test]
    async fn test_ttl_expiry() {
        let wl = WhitelistVerifier::new();
        let ip = ClientSource::Ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        wl.add(ip.clone(), Some(Duration::from_millis(1))).await;
        tokio::time::sleep(Duration::from_millis(5)).await;
        assert!(!wl.is_whitelisted(&ip).await.unwrap());
    }

    #[tokio::test]
    async fn test_remove() {
        let wl = WhitelistVerifier::new();
        let ip = ClientSource::Ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        wl.add(ip.clone(), None).await;
        assert_eq!(wl.len().await, 1);
        wl.remove(&ip).await;
        assert!(!wl.is_whitelisted(&ip).await.unwrap());
        assert!(wl.is_empty().await);
    }

    #[tokio::test]
    async fn test_mac_address() {
        let wl = WhitelistVerifier::new();
        let mac = ClientSource::Mac("AA:BB:CC:DD:EE:FF".to_string());
        wl.add(mac.clone(), None).await;
        assert!(wl.is_whitelisted(&mac).await.unwrap());
    }

    #[tokio::test]
    async fn test_remove_nonexistent() {
        let wl = WhitelistVerifier::new();
        let ip = ClientSource::Ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        wl.remove(&ip).await;
        assert!(wl.is_empty().await);
    }

    #[tokio::test]
    async fn test_multiple_entries() {
        let wl = WhitelistVerifier::new();
        let ip1 = ClientSource::Ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        let ip2 = ClientSource::Ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        let mac = ClientSource::Mac("AA:BB:CC:DD:EE:FF".to_string());
        wl.add(ip1.clone(), None).await;
        wl.add(ip2.clone(), None).await;
        wl.add(mac.clone(), None).await;
        assert_eq!(wl.len().await, 3);
        assert!(wl.is_whitelisted(&ip1).await.unwrap());
        assert!(wl.is_whitelisted(&ip2).await.unwrap());
        assert!(wl.is_whitelisted(&mac).await.unwrap());
    }

    #[tokio::test]
    async fn test_ipv6_whitelist() {
        let wl = WhitelistVerifier::new();
        let ip = ClientSource::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST));
        wl.add(ip.clone(), None).await;
        assert!(wl.is_whitelisted(&ip).await.unwrap());
    }

    #[tokio::test]
    async fn test_cleanup_expired() {
        let wl = WhitelistVerifier::new();
        let ip1 = ClientSource::Ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        let ip2 = ClientSource::Ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        wl.add(ip1.clone(), Some(Duration::from_millis(1))).await;
        wl.add(ip2.clone(), None).await;

        wl.add(ip2.clone(), None).await;
        wl.add(ip1.clone(), Some(Duration::from_millis(1))).await;

        assert_eq!(wl.len().await, 2);

        tokio::time::sleep(Duration::from_millis(5)).await;
        let cleaned = wl.cleanup_expired().await;
        assert_eq!(cleaned, 1);
        assert_eq!(wl.len().await, 1);
        assert!(!wl.is_whitelisted(&ip1).await.unwrap());
        assert!(wl.is_whitelisted(&ip2).await.unwrap());
    }

    #[tokio::test]
    async fn test_cleanup_no_expired() {
        let wl = WhitelistVerifier::new();
        let ip = ClientSource::Ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        wl.add(ip.clone(), None).await;
        assert_eq!(wl.cleanup_expired().await, 0);
        assert_eq!(wl.len().await, 1);
    }

    #[tokio::test]
    async fn test_re_add_replaces() {
        let wl = WhitelistVerifier::new();
        let ip = ClientSource::Ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        wl.add(ip.clone(), None).await;
        wl.add(ip.clone(), None).await;
        assert_eq!(wl.len().await, 1);
    }

    #[tokio::test]
    async fn test_empty_verifier() {
        let wl = WhitelistVerifier::new();
        assert!(wl.is_empty().await);
        assert_eq!(wl.len().await, 0);
    }
}
