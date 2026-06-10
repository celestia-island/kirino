use anyhow::Result;
use std::net::IpAddr;

pub struct NetworkSourceVerifier {
    allowed_networks: Vec<String>,
}

impl NetworkSourceVerifier {
    #[must_use]
    pub fn new(allowed_networks: Vec<String>) -> Self {
        Self { allowed_networks }
    }

    pub fn is_allowed(&self, source_ip: IpAddr) -> Result<bool> {
        for cidr in &self.allowed_networks {
            if ip_in_cidr(source_ip, cidr) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    #[must_use]
    pub fn allowed_networks(&self) -> &[String] {
        &self.allowed_networks
    }
}

fn ip_in_cidr(ip: IpAddr, cidr: &str) -> bool {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return match ip {
            IpAddr::V4(v4) => cidr.parse::<std::net::Ipv4Addr>().is_ok_and(|a| a == v4),
            IpAddr::V6(v6) => cidr.parse::<std::net::Ipv6Addr>().is_ok_and(|a| a == v6),
        };
    }

    let prefix_len: u32 = match parts[1].parse() {
        Ok(n) => n,
        Err(_) => return false,
    };

    match ip {
        IpAddr::V4(v4) => {
            if prefix_len > 32 {
                return false;
            }
            if let Ok(network) = parts[0].parse::<std::net::Ipv4Addr>() {
                let ip_bits = u32::from(v4);
                let net_bits = u32::from(network);
                let mask = if prefix_len == 0 {
                    0
                } else {
                    !0u32 << (32 - prefix_len)
                };
                return (ip_bits & mask) == (net_bits & mask);
            }
            false
        }
        IpAddr::V6(v6) => {
            if prefix_len > 128 {
                return false;
            }
            if let Ok(network) = parts[0].parse::<std::net::Ipv6Addr>() {
                let ip_bits = u128::from(v6);
                let net_bits = u128::from(network);
                let mask = if prefix_len == 0 {
                    0u128
                } else {
                    !0u128 << (128 - prefix_len)
                };
                return (ip_bits & mask) == (net_bits & mask);
            }
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_single_ip_match() {
        let v = NetworkSourceVerifier::new(vec!["192.168.1.1".to_string()]);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        assert!(v.is_allowed(ip).unwrap());
    }

    #[test]
    fn test_single_ip_no_match() {
        let v = NetworkSourceVerifier::new(vec!["192.168.1.1".to_string()]);
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        assert!(!v.is_allowed(ip).unwrap());
    }

    #[test]
    fn test_cidr_24_match() {
        let v = NetworkSourceVerifier::new(vec!["192.168.1.0/24".to_string()]);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        assert!(v.is_allowed(ip).unwrap());
    }

    #[test]
    fn test_cidr_24_no_match() {
        let v = NetworkSourceVerifier::new(vec!["192.168.1.0/24".to_string()]);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1));
        assert!(!v.is_allowed(ip).unwrap());
    }

    #[test]
    fn test_cidr_16() {
        let v = NetworkSourceVerifier::new(vec!["10.0.0.0/16".to_string()]);
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 255, 255));
        assert!(v.is_allowed(ip).unwrap());
        let ip2 = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 0));
        assert!(!v.is_allowed(ip2).unwrap());
    }

    #[test]
    fn test_cidr_32_exact_match() {
        let v = NetworkSourceVerifier::new(vec!["192.168.1.1/32".to_string()]);
        assert!(v
            .is_allowed(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
            .unwrap());
        assert!(!v
            .is_allowed(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)))
            .unwrap());
    }

    #[test]
    fn test_cidr_0_match_all() {
        let v = NetworkSourceVerifier::new(vec!["0.0.0.0/0".to_string()]);
        assert!(v.is_allowed(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))).unwrap());
        assert!(v
            .is_allowed(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)))
            .unwrap());
    }

    #[test]
    fn test_invalid_cidr_returns_false() {
        let v = NetworkSourceVerifier::new(vec!["not-a-cidr".to_string()]);
        assert!(!v
            .is_allowed(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
            .unwrap());
    }

    #[test]
    fn test_invalid_cidr_prefix_returns_false() {
        let v = NetworkSourceVerifier::new(vec!["10.0.0.0/abc".to_string()]);
        assert!(!v
            .is_allowed(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
            .unwrap());
    }

    #[test]
    fn test_ipv6_loopback() {
        let v = NetworkSourceVerifier::new(vec!["::1/128".to_string()]);
        let ip = IpAddr::V6(Ipv6Addr::LOCALHOST);
        assert!(v.is_allowed(ip).unwrap());
    }

    #[test]
    fn test_ipv6_subnet() {
        let v = NetworkSourceVerifier::new(vec!["2001:db8::/32".to_string()]);
        assert!(v
            .is_allowed(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)))
            .unwrap());
        assert!(!v
            .is_allowed(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb9, 0, 0, 0, 0, 0, 1)))
            .unwrap());
    }

    #[test]
    fn test_ipv6_all_any() {
        let v = NetworkSourceVerifier::new(vec!["::/0".to_string()]);
        assert!(v.is_allowed(IpAddr::V6(Ipv6Addr::LOCALHOST)).unwrap());
        assert!(v
            .is_allowed(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)))
            .unwrap());
    }

    #[test]
    fn test_ipv6_exact() {
        let v = NetworkSourceVerifier::new(vec!["fe80::1".to_string()]);
        assert!(v
            .is_allowed(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)))
            .unwrap());
        assert!(!v
            .is_allowed(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2)))
            .unwrap());
    }

    #[test]
    fn test_empty_allowed() {
        let v = NetworkSourceVerifier::new(vec![]);
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        assert!(!v.is_allowed(ip).unwrap());
    }

    #[test]
    fn test_multiple_networks() {
        let v = NetworkSourceVerifier::new(vec![
            "192.168.0.0/16".to_string(),
            "10.0.0.0/8".to_string(),
        ]);
        assert!(v
            .is_allowed(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
            .unwrap());
        assert!(v
            .is_allowed(IpAddr::V4(Ipv4Addr::new(10, 42, 0, 1)))
            .unwrap());
        assert!(!v
            .is_allowed(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)))
            .unwrap());
    }

    #[test]
    fn test_allowed_networks_accessor() {
        let v = NetworkSourceVerifier::new(vec!["10.0.0.0/8".to_string()]);
        assert_eq!(v.allowed_networks().len(), 1);
        assert_eq!(v.allowed_networks()[0], "10.0.0.0/8");
    }

    #[test]
    fn test_mixed_ipv4_ipv6_networks() {
        let v =
            NetworkSourceVerifier::new(vec!["192.168.1.0/24".to_string(), "::1/128".to_string()]);
        assert!(v
            .is_allowed(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
            .unwrap());
        assert!(v.is_allowed(IpAddr::V6(Ipv6Addr::LOCALHOST)).unwrap());
        assert!(!v
            .is_allowed(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
            .unwrap());
    }

    #[test]
    fn test_ipv4_network_against_ipv6_ip() {
        let v = NetworkSourceVerifier::new(vec!["192.168.1.0/24".to_string()]);
        assert!(!v.is_allowed(IpAddr::V6(Ipv6Addr::LOCALHOST)).unwrap());
    }

    #[test]
    fn test_prefix_len_over_32_returns_false() {
        let v = NetworkSourceVerifier::new(vec!["10.0.0.0/33".to_string()]);
        assert!(!v
            .is_allowed(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
            .unwrap());
    }

    #[test]
    fn test_prefix_len_over_128_returns_false() {
        let v = NetworkSourceVerifier::new(vec!["::1/129".to_string()]);
        assert!(!v.is_allowed(IpAddr::V6(Ipv6Addr::LOCALHOST)).unwrap());
    }

    #[test]
    fn test_prefix_len_exactly_32() {
        let v = NetworkSourceVerifier::new(vec!["10.0.0.0/32".to_string()]);
        assert!(v
            .is_allowed(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)))
            .unwrap());
        assert!(!v
            .is_allowed(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
            .unwrap());
    }
}
