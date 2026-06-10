use std::net::IpAddr;

pub struct NetworkSourceVerifier {
    allowed_networks: Vec<ParsedCidr>,
}

enum ParsedCidr {
    V4 { network: u32, mask: u32 },
    V6 { network: u128, mask: u128 },
    ExactIp(IpAddr),
}

impl NetworkSourceVerifier {
    pub fn new(allowed_networks: Vec<String>) -> Self {
        let parsed: Vec<ParsedCidr> = allowed_networks
            .iter()
            .filter_map(|cidr| parse_cidr(cidr))
            .collect();
        if parsed.len() != allowed_networks.len() {
            tracing::warn!(
                target: "kirino::verify::network_source",
                attempted = allowed_networks.len(),
                parsed = parsed.len(),
                "some CIDR entries failed to parse and were silently ignored"
            );
        }
        Self { allowed_networks: parsed }
    }

    pub fn is_allowed(&self, source_ip: IpAddr) -> bool {
        for entry in &self.allowed_networks {
            match entry {
                ParsedCidr::ExactIp(ip) if *ip == source_ip => return true,
                ParsedCidr::V4 { network, mask } => {
                    if let IpAddr::V4(v4) = source_ip {
                        let bits = u32::from(v4);
                        if (bits & mask) == (*network & mask) {
                            return true;
                        }
                    }
                }
                ParsedCidr::V6 { network, mask } => {
                    if let IpAddr::V6(v6) = source_ip {
                        let bits = u128::from(v6);
                        if (bits & mask) == (*network & mask) {
                            return true;
                        }
                    }
                }
                _ => {}
            }
        }
        false
    }

    #[must_use]
    pub fn allowed_networks_count(&self) -> usize {
        self.allowed_networks.len()
    }
}

fn parse_cidr(cidr: &str) -> Option<ParsedCidr> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return match cidr.parse::<std::net::Ipv4Addr>() {
            Ok(v4) => Some(ParsedCidr::ExactIp(IpAddr::V4(v4))),
            Err(_) => cidr
                .parse::<std::net::Ipv6Addr>()
                .ok()
                .map(|v6| ParsedCidr::ExactIp(IpAddr::V6(v6))),
        };
    }

    let prefix_len: u32 = parts[1].parse().ok()?;

    if let Ok(network) = parts[0].parse::<std::net::Ipv4Addr>() {
        if prefix_len > 32 {
            return None;
        }
        let mask = if prefix_len == 0 {
            0
        } else {
            !0u32 << (32 - prefix_len)
        };
        Some(ParsedCidr::V4 {
            network: u32::from(network),
            mask,
        })
    } else if let Ok(network) = parts[0].parse::<std::net::Ipv6Addr>() {
        if prefix_len > 128 {
            return None;
        }
        let mask = if prefix_len == 0 {
            0u128
        } else {
            !0u128 << (128 - prefix_len)
        };
        Some(ParsedCidr::V6 {
            network: u128::from(network),
            mask,
        })
    } else {
        None
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
        assert!(v.is_allowed(ip));
    }

    #[test]
    fn test_single_ip_no_match() {
        let v = NetworkSourceVerifier::new(vec!["192.168.1.1".to_string()]);
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        assert!(!v.is_allowed(ip));
    }

    #[test]
    fn test_cidr_24_match() {
        let v = NetworkSourceVerifier::new(vec!["192.168.1.0/24".to_string()]);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        assert!(v.is_allowed(ip));
    }

    #[test]
    fn test_cidr_24_no_match() {
        let v = NetworkSourceVerifier::new(vec!["192.168.1.0/24".to_string()]);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1));
        assert!(!v.is_allowed(ip));
    }

    #[test]
    fn test_cidr_16() {
        let v = NetworkSourceVerifier::new(vec!["10.0.0.0/16".to_string()]);
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 255, 255));
        assert!(v.is_allowed(ip));
        let ip2 = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 0));
        assert!(!v.is_allowed(ip2));
    }

    #[test]
    fn test_cidr_32_exact_match() {
        let v = NetworkSourceVerifier::new(vec!["192.168.1.1/32".to_string()]);
        assert!(v.is_allowed(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(!v.is_allowed(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2))));
    }

    #[test]
    fn test_cidr_0_match_all() {
        let v = NetworkSourceVerifier::new(vec!["0.0.0.0/0".to_string()]);
        assert!(v.is_allowed(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
        assert!(v.is_allowed(IpAddr::V4(Ipv4Addr::BROADCAST)));
    }

    #[test]
    fn test_invalid_cidr_returns_false() {
        let v = NetworkSourceVerifier::new(vec!["not-a-cidr".to_string()]);
        assert!(!v.is_allowed(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    }

    #[test]
    fn test_invalid_cidr_prefix_returns_false() {
        let v = NetworkSourceVerifier::new(vec!["10.0.0.0/abc".to_string()]);
        assert!(!v.is_allowed(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    }

    #[test]
    fn test_ipv6_loopback() {
        let v = NetworkSourceVerifier::new(vec!["::1/128".to_string()]);
        let ip = IpAddr::V6(Ipv6Addr::LOCALHOST);
        assert!(v.is_allowed(ip));
    }

    #[test]
    fn test_ipv6_subnet() {
        let v = NetworkSourceVerifier::new(vec!["2001:db8::/32".to_string()]);
        assert!(v.is_allowed(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))));
        assert!(!v.is_allowed(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb9, 0, 0, 0, 0, 0, 1))));
    }

    #[test]
    fn test_ipv6_all_any() {
        let v = NetworkSourceVerifier::new(vec!["::/0".to_string()]);
        assert!(v.is_allowed(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(v.is_allowed(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))));
    }

    #[test]
    fn test_ipv6_exact() {
        let v = NetworkSourceVerifier::new(vec!["fe80::1".to_string()]);
        assert!(v.is_allowed(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1))));
        assert!(!v.is_allowed(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2))));
    }

    #[test]
    fn test_empty_allowed() {
        let v = NetworkSourceVerifier::new(vec![]);
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        assert!(!v.is_allowed(ip));
    }

    #[test]
    fn test_multiple_networks() {
        let v = NetworkSourceVerifier::new(vec![
            "192.168.0.0/16".to_string(),
            "10.0.0.0/8".to_string(),
        ]);
        assert!(v.is_allowed(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(v.is_allowed(IpAddr::V4(Ipv4Addr::new(10, 42, 0, 1))));
        assert!(!v.is_allowed(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
    }

    #[test]
    fn test_allowed_networks_count() {
        let v = NetworkSourceVerifier::new(vec!["10.0.0.0/8".to_string()]);
        assert_eq!(v.allowed_networks_count(), 1);
    }

    #[test]
    fn test_mixed_ipv4_ipv6_networks() {
        let v = NetworkSourceVerifier::new(vec!["192.168.1.0/24".to_string(), "::1/128".to_string()]);
        assert!(v.is_allowed(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(v.is_allowed(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(!v.is_allowed(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    }

    #[test]
    fn test_ipv4_network_against_ipv6_ip() {
        let v = NetworkSourceVerifier::new(vec!["192.168.1.0/24".to_string()]);
        assert!(!v.is_allowed(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn test_prefix_len_over_32_returns_false() {
        let v = NetworkSourceVerifier::new(vec!["10.0.0.0/33".to_string()]);
        assert!(!v.is_allowed(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    }

    #[test]
    fn test_prefix_len_over_128_returns_false() {
        let v = NetworkSourceVerifier::new(vec!["::1/129".to_string()]);
        assert!(!v.is_allowed(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn test_prefix_len_exactly_32() {
        let v = NetworkSourceVerifier::new(vec!["10.0.0.0/32".to_string()]);
        assert!(v.is_allowed(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0))));
        assert!(!v.is_allowed(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    }
}
