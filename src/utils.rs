pub mod base64 {
    pub fn decode(input: &str) -> Vec<u8> {
        let lookup: [u8; 256] = {
            let mut table = [0xFFu8; 256];
            for (i, c) in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
                .iter()
                .enumerate()
            {
                table[*c as usize] = i as u8;
            }
            table
        };
        let bytes = input.as_bytes();
        let mut result = Vec::with_capacity(bytes.len() * 3 / 4);
        let mut accum: u32 = 0;
        let mut bits: u32 = 0;
        for &b in bytes {
            if b == b'=' || b == b'\n' || b == b'\r' || b == b' ' {
                continue;
            }
            let val = lookup[b as usize];
            if val == 0xFF {
                continue;
            }
            accum = (accum << 6) | u32::from(val);
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                result.push((accum >> bits) as u8);
            }
        }
        result
    }

    pub fn decode_url_safe(input: &str) -> Vec<u8> {
        let standard = input.replace('-', "+").replace('_', "/");
        let padded = {
            let mut s = standard;
            let pad = (4 - s.len() % 4) % 4;
            for _ in 0..pad {
                s.push('=');
            }
            s
        };
        decode(&padded)
    }

    pub fn encode(input: &[u8]) -> String {
        const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut result = String::new();
        for chunk in input.chunks(3) {
            let b0 = chunk[0] as u32;
            let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
            let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
            let triple = (b0 << 16) | (b1 << 8) | b2;
            result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
            result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
            if chunk.len() > 1 {
                result.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
            } else {
                result.push('=');
            }
            if chunk.len() > 2 {
                result.push(CHARS[(triple & 0x3F) as usize] as char);
            } else {
                result.push('=');
            }
        }
        result
    }

    pub fn decode_url_free_encode(input: &[u8]) -> String {
        let encoded = encode(input);
        encoded
            .trim_end_matches('=')
            .replace('+', "-")
            .replace('/', "_")
    }
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_eq_equal() {
        assert!(constant_time_eq(b"hello", b"hello"));
    }

    #[test]
    fn test_constant_time_eq_not_equal() {
        assert!(!constant_time_eq(b"hello", b"world"));
    }

    #[test]
    fn test_constant_time_eq_different_lengths() {
        assert!(!constant_time_eq(b"ab", b"abc"));
    }

    #[test]
    fn test_constant_time_eq_empty() {
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn test_base64_decode_empty() {
        assert!(base64::decode("").is_empty());
    }

    #[test]
    fn test_base64_decode_hello() {
        assert_eq!(base64::decode("aGVsbG8="), b"hello");
    }

    #[test]
    fn test_base64_decode_foobar() {
        assert_eq!(base64::decode("Zm9vYmFy"), b"foobar");
    }

    #[test]
    fn test_base64_decode_url_safe() {
        let result = base64::decode_url_safe("aGVsbG8");
        assert_eq!(result, b"hello");
    }

    #[test]
    fn test_base64_decode_with_whitespace() {
        assert_eq!(base64::decode("aGVs\n bG8="), b"hello");
    }

    #[test]
    fn test_base64_decode_padding_variants() {
        assert_eq!(base64::decode("YQ=="), b"a");
        assert_eq!(base64::decode("YWI="), b"ab");
        assert_eq!(base64::decode("YWJj"), b"abc");
    }
}
