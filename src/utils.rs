pub mod base64 {

    use anyhow::{anyhow, Result};

    pub fn decode(input: &str) -> Result<Vec<u8>> {
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
                return Err(anyhow!("invalid base64 character: {b:#04x}"));
            }
            accum = (accum << 6) | u32::from(val);
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                #[allow(clippy::cast_possible_truncation)]
                result.push((accum >> bits) as u8);
            }
        }
        Ok(result)
    }

    pub fn decode_url_safe(input: &str) -> Result<Vec<u8>> {
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

    #[must_use]
    pub fn encode(input: &[u8]) -> String {
        const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut result = String::new();
        for chunk in input.chunks(3) {
            let b0 = u32::from(chunk[0]);
            let b1 = if chunk.len() > 1 {
                u32::from(chunk[1])
            } else {
                0
            };
            let b2 = if chunk.len() > 2 {
                u32::from(chunk[2])
            } else {
                0
            };
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

    #[must_use]
    pub fn url_safe_encode(input: &[u8]) -> String {
        let encoded = encode(input);
        encoded
            .trim_end_matches('=')
            .replace('+', "-")
            .replace('/', "_")
    }
}

/// Minimal percent-encoding for URL query parameters.
#[must_use]
pub fn url_encode(input: &str) -> String {
    const HEX: &[u8] = b"0123456789ABCDEF";
    let mut result = String::with_capacity(input.len());
    for &byte in input.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                result.push(byte as char);
            }
            b' ' => result.push_str("%20"),
            _ => {
                result.push('%');
                result.push(HEX[(byte >> 4) as usize] as char);
                result.push(HEX[(byte & 0x0F) as usize] as char);
            }
        }
    }
    result
}

/// Constant-time byte comparison.
#[must_use]
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
        assert!(base64::decode("").unwrap().is_empty());
    }

    #[test]
    fn test_base64_decode_hello() {
        assert_eq!(base64::decode("aGVsbG8=").unwrap(), b"hello");
    }

    #[test]
    fn test_base64_decode_foobar() {
        assert_eq!(base64::decode("Zm9vYmFy").unwrap(), b"foobar");
    }

    #[test]
    fn test_base64_decode_url_safe() {
        let result = base64::decode_url_safe("aGVsbG8").unwrap();
        assert_eq!(result, b"hello");
    }

    #[test]
    fn test_base64_decode_with_whitespace() {
        assert_eq!(base64::decode("aGVs\n bG8=").unwrap(), b"hello");
    }

    #[test]
    fn test_base64_decode_padding_variants() {
        assert_eq!(base64::decode("YQ==").unwrap(), b"a");
        assert_eq!(base64::decode("YWI=").unwrap(), b"ab");
        assert_eq!(base64::decode("YWJj").unwrap(), b"abc");
    }

    #[test]
    fn test_base64_decode_invalid_char_rejected() {
        assert!(base64::decode("aGVs!bG8=").is_err());
    }

    #[test]
    fn test_url_encode_plain_text() {
        assert_eq!(url_encode("hello"), "hello");
        assert_eq!(url_encode("abc123"), "abc123");
    }

    #[test]
    fn test_url_encode_spaces() {
        assert_eq!(url_encode("a b"), "a%20b");
        assert_eq!(url_encode("hello world"), "hello%20world");
    }

    #[test]
    fn test_url_encode_special_chars() {
        assert_eq!(url_encode("a&b=c"), "a%26b%3Dc");
        assert_eq!(
            url_encode("https://example.com/path?q=1"),
            "https%3A%2F%2Fexample.com%2Fpath%3Fq%3D1"
        );
    }

    #[test]
    fn test_url_encode_unreserved_safe() {
        assert_eq!(url_encode("-._~"), "-._~");
    }

    #[test]
    fn test_url_encode_empty() {
        assert_eq!(url_encode(""), "");
    }
}
