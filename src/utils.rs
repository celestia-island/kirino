/// RFC 4648 base64url codec — the single house implementation.
///
/// URL-safe alphabet (`-`/`_`), padding neither emitted nor required on
/// encode, trailing `=` tolerated on decode, impossible lengths
/// (`len % 4 == 1`) and non-canonical trailing bits rejected so bytes
/// decoded from equal-length encodings stay unique (RFC 4648 §3.5).
///
/// WebAuthn consumers wrap [`decode`] to map errors onto their own
/// challenge error type; see
/// [`crate::auth::passport::webauthn::base64url_decode`].
pub mod base64url {
    /// A base64url decode failure.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Base64UrlDecodeError {
        /// Input length (before padding trim) is `len % 4 == 1`.
        InvalidLength,
        /// Byte at `index` is outside the base64url alphabet.
        InvalidByte {
            /// Offset of the offending byte in the input.
            index: usize,
            /// The offending byte value.
            byte: u8,
        },
        /// Trailing bits of the final quantum are non-zero; the input
        /// cannot have been produced by encoding bytes (RFC 4648 §3.5).
        NonCanonicalTrailingBits,
    }

    impl std::fmt::Display for Base64UrlDecodeError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::InvalidLength => write!(f, "invalid base64url length (len % 4 == 1)"),
                Self::InvalidByte { index, byte } => {
                    write!(f, "invalid base64url byte {byte:#04x} at index {index}")
                }
                Self::NonCanonicalTrailingBits => {
                    write!(f, "non-canonical trailing bits in base64url input")
                }
            }
        }
    }
    impl std::error::Error for Base64UrlDecodeError {}

    /// Encode bytes as unpadded RFC 4648 base64url (WebAuthn §4.2 form).
    #[must_use]
    pub fn encode(bytes: &[u8]) -> String {
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
        for chunk in bytes.chunks(3) {
            let b0 = chunk[0] as u32;
            let b1 = chunk.get(1).map_or(0, |&b| u32::from(b));
            let b2 = chunk.get(2).map_or(0, |&b| u32::from(b));
            let n = (b0 << 16) | (b1 << 8) | b2;
            out.push(TABLE[(n >> 18 & 63) as usize] as char);
            out.push(TABLE[(n >> 12 & 63) as usize] as char);
            if chunk.len() > 1 {
                out.push(TABLE[(n >> 6 & 63) as usize] as char);
            }
            if chunk.len() > 2 {
                out.push(TABLE[(n & 63) as usize] as char);
            }
        }
        out
    }

    /// Decode RFC 4648 base64url; trailing `=` tolerated but never required.
    ///
    /// # Errors
    ///
    /// [`Base64UrlDecodeError::InvalidLength`] when `len % 4 == 1`,
    /// [`Base64UrlDecodeError::InvalidByte`] on any byte outside the
    /// base64url alphabet (whitespace included), and
    /// [`Base64UrlDecodeError::NonCanonicalTrailingBits`] when the final
    /// quantum carries non-zero pad bits.
    pub fn decode(s: &str) -> Result<Vec<u8>, Base64UrlDecodeError> {
        fn val(c: u8) -> Option<u32> {
            match c {
                b'A'..=b'Z' => Some(u32::from(c - b'A')),
                b'a'..=b'z' => Some(u32::from(c - b'a') + 26),
                b'0'..=b'9' => Some(u32::from(c - b'0') + 52),
                b'-' => Some(62),
                b'_' => Some(63),
                _ => None,
            }
        }
        if s.len() % 4 == 1 {
            return Err(Base64UrlDecodeError::InvalidLength);
        }
        let s = s.trim_end_matches('=');
        let mut out = Vec::with_capacity(s.len() * 3 / 4 + 3);
        let mut acc: u32 = 0;
        let mut bits: u32 = 0;
        for (i, &c) in s.as_bytes().iter().enumerate() {
            let v = val(c).ok_or(Base64UrlDecodeError::InvalidByte { index: i, byte: c })?;
            acc = (acc << 6) | v;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push(((acc >> bits) & 0xff) as u8);
            }
            // Canonical tail: leftover pad bits after the final byte must be 0.
            if i == s.len() - 1 && bits > 0 && (acc & ((1 << bits) - 1)) != 0 {
                return Err(Base64UrlDecodeError::NonCanonicalTrailingBits);
            }
        }
        Ok(out)
    }
}

/// Constant-time byte comparison.
///
/// Compares the contents of `a` and `b` in constant time by iterating over
/// the longer of the two slices. This prevents timing side-channel attacks
/// that could leak the length of the shorter input.
#[must_use]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = u64::from(a.len() != b.len());
    let max_len = std::cmp::max(a.len(), b.len());
    for i in 0..max_len {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        diff |= u64::from(x ^ y);
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

    // RFC 4648 §10 known-answer vectors, base64url variant (unpadded).
    #[test]
    fn base64url_encode_rfc4648_vectors() {
        assert_eq!(base64url::encode(b""), "");
        assert_eq!(base64url::encode(b"f"), "Zg");
        assert_eq!(base64url::encode(b"fo"), "Zm8");
        assert_eq!(base64url::encode(b"foo"), "Zm9v");
        assert_eq!(base64url::encode(b"foob"), "Zm9vYg");
        assert_eq!(base64url::encode(b"fooba"), "Zm9vYmE");
        assert_eq!(base64url::encode(b"foobar"), "Zm9vYmFy");
        // Alphabet checks: 62 -> '-', 63 -> '_', never '+' or '/' or '='.
        assert_eq!(base64url::encode(&[0xfb, 0xff]), "-_8");
        assert_eq!(base64url::encode(&[0xfb, 0xff, 0xfe, 0xfd]), "-__-_Q");
    }

    // RFC 4648 §10 known-answer vectors, decode direction.
    #[test]
    fn base64url_decode_rfc4648_vectors() {
        assert_eq!(base64url::decode("").unwrap(), b"");
        assert_eq!(base64url::decode("Zg").unwrap(), b"f");
        assert_eq!(base64url::decode("Zm8").unwrap(), b"fo");
        assert_eq!(base64url::decode("Zm9v").unwrap(), b"foo");
        assert_eq!(base64url::decode("Zm9vYg").unwrap(), b"foob");
        assert_eq!(base64url::decode("Zm9vYmE").unwrap(), b"fooba");
        assert_eq!(base64url::decode("Zm9vYmFy").unwrap(), b"foobar");
        // Trailing padding tolerated though never required.
        assert_eq!(base64url::decode("Zg==").unwrap(), b"f");
        assert_eq!(base64url::decode("Zm8=").unwrap(), b"fo");
        assert_eq!(base64url::decode("Zm9v").unwrap(), b"foo");
    }

    #[test]
    fn base64url_decode_rejects_malformed() {
        assert_eq!(
            base64url::decode("A").unwrap_err(),
            base64url::Base64UrlDecodeError::InvalidLength
        );
        assert_eq!(
            base64url::decode("Zm9=").unwrap_err(),
            base64url::Base64UrlDecodeError::NonCanonicalTrailingBits
        );
        assert_eq!(
            base64url::decode("Zm$v").unwrap_err(),
            base64url::Base64UrlDecodeError::InvalidByte {
                index: 2,
                byte: b'$'
            }
        );
        // Standard-alphabet symbols are invalid in the URL-safe form.
        assert!(base64url::decode("+/8A").is_err());
        // Stricter than the retired utils codec: no whitespace tolerance.
        assert!(base64url::decode("Zm9 vYg").is_err());
    }

    #[test]
    fn base64url_roundtrip_all_lengths() {
        for len in 0..=64 {
            let data: Vec<u8> = (0..len).map(|i| (i * 7 + 13) as u8).collect();
            let encoded = base64url::encode(&data);
            assert!(!encoded.contains('='), "unpadded for len={len}");
            assert_eq!(
                base64url::decode(&encoded).unwrap(),
                data,
                "roundtrip failed for len={len}"
            );
        }
    }
}
