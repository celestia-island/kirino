//! `authenticatorData` parsing per W3C Web Authentication Level 2 §6.1.
//!
//! Layout (all big-endian):
//!
//! ```text
//! offset  size  field
//! 0       32    rpIdHash  = SHA-256(RP ID)
//! 32      1     flags     (UP|UV|BE|BS|AT|ED)
//! 33      4     signCount
//! 37      ...   attestedCredentialData (only when AT flag set)
//! n       ...   extensions        (only when ED flag set)
//! ```
//!
//! This module parses the structure itself so the verifier never has to trust
//! caller-decoded fields: the signature always covers the raw bytes, and the
//! values checked against policy are read back out of those same bytes.

use anyhow::{anyhow, Result};

/// Byte 32 of authenticatorData — User Present (UP).
pub const FLAG_UP: u8 = 0x01;
/// Byte 32 — User Verified (UV).
pub const FLAG_UV: u8 = 0x04;
/// Byte 32 — Backup Eligible (BE): the credential may be backed up in sync.
pub const FLAG_BE: u8 = 0x08;
/// Byte 32 — Backup State (BS): the credential is currently backed up.
pub const FLAG_BS: u8 = 0x10;
/// Byte 32 — Attested Credential Data included (AT).
pub const FLAG_AT: u8 = 0x40;
/// Byte 32 — Extension Data included (ED).
pub const FLAG_ED: u8 = 0x80;

/// Minimal structural length: rpIdHash(32) + flags(1) + signCount(4).
const HEADER_LEN: usize = 37;
/// Attested credential data length when AT is set:
/// aaguid(16) + credIdLen(2) = 18 bytes before the credential id.
const AAGUID_LEN: usize = 16;
/// Upper bound on a credential id we accept (L2 recommendation is ≤1023).
const MAX_CREDENTIAL_ID_LEN: usize = 2048;

/// Parsed view over raw `authenticatorData` bytes.
///
/// The raw bytes are retained because they participate in the assertion
/// signature; every accessor reads from a defensively parsed snapshot.
#[derive(Debug, Clone)]
pub struct AuthenticatorData<'a> {
    raw: &'a [u8],
    rp_id_hash: &'a [u8],
    flags: u8,
    sign_count: u32,
    /// Present only when the AT flag is set (registration responses).
    attested: Option<AttestedCredentialData<'a>>,
}

/// Attested credential data (`AT` flag): AAGUID + credential id + COSE key.
#[derive(Debug, Clone)]
pub struct AttestedCredentialData<'a> {
    pub aaguid: [u8; AAGUID_LEN],
    pub credential_id: &'a [u8],
    /// CBOR-map slice for the credential public key, left unparsed here —
    /// the verifier decodes it with `coset`.
    pub credential_public_key_cbor: &'a [u8],
}

impl<'a> AuthenticatorData<'a> {
    /// Parse and structurally validate raw authenticator bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when the buffer is shorter than the fixed header,
    /// when an extension/attested section claims more bytes than remain, or
    /// when trailing garbage follows a well-formed structure without ED.
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() < HEADER_LEN {
            return Err(anyhow!(
                "authenticatorData too short: {} < {HEADER_LEN}",
                raw.len()
            ));
        }

        let flags = raw[32];
        let sign_count = u32::from_be_bytes([raw[33], raw[34], raw[35], raw[36]]);

        let mut cursor = HEADER_LEN;

        let attested = if flags & FLAG_AT != 0 {
            // Layout: aaguid(16) || credIdLen(2, big-endian) || credId || COSE key.
            if raw.len() < cursor + AAGUID_LEN + 2 {
                return Err(anyhow!("attested credential data truncated at AAGUID"));
            }
            let mut aaguid = [0u8; AAGUID_LEN];
            aaguid.copy_from_slice(&raw[cursor..cursor + AAGUID_LEN]);
            cursor += AAGUID_LEN;

            let cred_len = usize::from(u16::from_be_bytes([raw[cursor], raw[cursor + 1]]));
            if cred_len > MAX_CREDENTIAL_ID_LEN {
                return Err(anyhow!("credential id length {cred_len} exceeds limit"));
            }
            cursor += 2;

            let credential_id = raw
                .get(cursor..cursor + cred_len)
                .ok_or_else(|| anyhow!("attested credential id truncated"))?;
            cursor += cred_len;

            // Credential public key is a CBOR map item. We locate its extent
            // with a lightweight CBOR header walk rather than a full decode
            // here (coset does the real parse in the verifier).
            let key_start = cursor;
            let key_end = cbor_item_len(&raw[cursor..])
                .ok_or_else(|| anyhow!("credential public key CBOR truncated"))?
                + cursor;
            let key_slice = raw
                .get(key_start..key_end)
                .ok_or_else(|| anyhow!("credential public key CBOR overruns buffer"))?;
            cursor = key_end;

            Some(AttestedCredentialData {
                aaguid,
                credential_id,
                credential_public_key_cbor: key_slice,
            })
        } else {
            None
        };

        if flags & FLAG_ED != 0 {
            // Extensions are a CBOR map; require it to be well-formed so we
            // never mistake trailing padding for signed content.
            let _ = cbor_item_slice(&raw[cursor..])
                .ok_or_else(|| anyhow!("extension data CBOR truncated"))?;
            cursor += cbor_item_len(&raw[cursor..]).unwrap_or(raw.len() - cursor);
        }

        if cursor != raw.len() {
            return Err(anyhow!(
                "trailing bytes after authenticatorData: {} extra",
                raw.len() - cursor
            ));
        }

        Ok(Self {
            rp_id_hash: &raw[..32],
            flags,
            sign_count,
            attested,
            raw,
        })
    }

    /// The full raw bytes (these are what the assertion signature covers).
    #[must_use]
    pub fn as_raw(&self) -> &'a [u8] {
        self.raw
    }

    /// RP ID hash (SHA-256 of the lowercased full RP ID) — compare against
    /// `Sha256(rp_id)` before trusting anything else.
    #[must_use]
    pub fn rp_id_hash(&self) -> &'a [u8] {
        self.rp_id_hash
    }

    /// Raw flags byte.
    #[must_use]
    pub fn flags(&self) -> u8 {
        self.flags
    }

    /// Whether the user-presence bit is set.
    #[must_use]
    pub fn user_present(&self) -> bool {
        self.flags & FLAG_UP != 0
    }

    /// Whether the user-verification bit is set.
    #[must_use]
    pub fn user_verified(&self) -> bool {
        self.flags & FLAG_UV != 0
    }

    /// Whether the credential qualifies for backup (BE).
    #[must_use]
    pub fn backup_eligible(&self) -> bool {
        self.flags & FLAG_BE != 0
    }

    /// Whether the credential is currently backed up (BS).
    #[must_use]
    pub fn backup_state(&self) -> bool {
        self.flags & FLAG_BS != 0
    }

    /// Signature counter read from the signed bytes.
    #[must_use]
    pub fn sign_count(&self) -> u32 {
        self.sign_count
    }

    /// Attested credential data, present on registration (AT flag).
    #[must_use]
    pub fn attested_credential_data(&self) -> Option<&AttestedCredentialData<'a>> {
        self.attested.as_ref()
    }
}

/// Return the byte slice occupied by the first complete CBOR item in `input`.
fn cbor_item_slice(input: &[u8]) -> Option<&[u8]> {
    let len = cbor_item_len(input)?;
    input.get(..len)
}

/// Measure the first CBOR item's encoded length, header included.
///
/// Supports exactly what COSE keys use: unsigned/negative ints, byte/text
/// strings, arrays and maps (definite lengths only — indefinite encoding is
/// not allowed inside COSE_KEY structures).
pub(crate) fn cbor_item_len(input: &[u8]) -> Option<usize> {
    let (&first, rest) = input.split_first()?;
    let major = first >> 5;
    let info = first & 0b0001_1111;

    // Returns the additional-info argument size plus its value.
    let arg = |info: u8, rest: &[u8]| -> Option<(usize, u64)> {
        match info {
            0..=23 => Some((0, u64::from(info))),
            24 => Some((1, u64::from(*rest.first()?))),
            25 => Some((
                2,
                u16::from_be_bytes(rest.get(..2)?.try_into().ok()?).into(),
            )),
            26 => Some((
                4,
                u32::from_be_bytes(rest.get(..4)?.try_into().ok()?).into(),
            )),
            27 => Some((8, u64::from_be_bytes(rest.get(..8)?.try_into().ok()?))),
            _ => None, // indefinite lengths & reserved → reject
        }
    };

    let (hdr_extra, value) = arg(info, rest)?;
    let payload_start = 1 + hdr_extra;

    let total = match major {
        0 | 1 | 7 => payload_start, // ints / simple values carry no payload
        2 | 3 => payload_start + value as usize, // byte / text strings
        4 | 6 => {
            // Arrays / tags: sum of contained items.
            let mut consumed = payload_start;
            for _ in 0..value {
                consumed += cbor_item_len(input.get(consumed..)?)?;
            }
            consumed
        }
        5 => {
            // Map: each pair contributes two items.
            let mut consumed = payload_start;
            for _ in 0..value {
                consumed += cbor_item_len(input.get(consumed..)?)?;
                consumed += cbor_item_len(input.get(consumed..)?)?;
            }
            consumed
        }
        _ => return None,
    };
    Some(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn header_bytes(flags: u8, count: u32, rp_id: &str) -> Vec<u8> {
        let mut v = Sha256::digest(rp_id.as_bytes()).to_vec();
        v.push(flags);
        v.extend_from_slice(&count.to_be_bytes());
        v
    }

    #[test]
    fn rejects_short_buffer() {
        assert!(AuthenticatorData::parse(&[0u8; 36]).is_err());
    }

    #[test]
    fn parses_header_fields() {
        let raw = header_bytes(FLAG_UP, 7, "example.com");
        let ad = AuthenticatorData::parse(&raw).unwrap();
        assert_eq!(ad.rp_id_hash(), Sha256::digest(b"example.com").as_slice());
        assert!(ad.user_present());
        assert!(!ad.user_verified());
        assert_eq!(ad.sign_count(), 7);
        assert!(ad.attested_credential_data().is_none());
    }

    #[test]
    fn at_flag_without_payload_is_rejected() {
        let raw = header_bytes(FLAG_UP | FLAG_AT, 0, "celestia.world");
        // AT promised attested credential data, none follows.
        assert!(AuthenticatorData::parse(&raw).is_err());
    }

    #[test]
    fn ed_flag_without_payload_is_rejected() {
        let raw = header_bytes(FLAG_UP | FLAG_ED, 3, "celestia.world");
        assert!(AuthenticatorData::parse(&raw).is_err());
    }

    #[test]
    fn cbor_len_measures_nested_structures() {
        // { 1: 2, -7: b"\xaa\xbb" } roughly; build via coset-independent bytes:
        // map(2){ uint(1)->uint(2), negint(-8)->bytes(2) }
        let bytes = [0xa2, 0x01, 0x02, 0x27, 0x42, 0xaa, 0xbb];
        assert_eq!(cbor_item_len(&bytes), Some(bytes.len()));
    }

    #[test]
    fn cbor_len_rejects_indefinite() {
        // Indefinite-length map start byte 0xBF.
        assert_eq!(cbor_item_len(&[0xbf]), None);
    }
}
