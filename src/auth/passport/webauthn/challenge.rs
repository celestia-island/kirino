//! Server-side, single-use WebAuthn challenge storage.
//!
//! Mirrors the house [`crate::auth::passport::pow::PowChallenge`] pattern:
//! in-memory map, TTL-based expiry, capacity cap with oldest-eviction,
//! consume-on-first-use. Two policy extras specific to WebAuthn:
//!
//! * challenges are bound to a *purpose* (register vs authenticate) so a
//!   registration challenge can never satisfy an authentication ceremony;
//! * register challenges may be bound to an authenticated user id so the
//!   finishing call can be tied to the session that started it.

use rand::RngExt;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::RwLock;

/// Ceremony purpose bound at issue time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengePurpose {
    /// Registration (`webauthn.create`) — optionally user-bound.
    Register,
    /// Authentication (`webauthn.get`) — always anonymous.
    Authenticate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebAuthnChallengeError {
    NotFound,
    Expired,
    PurposeMismatch,
    UserMismatch,
}

impl std::fmt::Display for WebAuthnChallengeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "challenge invalid or already used"),
            Self::Expired => write!(f, "challenge expired"),
            Self::PurposeMismatch => write!(f, "challenge purpose mismatch"),
            Self::UserMismatch => write!(f, "challenge user binding mismatch"),
        }
    }
}
impl std::error::Error for WebAuthnChallengeError {}

struct Entry {
    issued_at: Instant,
    purpose: ChallengePurpose,
    /// `Some(user_id)` ties this challenge to that account's session.
    user_id: Option<String>,
}

/// Thread-safe single-use challenge store. Default TTL 180 s, cap 10k.
pub struct WebAuthnChallengeStore {
    entries: Arc<RwLock<HashMap<String, Entry>>>,
    ttl: Duration,
    cap: usize,
}

impl Default for WebAuthnChallengeStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Process-wide challenge store.
///
/// HTTP layers typically issue a challenge in one request and consume it in
/// the next; a shared instance is required for that, and per-`AppState`
/// storage would force every consumer to plumb another field. Constructing
/// a private store remains possible (tests do), but embedders should use
/// this default via [`WebAuthnChallengeStore::shared`].
static SHARED_CHALLENGES: tokio::sync::OnceCell<WebAuthnChallengeStore> =
    tokio::sync::OnceCell::const_new();

impl WebAuthnChallengeStore {
    /// The process-wide store, lazily initialized with default limits.
    pub async fn shared() -> &'static Self {
        SHARED_CHALLENGES
            .get_or_init(|| async { Self::new() })
            .await
    }
}

impl WebAuthnChallengeStore {
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            ttl: Duration::from_secs(180),
            cap: 10_000,
        }
    }

    #[must_use]
    pub fn with_limits(ttl: Duration, cap: usize) -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            ttl,
            cap,
        }
    }

    /// Issue a fresh base64url(no padding) challenge string.
    ///
    /// # Errors
    ///
    /// Errors only on RNG failure surfaces, which rand does not raise; kept
    /// async signature-compatible with the PoW store.
    pub async fn issue(
        &self,
        purpose: ChallengePurpose,
        user_id: Option<&str>,
    ) -> Result<String, WebAuthnChallengeError> {
        self.prune().await;
        // Scope the thread RNG (ThreadRng is !Send) so it never lives
        // across an await point — keeps the returned future Send, which
        // axum-style handlers require.
        let encoded = {
            let mut rng = rand::rng();
            let raw: [u8; 32] = rng.random();
            base64url_encode(&Sha256::digest(raw))
        };
        let mut store = self.entries.write().await;
        if store.len() >= self.cap {
            // Evict oldest by issuance.
            let mut v: Vec<(String, Instant)> = store
                .iter()
                .map(|(k, e)| (k.clone(), e.issued_at))
                .collect();
            v.sort_by_key(|(_, t)| *t);
            let drop_n = v.len().saturating_sub(self.cap.saturating_sub(1));
            if drop_n > 0 {
                for (k, _) in v.into_iter().take(drop_n) {
                    store.remove(&k);
                }
            }
        }
        store.insert(
            encoded.clone(),
            Entry {
                issued_at: Instant::now(),
                purpose,
                user_id: user_id.map(ToString::to_string),
            },
        );
        Ok(encoded)
    }

    /// Consume the challenge (single use regardless of outcome) and enforce
    /// purpose + optional user binding before returning success.
    pub async fn verify(
        &self,
        challenge_b64: &str,
        expected_purpose: ChallengePurpose,
        expected_user: Option<&str>,
    ) -> Result<(), WebAuthnChallengeError> {
        let entry = {
            let mut store = self.entries.write().await;
            store.remove(challenge_b64)
        };
        let Some(entry) = entry else {
            return Err(WebAuthnChallengeError::NotFound);
        };
        if entry.issued_at.elapsed() > self.ttl {
            return Err(WebAuthnChallengeError::Expired);
        }
        if entry.purpose != expected_purpose {
            return Err(WebAuthnChallengeError::PurposeMismatch);
        }
        match (&entry.user_id, expected_user) {
            (Some(bound), Some(want)) if bound != want => {
                return Err(WebAuthnChallengeError::UserMismatch);
            }
            (Some(_), None) | (None, Some(_)) => {
                return Err(WebAuthnChallengeError::UserMismatch);
            }
            (None, None) | (Some(_), Some(_)) => {}
        }
        Ok(())
    }

    /// Live challenge count (tests / metrics).
    pub async fn len(&self) -> usize {
        self.entries.read().await.len()
    }

    /// Whether the store is empty (tests / metrics).
    pub async fn is_empty(&self) -> bool {
        self.entries.read().await.is_empty()
    }

    async fn prune(&self) {
        let mut store = self.entries.write().await;
        store.retain(|_, e| e.issued_at.elapsed() <= self.ttl);
    }
}

/// RFC 4648 base64url without padding.
///
/// RFC 4648 base64url **without** padding, exactly the encoding WebAuthn
/// §4.2 prescribes for `clientDataJSON.challenge` (browsers emit unpadded).
#[must_use]
pub fn base64url_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
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

/// Decode RFC 4648 base64url; trailing `=` tolerated but never required,
/// impossible lengths (`len % 4 == 1`) and non-canonical trailing bits
/// rejected so bytes decoded from equal-length encodings stay unique.
///
/// # Errors
///
/// [`WebAuthnChallengeError::NotFound`] on any malformed input.
pub fn base64url_decode(s: &str) -> Result<Vec<u8>, WebAuthnChallengeError> {
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
        return Err(WebAuthnChallengeError::NotFound);
    }
    let s = s.trim_end_matches('=');
    let mut out = Vec::with_capacity(s.len() * 3 / 4 + 3);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for (i, &c) in s.as_bytes().iter().enumerate() {
        let v = val(c).ok_or(WebAuthnChallengeError::NotFound)?;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
        // Canonical tail: leftover pad bits after the final byte must be 0.
        if i == s.len() - 1 && bits > 0 && (acc & ((1 << bits) - 1)) != 0 {
            return Err(WebAuthnChallengeError::NotFound);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn roundtrip_and_single_use() {
        let s = WebAuthnChallengeStore::new();
        let c = s.issue(ChallengePurpose::Authenticate, None).await.unwrap();
        assert!(s
            .verify(&c, ChallengePurpose::Authenticate, None)
            .await
            .is_ok());
        assert_eq!(
            s.verify(&c, ChallengePurpose::Authenticate, None).await,
            Err(WebAuthnChallengeError::NotFound)
        );
    }

    #[tokio::test]
    async fn purpose_mismatch_rejected() {
        let s = WebAuthnChallengeStore::new();
        let c = s.issue(ChallengePurpose::Register, None).await.unwrap();
        assert_eq!(
            s.verify(&c, ChallengePurpose::Authenticate, None).await,
            Err(WebAuthnChallengeError::PurposeMismatch)
        );
    }

    #[tokio::test]
    async fn user_binding_enforced() {
        let s = WebAuthnChallengeStore::new();
        let c = s
            .issue(ChallengePurpose::Register, Some("user-1"))
            .await
            .unwrap();
        // Wrong binding burns the challenge (single-use, any outcome).
        assert_eq!(
            s.verify(&c, ChallengePurpose::Register, Some("user-2"))
                .await,
            Err(WebAuthnChallengeError::UserMismatch)
        );
        // Already consumed — indistinguishable from unknown.
        assert_eq!(
            s.verify(&c, ChallengePurpose::Register, Some("user-1"))
                .await,
            Err(WebAuthnChallengeError::NotFound)
        );

        // A fresh correctly-bound challenge succeeds.
        let c2 = s
            .issue(ChallengePurpose::Register, Some("user-1"))
            .await
            .unwrap();
        assert!(s
            .verify(&c2, ChallengePurpose::Register, Some("user-1"))
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn expired_challenge_rejected_and_removed() {
        let s = WebAuthnChallengeStore::with_limits(Duration::from_millis(1), 100);
        let c = s.issue(ChallengePurpose::Authenticate, None).await.unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;
        assert_eq!(
            s.verify(&c, ChallengePurpose::Authenticate, None).await,
            Err(WebAuthnChallengeError::Expired)
        );
        assert_eq!(s.len().await, 0);
    }

    #[test]
    fn base64url_roundtrip_known_vectors() {
        // Unpadded per WebAuthn §4.2.
        assert_eq!(base64url_encode(b""), "");
        assert_eq!(base64url_encode(b"f"), "Zg");
        assert_eq!(base64url_encode(b"fo"), "Zm8");
        assert_eq!(base64url_encode(b"foo"), "Zm9v");
        assert_eq!(base64url_encode(b"foob"), "Zm9vYg");
        assert_eq!(base64url_encode(&[0xfb, 0xff]), "-_8");
        for case in [b"".as_slice(), b"a", b"ab", b"abc", b"\x00\xff\x10\x20"] {
            assert_eq!(
                base64url_decode(&base64url_encode(case)).unwrap(),
                case,
                "roundtrip {case:?}"
            );
        }
    }

    #[test]
    fn issued_challenges_are_unpadded_and_urlsafe() {
        // Regression: a padded challenge can never match the browser's
        // unpadded clientDataJSON.challenge string.
        for _ in 0..8 {
            let c = futures_lite_block_on(
                WebAuthnChallengeStore::new().issue(ChallengePurpose::Authenticate, None),
            )
            .unwrap();
            assert!(!c.contains('='), "challenge {c} must be unpadded");
            assert!(!c.contains('+') && !c.contains('/'), "{c} not url-safe");
        }
    }

    #[test]
    fn base64url_decode_rejects_malformed() {
        assert!(base64url_decode("A").is_err()); // len % 4 == 1
        assert!(base64url_decode("Zm9=").is_err()); // non-canonical trailing bits
        assert!(base64url_decode("Zm$v").is_err()); // alphabet violation
        assert_eq!(base64url_decode("Zg==").unwrap(), b"f"); // padding tolerated
    }

    /// Tiny block-on helper so codec tests don't need the tokio runtime.
    fn futures_lite_block_on<F: std::future::Future>(fut: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime")
            .block_on(fut)
    }
}
