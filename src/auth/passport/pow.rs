//! Hashcash-style proof-of-work challenge facility.
//!
//! `GET /health`-style endpoints hand the client `{ seed, bits }`; the
//! client searches for a `counter` such that
//! `SHA-256(UTF-8(seed) || UTF-8(decimal counter))` has at least `bits`
//! leading zero bits, then submits `{ seed, counter }` back. The seed is
//! single-use (consumed on the first verification attempt, success or
//! failure) and short-lived, so a solved proof cannot be replayed.
//!
//! Wire contract (must match the client solver, e.g. plana-ui's
//! `solvePow`): seed is the lowercase hex digest string; counter is the
//! decimal string; both are concatenated as UTF-8 without separators.
//!
//! Default difficulty is 12 bits (~4k expected hashes, ~30-110 ms in
//! typical client solvers) — enough to blunt blind scripting without
//! affecting real users. Clamp to [4, 32].

use rand::Rng;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use thiserror::Error;
use tokio::sync::RwLock;

/// Default proof-of-work difficulty (leading zero bits). 12 ≈ ~4k expected
/// hashes — a snappy default that still blunts blind scripting.
pub const DEFAULT_POW_BITS: u8 = 12;

/// How long an issued seed remains solvable.
const SEED_TTL_SECS: u64 = 120;

/// Maximum seeds retained (safety valve against flooding).
const SEED_STORE_CAP: usize = 10_000;

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum PowError {
    #[error("challenge seed invalid or already used")]
    InvalidSeed,
    #[error("challenge expired")]
    Expired,
    #[error("insufficient proof of work")]
    InsufficientWork,
    #[error("difficulty out of range [4, 32]")]
    InvalidBits,
}

/// A freshly issued challenge handed to the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PowChallengeIssued {
    pub seed: String,
    pub bits: u8,
}

struct SeedEntry {
    issued_at: Instant,
}

/// Thread-safe, single-use hashcash challenge store.
pub struct PowChallenge {
    seeds: Arc<RwLock<HashMap<String, SeedEntry>>>,
    ttl: Duration,
    cap: usize,
}

impl Default for PowChallenge {
    fn default() -> Self {
        Self::new()
    }
}

impl PowChallenge {
    /// Create a store with the default TTL (120s) and capacity (10k).
    #[must_use]
    pub fn new() -> Self {
        Self {
            seeds: Arc::new(RwLock::new(HashMap::new())),
            ttl: Duration::from_secs(SEED_TTL_SECS),
            cap: SEED_STORE_CAP,
        }
    }

    /// Create a store with custom TTL / capacity (tests, tuned deployments).
    #[must_use]
    pub fn with_limits(ttl: Duration, cap: usize) -> Self {
        Self {
            seeds: Arc::new(RwLock::new(HashMap::new())),
            ttl,
            cap,
        }
    }

    /// Issue a fresh challenge seed for the given difficulty.
    pub async fn issue(&self, bits: u8) -> Result<PowChallengeIssued, PowError> {
        if !(4..=32).contains(&bits) {
            return Err(PowError::InvalidBits);
        }
        self.prune().await;
        let seed = {
            let mut rng = rand::thread_rng();
            let raw: [u8; 32] = rng.gen();
            hex::encode(Sha256::digest(raw))
        };
        let mut store = self.seeds.write().await;
        if store.len() >= self.cap {
            // Evict the oldest entries (approx: drop everything past cap).
            let mut entries: Vec<(String, SeedEntry)> = store.drain().collect();
            entries.sort_by_key(|(_, e)| e.issued_at);
            store.extend(entries.into_iter().rev().take(self.cap));
        }
        store.insert(seed.clone(), SeedEntry { issued_at: Instant::now() });
        Ok(PowChallengeIssued { seed, bits })
    }

    /// Verify a submitted solution. The seed is consumed on the first
    /// attempt (success or failure), so a proof cannot be replayed.
    pub async fn verify(&self, seed: &str, counter: u64, bits: u8) -> Result<(), PowError> {
        let entry = self
            .seeds
            .write()
            .await
            .remove(seed)
            .ok_or(PowError::InvalidSeed)?;

        if entry.issued_at.elapsed() > self.ttl {
            return Err(PowError::Expired);
        }

        let mut hasher = Sha256::new();
        hasher.update(seed.as_bytes());
        hasher.update(counter.to_string().as_bytes());
        let hash = hasher.finalize();

        if leading_zero_bits(&hash) < u32::from(bits) {
            return Err(PowError::InsufficientWork);
        }
        Ok(())
    }

    async fn prune(&self) {
        let mut store = self.seeds.write().await;
        store.retain(|_, e| e.issued_at.elapsed() <= self.ttl);
    }

    /// Number of live seeds (tests / metrics).
    pub async fn len(&self) -> usize {
        self.seeds.read().await.len()
    }

    /// Whether the store is empty (tests / metrics).
    pub async fn is_empty(&self) -> bool {
        self.seeds.read().await.is_empty()
    }
}

/// Number of leading zero bits of a SHA-256 digest.
pub fn leading_zero_bits(hash: &[u8]) -> u32 {
    let mut count = 0u32;
    for &byte in hash {
        if byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros();
            break;
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    fn solution_seed_passes(challenge: &PowChallenge, seed: &str, bits: u8) -> bool {
        // Brute-force a counter synchronously against the same contract.
        let mut counter: u64 = 0;
        loop {
            let mut hasher = Sha256::new();
            hasher.update(seed.as_bytes());
            hasher.update(counter.to_string().as_bytes());
            let hash = hasher.finalize();
            if leading_zero_bits(&hash) >= u32::from(bits) {
                return counter != u64::MAX;
            }
            counter += 1;
        }
    }

    #[tokio::test]
    async fn issue_and_verify_roundtrip() {
        let challenge = PowChallenge::new();
        let issued = challenge.issue(DEFAULT_POW_BITS).await.unwrap();
        assert_eq!(issued.bits, DEFAULT_POW_BITS);
        assert!(!issued.seed.is_empty());

        // Find a valid counter for the issued seed.
        let mut counter: u64 = 0;
        let mut solution: Option<u64> = None;
        while counter < 100_000 {
            let mut hasher = Sha256::new();
            hasher.update(issued.seed.as_bytes());
            hasher.update(counter.to_string().as_bytes());
            let hash = hasher.finalize();
            if leading_zero_bits(&hash) >= u32::from(issued.bits) {
                solution = Some(counter);
                break;
            }
            counter += 1;
        }
        let counter = solution.expect("a valid counter within 100k attempts");
        assert!(challenge.verify(&issued.seed, counter, issued.bits).await.is_ok());

        // Single-use: the same seed must fail on replay.
        assert_eq!(
            challenge.verify(&issued.seed, counter, issued.bits).await,
            Err(PowError::InvalidSeed)
        );
    }

    #[tokio::test]
    async fn insufficient_work_is_rejected_and_consumed() {
        let challenge = PowChallenge::new();
        let issued = challenge.issue(DEFAULT_POW_BITS).await.unwrap();
        let err = challenge.verify(&issued.seed, 0, issued.bits).await.unwrap_err();
        assert_eq!(err, PowError::InsufficientWork);
        // Consumed even on failure.
        assert_eq!(
            challenge.verify(&issued.seed, 0, issued.bits).await,
            Err(PowError::InvalidSeed)
        );
    }

    #[tokio::test]
    async fn expired_seed_is_rejected() {
        let challenge = PowChallenge::with_limits(Duration::from_millis(1), 100);
        let issued = challenge.issue(8).await.unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;
        assert_eq!(challenge.verify(&issued.seed, 0, 8).await, Err(PowError::Expired));
    }

    #[tokio::test]
    async fn bits_out_of_range_is_rejected() {
        let challenge = PowChallenge::new();
        assert_eq!(challenge.issue(2).await, Err(PowError::InvalidBits));
        assert_eq!(challenge.issue(40).await, Err(PowError::InvalidBits));
    }

    #[tokio::test]
    async fn leading_zero_bits_counts_correctly() {
        let mut h = [0u8; 32];
        h[0] = 0x80;
        assert_eq!(leading_zero_bits(&h), 0);
        h[0] = 0x01;
        assert_eq!(leading_zero_bits(&h), 7);
        h[0] = 0x00;
        h[1] = 0x00;
        h[2] = 0x10;
        assert_eq!(leading_zero_bits(&h), 16 + 3);
    }
}
