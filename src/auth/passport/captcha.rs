use anyhow::{anyhow, Result};
use rand::Rng;
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::RwLock;

use crate::utils::constant_time_eq;

struct ChallengeEntry {
    answer: String,
    created_at: Instant,
    attempts: u32,
}

const DEFAULT_CAPTCHA_TTL_SECS: u64 = 300;
const DEFAULT_CAPTCHA_MAX_ATTEMPTS: u32 = 3;
const CAPTCHA_CLEANUP_THRESHOLD: usize = 1000;

pub struct CaptchaVerifier {
    challenges: Arc<RwLock<HashMap<String, ChallengeEntry>>>,
    ttl: Duration,
    max_attempts: u32,
    cleanup_handle: Option<tokio::task::JoinHandle<()>>,
}

impl std::fmt::Debug for CaptchaVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CaptchaVerifier")
            .field("ttl", &self.ttl)
            .field("max_attempts", &self.max_attempts)
            .field("has_cleanup_task", &self.cleanup_handle.is_some())
            .finish_non_exhaustive()
    }
}

impl CaptchaVerifier {
    #[must_use]
    pub fn new() -> Self {
        Self {
            challenges: Arc::new(RwLock::new(HashMap::new())),
            ttl: Duration::from_secs(DEFAULT_CAPTCHA_TTL_SECS),
            max_attempts: DEFAULT_CAPTCHA_MAX_ATTEMPTS,
            cleanup_handle: None,
        }
    }

    #[must_use]
    pub fn with_options(ttl: Duration, max_attempts: u32) -> Self {
        Self {
            challenges: Arc::new(RwLock::new(HashMap::new())),
            ttl,
            max_attempts: max_attempts.max(1),
            cleanup_handle: None,
        }
    }

    #[must_use]
    pub fn with_background_cleanup(mut self) -> Self {
        let challenges = self.challenges.clone();
        let ttl = self.ttl;
        self.cleanup_handle = Some(tokio::spawn(async move {
            let mut interval = tokio::time::interval(ttl / 2);
            loop {
                interval.tick().await;
                let mut chals = challenges.write().await;
                let now = Instant::now();
                chals.retain(|_, entry| now.duration_since(entry.created_at) <= ttl);
            }
        }));
        self
    }

    pub async fn verify(&self, challenge_id: &str, user_response: &str) -> Result<bool> {
        let mut challenges = self.challenges.write().await;
        let entry = challenges
            .get_mut(challenge_id)
            .ok_or_else(|| anyhow!("challenge not found or expired"))?;

        if Instant::now().duration_since(entry.created_at) > self.ttl {
            challenges.remove(challenge_id);
            return Err(anyhow!("challenge expired"));
        }

        if entry.attempts >= self.max_attempts {
            challenges.remove(challenge_id);
            return Err(anyhow!("too many attempts (max {})", self.max_attempts));
        }

        entry.attempts += 1;

        let correct = constant_time_eq(entry.answer.as_bytes(), user_response.trim().as_bytes());

        if correct {
            challenges.remove(challenge_id);
        }

        if challenges.len() > CAPTCHA_CLEANUP_THRESHOLD {
            let now = Instant::now();
            challenges.retain(|_, entry| now.duration_since(entry.created_at) <= self.ttl);
        }

        Ok(correct)
    }

    pub async fn generate_challenge(&self) -> Result<CaptchaChallenge> {
        let mut rng = rand::thread_rng();
        let a: u32 = rng.gen_range(1..100);
        let b: u32 = rng.gen_range(1..100);
        let answer = (a + b).to_string();
        let id = uuid::Uuid::now_v7().to_string();
        let challenge_text = format!("{a} + {b} = ?");

        let mut challenges = self.challenges.write().await;
        let now = Instant::now();
        challenges.retain(|_, entry| now.duration_since(entry.created_at) <= self.ttl);
        challenges.insert(
            id.clone(),
            ChallengeEntry {
                answer,
                created_at: now,
                attempts: 0,
            },
        );

        Ok(CaptchaChallenge {
            id,
            challenge_data: challenge_text.into_bytes(),
        })
    }

    #[must_use]
    pub async fn active_challenge_count(&self) -> usize {
        self.challenges.read().await.len()
    }

    pub async fn cleanup_expired(&self) {
        let mut challenges = self.challenges.write().await;
        let now = Instant::now();
        challenges.retain(|_, entry| now.duration_since(entry.created_at) <= self.ttl);
    }
}

impl Default for CaptchaVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for CaptchaVerifier {
    fn drop(&mut self) {
        if let Some(handle) = self.cleanup_handle.take() {
            handle.abort();
        }
    }
}

pub struct CaptchaChallenge {
    pub id: String,
    pub challenge_data: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_generate_and_verify() {
        let verifier = CaptchaVerifier::new();
        let challenge = verifier.generate_challenge().await.unwrap();
        let text = String::from_utf8(challenge.challenge_data.clone()).unwrap();
        let parts: Vec<&str> = text.split(" + ").collect();
        let a: u32 = parts[0].parse().unwrap();
        let b_str = parts[1].strip_suffix(" = ?").unwrap();
        let b: u32 = b_str.parse().unwrap();
        let answer = (a + b).to_string();

        assert!(verifier.verify(&challenge.id, &answer).await.unwrap());
    }

    #[tokio::test]
    async fn test_wrong_answer() {
        let verifier = CaptchaVerifier::new();
        let challenge = verifier.generate_challenge().await.unwrap();
        assert!(!verifier.verify(&challenge.id, "wrong").await.unwrap());
    }

    #[tokio::test]
    async fn test_challenge_single_use() {
        let verifier = CaptchaVerifier::new();
        let challenge = verifier.generate_challenge().await.unwrap();
        let text = String::from_utf8(challenge.challenge_data.clone()).unwrap();
        let parts: Vec<&str> = text.split(" + ").collect();
        let a: u32 = parts[0].parse().unwrap();
        let b: u32 = parts[1].strip_suffix(" = ?").unwrap().parse().unwrap();
        let answer = (a + b).to_string();

        assert!(verifier.verify(&challenge.id, &answer).await.unwrap());
        assert!(verifier.verify(&challenge.id, &answer).await.is_err());
    }

    #[tokio::test]
    async fn test_max_attempts() {
        let verifier = CaptchaVerifier::with_options(Duration::from_secs(300), 2);
        let challenge = verifier.generate_challenge().await.unwrap();

        assert!(!verifier.verify(&challenge.id, "wrong1").await.unwrap());
        assert!(!verifier.verify(&challenge.id, "wrong2").await.unwrap());
        assert!(verifier.verify(&challenge.id, "wrong3").await.is_err());
    }

    #[tokio::test]
    async fn test_unknown_challenge() {
        let verifier = CaptchaVerifier::new();
        assert!(verifier.verify("nonexistent", "0").await.is_err());
    }

    #[tokio::test]
    async fn test_active_challenge_count() {
        let verifier = CaptchaVerifier::new();
        assert_eq!(verifier.active_challenge_count().await, 0);
        verifier.generate_challenge().await.unwrap();
        verifier.generate_challenge().await.unwrap();
        assert_eq!(verifier.active_challenge_count().await, 2);
    }

    #[tokio::test]
    async fn test_expired_challenge() {
        let verifier = CaptchaVerifier::with_options(Duration::from_millis(1), 3);
        let challenge = verifier.generate_challenge().await.unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;
        assert!(verifier.verify(&challenge.id, "anything").await.is_err());
    }

    #[tokio::test]
    async fn test_multiple_challenges_independent() {
        let verifier = CaptchaVerifier::new();
        let ch1 = verifier.generate_challenge().await.unwrap();
        let ch2 = verifier.generate_challenge().await.unwrap();

        assert!(!verifier.verify(&ch1.id, "wrong").await.unwrap());
        assert!(!verifier.verify(&ch2.id, "wrong").await.unwrap());

        let text1 = String::from_utf8(ch1.challenge_data.clone()).unwrap();
        let parts: Vec<&str> = text1.split(" + ").collect();
        let a: u32 = parts[0].parse().unwrap();
        let b: u32 = parts[1].strip_suffix(" = ?").unwrap().parse().unwrap();
        let answer1 = (a + b).to_string();
        assert!(verifier.verify(&ch1.id, &answer1).await.unwrap());
    }
}
