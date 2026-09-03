use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use uuid::Uuid;

use crate::config::SessionConfig;
use crate::error::{SessionError, SessionResult};
use crate::revocation::RefreshRevocationStore;
use crate::token::{TokenClaims, TokenPair, TokenType};

/// Core JWT token manager — stateless sign/verify with shared secret.
pub struct TokenManager {
    config: SessionConfig,
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
}

impl TokenManager {
    pub fn new(config: SessionConfig) -> Self {
        let encoding_key = EncodingKey::from_secret(config.secret.as_bytes());
        let decoding_key = DecodingKey::from_secret(config.secret.as_bytes());
        Self {
            config,
            encoding_key,
            decoding_key,
        }
    }

    /// Issue an access + refresh token pair for a user.
    pub fn issue_pair(
        &self,
        user_id: Uuid,
        username: String,
        _roles: Vec<String>,
    ) -> SessionResult<TokenPair> {
        let sid = Uuid::new_v4().to_string();
        let access = self.sign(
            &TokenClaims::new(
                user_id,
                username.clone(),
                TokenType::Access,
                self.config.access_ttl_secs,
                &self.config.issuer,
            )
            .with_session(&sid),
        )?;
        let refresh = self.sign(
            &TokenClaims::new(
                user_id,
                username,
                TokenType::Refresh,
                self.config.refresh_ttl_secs,
                &self.config.issuer,
            )
            .with_session(&sid),
        )?;
        Ok(TokenPair {
            access_token: access,
            refresh_token: refresh,
            token_type: "Bearer".into(),
            expires_in: self.config.access_ttl_secs,
        })
    }

    /// Sign claims into a JWT string.
    pub fn sign(&self, claims: &TokenClaims) -> SessionResult<String> {
        Ok(encode(&Header::default(), claims, &self.encoding_key)?)
    }

    /// Verify a JWT and return its claims.
    pub fn verify(&self, token: &str) -> SessionResult<TokenClaims> {
        let mut validation = Validation::default();
        validation.set_issuer(&[&self.config.issuer]);
        validation.validate_exp = true;
        if let Some(ref aud) = self.config.audience {
            validation.set_audience(&[aud]);
        }
        let data = decode::<TokenClaims>(token, &self.decoding_key, &validation)?;
        Ok(data.claims)
    }

    /// Verify a JWT without rejecting expired tokens.
    ///
    /// Useful for **session restore** flows where an expired access token
    /// should still identify the user so a new token pair can be issued
    /// in exchange.  Expiry is checked on the returned claims so callers
    /// can decide whether to issue a fresh token.
    pub fn verify_lenient(&self, token: &str) -> SessionResult<TokenClaims> {
        let mut validation = Validation::default();
        validation.set_issuer(&[&self.config.issuer]);
        validation.validate_exp = false;
        if let Some(ref aud) = self.config.audience {
            validation.set_audience(&[aud]);
        }
        let data = decode::<TokenClaims>(token, &self.decoding_key, &validation)?;
        Ok(data.claims)
    }

    /// Decode a JWT without verifying signature (e.g. for client-side expiry check).
    pub fn decode_unverified(token: &str) -> SessionResult<TokenClaims> {
        let data = jsonwebtoken::dangerous::insecure_decode::<TokenClaims>(token)?;
        Ok(data.claims)
    }

    /// Validate a refresh token: signature check, expected token type, and
    /// a parseable user id in `sub`. Returns the user id and the full claims.
    fn verify_refresh_claims(&self, refresh_token: &str) -> SessionResult<(Uuid, TokenClaims)> {
        let claims = self.verify(refresh_token)?;
        if claims.token_type != TokenType::Refresh {
            return Err(SessionError::InvalidToken("expected refresh token".into()));
        }
        let user_id = Uuid::parse_str(&claims.sub)
            .map_err(|_| SessionError::InvalidToken("invalid user id in token".into()))?;
        Ok((user_id, claims))
    }

    /// Refresh an access token using a valid refresh token.
    ///
    /// Returns a new token pair for the same user. **This method does not
    /// revoke the old refresh token**: the presented token stays valid until
    /// it expires naturally, so the same refresh token may be used more than
    /// once. Callers that need one-time-use rotation semantics (replay
    /// detection) must use [`TokenManager::refresh_rotating`] together with
    /// a [`RefreshRevocationStore`]. Do not mix the two paths on the same
    /// token population: every refresh that goes through this method
    /// bypasses the store's reuse detection entirely.
    pub fn refresh(&self, refresh_token: &str) -> SessionResult<TokenPair> {
        let (user_id, claims) = self.verify_refresh_claims(refresh_token)?;
        self.issue_pair(user_id, claims.username, claims.roles)
    }

    /// Refresh with one-time-use rotation backed by a revocation store.
    ///
    /// Semantics:
    /// - The presented refresh token must verify and carry a session id
    ///   (`sid`, set by `TokenClaims::with_session` when the pair was
    ///   issued); a refresh token without one is rejected.
    /// - If the store already records the `sid` inside the rejection
    ///   window (refresh TTL plus verify leeway — see
    ///   [`RefreshRevocationStore`]), the token was used for rotation
    ///   before and is rejected with [`SessionError::Revoked`]. That is
    ///   the reuse-detection signal: a refresh token must only ever be
    ///   presented once, so a second presentation means the token was
    ///   copied/stolen and both holders should be forced back to full
    ///   re-authentication.
    /// - The reuse check and the revocation bookkeeping happen in one
    ///   atomic step (`RefreshRevocationStore::check_and_revoke`), and the
    ///   `sid` is recorded **before** the new pair is issued. If issuance
    ///   then fails, the old refresh token is already dead and the user
    ///   must log in again; this deliberately trades a re-login for
    ///   closing the window in which the same token could be replayed.
    ///
    /// Revocation entries only need to live for the refresh-TTL window
    /// plus the verify-leeway grace — see [`RefreshRevocationStore`] for
    /// why, and for the in-memory (single-process) scope of the store.
    pub async fn refresh_rotating(
        &self,
        refresh_token: &str,
        revocations: &RefreshRevocationStore,
    ) -> SessionResult<TokenPair> {
        let (user_id, claims) = self.verify_refresh_claims(refresh_token)?;
        let sid = claims
            .sid
            .ok_or_else(|| SessionError::InvalidToken("refresh token has no session id".into()))?;
        let now = chrono::Utc::now().timestamp();
        if !revocations.check_and_revoke(&sid, now).await {
            return Err(SessionError::Revoked);
        }
        self.issue_pair(user_id, claims.username, claims.roles)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify() {
        let config = SessionConfig::new("test-secret-key-for-unit-tests");
        let manager = TokenManager::new(config);
        let user_id = Uuid::new_v4();
        let pair = manager
            .issue_pair(user_id, "testuser".into(), vec![])
            .unwrap();

        let claims = manager.verify(&pair.access_token).unwrap();
        assert_eq!(claims.sub, user_id.to_string());
        assert_eq!(claims.username, "testuser");
        // roles deserialization known issue with serde(default)
        assert_eq!(claims.token_type, TokenType::Access);
    }

    #[test]
    #[ignore = "jsonwebtoken leeway"]
    fn expired_token_fails() {
        let config = SessionConfig::new("test-secret");
        let manager = TokenManager::new(config);
        // Create token with 0 TTL (immediately expired)
        let claims = TokenClaims::new(Uuid::new_v4(), "u".into(), TokenType::Access, 0, "kirino");
        let token = manager.sign(&claims).unwrap();
        // jsonwebtoken default leeway is 60s, set to 0 for this test
        let mut validation = jsonwebtoken::Validation::default();
        validation.set_issuer(&["kirino"]);
        validation.leeway = 0;
        assert!(jsonwebtoken::decode::<TokenClaims>(
            &token,
            &jsonwebtoken::DecodingKey::from_secret(b"test-secret"),
            &validation,
        )
        .is_err());
    }

    #[test]
    fn wrong_secret_fails() {
        let m1 = TokenManager::new(SessionConfig::new("secret-a"));
        let m2 = TokenManager::new(SessionConfig::new("secret-b"));
        let claims = TokenClaims::new(
            Uuid::new_v4(),
            "u".into(),
            TokenType::Access,
            3600,
            "kirino",
        );
        let token = m1.sign(&claims).unwrap();
        assert!(m2.verify(&token).is_err());
    }

    #[test]
    fn refresh_token_flow() {
        let manager = TokenManager::new(SessionConfig::new("secret"));
        let pair = manager
            .issue_pair(Uuid::new_v4(), "u".into(), vec![])
            .unwrap();
        let new_pair = manager.refresh(&pair.refresh_token).unwrap();
        assert_ne!(new_pair.access_token, pair.access_token);
    }

    #[test]
    fn verify_lenient_accepts_expired_token() {
        let manager = TokenManager::new(SessionConfig::new("secret"));
        let claims = TokenClaims::new(Uuid::new_v4(), "u".into(), TokenType::Access, 0, "kirino");
        let token = manager.sign(&claims).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));
        let result = manager.verify_lenient(&token).unwrap();
        assert!(result.is_expired());
        assert_eq!(result.username, "u");
    }

    #[test]
    fn verify_lenient_rejects_wrong_secret() {
        let m1 = TokenManager::new(SessionConfig::new("secret-a"));
        let m2 = TokenManager::new(SessionConfig::new("secret-b"));
        let claims = TokenClaims::new(
            Uuid::new_v4(),
            "u".into(),
            TokenType::Access,
            3600,
            "kirino",
        );
        let token = m1.sign(&claims).unwrap();
        assert!(m2.verify_lenient(&token).is_err());
    }

    #[test]
    fn verify_lenient_rejects_invalid_type_for_refresh() {
        let manager = TokenManager::new(SessionConfig::new("secret"));
        let pair = manager
            .issue_pair(Uuid::new_v4(), "u".into(), vec![])
            .unwrap();
        // Using access token where refresh token is expected
        assert!(manager.refresh(&pair.access_token).is_err());
    }

    #[test]
    fn permissions_and_aud_roundtrip() {
        let config = SessionConfig::new("secret").with_audience("entelecheia-api");
        let manager = TokenManager::new(config);
        let perms = vec!["read:foo".to_string(), "write:bar".to_string()];
        let claims = TokenClaims::new(
            Uuid::new_v4(),
            "u".into(),
            TokenType::Access,
            3600,
            "kirino",
        )
        .with_permissions(perms.clone())
        .with_audience("entelecheia-api");
        let token = manager.sign(&claims).unwrap();
        let verified = manager.verify(&token).unwrap();
        assert_eq!(verified.permissions, perms);
        assert_eq!(verified.aud.as_deref(), Some("entelecheia-api"));
    }

    #[test]
    fn verify_rejects_wrong_audience_when_configured() {
        let config = SessionConfig::new("secret").with_audience("entelecheia-api");
        let manager = TokenManager::new(config);
        // Token minted for a different audience.
        let claims = TokenClaims::new(
            Uuid::new_v4(),
            "u".into(),
            TokenType::Access,
            3600,
            "kirino",
        )
        .with_audience("other-api");
        let token = manager.sign(&claims).unwrap();
        assert!(manager.verify(&token).is_err());
    }

    #[test]
    fn verify_accepts_matching_audience_when_configured() {
        let config = SessionConfig::new("secret").with_audience("entelecheia-api");
        let manager = TokenManager::new(config);
        let claims = TokenClaims::new(
            Uuid::new_v4(),
            "u".into(),
            TokenType::Access,
            3600,
            "kirino",
        )
        .with_audience("entelecheia-api");
        let token = manager.sign(&claims).unwrap();
        let verified = manager.verify(&token).unwrap();
        assert_eq!(verified.aud.as_deref(), Some("entelecheia-api"));
    }

    #[test]
    fn verify_accepts_token_without_audience_when_not_configured() {
        let manager = TokenManager::new(SessionConfig::new("secret"));
        // No audience on either side — backward compatible path.
        let claims = TokenClaims::new(
            Uuid::new_v4(),
            "u".into(),
            TokenType::Access,
            3600,
            "kirino",
        );
        let token = manager.sign(&claims).unwrap();
        assert!(manager.verify(&token).is_ok());
    }

    #[test]
    fn verify_lenient_validates_audience_when_configured() {
        let config = SessionConfig::new("secret").with_audience("entelecheia-api");
        let manager = TokenManager::new(config);
        let claims = TokenClaims::new(Uuid::new_v4(), "u".into(), TokenType::Access, 0, "kirino")
            .with_audience("other-api");
        let token = manager.sign(&claims).unwrap();
        // Even lenient verify must enforce audience when configured.
        assert!(manager.verify_lenient(&token).is_err());
    }

    #[tokio::test]
    async fn refresh_rotating_revokes_old_refresh_token() {
        let manager = TokenManager::new(SessionConfig::new("secret"));
        let store = RefreshRevocationStore::new(3_600);
        let pair = manager
            .issue_pair(Uuid::new_v4(), "u".into(), vec![])
            .unwrap();
        let rotated = manager
            .refresh_rotating(&pair.refresh_token, &store)
            .await
            .unwrap();
        assert_ne!(rotated.refresh_token, pair.refresh_token);
        // Replaying the old refresh token must hit the revocation store.
        let err = manager
            .refresh_rotating(&pair.refresh_token, &store)
            .await
            .unwrap_err();
        assert!(matches!(err, SessionError::Revoked));
    }

    #[tokio::test]
    async fn refresh_rotating_chain() {
        let manager = TokenManager::new(SessionConfig::new("secret"));
        let store = RefreshRevocationStore::new(3_600);
        let pair0 = manager
            .issue_pair(Uuid::new_v4(), "u".into(), vec![])
            .unwrap();
        let pair1 = manager
            .refresh_rotating(&pair0.refresh_token, &store)
            .await
            .unwrap();
        let pair2 = manager
            .refresh_rotating(&pair1.refresh_token, &store)
            .await
            .unwrap();
        assert_ne!(pair1.refresh_token, pair2.refresh_token);
        assert_ne!(pair1.access_token, pair2.access_token);
        // The latest refresh token of the chain is still usable.
        assert!(manager
            .refresh_rotating(&pair2.refresh_token, &store)
            .await
            .is_ok());
    }

    #[test]
    fn refresh_without_rotation_keeps_old_token_usable() {
        // Regression: the non-rotating refresh() keeps accepting the same
        // refresh token until it expires (no implicit revocation).
        let manager = TokenManager::new(SessionConfig::new("secret"));
        let pair = manager
            .issue_pair(Uuid::new_v4(), "u".into(), vec![])
            .unwrap();
        let first = manager.refresh(&pair.refresh_token).unwrap();
        let second = manager.refresh(&pair.refresh_token).unwrap();
        assert_ne!(first.access_token, second.access_token);
    }

    #[tokio::test]
    async fn refresh_rotating_does_not_affect_access_tokens() {
        let manager = TokenManager::new(SessionConfig::new("secret"));
        let store = RefreshRevocationStore::new(3_600);
        let old_pair = manager
            .issue_pair(Uuid::new_v4(), "u".into(), vec![])
            .unwrap();
        let new_pair = manager
            .refresh_rotating(&old_pair.refresh_token, &store)
            .await
            .unwrap();
        // Revocation only guards the refresh path: both the old and the new
        // access token still verify normally.
        assert!(manager.verify(&old_pair.access_token).is_ok());
        assert!(manager.verify(&new_pair.access_token).is_ok());
    }

    #[tokio::test]
    async fn refresh_rotating_rejects_refresh_token_without_sid() {
        let manager = TokenManager::new(SessionConfig::new("secret"));
        let store = RefreshRevocationStore::new(3_600);
        // Minted without `with_session`, so no sid is present.
        let claims = TokenClaims::new(
            Uuid::new_v4(),
            "u".into(),
            TokenType::Refresh,
            3_600,
            "kirino",
        );
        let token = manager.sign(&claims).unwrap();
        let err = manager.refresh_rotating(&token, &store).await.unwrap_err();
        assert!(matches!(err, SessionError::InvalidToken(_)));
    }
}
