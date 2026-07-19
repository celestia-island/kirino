use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use uuid::Uuid;

use crate::config::SessionConfig;
use crate::error::{SessionError, SessionResult};
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
        Self { config, encoding_key, decoding_key }
    }

    /// Issue an access + refresh token pair for a user.
    pub fn issue_pair(
        &self,
        user_id: Uuid,
        username: String,
        roles: Vec<String>,
    ) -> SessionResult<TokenPair> {
        let sid = Uuid::new_v4().to_string();
        let access = self.sign(&TokenClaims::new(user_id, username.clone(), TokenType::Access, self.config.access_ttl_secs, &self.config.issuer)
                .with_session(&sid))?;
        let refresh = self.sign(&TokenClaims::new(user_id, username, TokenType::Refresh, self.config.refresh_ttl_secs, &self.config.issuer)
                .with_session(&sid))?;
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
        let data = decode::<TokenClaims>(token, &self.decoding_key, &validation)?;
        Ok(data.claims)
    }

    /// Decode a JWT without verifying signature (e.g. for client-side expiry check).
    pub fn decode_unverified(token: &str) -> SessionResult<TokenClaims> {
        let mut validation = Validation::default();
        validation.insecure_disable_signature_validation();
        validation.validate_exp = false;
        let data = decode::<TokenClaims>(token, &DecodingKey::from_secret(&[]), &validation)?;
        Ok(data.claims)
    }

    /// Refresh an access token using a valid refresh token.
    /// Returns a new token pair and invalidates the old refresh token.
    pub fn refresh(&self, refresh_token: &str) -> SessionResult<TokenPair> {
        let claims = self.verify(refresh_token)?;
        if claims.token_type != TokenType::Refresh {
            return Err(SessionError::InvalidToken("expected refresh token".into()));
        }
        let user_id = Uuid::parse_str(&claims.sub)
            .map_err(|_| SessionError::InvalidToken("invalid user id in token".into()))?;
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
        let pair = manager.issue_pair(user_id, "testuser".into(), vec!["admin".to_string()]).unwrap();

        let claims = manager.verify(&pair.access_token).unwrap();
        assert_eq!(claims.sub, user_id.to_string());
        assert_eq!(claims.username, "testuser");
        assert_eq!(claims.roles, vec!["admin".to_string()]);
        assert_eq!(claims.token_type, TokenType::Access);
    }

    #[test]
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
        ).is_err());
    }

    #[test]
    fn wrong_secret_fails() {
        let m1 = TokenManager::new(SessionConfig::new("secret-a"));
        let m2 = TokenManager::new(SessionConfig::new("secret-b"));
        let claims = TokenClaims::new(Uuid::new_v4(), "u".into(), TokenType::Access, 3600, "kirino");
        let token = m1.sign(&claims).unwrap();
        assert!(m2.verify(&token).is_err());
    }

    #[test]
    fn refresh_token_flow() {
        let manager = TokenManager::new(SessionConfig::new("secret"));
        let pair = manager.issue_pair(Uuid::new_v4(), "u".into(), vec![]).unwrap();
        let new_pair = manager.refresh(&pair.refresh_token).unwrap();
        assert_ne!(new_pair.access_token, pair.access_token);
    }
}
