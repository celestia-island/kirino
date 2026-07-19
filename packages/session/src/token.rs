use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TokenType {
    Access,
    Refresh,
}

/// Claims embedded in JWT tokens.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenClaims {
    /// Subject (user ID).
    pub sub: String,
    /// Username.
    pub username: String,
    /// Token type.
    pub token_type: TokenType,
    /// Issued at (Unix timestamp).
    pub iat: usize,
    /// Expiration (Unix timestamp).
    pub exp: usize,
    /// Issuer.
    pub iss: String,
    /// JWT ID (unique per token).
    pub jti: String,
    /// Session ID for tracking/revocation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    /// User roles.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<String>,
}

impl TokenClaims {
    pub fn new(
        user_id: Uuid,
        username: String,
        token_type: TokenType,
        ttl_secs: u64,
        issuer: &str,
    ) -> Self {
        let now = Utc::now();
        let iat = now.timestamp() as usize;
        let exp = (now.timestamp() as u64 + ttl_secs) as usize;
        Self {
            sub: user_id.to_string(),
            username,
            token_type,
            iat,
            exp,
            iss: issuer.into(),
            jti: Uuid::new_v4().to_string(),
            sid: None,
            roles: Vec::new(),
        }
    }

    pub fn with_session(mut self, sid: impl Into<String>) -> Self {
        self.sid = Some(sid.into());
        self
    }

    pub fn with_roles(mut self, roles: Vec<String>) -> Self {
        self.roles = roles;
        self
    }

    pub fn expiration(&self) -> DateTime<Utc> {
        DateTime::from_timestamp(self.exp as i64, 0).unwrap_or(DateTime::UNIX_EPOCH)
    }

    pub fn is_expired(&self) -> bool {
        Utc::now().timestamp() as usize >= self.exp
    }
}

/// A pair of access + refresh tokens.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: u64,
}
