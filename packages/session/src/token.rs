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
    /// Auxiliary user ID (backward compat — redundant with sub).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    /// Tenant ID for multi-tenant deployments.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// Cross-auth relay ID (UUIDv7, permanent).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relay_id: Option<String>,
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
            user_id: None,
            tenant_id: None,
            relay_id: None,
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

    pub fn with_user_id(mut self, user_id: impl Into<String>) -> Self {
        self.user_id = Some(user_id.into());
        self
    }

    pub fn with_tenant(mut self, tenant_id: impl Into<String>) -> Self {
        self.tenant_id = Some(tenant_id.into());
        self
    }

    pub fn with_relay(mut self, relay_id: impl Into<String>) -> Self {
        self.relay_id = Some(relay_id.into());
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
