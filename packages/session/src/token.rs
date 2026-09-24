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
    /// JWT `sub` — the **user's UUID** (string form) for tokens minted by
    /// this crate.
    ///
    /// Cross-crate divergence: the root crate's
    /// `kirino::auth::credential::basic::Claims` binds `sub` to the
    /// **username** (with the UUID in its `user_id` field). Never copy `sub`
    /// verbatim between the two claim sets — map through
    /// [`TokenClaims::sub_uuid`] / [`TokenClaims::sub_username`] instead.
    /// Sibling services minting their own `TokenClaims` may bind `sub` to
    /// non-user subjects (e.g. device serials for bootstrap tokens).
    pub sub: String,
    /// Username of the authenticated user (distinct from `sub`, which
    /// carries the user UUID).
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
    ///
    /// Removal target: drop in 0.8 once downstream readers migrate to
    /// [`TokenClaims::sub_uuid`] (`sub` already carries the same UUID).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    /// Tenant ID for multi-tenant deployments.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// Cross-auth relay ID (UUIDv7, permanent).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relay_id: Option<String>,
    /// Workspace scope (RBAC partitioning): when set, the session is
    /// scoped to this workspace and permission resolution should use it
    /// as the workspace context. Absent = the session is workspace-
    /// agnostic (permissions resolve against unscoped grants only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_id: Option<String>,
    /// Permissions carried in the token for authorization.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub permissions: Vec<String>,
    /// Audience (who the token is intended for).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
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
            workspace_id: None,
            permissions: Vec::new(),
            aud: None,
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

    /// Scope the session to one workspace (RBAC partitioning). The token
    /// carries the workspace uuid; consumers pass it to
    /// `resolve_permissions_in(..., Some(workspace_id))` so workspace-
    /// scoped grants apply during this session.
    pub fn with_workspace(mut self, workspace_id: impl Into<String>) -> Self {
        self.workspace_id = Some(workspace_id.into());
        self
    }

    pub fn with_permissions(mut self, permissions: Vec<String>) -> Self {
        self.permissions = permissions;
        self
    }

    pub fn with_audience(mut self, aud: impl Into<String>) -> Self {
        self.aud = Some(aud.into());
        self
    }

    /// The token subject's stable user identifier — the `sub` claim, which
    /// this crate binds to the user UUID.
    ///
    /// Migration-safe counterpart of
    /// `kirino::auth::credential::basic::Claims::sub_uuid`: in that claim
    /// set the UUID lives in `user_id`, while here it is `sub` — this
    /// accessor returns it uniformly.
    #[must_use]
    pub fn sub_uuid(&self) -> &str {
        &self.sub
    }

    /// The token subject's username — the `username` claim.
    ///
    /// Migration-safe counterpart of
    /// `kirino::auth::credential::basic::Claims::sub_username`: in that
    /// claim set the username is what `sub` carries.
    #[must_use]
    pub fn sub_username(&self) -> &str {
        &self.username
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sub_accessors_pin_cross_crate_semantics() {
        let uid = Uuid::new_v4();
        let claims = TokenClaims::new(uid, "alice".into(), TokenType::Access, 60, "kirino");
        // Semantic accessors agree with the root crate's Claims accessors
        // regardless of which claim set carries which value.
        assert_eq!(claims.sub_uuid(), uid.to_string());
        assert_eq!(claims.sub_username(), "alice");
        // Wire compatibility: this claim set still carries the user UUID in
        // `sub` and the login name in `username` — do not silently change
        // either.
        let json = serde_json::to_string(&claims).unwrap();
        assert!(json.contains(&format!("\"sub\":\"{uid}\"")), "{json}");
        assert!(json.contains("\"username\":\"alice\""), "{json}");
    }
}
