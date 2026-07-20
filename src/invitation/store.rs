use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use chrono::{Duration, Utc};
use uuid::Uuid;

use super::token::generate_token;
use super::types::{
    AcceptInvitationParams, CreateInvitationParams, Invitation, InvitationMode,
    InvitationStatus, OpenInvitationResult,
};

/// Storage and lifecycle for invitations.
pub trait InvitationStore: Send + Sync {
    fn create(
        &self,
        invited_by: Uuid,
        params: CreateInvitationParams,
    ) -> Result<Invitation, InvitationError>;

    fn open(
        &self,
        token: &str,
        client_ip: Option<&str>,
        client_ua: Option<&str>,
    ) -> Result<OpenInvitationResult, InvitationError>;

    fn accept(
        &self,
        params: AcceptInvitationParams,
    ) -> Result<(Uuid, String), InvitationError>;

    fn find_by_token(&self, token: &str) -> Result<Option<Invitation>, InvitationError>;

    fn list_by_group(&self, group_id: Uuid) -> Result<Vec<Invitation>, InvitationError>;

    fn revoke(&self, token: &str, revoked_by: Uuid) -> Result<(), InvitationError>;

    fn expire_stale(&self) -> Result<u64, InvitationError>;
}

#[derive(Debug, thiserror::Error)]
pub enum InvitationError {
    #[error("invitation not found")]
    NotFound,
    #[error("invitation already used or revoked")]
    AlreadyUsed,
    #[error("invitation has expired")]
    Expired,
    #[error("open window has expired ({0}s remaining)")]
    OpenWindowExpired(i64),
    #[error("IP does not match the original opener")]
    IpMismatch,
    #[error("multiple links from same IP not allowed")]
    MultiIpDenied,
    #[error("cannot accept in current status: {0}")]
    InvalidStatus(InvitationStatus),
    #[error("{0}")]
    Other(String),
}

// ── In-memory store ──────────────────────────────────────────────

pub struct InMemoryInvitationStore {
    inner: Arc<Mutex<HashMap<Uuid, Invitation>>>,
    token_index: Arc<Mutex<HashMap<String, Uuid>>>,
}

impl InMemoryInvitationStore {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            token_index: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl Default for InMemoryInvitationStore {
    fn default() -> Self {
        Self::new()
    }
}

impl InvitationStore for InMemoryInvitationStore {
    fn create(
        &self,
        invited_by: Uuid,
        params: CreateInvitationParams,
    ) -> Result<Invitation, InvitationError> {
        let token = generate_token();
        let now = Utc::now();
        let ttl = Duration::seconds(params.ttl_secs.unwrap_or(604800) as i64);

        let invitation = Invitation {
            id: Uuid::new_v4(),
            token: token.clone(),
            group_id: params.group_id,
            invited_by,
            mode: params.mode,
            invitee_email: params.invitee_email,
            role: params.role.unwrap_or_else(|| "member".into()),
            max_uses: params.max_uses.unwrap_or(1),
            use_count: 0,
            allow_multi_ip: params.allow_multi_ip.unwrap_or(true),
            status: InvitationStatus::Pending,
            opened_at: None,
            opened_ip: None,
            opened_ua: None,
            expires_at: now + ttl,
            accepted_at: None,
            accepted_by: None,
            created_at: now,
        };

        let id = invitation.id;
        self.inner
            .lock()
            .map_err(|e| InvitationError::Other(e.to_string()))?
            .insert(id, invitation.clone());
        self.token_index
            .lock()
            .map_err(|e| InvitationError::Other(e.to_string()))?
            .insert(token, id);

        Ok(invitation)
    }

    fn open(
        &self,
        token: &str,
        client_ip: Option<&str>,
        client_ua: Option<&str>,
    ) -> Result<OpenInvitationResult, InvitationError> {
        let id = {
            let idx = self
                .token_index
                .lock()
                .map_err(|e| InvitationError::Other(e.to_string()))?;
            idx.get(token).cloned().ok_or(InvitationError::NotFound)?
        };

        let mut map = self
            .inner
            .lock()
            .map_err(|e| InvitationError::Other(e.to_string()))?;
        let inv = map.get_mut(&id).ok_or(InvitationError::NotFound)?;

        if inv.mode != InvitationMode::Direct {
            return Err(InvitationError::Other(
                "open is only valid for Direct-mode invitations".into(),
            ));
        }

        let now = Utc::now();
        if now > inv.expires_at {
            inv.status = InvitationStatus::Expired;
            return Err(InvitationError::Expired);
        }

        if inv.status != InvitationStatus::Pending && inv.status != InvitationStatus::Opened {
            return Err(InvitationError::InvalidStatus(inv.status));
        }

        let opened_at = match inv.opened_at {
            Some(t) => t,
            None => {
                let t = now;
                inv.opened_at = Some(t);
                inv.opened_ip = client_ip.map(|s| s.to_string());
                inv.opened_ua = client_ua.map(|s| s.to_string());
                inv.status = InvitationStatus::Opened;
                t
            },
        };

        let window_secs = 300i64;
        let elapsed = (now - opened_at).num_seconds();
        let remaining = window_secs - elapsed;

        if remaining <= 0 {
            inv.status = InvitationStatus::Expired;
            return Err(InvitationError::OpenWindowExpired(remaining));
        }

        Ok(OpenInvitationResult {
            token: token.to_string(),
            group_id: inv.group_id,
            group_name: None,
            invited_by_name: None,
            window_remaining_secs: remaining,
        })
    }

    fn accept(
        &self,
        params: AcceptInvitationParams,
    ) -> Result<(Uuid, String), InvitationError> {
        let id = {
            let idx = self
                .token_index
                .lock()
                .map_err(|e| InvitationError::Other(e.to_string()))?;
            idx.get(&params.token).cloned().ok_or(InvitationError::NotFound)?
        };

        let mut map = self
            .inner
            .lock()
            .map_err(|e| InvitationError::Other(e.to_string()))?;
        let inv = map.get_mut(&id).ok_or(InvitationError::NotFound)?;

        let now = Utc::now();

        match inv.status {
            InvitationStatus::Pending | InvitationStatus::Opened => {},
            InvitationStatus::Accepted => return Err(InvitationError::AlreadyUsed),
            InvitationStatus::Expired => return Err(InvitationError::Expired),
            InvitationStatus::Revoked => return Err(InvitationError::AlreadyUsed),
            InvitationStatus::Exhausted => return Err(InvitationError::AlreadyUsed),
        }

        if now > inv.expires_at {
            inv.status = InvitationStatus::Expired;
            return Err(InvitationError::Expired);
        }

        if inv.mode == InvitationMode::Direct {
            if let Some(opened_at) = inv.opened_at {
                let window_secs = 300i64;
                if (now - opened_at).num_seconds() > window_secs {
                    inv.status = InvitationStatus::Expired;
                    return Err(InvitationError::OpenWindowExpired(0));
                }
            }
            if let (Some(ref stored_ip), Some(ref req_ip)) =
                (&inv.opened_ip, &params.client_ip)
            {
                if stored_ip != req_ip {
                    return Err(InvitationError::IpMismatch);
                }
            }
        }

        inv.use_count += 1;
        if inv.use_count >= inv.max_uses {
            inv.status = InvitationStatus::Accepted;
        }
        inv.accepted_at = Some(now);
        inv.accepted_by = Some(Uuid::new_v4());

        let role = inv.role.clone();
        let group_id = inv.group_id;
        Ok((group_id, role))
    }

    fn find_by_token(&self, token: &str) -> Result<Option<Invitation>, InvitationError> {
        let idx = self
            .token_index
            .lock()
            .map_err(|e| InvitationError::Other(e.to_string()))?;
        let id = match idx.get(token) {
            Some(id) => *id,
            None => return Ok(None),
        };
        let map = self
            .inner
            .lock()
            .map_err(|e| InvitationError::Other(e.to_string()))?;
        Ok(map.get(&id).cloned())
    }

    fn list_by_group(&self, group_id: Uuid) -> Result<Vec<Invitation>, InvitationError> {
        let map = self
            .inner
            .lock()
            .map_err(|e| InvitationError::Other(e.to_string()))?;
        let mut list: Vec<_> = map
            .values()
            .filter(|inv| inv.group_id == group_id)
            .cloned()
            .collect();
        list.sort_by_key(|inv| inv.created_at);
        list.reverse();
        Ok(list)
    }

    fn revoke(&self, token: &str, _revoked_by: Uuid) -> Result<(), InvitationError> {
        let id = {
            let idx = self
                .token_index
                .lock()
                .map_err(|e| InvitationError::Other(e.to_string()))?;
            idx.get(token).cloned().ok_or(InvitationError::NotFound)?
        };
        let mut map = self
            .inner
            .lock()
            .map_err(|e| InvitationError::Other(e.to_string()))?;
        let inv = map.get_mut(&id).ok_or(InvitationError::NotFound)?;
        if inv.status != InvitationStatus::Revoked {
            inv.status = InvitationStatus::Revoked;
        }
        Ok(())
    }

    fn expire_stale(&self) -> Result<u64, InvitationError> {
        let now = Utc::now();
        let mut map = self
            .inner
            .lock()
            .map_err(|e| InvitationError::Other(e.to_string()))?;
        let mut count = 0u64;
        for inv in map.values_mut() {
            if matches!(inv.status, InvitationStatus::Pending | InvitationStatus::Opened)
                && now > inv.expires_at
            {
                inv.status = InvitationStatus::Expired;
                count += 1;
            }
        }
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_params() -> CreateInvitationParams {
        CreateInvitationParams {
            group_id: Uuid::new_v4(),
            mode: InvitationMode::Direct,
            invitee_email: None,
            role: None,
            max_uses: Some(1),
            allow_multi_ip: Some(true),
            ttl_secs: Some(3600),
            open_window_secs: Some(300),
        }
    }

    #[test]
    fn create_and_find() {
        let store = InMemoryInvitationStore::new();
        let inv = store.create(Uuid::new_v4(), make_params()).unwrap();
        assert_eq!(inv.status, InvitationStatus::Pending);
        assert_eq!(inv.token.len(), 64);

        let found = store.find_by_token(&inv.token).unwrap().unwrap();
        assert_eq!(found.id, inv.id);
    }

    #[test]
    fn open_then_accept_direct_mode() {
        let store = InMemoryInvitationStore::new();
        let inv = store.create(Uuid::new_v4(), make_params()).unwrap();

        let opened = store
            .open(&inv.token, Some("10.0.0.1"), Some("test-ua"))
            .unwrap();
        assert!(opened.window_remaining_secs > 0);

        let (group_id, role) = store
            .accept(AcceptInvitationParams {
                token: inv.token.clone(),
                username: "newuser".into(),
                password: "password123".into(),
                email: None,
                client_ip: Some("10.0.0.1".into()),
                client_ua: Some("test-ua".into()),
            })
            .unwrap();
        assert_eq!(group_id, inv.group_id);
        assert_eq!(role, "member");
    }

    #[test]
    fn ip_mismatch_rejected() {
        let store = InMemoryInvitationStore::new();
        let inv = store.create(Uuid::new_v4(), make_params()).unwrap();
        store.open(&inv.token, Some("10.0.0.1"), None).unwrap();

        let err = store
            .accept(AcceptInvitationParams {
                token: inv.token.clone(),
                username: "hacker".into(),
                password: "pw".into(),
                email: None,
                client_ip: Some("10.0.0.99".into()),
                client_ua: None,
            })
            .unwrap_err();
        assert!(matches!(err, InvitationError::IpMismatch));
    }

    #[test]
    fn replay_rejected() {
        let store = InMemoryInvitationStore::new();
        let inv = store.create(Uuid::new_v4(), make_params()).unwrap();
        store.open(&inv.token, None, None).unwrap();

        let p = AcceptInvitationParams {
            token: inv.token.clone(),
            username: "u1".into(),
            password: "pw".into(),
            email: None,
            client_ip: None,
            client_ua: None,
        };
        store.accept(p.clone()).unwrap();
        let err = store.accept(p).unwrap_err();
        assert!(matches!(err, InvitationError::AlreadyUsed));
    }

    #[test]
    fn revoke_and_reject() {
        let store = InMemoryInvitationStore::new();
        let inv = store.create(Uuid::new_v4(), make_params()).unwrap();
        store.revoke(&inv.token, Uuid::new_v4()).unwrap();

        let err = store
            .accept(AcceptInvitationParams {
                token: inv.token.clone(),
                username: "u".into(),
                password: "pw".into(),
                email: None,
                client_ip: None,
                client_ua: None,
            })
            .unwrap_err();
        assert!(matches!(err, InvitationError::AlreadyUsed));
    }
}
