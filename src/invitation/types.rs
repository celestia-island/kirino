use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Invitation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvitationMode {
    /// Admin sends form, invitee applies, admin approves.
    Approval,
    /// Admin generates a unique link, invitee registers directly.
    Direct,
}

/// Invitation lifecycle status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvitationStatus {
    /// Created but not yet opened or used.
    Pending,
    /// Link has been opened (Direct mode only), 5-min clock running.
    Opened,
    /// Successfully accepted.
    Accepted,
    /// Past expiry, never used.
    Expired,
    /// Explicitly revoked by admin.
    Revoked,
    /// Fully consumed (max_uses reached for multi-use).
    Exhausted,
}

impl InvitationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Opened => "opened",
            Self::Accepted => "accepted",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
            Self::Exhausted => "exhausted",
        }
    }
}

impl std::fmt::Display for InvitationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An invitation record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invitation {
    pub id: Uuid,
    /// 256-bit hex token, URL-safe.
    pub token: String,
    /// Target group the invitee joins on acceptance.
    pub group_id: Uuid,
    /// Admin who created the invitation.
    pub invited_by: Uuid,
    pub mode: InvitationMode,
    /// Optional email for Approval mode.
    pub invitee_email: Option<String>,
    /// Role assigned on join.
    pub role: String,
    /// Maximum number of redemptions (1 = single-use).
    pub max_uses: u16,
    /// Current redemption count.
    pub use_count: u16,
    /// Whether the same IP/machine may use multiple different links.
    pub allow_multi_ip: bool,
    pub status: InvitationStatus,
    /// When the link was first opened (Direct mode).
    pub opened_at: Option<DateTime<Utc>>,
    /// IP that first opened the link.
    pub opened_ip: Option<String>,
    /// User-Agent that first opened the link.
    pub opened_ua: Option<String>,
    /// Absolute expiry timestamp.
    pub expires_at: DateTime<Utc>,
    /// When the invitation was accepted.
    pub accepted_at: Option<DateTime<Utc>>,
    /// User ID that accepted.
    pub accepted_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

/// Parameters for creating an invitation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateInvitationParams {
    pub group_id: Uuid,
    pub mode: InvitationMode,
    pub invitee_email: Option<String>,
    pub role: Option<String>,
    pub max_uses: Option<u16>,
    pub allow_multi_ip: Option<bool>,
    /// Lifetime in seconds from creation. Default: 604800 (7 days).
    pub ttl_secs: Option<u64>,
    /// Direct-mode window in seconds from first open. Default: 300 (5 min).
    pub open_window_secs: Option<u64>,
}

/// Parameters for accepting an invitation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcceptInvitationParams {
    pub token: String,
    pub username: String,
    pub password: String,
    pub email: Option<String>,
    /// Client IP for binding checks.
    pub client_ip: Option<String>,
    /// Client User-Agent for binding checks.
    pub client_ua: Option<String>,
}

/// Result of opening an invitation link (Direct-mode pre-registration).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenInvitationResult {
    pub token: String,
    pub group_id: Uuid,
    pub group_name: Option<String>,
    pub invited_by_name: Option<String>,
    /// Seconds remaining in the open window.
    pub window_remaining_secs: i64,
}
