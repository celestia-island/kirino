pub mod memory;

#[cfg(feature = "rbac-db-session")]
pub mod db_session;

/// Audit kirino-R1-SESS-4: DB-backed revocation backend (feature
/// `rbac-db-session`).
#[cfg(feature = "rbac-db-session")]
pub mod db_revocation;

/// Audit perfsec PS-TOTP: DB-backed TOTP replay guard over the shared
/// `mfa_factors` table (feature `rbac-db-session`).
#[cfg(feature = "rbac-db-session")]
pub mod db_totp_replay;
