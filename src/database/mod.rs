pub mod memory;

#[cfg(feature = "rbac-db-session")]
pub mod db_session;

/// Audit kirino-R1-SESS-4: DB-backed revocation backend (feature
/// `rbac-db-session`).
#[cfg(feature = "rbac-db-session")]
pub mod db_revocation;
