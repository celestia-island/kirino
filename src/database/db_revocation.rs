//! DB-backed JWT revocation store (audit kirino-R1-SESS-4).
//!
//! The process-local [`MemoryRevocationBackend`] gives single-replica
//! semantics: a revocation issued on one replica is invisible to the
//! others, so a "logged out everywhere" flow leaves tokens live on every
//! replica but the one that handled the logout. This store shares the
//! `jwt_revocations` table across replicas — same schema contract as
//! `DbSessionStore` (hosts run the DDL; this crate has no migration
//! tooling).

use anyhow::Result;

use lacrymira::Value;
use lacrymira_pg::PgExecutor;

use crate::{auth::credential::RevocationBackend, database::raw};

/// DB-backed revocation backend. Every replica points at the same
/// database and revocations propagate on the next read.
#[derive(Debug, Clone)]
pub struct DbRevocationStore {
    conn: PgExecutor,
}

impl DbRevocationStore {
    pub fn new(conn: PgExecutor) -> Self {
        Self { conn }
    }

    /// Creates the `jwt_revocations` table if it does not exist. The DDL
    /// is emitted directly, mirroring the `DbSessionStore` convention.
    pub async fn ensure_schema(&self) -> Result<()> {
        self.conn
            .execute(&raw::sql(
                "CREATE TABLE IF NOT EXISTS jwt_revocations ( \
                    key TEXT PRIMARY KEY, \
                    not_before BIGINT NOT NULL, \
                    revoked_at TIMESTAMPTZ NOT NULL DEFAULT NOW() \
                )",
                Vec::new(),
            ))
            .await?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl RevocationBackend for DbRevocationStore {
    async fn revoke(&self, key: &str, not_before: i64) {
        let cmd = raw::sql(
            "INSERT INTO jwt_revocations (key, not_before) VALUES ($1, $2) \
             ON CONFLICT (key) DO UPDATE SET not_before = GREATEST(jwt_revocations.not_before, $2)",
            vec![Value::Text(key.to_string()), Value::I64(not_before)],
        );
        if let Err(e) = self.conn.execute(&cmd).await {
            tracing::error!(key, error = %e, "DB revocation write failed");
        }
    }

    async fn get_not_before(&self, key: &str) -> Option<i64> {
        let cmd = raw::sql(
            "SELECT not_before FROM jwt_revocations WHERE key = $1",
            vec![Value::Text(key.to_string())],
        );
        match self.conn.execute(&cmd).await {
            Ok(reply) => raw::first_row(&reply)
                .and_then(|(columns, row)| raw::cell(columns, row, "not_before").ok())
                .and_then(|v| raw::as_i64(v).ok()),
            Err(e) => {
                // R2 review: with this backend installed there is NO
                // memory layer behind it — a failed read means the
                // revocation check is blind for this key until the DB
                // recovers. Surfaced at error so the operator sees the
                // coverage gap in the trace.
                tracing::error!(key, error = %e, "DB revocation read failed; revocation check is blind for this key");
                None
            }
        }
    }

    async fn cleanup_before(&self, cutoff: i64) {
        // R2 review: entries with not_before >= cutoff are still LIVE
        // (they revoke tokens issued after the cutoff) — only STRICTLY
        // OLDER entries can never match again and are safe to delete.
        let cmd = raw::sql(
            "DELETE FROM jwt_revocations WHERE not_before < $1",
            vec![Value::I64(cutoff)],
        );
        if let Err(e) = self.conn.execute(&cmd).await {
            tracing::error!(error = %e, "DB revocation cleanup failed");
        }
    }
}
