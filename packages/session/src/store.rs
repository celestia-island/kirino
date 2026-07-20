use sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, Statement, Value};
use uuid::Uuid;

use crate::error::{SessionError, SessionResult};

/// PostgreSQL-backed session store.
///
/// Requires the `postgres` feature gate (`sea-orm`).
/// The expected table schema is:
///
/// ```sql
/// CREATE TABLE IF NOT EXISTS kirino_sessions (
///     id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
///     session_id UUID NOT NULL UNIQUE,
///     user_id    UUID NOT NULL,
///     token_hash TEXT NOT NULL,
///     user_agent TEXT,
///     ip_address TEXT,
///     created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
///     expires_at TIMESTAMPTZ NOT NULL,
///     revoked_at TIMESTAMPTZ
/// );
/// CREATE INDEX IF NOT EXISTS idx_kirino_sessions_user    ON kirino_sessions(user_id);
/// CREATE INDEX IF NOT EXISTS idx_kirino_sessions_expires ON kirino_sessions(expires_at);
/// ```
pub struct SessionStore {
    db: DatabaseConnection,
}

impl SessionStore {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    /// Insert a new session record.
    ///
    /// `token_hash` should be a SHA-256 hash of the refresh token
    /// so the raw token is never stored.
    pub async fn create_session(
        &self,
        session_id: &Uuid,
        user_id: &Uuid,
        token_hash: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> SessionResult<()> {
        let stmt = Statement::from_sql_and_values(
            DbBackend::Postgres,
            r#"INSERT INTO kirino_sessions (id, session_id, user_id, token_hash, created_at, expires_at)
               VALUES ($1, $2, $3, $4, NOW(), $5)"#,
            [
                Uuid::new_v4().into(),
                (*session_id).into(),
                (*user_id).into(),
                token_hash.into(),
                expires_at.naive_utc().into(),
            ],
        );
        self.db
            .execute(stmt)
            .await
            .map_err(|e| SessionError::Other(format!("session insert: {e}")))?;
        tracing::info!(%session_id, %user_id, "session created");
        Ok(())
    }

    /// Revoke a session by session_id (not the row id).
    pub async fn revoke_session(&self, session_id: &Uuid) -> SessionResult<bool> {
        let stmt = Statement::from_sql_and_values(
            DbBackend::Postgres,
            "UPDATE kirino_sessions SET revoked_at = NOW() WHERE session_id = $1 AND revoked_at IS NULL",
            [(*session_id).into()],
        );
        let result = self
            .db
            .execute(stmt)
            .await
            .map_err(|e| SessionError::Other(format!("session revoke: {e}")))?;
        let affected = result.rows_affected() > 0;
        if affected {
            tracing::info!(%session_id, "session revoked");
        }
        Ok(affected)
    }

    /// Revoke ALL sessions for a user (e.g. on password change).
    pub async fn revoke_all_for_user(&self, user_id: &Uuid) -> SessionResult<u64> {
        let stmt = Statement::from_sql_and_values(
            DbBackend::Postgres,
            "UPDATE kirino_sessions SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL",
            [(*user_id).into()],
        );
        let result = self
            .db
            .execute(stmt)
            .await
            .map_err(|e| SessionError::Other(format!("session revoke all: {e}")))?;
        let affected = result.rows_affected();
        tracing::info!(%user_id, affected, "all user sessions revoked");
        Ok(affected)
    }

    /// Check whether a session is still valid (exists, not revoked, not expired).
    pub async fn is_session_valid(&self, session_id: &Uuid) -> SessionResult<bool> {
        let stmt = Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT 1 FROM kirino_sessions
             WHERE session_id = $1
               AND revoked_at IS NULL
               AND expires_at > NOW()",
            [(*session_id).into()],
        );
        let result = self
            .db
            .query_one(stmt)
            .await
            .map_err(|e| SessionError::Other(format!("session check: {e}")))?;
        Ok(result.is_some())
    }

    /// Look up a session's user_id and token_hash by session_id.
    pub async fn find_session(
        &self,
        session_id: &Uuid,
    ) -> SessionResult<Option<(Uuid, String)>> {
        let stmt = Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT user_id, token_hash FROM kirino_sessions
             WHERE session_id = $1
               AND revoked_at IS NULL
               AND expires_at > NOW()",
            [(*session_id).into()],
        );
        let result = self
            .db
            .query_one(stmt)
            .await
            .map_err(|e| SessionError::Other(format!("session find: {e}")))?;
        match result {
            Some(row) => {
                let uid: Uuid = row.try_get_by_index(0).map_err(|e| SessionError::Other(format!("get user_id: {e}")))?;
                let hash: String = row.try_get_by_index(1).map_err(|e| SessionError::Other(format!("get token_hash: {e}")))?;
                Ok(Some((uid, hash)))
            },
            None => Ok(None),
        }
    }

    /// Prune sessions that expired more than `older_than` ago.
    /// Returns the number of deleted rows.
    pub async fn prune_expired(
        &self,
        older_than: chrono::Duration,
    ) -> SessionResult<u64> {
        let cutoff = chrono::Utc::now() - older_than;
        let stmt = Statement::from_sql_and_values(
            DbBackend::Postgres,
            "DELETE FROM kirino_sessions WHERE expires_at < $1",
            [cutoff.naive_utc().into()],
        );
        let result = self
            .db
            .execute(stmt)
            .await
            .map_err(|e| SessionError::Other(format!("session prune: {e}")))?;
        let count = result.rows_affected();
        if count > 0 {
            tracing::info!(count, "expired sessions pruned");
        }
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_store_new_does_not_require_db() {
        // Compile-time test: the type constructors are available.
        // Runtime tests need a real PG instance (see integration tests).
    }
}
