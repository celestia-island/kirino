use uuid::Uuid;

use lacrymira::{Command, Dialect, Reply, Value};
use lacrymira_pg::PgExecutor;

use crate::error::{SessionError, SessionResult};

/// Build a raw PostgreSQL SQL command with bound parameters.
fn sql(text: impl Into<String>, params: Vec<Value>) -> Command {
    Command::Sql {
        dialect: Dialect::Postgres,
        text: text.into(),
        params,
    }
}

/// Affected-row count of a reply (`0` for row-producing replies).
fn affected(reply: &Reply) -> u64 {
    match reply {
        Reply::Affected(n) => *n,
        _ => 0,
    }
}

/// The first row of a row-producing reply (`None` = no rows came back).
fn first_row(reply: &Reply) -> Option<&[Value]> {
    match reply {
        Reply::Rows { rows, .. } => rows.first().map(Vec::as_slice),
        _ => None,
    }
}

/// Decode cell `idx` of a row as a [`Uuid`] (accepts text form too).
fn uuid_at(row: &[Value], idx: usize) -> SessionResult<Uuid> {
    match row.get(idx) {
        Some(Value::Uuid(s)) | Some(Value::Text(s)) => s
            .parse()
            .map_err(|e| SessionError::Other(format!("invalid UUID cell: {e}"))),
        other => Err(SessionError::Other(format!(
            "expected a UUID cell, got {other:?}"
        ))),
    }
}

/// Decode cell `idx` of a row as a `String`.
fn text_at(row: &[Value], idx: usize) -> SessionResult<String> {
    match row.get(idx) {
        Some(Value::Text(s)) => Ok(s.clone()),
        other => Err(SessionError::Other(format!(
            "expected a text cell, got {other:?}"
        ))),
    }
}

/// PostgreSQL-backed session store.
///
/// Requires the `postgres` feature gate (`lacrymira`).
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
    db: PgExecutor,
}

impl SessionStore {
    pub fn new(db: PgExecutor) -> Self {
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
        let cmd = sql(
            r#"INSERT INTO kirino_sessions (id, session_id, user_id, token_hash, created_at, expires_at)
               VALUES ($1, $2, $3, $4, NOW(), $5)"#,
            vec![
                Value::Uuid(Uuid::new_v4().to_string()),
                Value::Uuid((*session_id).to_string()),
                Value::Uuid((*user_id).to_string()),
                Value::Text(token_hash.to_string()),
                Value::Timestamp(expires_at.to_rfc3339()),
            ],
        );
        self.db.execute(&cmd).await.map_err(|e| {
            tracing::warn!(target: "kirino_session::store", error = %e, "session insert failed");
            SessionError::Other("session insert failed".into())
        })?;
        tracing::info!(%session_id, %user_id, "session created");
        Ok(())
    }

    /// Revoke a session by session_id (not the row id).
    pub async fn revoke_session(&self, session_id: &Uuid) -> SessionResult<bool> {
        let cmd = sql(
            "UPDATE kirino_sessions SET revoked_at = NOW() WHERE session_id = $1 AND revoked_at IS NULL",
            vec![Value::Uuid((*session_id).to_string())],
        );
        let reply = self.db.execute(&cmd).await.map_err(|e| {
            tracing::warn!(target: "kirino_session::store", error = %e, "session revoke failed");
            SessionError::Other("session revoke failed".into())
        })?;
        let is_revoked = affected(&reply) > 0;
        if is_revoked {
            tracing::info!(%session_id, "session revoked");
        }
        Ok(is_revoked)
    }

    /// Revoke ALL sessions for a user (e.g. on password change).
    pub async fn revoke_all_for_user(&self, user_id: &Uuid) -> SessionResult<u64> {
        let cmd = sql(
            "UPDATE kirino_sessions SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL",
            vec![Value::Uuid((*user_id).to_string())],
        );
        let reply = self
            .db
            .execute(&cmd)
            .await
            .map_err(|e| {
            tracing::warn!(target: "kirino_session::store", error = %e, "session revoke all failed");
            SessionError::Other("session revoke all failed".into())
        })?;
        let count = affected(&reply);
        tracing::info!(%user_id, count, "all user sessions revoked");
        Ok(count)
    }

    /// Check whether a session is still valid (exists, not revoked, not expired).
    pub async fn is_session_valid(&self, session_id: &Uuid) -> SessionResult<bool> {
        let cmd = sql(
            "SELECT 1 FROM kirino_sessions
             WHERE session_id = $1
               AND revoked_at IS NULL
               AND expires_at > NOW()",
            vec![Value::Uuid((*session_id).to_string())],
        );
        let reply = self.db.execute(&cmd).await.map_err(|e| {
            tracing::warn!(target: "kirino_session::store", error = %e, "session check failed");
            SessionError::Other("session check failed".into())
        })?;
        Ok(first_row(&reply).is_some())
    }

    /// Look up a session's user_id and token_hash by session_id.
    pub async fn find_session(&self, session_id: &Uuid) -> SessionResult<Option<(Uuid, String)>> {
        let cmd = sql(
            "SELECT user_id, token_hash FROM kirino_sessions
             WHERE session_id = $1
               AND revoked_at IS NULL
               AND expires_at > NOW()",
            vec![Value::Uuid((*session_id).to_string())],
        );
        let reply = self.db.execute(&cmd).await.map_err(|e| {
            tracing::warn!(target: "kirino_session::store", error = %e, "session find failed");
            SessionError::Other("session find failed".into())
        })?;
        match first_row(&reply) {
            Some(row) => {
                let uid: Uuid = uuid_at(row, 0).map_err(|e| {
            tracing::warn!(target: "kirino_session::store", error = %e, "get user_id failed");
            SessionError::Other("get user_id failed".into())
        })?;
                let hash: String = text_at(row, 1).map_err(|e| {
            tracing::warn!(target: "kirino_session::store", error = %e, "get token_hash failed");
            SessionError::Other("get token_hash failed".into())
        })?;
                Ok(Some((uid, hash)))
            }
            None => Ok(None),
        }
    }

    /// Prune sessions that expired more than `older_than` ago.
    /// Returns the number of deleted rows.
    pub async fn prune_expired(&self, older_than: chrono::Duration) -> SessionResult<u64> {
        let cutoff = chrono::Utc::now() - older_than;
        let cmd = sql(
            "DELETE FROM kirino_sessions WHERE expires_at < $1",
            vec![Value::Timestamp(cutoff.to_rfc3339())],
        );
        let reply = self.db.execute(&cmd).await.map_err(|e| {
            tracing::warn!(target: "kirino_session::store", error = %e, "session prune failed");
            SessionError::Other("session prune failed".into())
        })?;
        let count = affected(&reply);
        if count > 0 {
            tracing::info!(count, "expired sessions pruned");
        }
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn session_store_new_does_not_require_db() {
        // Compile-time test: the type constructors are available.
        // Runtime tests need a real PG instance (see integration tests).
    }
}
