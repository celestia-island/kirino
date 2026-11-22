use anyhow::Result;
use uuid::Uuid;

use async_trait::async_trait;
use lacrymira::Value;
use lacrymira_pg::PgExecutor;

use crate::{
    database::raw,
    rbac::store::persistence::{PersistentSessionStore, SessionRow},
};

#[derive(Debug, Clone)]
pub struct DbSessionStore {
    conn: PgExecutor,
}

impl DbSessionStore {
    pub fn new(conn: PgExecutor) -> Self {
        Self { conn }
    }
}

#[async_trait]
impl PersistentSessionStore for DbSessionStore {
    async fn save_session(&self, row: &SessionRow) -> Result<()> {
        let roles_json = serde_json::to_string(&row.active_roles)?;
        let context_str = row
            .context
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;
        let cmd = raw::sql(
            "INSERT INTO rbac_sessions (id, subject_id, active_roles, context, expires_at, created_at) VALUES ($1, $2, $3::jsonb, $4::jsonb, $5, $6, NOW())",
            vec![
                Value::Uuid(row.id.to_string()),
                Value::Text(row.subject_id.clone()),
                Value::Text(roles_json),
                context_str.map_or(Value::Null, Value::Text),
                Value::Timestamp(row.expires_at.to_rfc3339()),
                Value::Timestamp(row.created_at.to_rfc3339()),
            ],
        );
        self.conn.execute(&cmd).await?;

        Ok(())
    }

    async fn load_session(&self, id: Uuid) -> Result<Option<SessionRow>> {
        let cmd = raw::sql(
            "SELECT id, subject_id, active_roles, context, expires_at, created_at FROM rbac_sessions WHERE id = $1",
            vec![Value::Uuid(id.to_string())],
        );
        if let Some((columns, row)) = raw::first_row(&self.conn.execute(&cmd).await?) {
            let active_roles: Vec<String> = {
                let raw_json = raw::as_text(raw::cell(columns, row, "active_roles")?)?;
                serde_json::from_str(&raw_json).map_err(|e| {
                    anyhow::anyhow!("corrupted active_roles JSON for session {}: {e}", id)
                })?
            };
            let context: Option<serde_json::Value> =
                match raw::as_opt_text(raw::cell(columns, row, "context")?) {
                    Ok(Some(s)) => Some(serde_json::from_str(&s).map_err(|e| {
                        anyhow::anyhow!("corrupted context JSON for session {}: {e}", id)
                    })?),
                    Ok(None) => None,
                    Err(e) => {
                        tracing::warn!(target: "kirino::database::pg_session",
                        "failed to read context for session {}: {e}", id);
                        None
                    }
                };
            let expires_at_str = raw::as_text(raw::cell(columns, row, "expires_at")?)?;
            let expires_at =
                chrono::DateTime::parse_from_rfc3339(&expires_at_str)?.with_timezone(&chrono::Utc);
            let created_at_str = raw::as_text(raw::cell(columns, row, "created_at")?)?;
            let created_at =
                chrono::DateTime::parse_from_rfc3339(&created_at_str)?.with_timezone(&chrono::Utc);
            let subject_id = raw::as_text(raw::cell(columns, row, "subject_id")?)?;
            Ok(Some(SessionRow {
                id,
                subject_id,
                active_roles,
                context,
                version: 0,
                expires_at,
                created_at,
            }))
        } else {
            Ok(None)
        }
    }

    async fn delete_session(&self, id: Uuid) -> Result<()> {
        let cmd = raw::sql(
            "DELETE FROM rbac_sessions WHERE id = $1",
            vec![Value::Uuid(id.to_string())],
        );
        self.conn.execute(&cmd).await?;

        Ok(())
    }

    async fn update_roles(&self, id: Uuid, active_roles: &[String]) -> Result<()> {
        let roles_json = serde_json::to_string(active_roles)?;
        let cmd = raw::sql(
            "UPDATE rbac_sessions SET active_roles = $1::jsonb, updated_at = NOW() WHERE id = $2",
            vec![Value::Text(roles_json), Value::Uuid(id.to_string())],
        );
        if raw::affected(&self.conn.execute(&cmd).await?) == 0 {
            return Err(anyhow::anyhow!("session {} not found", id));
        }
        Ok(())
    }

    async fn cleanup_expired(&self) -> Result<usize> {
        let cmd = raw::sql(
            "DELETE FROM rbac_sessions WHERE expires_at < NOW()",
            Vec::new(),
        );
        let n = raw::affected(&self.conn.execute(&cmd).await?);
        Ok(n as usize)
    }

    async fn load_session_metadata(&self, subject_id: &str) -> Result<Option<SessionRow>> {
        let cmd = raw::sql(
            "SELECT id, subject_id, active_roles, context, version, expires_at, created_at FROM rbac_sessions WHERE subject_id = $1 ORDER BY created_at DESC LIMIT 1",
            vec![Value::Text(subject_id.to_string())],
        );
        if let Some((columns, row)) = raw::first_row(&self.conn.execute(&cmd).await?) {
            let version: i64 = raw::as_i64(raw::cell(columns, row, "version")?)?;
            Ok(Some(SessionRow {
                id: raw::as_uuid(raw::cell(columns, row, "id")?)?,
                subject_id: raw::as_text(raw::cell(columns, row, "subject_id")?)?,
                active_roles: serde_json::from_str(&raw::as_text(raw::cell(
                    columns,
                    row,
                    "active_roles",
                )?)?)?,
                context: raw::as_opt_text(raw::cell(columns, row, "context")?)?
                    .map(|s| serde_json::from_str(&s))
                    .transpose()?,
                version: version as u64,
                expires_at: chrono::DateTime::parse_from_rfc3339(&raw::as_text(raw::cell(
                    columns,
                    row,
                    "expires_at",
                )?)?)?
                .with_timezone(&chrono::Utc),
                created_at: chrono::DateTime::parse_from_rfc3339(&raw::as_text(raw::cell(
                    columns,
                    row,
                    "created_at",
                )?)?)?
                .with_timezone(&chrono::Utc),
            }))
        } else {
            Ok(None)
        }
    }

    async fn bump_version(&self, subject_id: &str, version: u64) -> Result<()> {
        let cmd = raw::sql(
            "UPDATE rbac_sessions SET version = $1 WHERE subject_id = $2",
            vec![
                Value::I64(version as i64),
                Value::Text(subject_id.to_string()),
            ],
        );
        self.conn.execute(&cmd).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    //! PostgreSQL integration tests for [`DbSessionStore`].
    //!
    //! These require a live PostgreSQL instance. They are `#[ignore]`'d so the
    //! normal `cargo test` run does not need a database. Run them explicitly:
    //!
    //! ```text
    //! docker compose up -d
    //! export DATABASE_URL=postgres://kirino:kirino@localhost:5432/kirino_test
    //! cargo test --lib --features rbac-pg-session -- --ignored pg_session
    //! ```
    //!
    //! On CI they run in the `pg-integration` job (see
    //! `.github/workflows/checks.yml`), which provisions a `postgres:16`
    //! service container with `DATABASE_URL` set accordingly.

    use std::env;

    use uuid::Uuid;

    use lacrymira_pg::PgExecutor;

    use super::DbSessionStore;
    use crate::database::raw;
    use crate::rbac::store::persistence::{PersistentSessionStore, SessionRow};

    /// Default connection string used when `DATABASE_URL` is unset. Matches the
    /// `docker-compose.yml` and CI service container defaults.
    const DEFAULT_DATABASE_URL: &str = "postgres://kirino:kirino@localhost:5432/kirino_test";

    async fn connect() -> PgExecutor {
        let url = env::var("DATABASE_URL").unwrap_or_else(|_| DEFAULT_DATABASE_URL.to_string());
        PgExecutor::connect(&url)
            .await
            .unwrap_or_else(|e| panic!("failed to connect to PostgreSQL at {url}: {e}"))
    }

    /// Creates the `rbac_sessions` table if it does not exist, and truncates it
    /// so each test starts from a clean slate. The DDL mirrors the queries in
    /// `DbSessionStore` and is emitted directly (no ORM entity) so the tests
    /// stay independent of any migration tooling the host application might use.
    async fn setup_schema(conn: &PgExecutor) {
        // Build the CREATE TABLE from the model. No ORM entity exists here, so
        // the DDL is emitted directly to stay aligned with the queries in
        // `DbSessionStore`.
        conn.execute(&raw::sql(
            "CREATE TABLE IF NOT EXISTS rbac_sessions ( \
                id UUID PRIMARY KEY, \
                subject_id TEXT NOT NULL, \
                active_roles JSONB NOT NULL, \
                context JSONB, \
                expires_at TIMESTAMPTZ NOT NULL, \
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), \
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW() \
            )",
            Vec::new(),
        ))
        .await
        .expect("create rbac_sessions table");
        conn.execute(&raw::sql("TRUNCATE TABLE rbac_sessions", Vec::new()))
            .await
            .expect("truncate rbac_sessions table");
    }

    fn sample_row(id: Uuid) -> SessionRow {
        SessionRow {
            id,
            subject_id: "subject-1".to_string(),
            active_roles: vec!["admin".to_string(), "viewer".to_string()],
            context: Some(serde_json::json!({"ip": "10.0.0.1"})),
            version: 0,
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            created_at: chrono::Utc::now(),
        }
    }

    #[tokio::test]
    #[ignore = "requires a live PostgreSQL instance (see module docs)"]
    async fn pg_save_and_load_session_roundtrip() {
        let conn = connect().await;
        setup_schema(&conn).await;

        let store = DbSessionStore::new(conn);
        let id = Uuid::now_v7();
        let row = sample_row(id);

        store.save_session(&row).await.expect("save_session");

        let loaded = store
            .load_session(id)
            .await
            .expect("load_session")
            .expect("session should exist");
        assert_eq!(loaded.id, row.id);
        assert_eq!(loaded.subject_id, row.subject_id);
        assert_eq!(loaded.active_roles, row.active_roles);
        assert_eq!(loaded.context, row.context);
    }

    #[tokio::test]
    #[ignore = "requires a live PostgreSQL instance (see module docs)"]
    async fn pg_load_missing_session_returns_none() {
        let conn = connect().await;
        setup_schema(&conn).await;

        let store = DbSessionStore::new(conn);
        let loaded = store
            .load_session(Uuid::now_v7())
            .await
            .expect("load_session");
        assert!(loaded.is_none(), "missing session must resolve to None");
    }

    #[tokio::test]
    #[ignore = "requires a live PostgreSQL instance (see module docs)"]
    async fn pg_delete_session_removes_it() {
        let conn = connect().await;
        setup_schema(&conn).await;

        let store = DbSessionStore::new(conn);
        let id = Uuid::now_v7();
        store
            .save_session(&sample_row(id))
            .await
            .expect("save_session");
        assert!(store.load_session(id).await.unwrap().is_some());

        store.delete_session(id).await.expect("delete_session");
        assert!(
            store.load_session(id).await.unwrap().is_none(),
            "session must be gone after delete"
        );
    }

    #[tokio::test]
    #[ignore = "requires a live PostgreSQL instance (see module docs)"]
    async fn pg_update_roles_persists_change() {
        let conn = connect().await;
        setup_schema(&conn).await;

        let store = DbSessionStore::new(conn);
        let id = Uuid::now_v7();
        store
            .save_session(&sample_row(id))
            .await
            .expect("save_session");

        let new_roles = vec!["operator".to_string()];
        store
            .update_roles(id, &new_roles)
            .await
            .expect("update_roles");

        let loaded = store.load_session(id).await.unwrap().unwrap();
        assert_eq!(loaded.active_roles, new_roles);
    }

    #[tokio::test]
    #[ignore = "requires a live PostgreSQL instance (see module docs)"]
    async fn pg_update_roles_missing_session_errors() {
        let conn = connect().await;
        setup_schema(&conn).await;

        let store = DbSessionStore::new(conn);
        let result = store.update_roles(Uuid::now_v7(), &["x".to_string()]).await;
        assert!(
            result.is_err(),
            "updating roles on a missing session must error (fail-closed)"
        );
    }

    #[tokio::test]
    #[ignore = "requires a live PostgreSQL instance (see module docs)"]
    async fn pg_cleanup_expired_removes_only_expired() {
        let conn = connect().await;
        setup_schema(&conn).await;

        let store = DbSessionStore::new(conn);
        let now = chrono::Utc::now();

        // expired
        let expired = SessionRow {
            id: Uuid::now_v7(),
            subject_id: "expired".to_string(),
            active_roles: vec![],
            context: None,
            version: 0,
            expires_at: now - chrono::Duration::minutes(5),
            created_at: now - chrono::Duration::hours(1),
        };
        // still valid
        let valid = SessionRow {
            id: Uuid::now_v7(),
            subject_id: "valid".to_string(),
            active_roles: vec![],
            context: None,
            version: 0,
            expires_at: now + chrono::Duration::hours(1),
            created_at: now,
        };
        store.save_session(&expired).await.unwrap();
        store.save_session(&valid).await.unwrap();

        let removed = store.cleanup_expired().await.expect("cleanup_expired");
        assert_eq!(removed, 1, "exactly one expired session should be removed");
        assert!(store.load_session(valid.id).await.unwrap().is_some());
        assert!(store.load_session(expired.id).await.unwrap().is_none());
    }
}
