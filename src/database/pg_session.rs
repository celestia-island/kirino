use anyhow::Result;
use async_trait::async_trait;
use sea_orm::{ConnectionTrait, DatabaseConnection, Statement};
use uuid::Uuid;
use uuid::Uuid;

use async_trait::async_trait;
use sea_orm::{ConnectionTrait, DatabaseConnection, Statement};

use crate::rbac::store::persistence::{PersistentSessionStore, SessionRow};

#[derive(Debug, Clone)]
pub struct PgSessionStore {
    conn: DatabaseConnection,
}

impl PgSessionStore {
    pub fn new(conn: DatabaseConnection) -> Self {
        Self { conn }
    }
}

#[async_trait]
impl PersistentSessionStore for PgSessionStore {
    async fn save_session(&self, row: &SessionRow) -> Result<()> {
        let roles_json = serde_json::to_string(&row.active_roles)?;
        let context_str = row
            .context
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;
        let stmt = Statement::from_sql_and_values(
            self.conn.get_database_backend(),
            "INSERT INTO rbac_sessions (id, subject_id, active_roles, context, expires_at, created_at, updated_at) VALUES ($1, $2, $3::jsonb, $4::jsonb, $5, $6, NOW())",
            [
                row.id.to_string().into(),
                row.subject_id.as_str().into(),
                roles_json.into(),
                context_str.into(),
                row.expires_at.to_rfc3339().into(),
                row.created_at.to_rfc3339().into(),
            ],
        );
        self.conn.execute(stmt).await?;

        self.conn.execute_raw(stmt).await?;

        Ok(())
    }

    async fn load_session(&self, id: Uuid) -> Result<Option<SessionRow>> {
        let stmt = Statement::from_sql_and_values(
            self.conn.get_database_backend(),
            "SELECT id, subject_id, active_roles, context, expires_at, created_at FROM rbac_sessions WHERE id = $1",
            [id.to_string().into()],
        );
        if let Some(row) = self.conn.query_one(stmt).await? {

        if let Some(row) = self.conn.query_one_raw(stmt).await? {

            let active_roles: Vec<String> = {
                let raw: String = row.try_get("rbac_sessions", "active_roles")?;
                serde_json::from_str(&raw).map_err(|e| {
                    anyhow::anyhow!("corrupted active_roles JSON for session {}: {e}", id)
                })?
            };
            let context: Option<serde_json::Value> = match row
                .try_get::<Option<String>>("rbac_sessions", "context")
            {
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
            let context: Option<serde_json::Value> =
                match row.try_get::<Option<String>>("rbac_sessions", "context") {
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

            let expires_at_str = row.try_get::<String>("rbac_sessions", "expires_at")?;
            let expires_at =
                chrono::DateTime::parse_from_rfc3339(&expires_at_str)?.with_timezone(&chrono::Utc);
            let created_at_str = row.try_get::<String>("rbac_sessions", "created_at")?;
            let created_at =
                chrono::DateTime::parse_from_rfc3339(&created_at_str)?.with_timezone(&chrono::Utc);
            let subject_id = row.try_get::<String>("rbac_sessions", "subject_id")?;
            Ok(Some(SessionRow {
                id,
                subject_id,
                active_roles,
                context,
                expires_at,
                created_at,
            }))
        } else {
            Ok(None)
        }
    }

    async fn delete_session(&self, id: Uuid) -> Result<()> {
        let stmt = Statement::from_sql_and_values(
            self.conn.get_database_backend(),
            "DELETE FROM rbac_sessions WHERE id = $1",
            [id.to_string().into()],
        );
        self.conn.execute(stmt).await?;

        self.conn.execute_raw(stmt).await?;

        Ok(())
    }

    async fn update_roles(&self, id: Uuid, active_roles: &[String]) -> Result<()> {
        let roles_json = serde_json::to_string(active_roles)?;
        let stmt = Statement::from_sql_and_values(
            self.conn.get_database_backend(),
            "UPDATE rbac_sessions SET active_roles = $1::jsonb, updated_at = NOW() WHERE id = $2",
            [roles_json.into(), id.to_string().into()],
        );
        let result = self.conn.execute(stmt).await?;

        let result = self.conn.execute_raw(stmt).await?;

        if result.rows_affected() == 0 {
            return Err(anyhow::anyhow!("session {} not found", id));
        }
        Ok(())
    }

    async fn cleanup_expired(&self) -> Result<usize> {
        let stmt = Statement::from_string(
            self.conn.get_database_backend(),
            "DELETE FROM rbac_sessions WHERE expires_at < NOW()",
        );
        let result = self.conn.execute(stmt).await?;
        Ok(result.rows_affected() as usize)
    }
}
        let result = self.conn.execute_raw(stmt).await?;
        Ok(result.rows_affected() as usize)
    }
}

#[cfg(test)]
mod tests {
    //! PostgreSQL integration tests for [`PgSessionStore`].
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

    use sea_orm::{ConnectionTrait, Database, DatabaseConnection, Statement};
    use uuid::Uuid;

    use super::PgSessionStore;
    use crate::rbac::store::persistence::{PersistentSessionStore, SessionRow};

    /// Default connection string used when `DATABASE_URL` is unset. Matches the
    /// `docker-compose.yml` and CI service container defaults.
    const DEFAULT_DATABASE_URL: &str = "postgres://kirino:kirino@localhost:5432/kirino_test";

    async fn connect() -> DatabaseConnection {
        let url = env::var("DATABASE_URL").unwrap_or_else(|_| DEFAULT_DATABASE_URL.to_string());
        Database::connect(url.as_str())
            .await
            .unwrap_or_else(|e| panic!("failed to connect to PostgreSQL at {url}: {e}"))
    }

    /// Creates the `rbac_sessions` table if it does not exist, and truncates it
    /// so each test starts from a clean slate. The DDL mirrors the queries in
    /// `PgSessionStore` and is emitted directly (no sea-orm entity) so the tests
    /// stay independent of any migration tooling the host application might use.
    async fn setup_schema(conn: &DatabaseConnection) {
        // Build the CREATE TABLE from the model. `Schema::create_table_from_entity`
        // is not available because there is no sea-orm entity here, so emit the
        // DDL directly to stay aligned with the queries in `PgSessionStore`.
        let backend = conn.get_database_backend();
        conn.execute_raw(Statement::from_string(
            backend,
            "CREATE TABLE IF NOT EXISTS rbac_sessions ( \
                id UUID PRIMARY KEY, \
                subject_id TEXT NOT NULL, \
                active_roles JSONB NOT NULL, \
                context JSONB, \
                expires_at TIMESTAMPTZ NOT NULL, \
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), \
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW() \
            )",
        ))
        .await
        .expect("create rbac_sessions table");
        conn.execute_raw(Statement::from_string(
            backend,
            "TRUNCATE TABLE rbac_sessions",
        ))
        .await
        .expect("truncate rbac_sessions table");
    }

    fn sample_row(id: Uuid) -> SessionRow {
        SessionRow {
            id,
            subject_id: "subject-1".to_string(),
            active_roles: vec!["admin".to_string(), "viewer".to_string()],
            context: Some(serde_json::json!({"ip": "10.0.0.1"})),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            created_at: chrono::Utc::now(),
        }
    }

    #[tokio::test]
    #[ignore = "requires a live PostgreSQL instance (see module docs)"]
    async fn pg_save_and_load_session_roundtrip() {
        let conn = connect().await;
        setup_schema(&conn).await;

        let store = PgSessionStore::new(conn);
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

        let store = PgSessionStore::new(conn);
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

        let store = PgSessionStore::new(conn);
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

        let store = PgSessionStore::new(conn);
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

        let store = PgSessionStore::new(conn);
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

        let store = PgSessionStore::new(conn);
        let now = chrono::Utc::now();

        // expired
        let expired = SessionRow {
            id: Uuid::now_v7(),
            subject_id: "expired".to_string(),
            active_roles: vec![],
            context: None,
            expires_at: now - chrono::Duration::minutes(5),
            created_at: now - chrono::Duration::hours(1),
        };
        // still valid
        let valid = SessionRow {
            id: Uuid::now_v7(),
            subject_id: "valid".to_string(),
            active_roles: vec![],
            context: None,
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

