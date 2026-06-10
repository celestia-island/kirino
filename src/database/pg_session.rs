use anyhow::Result;
use async_trait::async_trait;
use sea_orm::{ConnectionTrait, DatabaseConnection, Statement};
use uuid::Uuid;

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
        Ok(())
    }

    async fn load_session(&self, id: Uuid) -> Result<Option<SessionRow>> {
        let stmt = Statement::from_sql_and_values(
            self.conn.get_database_backend(),
            "SELECT id, subject_id, active_roles, context, expires_at, created_at FROM rbac_sessions WHERE id = $1",
            [id.to_string().into()],
        );
        if let Some(row) = self.conn.query_one(stmt).await? {
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
