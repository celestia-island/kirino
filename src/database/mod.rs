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

/// Shared glue for the raw-SQL stores (feature `rbac-db-session`): builds
/// lacrymira `Command::Sql` values and reads typed cells back out of
/// `Reply::Rows` without any ORM entity machinery.
#[cfg(feature = "rbac-db-session")]
pub(crate) mod raw {
    use anyhow::Result;
    use lacrymira::{Command, Dialect, Reply, Value};

    /// Build a raw PostgreSQL SQL command with bound parameters.
    pub(crate) fn sql(text: impl Into<String>, params: Vec<Value>) -> Command {
        Command::Sql {
            dialect: Dialect::Postgres,
            text: text.into(),
            params,
        }
    }

    /// Affected-row count of a reply (`0` for row-producing replies).
    pub(crate) fn affected(reply: &Reply) -> u64 {
        match reply {
            Reply::Affected(n) => *n,
            _ => 0,
        }
    }

    /// The first row of a row-producing reply, with its column names.
    ///
    /// `None` covers both a count-only reply and a statement that produced
    /// no rows (lacrymira reports a zero-row raw SELECT as `Affected(0)`).
    pub(crate) fn first_row(reply: &Reply) -> Option<(&[String], &[Value])> {
        match reply {
            Reply::Rows { columns, rows } => {
                rows.first().map(|row| (columns.as_slice(), row.as_slice()))
            }
            _ => None,
        }
    }

    /// Column value by name.
    pub(crate) fn cell<'a>(columns: &[String], row: &'a [Value], name: &str) -> Result<&'a Value> {
        let idx = columns
            .iter()
            .position(|c| c == name)
            .ok_or_else(|| anyhow::anyhow!("column {name:?} missing from the reply"))?;
        row.get(idx)
            .ok_or_else(|| anyhow::anyhow!("column {name:?} missing from the row"))
    }

    /// Any string-backed value (text, json, uuid, timestamp) as `String`.
    pub(crate) fn as_text(v: &Value) -> Result<String> {
        match v {
            Value::Text(s) | Value::Json(s) | Value::Uuid(s) | Value::Timestamp(s) => Ok(s.clone()),
            other => Err(anyhow::anyhow!("expected a text-like value, got {other:?}")),
        }
    }

    /// [`as_text`] with SQL NULL mapped to `None`.
    pub(crate) fn as_opt_text(v: &Value) -> Result<Option<String>> {
        match v {
            Value::Null => Ok(None),
            other => as_text(other).map(Some),
        }
    }

    /// Integer value as `i64`.
    pub(crate) fn as_i64(v: &Value) -> Result<i64> {
        match v {
            Value::I64(n) => Ok(*n),
            Value::I32(n) => Ok(i64::from(*n)),
            other => Err(anyhow::anyhow!("expected an integer value, got {other:?}")),
        }
    }

    /// [`as_i64`] with SQL NULL mapped to `None`.
    pub(crate) fn as_opt_i64(v: &Value) -> Result<Option<i64>> {
        match v {
            Value::Null => Ok(None),
            other => as_i64(other).map(Some),
        }
    }

    /// UUID value parsed back into [`uuid::Uuid`] (accepts text form too).
    pub(crate) fn as_uuid(v: &Value) -> Result<uuid::Uuid> {
        match v {
            Value::Uuid(s) | Value::Text(s) => s
                .parse()
                .map_err(|e| anyhow::anyhow!("invalid UUID {s:?}: {e}")),
            other => Err(anyhow::anyhow!("expected a UUID value, got {other:?}")),
        }
    }
}
