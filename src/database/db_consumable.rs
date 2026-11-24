//! DB-backed [`ConsumableStore`] (feature `store-db`).
//!
//! The multi-replica backend: one `DELETE … RETURNING` is the whole claim,
//! so PostgreSQL decides who wins and every other replica sees the result
//! on its next statement. No advisory locks, no read-then-write, no window
//! in which two replicas both believe a credential is theirs.
//!
//! Contrast with the shape this replaces downstream: `SELECT` the code,
//! validate it, then `DELETE` it and check only that the delete did not
//! *error*. A `DELETE` matching nothing is a success, so two racing
//! exchanges both proceed. Here a claim that matches nothing returns zero
//! rows, which is [`Claim::Lost`](crate::auth::store::Claim::Lost).
//!
//! Schema (`ensure_schema`):
//!
//! ```sql
//! CREATE TABLE IF NOT EXISTS kirino_consumables (
//!     fingerprint TEXT PRIMARY KEY,   -- hex sha256 of the token, never the token
//!     payload     JSONB NOT NULL,
//!     expires_at  BIGINT NOT NULL,    -- unix seconds
//!     created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
//! );
//! ```
//!
//! Storing `expires_at` as `BIGINT` rather than a timestamp keeps the
//! comparison exactly the caller's clock (the trait takes `now`), so a
//! database in another time zone cannot shift an expiry.

use std::marker::PhantomData;

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use lacrymira::Value;
use lacrymira_pg::PgExecutor;
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::auth::store::consumable::{fingerprint, Claim, ConsumableStore};
use crate::database::raw;

/// Default table name.
pub const DEFAULT_TABLE: &str = "kirino_consumables";

/// Transaction-scoped advisory lock key serialising `ensure_schema` across
/// replicas booting together (spelled `kirino` + `cs` in ASCII; the value is
/// arbitrary, it only has to be stable and not collide with another
/// advisory-lock user in the same database).
const SCHEMA_WARMUP_LOCK_KEY: i64 = 0x6b69_7269_6e6f_6373;

/// DB-backed [`ConsumableStore`].
///
/// `P` must round-trip through JSON: the parked payload is stored in a
/// `jsonb` column, so no schema change is needed per credential type.
pub struct DbConsumableStore<P> {
    conn: PgExecutor,
    table: String,
    /// `fn() -> P` keeps `Send`/`Sync` independent of `P` — the store holds
    /// no `P` itself, it only names it.
    payload: PhantomData<fn() -> P>,
}

impl<P> std::fmt::Debug for DbConsumableStore<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DbConsumableStore")
            .field("table", &self.table)
            .finish_non_exhaustive()
    }
}

impl<P> Clone for DbConsumableStore<P> {
    fn clone(&self) -> Self {
        Self {
            conn: self.conn.clone(),
            table: self.table.clone(),
            payload: PhantomData,
        }
    }
}

impl<P> DbConsumableStore<P> {
    /// A store over [`DEFAULT_TABLE`].
    #[must_use]
    pub fn new(conn: PgExecutor) -> Self {
        Self {
            conn,
            table: DEFAULT_TABLE.to_string(),
            payload: PhantomData,
        }
    }

    /// A store over a host-chosen table (an existing schema, or one table per
    /// credential family).
    ///
    /// # Errors
    ///
    /// [`anyhow::Error`] when `table` is not a plain PostgreSQL identifier
    /// (ASCII letters, digits, `_`; not starting with a digit; at most 63
    /// bytes). Names are interpolated into SQL — identifiers cannot be bound
    /// as parameters — so an unusable one is rejected rather than quoted in.
    pub fn with_table(conn: PgExecutor, table: &str) -> Result<Self> {
        Ok(Self {
            conn,
            table: raw::ident("table", table)?,
            payload: PhantomData,
        })
    }

    /// Create the table if it is absent.
    ///
    /// Wrapped in a transaction that first takes an advisory lock:
    /// `CREATE TABLE IF NOT EXISTS` is not safe against concurrent creators
    /// (PostgreSQL can fail the loser with a `pg_type` unique violation), and
    /// replicas booting together is exactly the deployment this store exists
    /// for.
    ///
    /// # Errors
    ///
    /// The database error when the DDL fails.
    pub async fn ensure_schema(&self) -> Result<()> {
        let mut txn = self.conn.begin().await?;
        txn.execute(&raw::sql(
            "SELECT pg_advisory_xact_lock($1)::text AS locked",
            vec![Value::I64(SCHEMA_WARMUP_LOCK_KEY)],
        ))
        .await?;
        txn.execute(&raw::sql(
            format!(
                "CREATE TABLE IF NOT EXISTS {} ( \
                    fingerprint TEXT PRIMARY KEY, \
                    payload JSONB NOT NULL, \
                    expires_at BIGINT NOT NULL, \
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW() \
                )",
                self.table
            ),
            Vec::new(),
        ))
        .await?;
        txn.commit().await?;
        Ok(())
    }
}

#[async_trait]
impl<P> ConsumableStore<P> for DbConsumableStore<P>
where
    P: Serialize + DeserializeOwned + Send + Sync + 'static,
{
    async fn put(&self, token: &str, payload: P, expires_at: DateTime<Utc>) -> Result<()> {
        let key = fingerprint(token);
        let now = Utc::now().timestamp();
        let body = serde_json::to_string(&payload).context("payload is not JSON-serialisable")?;
        // Insert, or replace ONLY when the existing entry has already
        // expired. The `WHERE` on the update is what refuses a live
        // duplicate: a conflict whose row is still alive affects zero rows.
        let reply = self
            .conn
            .execute(&raw::sql(
                format!(
                    "INSERT INTO {table} (fingerprint, payload, expires_at) VALUES ($1, $2, $3) \
                     ON CONFLICT (fingerprint) DO UPDATE SET \
                        payload = EXCLUDED.payload, expires_at = EXCLUDED.expires_at \
                     WHERE {table}.expires_at <= $4",
                    table = self.table
                ),
                vec![
                    Value::Text(key),
                    Value::Json(body),
                    Value::I64(expires_at.timestamp()),
                    Value::I64(now),
                ],
            ))
            .await?;
        if raw::affected(&reply) == 0 {
            bail!("token is already parked and still live; tokens must be unique per credential");
        }
        Ok(())
    }

    async fn claim(&self, token: &str, now: DateTime<Utc>) -> Result<Claim<P>> {
        let key = fingerprint(token);
        // The whole claim: one statement deletes and returns. Whoever's
        // DELETE returns the row owns the credential; everyone else gets
        // zero rows, i.e. `Lost`.
        let reply = self
            .conn
            .execute(&raw::sql(
                format!(
                    "DELETE FROM {} WHERE fingerprint = $1 \
                     RETURNING payload, expires_at",
                    self.table
                ),
                vec![Value::Text(key)],
            ))
            .await?;
        let Some((columns, row)) = raw::first_row(&reply) else {
            return Ok(Claim::Lost);
        };
        let expires_at = raw::as_i64(raw::cell(columns, row, "expires_at")?)?;
        let body = raw::as_text(raw::cell(columns, row, "payload")?)?;
        if expires_at <= now.timestamp() {
            // Consumed but dead. The row is already gone; report a loss so a
            // caller cannot distinguish "expired" from "never existed".
            return Ok(Claim::Lost);
        }
        let payload: P =
            serde_json::from_str(&body).context("parked payload is not decodable as P")?;
        Ok(Claim::Won(payload))
    }

    async fn sweep(&self, now: DateTime<Utc>) -> Result<u64> {
        let reply = self
            .conn
            .execute(&raw::sql(
                format!("DELETE FROM {} WHERE expires_at <= $1", self.table),
                vec![Value::I64(now.timestamp())],
            ))
            .await?;
        Ok(raw::affected(&reply))
    }
}

#[cfg(test)]
mod tests {
    //! PostgreSQL integration tests for [`DbConsumableStore`].
    //!
    //! `#[ignore]`'d so the normal `cargo test` run needs no database — the
    //! same convention as the `DbSessionStore` and `DbTotpReplayGuard`
    //! suites. Run them explicitly:
    //!
    //! ```text
    //! export DATABASE_URL=postgres://kirino:kirino@localhost:5432/kirino_test
    //! cargo test --lib --features store-db -- --ignored db_consumable
    //! ```
    //!
    //! Every case uses the shared default table with a per-test token, so
    //! suites can run against the same database without truncation.

    use std::env;
    use std::sync::Arc;

    use chrono::Duration;
    use lacrymira_pg::PgExecutor;

    use super::*;

    const DEFAULT_DATABASE_URL: &str = "postgres://kirino:kirino@localhost:5432/kirino_test";

    async fn store() -> DbConsumableStore<String> {
        let url = env::var("DATABASE_URL").unwrap_or_else(|_| DEFAULT_DATABASE_URL.to_string());
        let conn = PgExecutor::connect(&url)
            .await
            .unwrap_or_else(|e| panic!("failed to connect to PostgreSQL at {url}: {e}"));
        let store = DbConsumableStore::<String>::new(conn);
        store.ensure_schema().await.expect("ensure schema");
        store
    }

    fn unique_token() -> String {
        format!("db-consumable-{}", uuid::Uuid::now_v7())
    }

    #[tokio::test]
    #[ignore]
    async fn db_consumable_exactly_one_racer_wins() {
        let store = Arc::new(store().await);
        let token = unique_token();
        store
            .put(
                &token,
                "grant".to_string(),
                Utc::now() + Duration::seconds(60),
            )
            .await
            .expect("park");

        let mut handles = Vec::new();
        for _ in 0..16 {
            let store = Arc::clone(&store);
            let token = token.clone();
            handles.push(tokio::spawn(async move {
                store.claim(&token, Utc::now()).await
            }));
        }
        let mut winners = 0usize;
        for handle in handles {
            if let Claim::Won(payload) = handle.await.expect("task").expect("claim") {
                assert_eq!(payload, "grant");
                winners += 1;
            }
        }
        // MUT:db-naive-claim — a select-then-delete backend yields >1 here.
        assert_eq!(winners, 1, "one DELETE … RETURNING, one winner");
    }

    #[tokio::test]
    #[ignore]
    async fn db_consumable_expired_claim_loses() {
        let store = store().await;
        let token = unique_token();
        store
            .put(
                &token,
                "grant".to_string(),
                Utc::now() - Duration::seconds(5),
            )
            .await
            .expect("park expired");
        assert_eq!(
            store.claim(&token, Utc::now()).await.expect("claim"),
            Claim::Lost
        );
        // Consumed either way: the row is gone, so a later claim is a loss
        // for a different reason and the entry does not linger.
        assert_eq!(
            store.claim(&token, Utc::now()).await.expect("claim"),
            Claim::Lost
        );
    }

    #[tokio::test]
    #[ignore]
    async fn db_consumable_refuses_a_live_duplicate_but_replaces_a_dead_one() {
        let store = store().await;
        let token = unique_token();
        store
            .put(
                &token,
                "first".to_string(),
                Utc::now() + Duration::seconds(60),
            )
            .await
            .expect("park");
        let err = store
            .put(
                &token,
                "second".to_string(),
                Utc::now() + Duration::seconds(60),
            )
            .await
            .expect_err("a live duplicate must be refused");
        assert!(err.to_string().contains("already parked"), "{err}");
        // The refused put did not clobber the parked payload.
        assert_eq!(
            store.claim(&token, Utc::now()).await.expect("claim"),
            Claim::Won("first".to_string())
        );

        let dead = unique_token();
        store
            .put(&dead, "old".to_string(), Utc::now() - Duration::seconds(1))
            .await
            .expect("park expired");
        store
            .put(&dead, "new".to_string(), Utc::now() + Duration::seconds(60))
            .await
            .expect("a dead entry does not block a fresh one");
        assert_eq!(
            store.claim(&dead, Utc::now()).await.expect("claim"),
            Claim::Won("new".to_string())
        );
    }

    #[tokio::test]
    #[ignore]
    async fn db_consumable_sweep_removes_only_expired_rows() {
        let store = store().await;
        let dead = unique_token();
        let live = unique_token();
        store
            .put(&dead, "x".to_string(), Utc::now() - Duration::seconds(10))
            .await
            .expect("park");
        store
            .put(&live, "y".to_string(), Utc::now() + Duration::seconds(60))
            .await
            .expect("park");
        let removed = store.sweep(Utc::now()).await.expect("sweep");
        assert!(
            removed >= 1,
            "the expired row was swept (removed {removed})"
        );
        assert_eq!(
            store.claim(&live, Utc::now()).await.expect("claim"),
            Claim::Won("y".to_string()),
            "a live row survives the sweep"
        );
    }
}
