//! Shared TOTP replay guard backed by the `mfa_factors` table.
//!
//! [`MemoryRevocationBackend`](crate::auth::credential::basic::MemoryRevocationBackend)
//! style process-local state cannot stop a TOTP replay from hitting a
//! different replica: an MFA code is replayed against replica B while the
//! process-local mark lives on replica A, and inside the ±1 window
//! (RFC 6238 §5.1) both accept it. This store keys the high-water mark by
//! factor in the shared database, so a step consumed on any replica is
//! consumed for all of them.
//!
//! Like [`DbSessionStore`](crate::database::db_session::DbSessionStore) and
//! [`DbRevocationStore`](crate::database::db_revocation::DbRevocationStore),
//! the table lives in the host's schema: this crate carries no migration
//! tooling.
//! [`ensure_schema`](crate::database::db_totp_replay::DbTotpReplayGuard::ensure_schema)
//! is an idempotent convenience for hosts that do not run their own migrations,
//! and it is upgrade-safe — a deployment that already has `mfa_factors`
//! without the replay column gets it added as `NULL`, which means "no step
//! consumed yet", so every enrolled factor keeps working on first login
//! after the upgrade.
//!
//! ## Schema contract
//!
//! | column | type | meaning |
//! |---|---|---|
//! | `factor_id` | `TEXT PRIMARY KEY` | the factor that owns the TOTP secret |
//! | `totp_last_used_step` | `BIGINT NULL` | highest accepted TOTP time step |
//!
//! Hosts whose factor table has other names or extra columns can point the
//! guard at it with
//! [`with_names`](crate::database::db_totp_replay::DbTotpReplayGuard::with_names)
//! (the two columns above must exist); a column of a *different* name will
//! not do, because the CAS predicate and the upsert write the replay column
//! by name.
//!
//! On a host-owned table the factor **row** must already exist: a missing
//! row fails closed only when the host's NOT NULL constraints reject the
//! insert (which is the common shape but incidental, not by design — R2
//! F2); on a table with nullable/defaulted columns the upsert would create
//! a phantom row. Point the guard at a dedicated table (the default) or
//! seed the factor row first.

use anyhow::Result;

use lacrymira::Value;
use lacrymira_pg::PgExecutor;

use crate::{auth::passport::totp_replay::TotpReplayGuard, database::raw, error::KirinoError};

/// Default factor table (schema contract in the module docs).
pub const DEFAULT_FACTOR_TABLE: &str = "mfa_factors";
/// Default factor id column.
pub const DEFAULT_FACTOR_ID_COLUMN: &str = "factor_id";
/// Default replay-mark column.
pub const DEFAULT_STEP_COLUMN: &str = "totp_last_used_step";

/// Longest identifier PostgreSQL accepts.
const MAX_IDENT_LEN: usize = 63;

/// Transaction-scoped advisory lock key that serialises
/// [`DbTotpReplayGuard::ensure_schema`] across replicas.
///
/// Spelled `kirino` + `mf` in ASCII; the value is arbitrary, it only has to
/// be stable and not collide with another advisory-lock user in the same
/// database.
const SCHEMA_WARMUP_LOCK_KEY: i64 = 0x6b69_7269_6e6f_6d66;

/// DB-backed [`TotpReplayGuard`]. Every replica points at the same database
/// and a consumed step propagates on the next attempt.
#[derive(Debug, Clone)]
pub struct DbTotpReplayGuard {
    conn: PgExecutor,
    factor_table: String,
    factor_id_column: String,
    step_column: String,
}

impl DbTotpReplayGuard {
    /// Creates a guard over the default `mfa_factors` shape.
    #[must_use]
    pub fn new(conn: PgExecutor) -> Self {
        Self {
            conn,
            factor_table: DEFAULT_FACTOR_TABLE.to_string(),
            factor_id_column: DEFAULT_FACTOR_ID_COLUMN.to_string(),
            step_column: DEFAULT_STEP_COLUMN.to_string(),
        }
    }

    /// Creates a guard over a factor table with host-chosen names — for a
    /// host whose MFA table already exists (or is named per service).
    ///
    /// Names are interpolated into the SQL (identifiers cannot be bound as
    /// parameters), so each one is validated as a plain PostgreSQL
    /// identifier: ASCII letters, digits and `_`, not starting with a
    /// digit, at most 63 bytes. Anything else is rejected rather than
    /// quoted into the statement.
    ///
    /// # Errors
    ///
    /// Returns [`KirinoError::Validation`] for an unusable identifier.
    pub fn with_names(
        conn: PgExecutor,
        factor_table: &str,
        factor_id_column: &str,
        step_column: &str,
    ) -> Result<Self> {
        Ok(Self {
            conn,
            factor_table: validated_ident("factor table", factor_table)?,
            factor_id_column: validated_ident("factor id column", factor_id_column)?,
            step_column: validated_ident("step column", step_column)?,
        })
    }

    /// Creates the factor table / replay column if the host has not.
    ///
    /// Two idempotent statements, both safe on an existing deployment:
    ///
    /// - `CREATE TABLE IF NOT EXISTS` for a fresh install;
    /// - `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` when `mfa_factors`
    ///   predates replay protection. The new column is `NULL` for every
    ///   existing row, which is exactly "no step consumed yet" — the next
    ///   successful verification seeds it.
    ///
    /// # Concurrency
    ///
    /// The two statements run inside one transaction that first takes a
    /// transaction-scoped advisory lock. `CREATE TABLE IF NOT EXISTS` is
    /// *not* safe against concurrent creators — PostgreSQL can fail the
    /// loser with a `pg_type` unique violation — and replicas booting
    /// together is precisely the deployment this guard exists for. The
    /// lock serialises the warm-up; whoever arrives second sees the table
    /// and the column already in place and the statements become no-ops.
    ///
    /// # Errors
    ///
    /// Returns the database error when either statement fails.
    pub async fn ensure_schema(&self) -> Result<()> {
        let (table, id, step) = self.qualified_names();
        let mut txn = self.conn.begin().await?;
        txn.execute(&raw::sql(
            "SELECT pg_advisory_xact_lock($1)",
            vec![Value::I64(SCHEMA_WARMUP_LOCK_KEY)],
        ))
        .await?;
        txn.execute(&raw::sql(
            format!(
                "CREATE TABLE IF NOT EXISTS {table} ( \
                    {id} TEXT PRIMARY KEY, \
                    {step} BIGINT NULL \
                )"
            ),
            Vec::new(),
        ))
        .await?;
        txn.execute(&raw::sql(
            format!("ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {step} BIGINT NULL"),
            Vec::new(),
        ))
        .await?;
        txn.commit().await?;
        Ok(())
    }

    /// Reports a failed CAS as a rejection.
    ///
    /// Fail closed: a mark that cannot be written is not a mark that allows
    /// the code. The secret itself lives in the same database, so a broken
    /// connection fails the whole verification anyway — this only makes sure
    /// the failure cannot be mistaken for "not used yet".
    fn reject_closed(&self, factor_id: &str, error: &lacrymira::Error) -> bool {
        tracing::error!(
            factor_id,
            error = %error,
            "TOTP replay CAS failed; rejecting the code (fail closed)"
        );
        false
    }

    /// `(table, factor id column, step column)` — the raw names, used to
    /// format the SQL below.
    fn qualified_names(&self) -> (&str, &str, &str) {
        (
            &self.factor_table,
            &self.factor_id_column,
            &self.step_column,
        )
    }
}

/// Accepts only a plain PostgreSQL identifier (letters, digits, `_`; not
/// starting with a digit; ≤63 bytes) so it can be interpolated into SQL
/// without quoting games.
fn validated_ident(what: &str, name: &str) -> Result<String> {
    let usable = !name.is_empty()
        && name.len() <= MAX_IDENT_LEN
        && name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    if !usable {
        return Err(KirinoError::Validation(format!(
            "{what} must be a plain PostgreSQL identifier (letters, digits, '_'; \
             not starting with a digit; at most {MAX_IDENT_LEN} bytes), got {name:?}"
        ))
        .into());
    }
    Ok(name.to_string())
}

#[async_trait::async_trait]
impl TotpReplayGuard for DbTotpReplayGuard {
    async fn accept_step(&self, factor_id: &str, step: i64) -> bool {
        let (table, id, step_col) = self.qualified_names();

        // Path 1 — the normal case, and the only one that can happen on a
        // host-owned factor table (its row exists because it holds the
        // secret): advance the mark, but only for a strictly newer step.
        // One statement is the whole check-and-set, so of two concurrent
        // submitters of the same code exactly one gets a row back.
        let advance = raw::sql(
            format!(
                "UPDATE {table} SET {step_col} = $2 \
                 WHERE {id} = $1 \
                   AND ({step_col} IS NULL OR {step_col} < $2) \
                 RETURNING {step_col}"
            ),
            vec![Value::Text(factor_id.to_string()), Value::I64(step)],
        );
        match self.conn.execute(&advance).await {
            Ok(reply) if raw::first_row(&reply).is_some() => return true,
            // Either the step is a replay (row there, mark not older) or the
            // factor has no row yet — path 2 decides which.
            Ok(_) => {}
            Err(e) => return self.reject_closed(factor_id, &e),
        }

        // Path 2 — the factor row does not exist yet (first verification on
        // a table this guard created itself). Claim it with the same CAS
        // predicate; the `ON CONFLICT` branch keeps the answer correct when
        // another replica inserts the row in the same window.
        let claim = raw::sql(
            format!(
                "INSERT INTO {table} ({id}, {step_col}) VALUES ($1, $2) \
                 ON CONFLICT ({id}) DO UPDATE SET {step_col} = \
                    GREATEST(EXCLUDED.{step_col}, COALESCE({table}.{step_col}, -1)) \
                 WHERE {table}.{step_col} IS NULL \
                    OR {table}.{step_col} < EXCLUDED.{step_col} \
                 RETURNING {step_col}"
            ),
            vec![Value::Text(factor_id.to_string()), Value::I64(step)],
        );
        match self.conn.execute(&claim).await {
            Ok(reply) => raw::first_row(&reply).is_some(),
            // The row appeared in between and its mark is not older: the
            // concurrent verification won.
            Err(e) => self.reject_closed(factor_id, &e),
        }
    }

    async fn last_used_step(&self, factor_id: &str) -> Option<i64> {
        let (table, id, step_col) = self.qualified_names();
        let cmd = raw::sql(
            format!("SELECT {step_col} FROM {table} WHERE {id} = $1"),
            vec![Value::Text(factor_id.to_string())],
        );
        match self.conn.execute(&cmd).await {
            // Single-column projection: read it positionally rather than
            // by name.
            Ok(reply) => match raw::first_row(&reply).and_then(|(_, row)| row.first()) {
                Some(v) => match raw::as_opt_i64(v) {
                    Ok(step) => step,
                    Err(e) => {
                        tracing::error!(
                            factor_id,
                            error = %e,
                            "TOTP replay mark could not be decoded"
                        );
                        None
                    }
                },
                None => None,
            },
            Err(e) => {
                tracing::error!(
                    factor_id,
                    error = %e,
                    "TOTP replay mark read failed; reporting no recorded step"
                );
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! PostgreSQL integration tests for [`DbTotpReplayGuard`].
    //!
    //! These require a live PostgreSQL instance. They are `#[ignore]`'d so
    //! the normal `cargo test` run does not need a database — same
    //! convention as the `DbSessionStore` integration tests. Run them
    //! explicitly:
    //!
    //! ```text
    //! docker compose up -d
    //! export DATABASE_URL=postgres://kirino:kirino@localhost:5432/kirino_test
    //! cargo test --lib --features rbac-db-session -- --ignored pg_totp
    //! ```
    //!
    //! On CI they run alongside the `pg-integration` job (see
    //! `.github/workflows/checks.yml`), which provisions a `postgres:16`
    //! service container with `DATABASE_URL` set accordingly.

    use std::env;

    use uuid::Uuid;

    use lacrymira_pg::PgExecutor;

    use super::DbTotpReplayGuard;
    use crate::auth::passport::dynamic_password::TotpVerifier;
    use crate::auth::passport::totp_replay::TotpReplayGuard;
    use crate::database::raw;

    /// Default connection string used when `DATABASE_URL` is unset. Matches
    /// the `docker-compose.yml` and CI service container defaults.
    const DEFAULT_DATABASE_URL: &str = "postgres://kirino:kirino@localhost:5432/kirino_test";

    async fn connect() -> PgExecutor {
        let url = env::var("DATABASE_URL").unwrap_or_else(|_| DEFAULT_DATABASE_URL.to_string());
        PgExecutor::connect(&url)
            .await
            .unwrap_or_else(|e| panic!("failed to connect to PostgreSQL at {url}: {e}"))
    }

    /// A fresh factor id per test: the table is shared between tests (and
    /// possibly with other suites), so isolation comes from the key, not
    /// from truncation.
    fn factor_id() -> String {
        format!("totp-test-{}", Uuid::now_v7())
    }

    async fn guard() -> DbTotpReplayGuard {
        let conn = connect().await;
        let guard = DbTotpReplayGuard::new(conn);
        guard
            .ensure_schema()
            .await
            .expect("ensure_schema must create mfa_factors");
        guard
    }

    /// (c) A row that predates replay protection has a NULL step column and
    /// must verify on first use after the upgrade.
    #[tokio::test]
    #[ignore = "requires PostgreSQL; see the module docs for how to run it"]
    async fn pg_totp_null_step_verifies_on_first_use() {
        let guard = guard().await;
        let factor = factor_id();
        assert_eq!(guard.last_used_step(&factor).await, None);

        let totp = TotpVerifier::new(b"pg-fresh-factor-secret".to_vec());
        let code = totp.generate().unwrap();
        assert!(
            totp.verify_with_guard(&code, &factor, &guard)
                .await
                .unwrap(),
            "a factor with a NULL totp_last_used_step must pass its first verification"
        );
        assert!(
            guard.last_used_step(&factor).await.is_some(),
            "the successful verification must seed the replay mark"
        );
    }

    /// (a) The same code inside the same window is accepted once and
    /// rejected afterwards — even through a *fresh* verifier, which is the
    /// per-request shape the memory-only path cannot defend.
    #[tokio::test]
    #[ignore = "requires PostgreSQL; see the module docs for how to run it"]
    async fn pg_totp_rejects_replayed_step() {
        let guard = guard().await;
        let factor = factor_id();
        let secret = b"pg-replay-secret".to_vec();

        let first = TotpVerifier::new(secret.clone());
        let step = first.current_step();
        let code = first.generate().unwrap();
        assert!(first
            .verify_with_guard(&code, &factor, &guard)
            .await
            .unwrap());

        // Skip the ~1-in-10^6 case where adjacent windows share a code.
        let collision = first.code_at(step).unwrap() == first.code_at(step + 1).unwrap();
        if !collision {
            let second = TotpVerifier::new(secret);
            assert!(
                !second
                    .verify_with_guard(&code, &factor, &guard)
                    .await
                    .unwrap(),
                "a replayed code must be rejected by the shared mark"
            );
        }
    }

    /// (b) A strictly newer step is accepted and advances the mark; the
    /// steps below it stay rejected.
    #[tokio::test]
    #[ignore = "requires PostgreSQL; see the module docs for how to run it"]
    async fn pg_totp_accepts_newer_step_and_keeps_mark_monotonic() {
        let guard = guard().await;
        let factor = factor_id();

        assert!(guard.accept_step(&factor, 1_000).await);
        assert!(
            !guard.accept_step(&factor, 1_000).await,
            "the same step is a replay"
        );
        assert!(
            !guard.accept_step(&factor, 999).await,
            "an older step is a replay"
        );
        assert!(
            guard.accept_step(&factor, 1_001).await,
            "a newer step is normal use"
        );
        assert_eq!(guard.last_used_step(&factor).await, Some(1_001));
        assert!(
            !guard.accept_step(&factor, 1_001).await,
            "the advanced mark still rejects its own step"
        );
    }

    /// (d) Two concurrent submitters of one code: the upsert's CAS admits
    /// exactly one.
    #[tokio::test]
    #[ignore = "requires PostgreSQL; see the module docs for how to run it"]
    async fn pg_totp_concurrent_same_step_single_winner() {
        let guard = guard().await;
        let factor = factor_id();
        let step = 1_234_567i64;

        let (first, second) = tokio::join!(
            guard.accept_step(&factor, step),
            guard.accept_step(&factor, step),
        );
        assert!(
            first ^ second,
            "exactly one concurrent accept of the same step may win (got {first}/{second})"
        );
        assert_eq!(guard.last_used_step(&factor).await, Some(step));
    }

    /// Path 1 (`UPDATE … WHERE … RETURNING`) must be a single-statement
    /// CAS: race two callers for a step ABOVE an already-seeded mark (row
    /// exists, so path 2 never runs) — exactly one must win (R2 F1: the
    /// unseeded race only ever exercised path 2).
    #[tokio::test]
    #[ignore]
    async fn pg_totp_seeded_race_single_winner_on_the_update_path() {
        let guard = guard().await;
        for round in 0..5u32 {
            let f = factor_id();
            let seeded = 1_700_000_000i64 + i64::from(round) * 100;
            assert!(
                guard.accept_step(&f, seeded).await,
                "seed the row so path 1 is the only path that can fire"
            );
            let contested = seeded + 1;
            let (a, b) = tokio::join!(
                guard.accept_step(&f, contested),
                guard.accept_step(&f, contested),
            );
            let wins = usize::from(a) + usize::from(b);
            assert_eq!(wins, 1, "exactly one of the two concurrent claims wins");
            assert_eq!(
                guard.last_used_step(&f).await,
                Some(contested),
                "the mark lands on the contested step"
            );
        }
    }

    /// Two guards on separate connections (the multi-replica shape) share
    /// one mark: the code accepted on "replica A" is a replay on "replica B".
    #[tokio::test]
    #[ignore = "requires PostgreSQL; see the module docs for how to run it"]
    async fn pg_totp_rejects_replay_across_replicas() {
        let replica_a = guard().await;
        let replica_b = DbTotpReplayGuard::new(connect().await);
        let factor = factor_id();
        let secret = b"pg-cross-replica-secret".to_vec();

        let verifier = TotpVerifier::new(secret.clone());
        let step = verifier.current_step();
        let code = verifier.generate().unwrap();

        assert!(verifier
            .verify_with_guard(&code, &factor, &replica_a)
            .await
            .unwrap());
        if verifier.code_at(step).unwrap() == verifier.code_at(step + 1).unwrap() {
            return;
        }
        assert!(
            !TotpVerifier::new(secret)
                .verify_with_guard(&code, &factor, &replica_b)
                .await
                .unwrap(),
            "a code consumed on replica A must be a replay on replica B"
        );
    }

    /// The guard refuses identifiers that would have to be quoted, instead
    /// of interpolating them.
    #[test]
    fn rejects_unsafe_identifiers() {
        for name in ["", "1table", "mfa factors", "mfa;DROP TABLE x", "t\"x"] {
            assert!(
                super::validated_ident("factor table", name).is_err(),
                "{name:?} must be rejected"
            );
        }
        assert!(super::validated_ident("factor table", "mfa_factors").is_ok());
        assert!(super::validated_ident("factor table", "_pf2_mfa").is_ok());
        assert!(super::validated_ident("factor table", &"a".repeat(64)).is_err());
    }

    /// Upgrade path: a deployment whose factor table predates replay
    /// protection (rows already enrolled, replay column absent) must gain
    /// the column as NULL and keep verifying — an upgrade may not lock
    /// enrolled users out.
    #[tokio::test]
    #[ignore = "requires PostgreSQL; see the module docs for how to run it"]
    async fn pg_totp_upgrades_a_preexisting_factor_table() {
        let conn = connect().await;
        let table = format!("totp_legacy_test_{}", Uuid::now_v7().simple());

        // The pre-upgrade shape: an enrollment row, no replay column.
        conn.execute(&raw::sql(
            format!("CREATE TABLE {table} (id TEXT PRIMARY KEY, secret TEXT NOT NULL)"),
            Vec::new(),
        ))
        .await
        .expect("create the legacy factor table");
        conn.execute(&raw::sql(
            format!("INSERT INTO {table} (id, secret) VALUES ('factor-legacy', 'enrolled')"),
            Vec::new(),
        ))
        .await
        .expect("seed an enrolled factor");

        let guard =
            DbTotpReplayGuard::with_names(conn.clone(), &table, "id", "totp_last_used_step")
                .expect("valid identifiers");
        assert_eq!(
            guard.last_used_step("factor-legacy").await,
            None,
            "a column that does not exist yet reads as 'never used'"
        );

        guard
            .ensure_schema()
            .await
            .expect("ensure_schema must add the replay column to the existing table");

        let totp = TotpVerifier::new(b"legacy-factor-secret".to_vec());
        let code = totp.generate().unwrap();
        assert!(
            totp.verify_with_guard(&code, "factor-legacy", &guard)
                .await
                .unwrap(),
            "an enrolled factor with a NULL replay mark must verify after the upgrade"
        );
        assert!(
            guard.last_used_step("factor-legacy").await.is_some(),
            "the mark must be seeded by the first verification"
        );

        conn.execute(&raw::sql(
            format!("DROP TABLE IF EXISTS {table}"),
            Vec::new(),
        ))
        .await
        .expect("drop the legacy test table");
    }

    /// `with_names` reaches the custom table (and the default one stays
    /// untouched).
    #[tokio::test]
    #[ignore = "requires PostgreSQL; see the module docs for how to run it"]
    async fn pg_totp_custom_table_names() {
        let conn = connect().await;
        let table = format!("totp_factor_test_{}", Uuid::now_v7().simple());
        let guard = DbTotpReplayGuard::with_names(conn.clone(), &table, "id", "last_step")
            .expect("valid identifiers");
        guard.ensure_schema().await.expect("ensure_schema");

        assert!(guard.accept_step("factor-x", 10).await);
        assert!(!guard.accept_step("factor-x", 10).await);
        assert_eq!(guard.last_used_step("factor-x").await, Some(10));

        // Clean up the per-test table (the name is generated above, never
        // derived from input).
        conn.execute(&raw::sql(
            format!("DROP TABLE IF EXISTS {table}"),
            Vec::new(),
        ))
        .await
        .expect("drop test table");
    }
}
