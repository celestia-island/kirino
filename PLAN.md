# kirino — Issues & Action Plan

Generated 2026-06-30 from deep code audit. Last updated 2026-07-04.

kirino is the zero-trust authentication & RBAC framework (v0.5.0, SySL-1.0). Implements RBAC0/1/2 per ANSI INCITS 359-2004 with dynamic authorization.

**Status legend**: ✅ done in-tree · ⏳ deferred / external · 🔴 open

## Critical

### 1. Version mismatch with entelecheia consumer
- entelecheia pins `kirino = "^0.4"` but kirino is at v0.5.0
- Pre-1.0 semver: breaking changes allowed between minor versions
- **Cannot be resolved inside this repository.** entelecheia is a separate
  consumer repo; its dependency pin cannot be verified or fixed from here.
- **Action (must be done in the entelecheia repo)**: Either confirm 0.4.x API
  is compatible and still maintained, or update entelecheia to `^0.5`. Open a
  tracking issue in `celestia-island/entelecheia` and link it back here.
- **Status**: needs verification in the entelecheia repository — **not** done.

## High

### 2. sea-orm dependency is release candidate
- `sea-orm = "^2.0.0-rc"` for PostgreSQL-backed stores
- **Fix**: Pin to exact RC version. Monitor for 2.0 stable release.
- **Status**: ✅ done — pinned to `=2.0.0-rc.41` (commit `b3c9354`). Re-pin if a
  caret-normalization pass reintroduces `^2.0.0-rc`. Still monitor for 2.0 stable.

### 3. yuuka dependency is obscure
- `yuuka = "^0.5"` — a proc-macro crate by the same author, not widely used
- If yuuka breaks or is abandoned, kirino's build breaks
- **Fix**: Consider vendoring the yuuka macros that kirino uses, or ensure yuuka has its own stability guarantees.
- **Status**: ✅ mitigated — yuuka is now a path dependency on the sibling repo
  (`../yuuka`, commit `07abd4a`), so the build no longer depends on crates.io for
  it. A formal "vendor the macros" (copy sources in-tree) is still possible but
  not required while the sibling repo tracks kirino.

## Medium

### 4. No security audit
- Despite being a security-critical library, no documented external security review
- **Fix**: Document the threat model. Consider commissioning a security audit before production deployment.
- **Status**: ⏳ partially done — the threat model exists (`docs/THREAT_MODEL.md`)
  and a `SECURITY.md` reporting policy was added (commit `4cdb3f5`), which
  **honestly states that no third-party audit has been performed** (per
  THREAT_MODEL.md §5). The audit itself remains 🔴 open and recommended before
  production deployment.

### 5. No performance benchmarks
- RBAC engine with TTL cache, dynamic auth with 5-dimension risk scoring — no benchmarks exist
- **Fix**: Add criterion benchmarks for: permission check hot path, hierarchical role resolution (deep chains), constraint validation, dynamic auth scoring.
- **Status**: ✅ done — all four criterion benchmark groups now exist in
  `benches/rbac.rs`, each gated behind its providing feature so the file
  compiles under any feature combination:
  `permission_check` (default), `hierarchical_resolution` (`rbac-hierarchy`,
  depth-10 inheritance chain), `constraint_validation` (`rbac-constraints`,
  exercising all five policy kinds: SSD, DSD, prerequisite, cardinality, and
  temporal/time-window), and `dynamic_auth` (`rbac-dynamic`, 5-dimension risk
  score + full `authorize()` verdict). Verified with
  `cargo bench --no-run`, `cargo check --benches`, and
  `cargo clippy --benches -- -D warnings` under
  `--features rbac-hierarchy,rbac-constraints,rbac-dynamic` (the `rbac-pg-session`
  feature is excluded from the bench gate because its `sea-orm` dep requires a
  newer rustc than the in-tree toolchain).

### 6. No integration tests with real PostgreSQL
- InMemory stores are tested; PostgreSQL stores (`rbac-pg-session` feature) are not
- **Fix**: Add docker-compose + integration tests for PG-backed stores.
- **Status**: ✅ done — `docker-compose.yml`, a CI `pg-integration` job, and six
  `#[ignore]`'d integration tests in `src/database/pg_session.rs` were added
  (commit `2d71858`). The default test suite is unaffected.

## Strengths (for reference)
- Full RBAC0/1/2 implementation (ANSI INCITS 359-2004 compliant)
- Deny-override semantics throughout
- Proper cycle detection with DFS for role hierarchies
- DO-178C inspired autonomy levels (L0-L4)
- Well-documented with 8-language docs and mermaid diagrams
- Comprehensive unit tests (20+ in engine.rs, 11+ in hierarchy)
