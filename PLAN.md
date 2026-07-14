# kirino — Issues & Action Plan

Generated 2026-06-30 from deep code audit. Last updated 2026-07-04.

## Refresh log 2026-07-14

- **当前分支**：`dev` · 领先 `origin/dev` 0 commits · 工作区有 1 项 dirty
- **最近提交**：`🔧 Pin script recipes to the resolved Git Bash to survive WSL shadowing.` (`7708c69`)
- **未提交改动**：
  - `Cargo.toml`（未 stage 的修改；按 git 状态确认是依赖 / patch 段调整，待定）
- **后续动作**：
  1. 先 `git diff Cargo.toml` 确认本次未提交改动的性质：若是版本 bump / 新增依赖，确认与 kirino v0.5.0 (SySL-1.0) 的 RBAC0/1/2 公开 API 兼容；若是内联 `[patch.*]`，跟进跨仓 `[patch]` 收敛到 `~/.cargo/config.toml`（见 `entelecheia/PLAN.md` §6 跨仓依赖约定）的迁移计划，把 `[patch]` 段挪出 workspace。
  2. 把「§ Critical 1. Version mismatch with entelecheia consumer」一节提到的 entelecheia `kirino = "^0.4"` 与 kirino v0.5.0 不一致问题，更新到本 Refresh log 的跨仓依赖条目里，并提醒 entelecheia 维护者 bump 上限（这是跨仓协调，无法在 kirino 仓内单方面解决）。
  3. 在顶层 `patches/` 长期方案中登记 kirino RBAC v0.5.0 升级到 v0.6（如有）时的 breaking-change 流程（ANSI INCITS 359-2004 RBAC0/1/2 行为不能被无声修改）。
- **跨仓依赖**：上游依据 → `entelecheia/PLAN.md`；被 entelecheia 消费（entelecheia `Cargo.toml` pin `kirino = "^0.4"`，但本地已是 v0.5.0，存在跨仓版本失配）；同生态 sibling 仓 → `hifumi`（构建脚本/just 配方风格一致）、`aoba`（IPC 与 kirino 的 auth/RBAC 常组合出现）。

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
