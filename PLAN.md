# kirino — Issues & Action Plan

Generated 2026-06-30 from deep code audit.

kirino is the zero-trust authentication & RBAC framework (v0.5.0, SySL-1.0). Implements RBAC0/1/2 per ANSI INCITS 359-2004 with dynamic authorization.

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

### 3. yuuka dependency is obscure
- `yuuka = "^0.5"` — a proc-macro crate by the same author, not widely used
- If yuuka breaks or is abandoned, kirino's build breaks
- **Fix**: Consider vendoring the yuuka macros that kirino uses, or ensure yuuka has its own stability guarantees.

## Medium

### 4. No security audit
- Despite being a security-critical library, no documented external security review
- **Fix**: Document the threat model. Consider commissioning a security audit before production deployment.

### 5. No performance benchmarks
- RBAC engine with TTL cache, dynamic auth with 5-dimension risk scoring — no benchmarks exist
- **Fix**: Add criterion benchmarks for: permission check hot path, hierarchical role resolution (deep chains), constraint validation, dynamic auth scoring.

### 6. No integration tests with real PostgreSQL
- InMemory stores are tested; PostgreSQL stores (`rbac-pg-session` feature) are not
- **Fix**: Add docker-compose + integration tests for PG-backed stores.

## Strengths (for reference)
- Full RBAC0/1/2 implementation (ANSI INCITS 359-2004 compliant)
- Deny-override semantics throughout
- Proper cycle detection with DFS for role hierarchies
- DO-178C inspired autonomy levels (L0-L4)
- Well-documented with 8-language docs and mermaid diagrams
- Comprehensive unit tests (20+ in engine.rs, 11+ in hierarchy)
