# kirino Threat Model

This document describes the security architecture of **kirino** (v0.5.0), a
zero-trust authentication and RBAC framework. It is intended for security
reviewers, integrators, and downstream maintainers. It is **not** a complete
formal audit — see [§ External Audit](#external-audit).

kirino is security-critical infrastructure: a single incorrect authorization
decision is a privilege-escalation vulnerability. Every design choice below
should be read with that in mind.

---

## 1. Trust Boundaries

kirino is a library (`crate-type = ["rlib"]`); it is embedded in a host
application that supplies the persistence layer. The trust boundaries are:

| # | Boundary | Crossing asset | Trust posture |
|---|----------|----------------|---------------|
| B1 | **Host application → kirino** | `Subject`, `Permission`, and the *trusted* trait impls the host provides (`AssignmentStore`, `RoleRegistry`, `PermissionRegistry`) | kirino trusts the host to authenticate the `Subject` *before* asking for an authorization decision. kirino never proves identity. |
| B2 | **Decision engine → stores** | Role/permission/assignment/denial data, from in-memory or PostgreSQL (`rbac-pg-session`) | The engine treats store data as authoritative when present, but treats **store *errors* as deny** (fail-closed). |
| B3 | **Dynamic arbiter → trust/anomaly state** | `TrustScore`s and per-delegator anomaly baselines | Trust is mutable state driven by feedback outcomes; staleness is bounded by time-decay. |
| B4 | **Engine → permission cache** | `(subject, permission) -> bool` decisions cached with a TTL | Cache is a *performance* optimization whose staleness window must be controlled. |

kirino makes **no assumptions about the network**: it neither opens sockets nor
manages transport. All I/O crosses these boundaries through host-supplied trait
implementations.

---

## 2. What kirino Protects Against

### 2.1 Privilege escalation via permission resolution
`RbacEngine::check` (`src/rbac/engine.rs:151`) grants a permission **only** if it
appears in the permission set of a role assigned to the subject. There is no
wildcard or implicit grant. A subject with no matching role is denied
(`engine.rs:185-186`).

### 2.2 Deny-override semantics (fail-closed)
kirino is deny-override throughout. For every check the engine evaluates, in
order (`check_cached_deny_extra`, `engine.rs:108`):

1. **Cache** — if a prior decision exists for `(subject, permission)`, it is
   reused.
2. **Denied permissions** — if the permission is in `denied_permissions`, the
   decision is `false` and **denial is cached**.
3. **Extra permissions** — if present in `extra_permissions`, decision is `true`.
4. **Role permissions** — only then are assigned roles consulted.

Consequence: an explicit **deny always wins** over both role membership and
extra grants (`tests test_deny_override`, `test_deny_overrides_extra`).

Crucially, this is **fail-closed on store errors**: if querying
`denied_permissions` *or* `extra_permissions` *or* `roles_of` returns `Err`, the
check returns `false` and the error is logged but **not cached**
(`engine.rs:120-127`, `137-144`, `154-162`, `176-182`). A transient store outage
therefore degrades to *deny*, never to *allow*.

### 2.3 Role-hierarchy cycles (DoS / infinite recursion)
RBAC2 hierarchy resolution could be driven into infinite recursion by a cyclic
role graph. kirino defends in two ways:

- **`resolve_role_chain`** (`src/rbac/hierarchy/mod.rs:51`) carries a `visited`
  set, so even a cyclic graph terminates and returns the union of reachable
  permissions (`test_resolve_chain_with_cycle_terminates`).
- **`detect_cycle` / `dfs`** (`hierarchy/mod.rs:81`) performs a DFS with a
  recursion-path set to *detect* cycles so they can be rejected at configuration
  time (`test_detect_cycle`, `test_self_cycle`, `test_three_way_cycle`).

### 2.4 Constraint violations (RBAC2 SoD)
`ConstraintValidator` (`src/rbac/constraints/validator.rs`) enforces Static/
Dynamic Separation of Duty (SSD/DSD), prerequisite roles, role cardinality, and
temporal (time-window) validity before a role may be assigned or activated
(`validate_assignment`). This prevents conflicting-role over-assignment and
out-of-window activation.

### 2.5 Stale dynamic authorization
Dynamic authz (`rbac-dynamic`) scores risk on five dimensions and maps it to an
autonomy level (L0–L4). Staleness is bounded on two axes:

- **Trust decay** — `TrustDecayWorker` (spawned via
  `AuthorizationArbiter::spawn_trust_decay`, `arbiter.rs:109`) reduces trust
  scores over time so an idle/compromised delegator drifts toward lower autonomy.
- **Permission cache TTL** — `TtlPermissionCache` (default 300 s,
  `engine.rs:63`) bounds how long a cached decision can diverge from the store,
  and exposes `invalidate_subject_cache` / `invalidate_all_cache` for forced
  refresh on policy change.

### 2.6 Dynamic-authz resource exhaustion
The anomaly-detector map is capped (`MAX_ANOMALY_DETECTORS = 10_000`,
`arbiter.rs:21`); above the cap new delegators fall back to a conservative
default anomaly score rather than growing memory unbounded
(`arbiter.rs:260-282`).

### 2.7 Incident response
`AuthorizationArbiter::lockdown` (`arbiter.rs:338`) freezes a delegator to L0
(every action denied, risk forced to 1.0) and pins a low trust score;
`restore` (`arbiter.rs:362`) reverses it under operator control.

---

## 3. What kirino Does NOT Cover (Out of Scope)

Integrators must not assume kirino provides any of the following:

- **Transport security.** kirino performs no TLS/mTLS. Channel protection is the
  host's responsibility.
- **Secret and key management.** JWT signing keys, Argon2 parameters/secrets,
  and any DB credentials are owned by the host. kirino only *uses* them.
- **Identity proofing / authentication strength.** kirino verifies passwords
  (Argon2, `auth-password`) and JWTs (`auth-jwt`), but the strength of
  credential issuance, MFA enrollment, and recovery flows is out of scope. A
  `Subject` reaching the engine is assumed already authenticated by the host (B1).
- **Timing / side-channel resistance of permission checks.** Decisions use
  `HashSet`/`HashMap` membership tests which are **not** constant-time. Do not
  rely on kirino to hide *which* permission was checked via timing if that is in
  your threat model.
- **Audit log tamper-resistance/durability.** `InMemoryAuditSink` is volatile and
  not tamper-evident; durable/append-only audit storage must be supplied by the
  host.
- **Store implementation correctness.** The in-memory stores use `tokio::sync`
  locks; the correctness, concurrency, and migration of any host-provided store
  (including the PostgreSQL-backed stores) is the integrator's responsibility.
  kirino only guarantees that store *errors* fail closed at the engine boundary.

---

## 4. Failure & Denial Semantics (summary)

| Condition | Result |
|-----------|--------|
| Permission in `denied_permissions` | **Deny** (cached) |
| Store error on denied/extra/roles | **Deny** (not cached; logged) |
| Permission in role set or `extra_permissions` | **Allow** (cached) |
| Dynamic verdict autonomy < L3 | **Deny** (mitigation strategy attached) |
| Delegator locked down (L0) | **Deny**, risk = 1.0 |
| Cyclic hierarchy at resolve time | Terminates; reachable perms returned; cycle detectable via `detect_cycle` |

The invariant is: **absent or failing evidence never yields access.**

---

## 5. External Audit

kirino has **not** undergone a formal third-party security audit. Because it is
authorization-critical, an external review is strongly recommended **before
production deployment**, with particular attention to:

- Fuzzing the hierarchy resolver (`resolve_role_chain`, `detect_cycle`) against
  adversarial/deep/cyclic role graphs.
- Fuzzing the dynamic arbiter (`risk_score`, `authorize`) and policy validator
  (`DynamicPolicy::validate`) against malformed weights and thresholds.
- Review of the timing characteristics noted in §3 for environments where
  permission-set membership is sensitive.
- Review of the fail-closed store-error paths to confirm no code path can convert
  an `Err` into an allow.

Coordinate disclosures via the repository's maintainers; a `SECURITY.md`
reporting policy should accompany production rollout.
