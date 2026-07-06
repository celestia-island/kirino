# Security Policy

## Reporting a Vulnerability

kirino is a security-critical authorization library: a single incorrect
authorization decision is a privilege-escalation vulnerability. We take security
reports seriously and welcome responsible disclosure.

**Please do NOT open a public GitHub issue for security vulnerabilities.**

Instead, report vulnerabilities privately using **GitHub's private vulnerability
reporting**:

1. Go to <https://github.com/celestia-island/kirino/security/advisories/new>
2. Fill in the advisory form with a description, reproduction steps, and impact.
3. Submit the report — it is visible only to the repository maintainers.

If GitHub private reporting is unavailable, contact the maintainers directly via
the contact listed on the celestia-island organization profile.

Please include the following when possible:

- A clear description of the vulnerability and its security impact.
- The version of kirino affected (and the feature flags in use).
- A minimal reproduction (code sample, role graph, or input that triggers it).
- Any suggested mitigations.

### Response Expectations

- **Acknowledgement**: within **3 business days**.
- **Initial assessment**: within **14 days**, including a severity rating and a
  planned remediation timeline.
- **Coordinated disclosure**: we will work with you on a public advisory once a
  fix is available. Please refrain from public disclosure until a patch is
  released, or until we mutually agree otherwise.

## Supported Versions

Only the latest released minor line receives security fixes. Pre-1.0 versions
allow breaking changes between minor versions per SemVer, so older lines are not
maintained.

| Version | Supported          |
|---------|--------------------|
| 0.5.x   | :white_check_mark: |
| < 0.5   | :x:                |

## Scope

### In Scope

- kirino's RBAC engine (`src/rbac/`) — permission resolution, deny-override
  semantics, role-hierarchy resolution and cycle handling.
- The dynamic authorization arbiter (`rbac-dynamic` feature) — risk scoring,
  trust decay, anomaly detection, lockdown/restore.
- Constraint enforcement (RBAC2: SSD/DSD/cardinality/prerequisite/temporal).
- Authentication helpers shipped with the crate (Argon2 verification under
  `auth-password`, JWT issuance/verification under `auth-jwt`).
- Fail-closed behavior on store errors at the engine boundary.

### Out of Scope

The following are explicitly **out of scope** and documented as such in
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md). Reports about them will be closed;
see the threat model for the responsibilities that fall on the host application:

- Transport security (TLS/mTLS) — kirino performs none; the host owns channels.
- Secret and key management — JWT keys, Argon2 parameters, and DB credentials
  are owned and provisioned by the host.
- Identity proofing / authentication strength — a `Subject` reaching the engine
  is assumed already authenticated by the host.
- Timing / side-channel resistance of permission checks — decision paths use
  `HashSet`/`HashMap` membership tests that are **not** constant-time.
- Durability or tamper-resistance of audit logs — the in-memory audit sink is
  volatile; durable/append-only audit storage is the host's responsibility.
- Correctness, concurrency, and schema migration of host-provided persistence
  backends (including the PostgreSQL-backed stores). kirino only guarantees that
  store *errors* fail closed at the engine boundary.

## Security Audit Status

**kirino has not undergone a formal third-party security audit.**

It is authorization-critical infrastructure, and an external review is strongly
recommended before production deployment. See
[docs/THREAT_MODEL.md §5 External Audit](docs/THREAT_MODEL.md#5-external-audit)
for the recommended review focus areas (fuzzing the hierarchy resolver, the
dynamic arbiter, the policy validator, the fail-closed store-error paths, and
the timing characteristics noted above) and the open audit items tracked in
[PLAN.md](PLAN.md).

Until such an audit is completed and published here, integrators should perform
their own review appropriate to their threat model.
