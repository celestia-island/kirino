# Security Policy

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.**

Report it privately through GitHub Security Advisories:

> https://github.com/celestia-island/kirino/security/advisories/new

If advisories are unavailable to you, email security@celestia.world with a clear description
and reproduction steps. Include (1) the affected component and version, (2) the attack
vector and impact, (3) reproduction steps, (4) suggested mitigations, and whether you
intend to publish.

## Scope

In scope, across the organization:

- authentication bypass, JWT/OAuth weaknesses, session handling flaws;
- API key or credential disclosure, or improper storage;
- authorization and RBAC enforcement gaps, cross-tenant or cross-workspace access;
- injection (SQL, command, SSRF, XSS), insecure deserialization, path traversal;
- anything that lets a network peer reach a hardware command path, a safety interlock,
  or a write whitelist without an explicit operator grant;
- billing-ledger integrity: minting, double spending, or unbalanced entries;
- supply chain: build scripts, CI workflows, dependency confusion, artefact substitution.

Out of scope:

- vulnerabilities in upstream dependencies that are not exploitable through this project;
- self-hosted deployments configured against documented guidance;
- denial of service against public model-provider endpoints.

## Response targets

| Stage | Target |
|---|---|
| Agent acknowledgment | 10 minutes |
| Human acknowledgment | 1 calendar day |
| Initial assessment | 3 calendar days |
| Fix or mitigation | 30 calendar days, severity-dependent |

## What we will not accept

Bulk, machine-generated reports that were never verified against a running build, and
reports that consist only of scanner output. They will be closed without review. This
is a deliberate policy against report flooding, not a dismissal of genuine findings.

## Supported versions

Only the current default branch (`master`; a few repositories use `main`) receives
security fixes. The retired `dev` branch model is not supported — do not report against
it and do not open pull requests against it.

---
*Canonical file maintained in the organization metadata repository; changes apply to
every repository that adopts it.*

<!-- repository-specific notes below this line -->
## Repository-specific security notes

`kirino` is a security-critical authorization library: a single incorrect
authorization decision is a privilege-escalation vulnerability. The following
notes are specific to this repository and extend the policy above.

### What to include in a report

- a clear description of the vulnerability and its security impact;
- the version of `kirino` affected, and the feature flags in use;
- a minimal reproduction — a code sample, role graph, or input that triggers it;
- any suggested mitigation.

### Response expectations

- **acknowledgement**: within **3 business days**;
- **initial assessment**: within **14 days**, including a severity rating and a
  planned remediation timeline;
- **coordinated disclosure**: we work with you on a public advisory once a fix is
  available. Please refrain from public disclosure until a patch is released, or
  until we mutually agree otherwise.

### Supported versions

Only the latest released minor line receives security fixes. Pre-1.0 versions
allow breaking changes between minor versions under SemVer, so older lines are
not maintained.

| Version | Supported |
|---|---|
| 0.6.x | yes |
| < 0.6 | no |

### Surfaces of particular interest

Authorization decisions and grant resolution, session and token handling
(`kirino-session`), the RBAC engine and workspace/group guards, password and
passkey verification, and the invitation store.
