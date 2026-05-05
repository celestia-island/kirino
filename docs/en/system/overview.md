# System Overview

Kirino is a layered authentication and authorization framework. Each layer builds on the one below it, with clear trait boundaries for customization.

```mermaid
graph TD
    subgraph SERVICE["Service Layer"]
        AUTH["AuthService<br/>register / login / verify"]
        SESSION["SessionManager<br/>create / activate / destroy"]
    end

    subgraph AUTHN["Authentication Layer"]
        IDENTITY["Identity<br/>Anonymous / Basic / Temporary / Service"]
        CREDENTIAL["Credential<br/>OneTime / JWT / ServiceToken"]
        PASSPORT["Passport<br/>StaticPassword / KeyPair / OAuth / DynamicPassword / Captcha / Biometric"]
    end

    subgraph AUTHZ["Authorization Layer (RBAC)"]
        ENGINE["RbacEngine<br/>check / check_batch / check_hierarchical"]
        STORE["AssignmentStore<br/>RoleStore"]
        CONSTRAINTS["ConstraintValidator<br/>SSD / DSD / Cardinality / Prerequisite"]
        CACHE["PermissionCache<br/>TTL-based LRU"]
        AUDIT["AuditLogger"]
    end

    subgraph DB["Database Layer"]
        MEMORY["InMemory Stores<br/>(zero-dependency reference impl)"]
        SQL["SQL Backend<br/>(feature: rbac-sql)"]
        REDIS["Redis Cache<br/>(feature: rbac-redis)"]
    end

    IDENTITY --> CREDENTIAL
    CREDENTIAL --> PASSPORT
    PASSPORT --> AUTH
    AUTH --> SESSION
    SESSION --> ENGINE
    ENGINE --> STORE
    ENGINE --> CONSTRAINTS
    ENGINE --> CACHE
    ENGINE --> AUDIT
    STORE --> MEMORY
    STORE --> SQL
    CACHE --> REDIS
```

## Authentication Layer

Kirino authenticates users through a three-step pipeline:

```mermaid
flowchart LR
    I["Identity<br/>Who are you?"]
    C["Credential<br/>Prove it"]
    P["Passport<br/>Challenge accepted"]

    I --> C --> P
```

### Identity Types

| Type | Description |
|------|-------------|
| **Anonymous** | Unauthenticated visitor, minimal permissions |
| **Basic** | Standard user, starts with minimal permissions |
| **Temporary** | Time-limited account, auto-expires |
| **Service** | Service account for permission delegation |

### Credential Types

| Type | Description |
|------|-------------|
| **OneTimeToken** | Single-use token, consumed on first use |
| **Basic (JWT)** | JSON Web Token with claims and expiry |
| **ServiceToken** | Long-lived token for service accounts |

### Passport (Challenge) Types

| Type | Description |
|------|-------------|
| **StaticPassword** | Password verified via argon2 |
| **KeyPair** | SSH key or TLS certificate verification |
| **OAuth** | Third-party OAuth provider |
| **DynamicPassword** | TOTP/HOTP, email code, SMS code |
| **Captcha** | reCAPTCHA or similar bot detection |
| **Biological** | Fingerprint, voice, face recognition |
| **TemporaryWhitelist** | Time-limited whitelist entry |

## Authorization Layer

The RBAC engine follows the ANSI INCITS 359-2004 standard and implements all three RBAC levels:

```mermaid
graph TD
    subgraph RBAC0["RBAC0 — Base"]
        B0["Subject ↔ Role ↔ Permission"]
    end
    subgraph RBAC1["RBAC1 — Hierarchy"]
        B1["Role inheritance with cycle detection"]
    end
    subgraph RBAC2["RBAC2 — Constraints"]
        B2["SSD / DSD / Cardinality / Prerequisite / Temporal"]
    end
    RBAC0 --> RBAC1 --> RBAC2
```

### Core Design Principles

1. **Fully generic**: Downstream projects define their own `Permission` and `Subject` types via traits.
2. **Deny-override semantics**: Denied permissions always take precedence.
3. **In-memory first**: All backends have zero-dependency reference implementations.
4. **Layered**: RBAC0/1/2 are layered as separate impl blocks on `RbacEngine`.
5. **Cache-aware**: Permission checks are cached with TTL for performance.

## Session Management

Sessions bridge authentication and authorization:

```mermaid
sequenceDiagram
    participant U as User
    participant A as AuthService
    participant SM as SessionManager
    participant E as RbacEngine

    U->>A: login(credentials)
    A->>A: verify credentials
    A->>SM: create_session(subject, roles)
    SM->>SM: validate DSD constraints
    SM-->>A: Session
    A-->>U: JWT token
    U->>E: check(permission)
    E->>E: resolve roles → hierarchy → constraints
    E-->>U: allow / deny
```

## Where to Start

- **Quick start**: See [Quick Start Guide](../guides/quick-start.md) for a minimal setup.
- **RBAC concepts**: See [RBAC Core Concepts](../guides/concepts.md) for detailed RBAC theory.
- **Installation**: See [Installation Guide](../guides/installation.md) for feature flags and dependencies.
- **Glossary**: See [Glossary](../guides/glossary.md) for key term definitions.
