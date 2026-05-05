# Installation

## Cargo.toml

```toml
[dependencies]
kirino = "0.1"
```

## Feature Flags

| Feature | Description | Dependencies |
|---------|-------------|--------------|
| (default) | RBAC core + in-memory backends | — |
| `rbac-core` | RBAC traits + engine only | — |
| `rbac-inmemory` | In-memory assignment/role stores | `rbac-core` |
| `rbac-hierarchy` | RBAC1 hierarchical role inheritance | `rbac-core` |
| `rbac-constraints` | RBAC2 constraint models (SSD/DSD) | `rbac-core` |
| `rbac-sql` | SQL-based persistent stores | `sqlx` |
| `rbac-sea-orm` | SeaORM entity models | `sea-orm` |
| `rbac-redis` | Redis-based permission cache | `redis` |
| `rbac-full` | All features enabled | all above |

### Example: Full-featured setup

```toml
[dependencies]
kirino = { version = "0.1", features = ["rbac-full"] }
```

### Example: Minimal setup

```toml
[dependencies]
kirino = { version = "0.1", default-features = false, features = ["rbac-core"] }
```

## Verify Installation

```bash
cargo build
cargo test
```

All tests should pass without errors.

## Requirements

- Rust 1.75+ (edition 2021)
- Optional: PostgreSQL (for `rbac-sql`), Redis (for `rbac-redis`), SeaORM CLI (for `rbac-sea-orm`)
