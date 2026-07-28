# 安装

## Cargo.toml

```toml
[dependencies]
kirino = "0.1"
```

## 功能标志

| 功能 | 描述 | 依赖 |
|---------|-------------|--------------|
| (默认) | RBAC 核心 + 内存后端 | — |
| `rbac-core` | 仅 RBAC trait 和引擎 | — |
| `rbac-inmemory` | 内存分配/角色存储 | `rbac-core` |
| `rbac-hierarchy` | RBAC1 层级角色继承 | `rbac-core` |
| `rbac-constraints` | RBAC2 约束模型 (SSD/DSD) | `rbac-core` |
| `rbac-sql` | 基于 SQL 的持久化存储 | `sqlx` |
| `rbac-sea-orm` | SeaORM 实体模型 | `sea-orm` |
| `rbac-redis` | 基于 Redis 的权限缓存 | `redis` |
| `rbac-full` | 所有功能启用 | 全部上述 |

### 示例：全功能配置

```toml
[dependencies]
kirino = { version = "0.1", features = ["rbac-full"] }
```

### 示例：最小配置

```toml
[dependencies]
kirino = { version = "0.1", default-features = false, features = ["rbac-core"] }
```

## 验证安装

```bash
cargo build
cargo test
```

所有测试应该无错误通过。

## 要求

- Rust 1.75+（edition 2021）
- 可选：PostgreSQL（用于 `rbac-sql`）、Redis（用于 `rbac-redis`）、SeaORM CLI（用于 `rbac-sea-orm`）
