# 安裝

## Cargo.toml

```toml
[dependencies]
kirino = "0.1"
```

## 功能旗標

| 功能 | 說明 | 依賴 |
|---------|-------------|--------------|
| (預設) | RBAC 核心 + 記憶體後端 | — |
| `rbac-core` | 僅 RBAC trait 和引擎 | — |
| `rbac-inmemory` | 記憶體指派/角色儲存 | `rbac-core` |
| `rbac-hierarchy` | RBAC1 層級角色繼承 | `rbac-core` |
| `rbac-constraints` | RBAC2 約束模型 (SSD/DSD) | `rbac-core` |
| `rbac-sql` | 基於 SQL 的持久化儲存 | `sqlx` |
| `rbac-sea-orm` | SeaORM 實體模型 | `sea-orm` |
| `rbac-redis` | 基於 Redis 的權限快取 | `redis` |
| `rbac-full` | 所有功能啟用 | 全部上述 |

### 範例：全功能設定

```toml
[dependencies]
kirino = { version = "0.1", features = ["rbac-full"] }
```

### 範例：最小設定

```toml
[dependencies]
kirino = { version = "0.1", default-features = false, features = ["rbac-core"] }
```

## 驗證安裝

```bash
cargo build
cargo test
```

所有測試應該無錯誤通過。

## 需求

- Rust 1.75+（edition 2021）
- 可選：PostgreSQL（用於 `rbac-sql`）、Redis（用於 `rbac-redis`）、SeaORM CLI（用於 `rbac-sea-orm`）
