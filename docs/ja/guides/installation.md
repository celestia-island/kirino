# インストール

## Cargo.toml

```toml
[dependencies]
kirino = "0.1"
```

## フィーチャーフラグ

| フィーチャー | 説明 | 依存関係 |
|---------|-------------|--------------|
| (デフォルト) | RBAC コア + インメモリバックエンド | — |
| `rbac-core` | RBAC trait とエンジンのみ | — |
| `rbac-inmemory` | インメモリ割り当て/ロールストア | `rbac-core` |
| `rbac-hierarchy` | RBAC1 階層型ロール継承 | `rbac-core` |
| `rbac-constraints` | RBAC2 制約モデル (SSD/DSD) | `rbac-core` |
| `rbac-sql` | SQL ベースの永続ストア | `sqlx` |
| `rbac-sea-orm` | SeaORM エンティティモデル | `sea-orm` |
| `rbac-redis` | Redis ベースのパーミッションキャッシュ | `redis` |
| `rbac-full` | すべての機能を有効化 | 上記すべて |

### 例：フル機能セットアップ

```toml
[dependencies]
kirino = { version = "0.1", features = ["rbac-full"] }
```

### 例：最小構成

```toml
[dependencies]
kirino = { version = "0.1", default-features = false, features = ["rbac-core"] }
```

## インストールの確認

```bash
cargo build
cargo test
```

すべてのテストがエラーなく通過することを確認してください。

## 要件

- Rust 1.75+（edition 2021）
- オプション：PostgreSQL（`rbac-sql` 用）、Redis（`rbac-redis` 用）、SeaORM CLI（`rbac-sea-orm` 用）
