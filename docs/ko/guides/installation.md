# 설치

## Cargo.toml

```toml
[dependencies]
kirino = "0.1"
```

## 기능 플래그

| 기능 | 설명 | 의존성 |
|---------|-------------|--------------|
| (기본값) | RBAC 코어 + 인메모리 백엔드 | — |
| `rbac-core` | RBAC trait 및 엔진만 | — |
| `rbac-inmemory` | 인메모리 할당/역할 저장소 | `rbac-core` |
| `rbac-hierarchy` | RBAC1 계층형 역할 상속 | `rbac-core` |
| `rbac-constraints` | RBAC2 제약 모델 (SSD/DSD) | `rbac-core` |
| `rbac-sql` | SQL 기반 영구 저장소 | `sqlx` |
| `rbac-sea-orm` | SeaORM 엔티티 모델 | `sea-orm` |
| `rbac-redis` | Redis 기반 권한 캐시 | `redis` |
| `rbac-full` | 모든 기능 활성화 | 위 모두 |

### 예제: 전체 기능 설정

```toml
[dependencies]
kirino = { version = "0.1", features = ["rbac-full"] }
```

### 예제: 최소 설정

```toml
[dependencies]
kirino = { version = "0.1", default-features = false, features = ["rbac-core"] }
```

## 설치 확인

```bash
cargo build
cargo test
```

모든 테스트가 오류 없이 통과해야 합니다.

## 요구사항

- Rust 1.75+ (edition 2021)
- 선택: PostgreSQL (`rbac-sql`용), Redis (`rbac-redis`용), SeaORM CLI (`rbac-sea-orm`용)
