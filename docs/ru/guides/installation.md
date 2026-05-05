# Установка

## Cargo.toml

```toml
[dependencies]
kirino = "0.1"
```

## Флаги функциональности

| Функция | Описание | Зависимости |
|---------|-------------|--------------|
| (по умолчанию) | Ядро RBAC + бэкенды в памяти | — |
| `rbac-core` | Только trait и движок RBAC | — |
| `rbac-inmemory` | Хранилища назначений/ролей в памяти | `rbac-core` |
| `rbac-hierarchy` | RBAC1 иерархическое наследование ролей | `rbac-core` |
| `rbac-constraints` | RBAC2 модели ограничений (SSD/DSD) | `rbac-core` |
| `rbac-sql` | Постоянные хранилища на основе SQL | `sqlx` |
| `rbac-sea-orm` | Модели сущностей SeaORM | `sea-orm` |
| `rbac-redis` | Кэш разрешений на основе Redis | `redis` |
| `rbac-full` | Все функции включены | всё выше |

### Пример: полная конфигурация

```toml
[dependencies]
kirino = { version = "0.1", features = ["rbac-full"] }
```

### Пример: минимальная конфигурация

```toml
[dependencies]
kirino = { version = "0.1", default-features = false, features = ["rbac-core"] }
```

## Проверка установки

```bash
cargo build
cargo test
```

Все тесты должны проходить без ошибок.

## Требования

- Rust 1.75+ (edition 2021)
- Опционально: PostgreSQL (для `rbac-sql`), Redis (для `rbac-redis`), SeaORM CLI (для `rbac-sea-orm`)
