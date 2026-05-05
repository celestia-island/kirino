# Instalación

## Cargo.toml

```toml
[dependencies]
kirino = "0.1"
```

## Banderas de Funcionalidad

| Funcionalidad | Descripción | Dependencias |
|---------|-------------|--------------|
| (por defecto) | Núcleo RBAC + backends en memoria | — |
| `rbac-core` | Solo traits y motor RBAC | — |
| `rbac-inmemory` | Almacenes de asignación/roles en memoria | `rbac-core` |
| `rbac-hierarchy` | RBAC1 herencia jerárquica de roles | `rbac-core` |
| `rbac-constraints` | RBAC2 modelos de restricción (SSD/DSD) | `rbac-core` |
| `rbac-sql` | Almacenes persistentes basados en SQL | `sqlx` |
| `rbac-sea-orm` | Modelos de entidad SeaORM | `sea-orm` |
| `rbac-redis` | Caché de permisos basado en Redis | `redis` |
| `rbac-full` | Todas las funcionalidades habilitadas | todo lo anterior |

### Ejemplo: Configuración completa

```toml
[dependencies]
kirino = { version = "0.1", features = ["rbac-full"] }
```

### Ejemplo: Configuración mínima

```toml
[dependencies]
kirino = { version = "0.1", default-features = false, features = ["rbac-core"] }
```

## Verificar Instalación

```bash
cargo build
cargo test
```

Todas las pruebas deben pasar sin errores.

## Requisitos

- Rust 1.75+ (edition 2021)
- Opcional: PostgreSQL (para `rbac-sql`), Redis (para `rbac-redis`), SeaORM CLI (para `rbac-sea-orm`)
