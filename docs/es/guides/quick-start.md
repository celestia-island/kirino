# Inicio Rápido

## Requisitos Previos
- Rust (edition 2021, se recomienda stable)
- Un proyecto para integrar kirino

## Agregar Dependencia

Agrega kirino a tu `Cargo.toml`:

```toml
[dependencies]
kirino = "0.1"
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
```

## Definir Tus Permisos

```rust
use serde::{Deserialize, Serialize};
use kirino::rbac::traits::Permission;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
enum MyPermission {
    DocumentRead,
    DocumentWrite,
    UserManage,
    SystemAdmin,
}

impl Permission for MyPermission {
    fn name(&self) -> &str {
        match self {
            Self::DocumentRead => "document:read",
            Self::DocumentWrite => "document:write",
            Self::UserManage => "user:manage",
            Self::SystemAdmin => "system:admin",
        }
    }

    fn domain(&self) -> &str {
        match self {
            Self::DocumentRead | Self::DocumentWrite => "document",
            Self::UserManage => "user",
            Self::SystemAdmin => "system",
        }
    }
}
```

## Configurar el Motor RBAC

```rust
use kirino::rbac::prelude::*;

async fn build_engine() -> RbacEngine<
    StringSubject,
    MyPermission,
    SimpleRole<MyPermission>,
    InMemoryAssignmentStore<StringSubject, SimpleRole<MyPermission>, MyPermission>,
> {
    // 1. Registrar todos los permisos conocidos
    let perm_registry = StaticPermissionRegistry::from_set(
        [MyPermission::DocumentRead, MyPermission::DocumentWrite,
         MyPermission::UserManage, MyPermission::SystemAdmin].into()
    );

    // 2. Definir roles con sus conjuntos de permisos
    let mut role_registry = StaticRoleRegistry::new();
    role_registry.register(SimpleRole::new("admin", [MyPermission::DocumentRead,
        MyPermission::DocumentWrite, MyPermission::UserManage, MyPermission::SystemAdmin].into()));
    role_registry.register(SimpleRole::new("editor", [MyPermission::DocumentRead,
        MyPermission::DocumentWrite].into()));
    role_registry.register(SimpleRole::new("viewer", [MyPermission::DocumentRead].into()));

    // 3. Crear almacenes en memoria
    let assignment_store = InMemoryAssignmentStore::new();
    let role_store = InMemoryRoleStore::new();

    // 4. Construir el motor
    RbacEngine::new(
        Arc::new(role_registry),
        Arc::new(perm_registry),
        Arc::new(assignment_store),
    )
}
```

## Verificar Permisos

```rust
#[tokio::main]
async fn main() {
    let engine = build_engine().await;

    // Asignar rol admin a un usuario
    let alice = StringSubject::new("alice");
    engine.assign_role(&alice, "admin").await.unwrap();

    // Verificar permiso
    assert!(engine.check(&alice, &MyPermission::DocumentWrite).await);
    assert!(!engine.check(&alice, &MyPermission::SystemAdmin).await);
}
```

## Usar el AuthService Integrado

Para una configuración completa con autenticación, usa `AuthService`:

```rust
use kirino::service::login::{AuthService, build_default_engine};
use std::sync::Arc;

let engine = Arc::new(build_default_engine());
let service = AuthService::new(engine);

// El primer usuario registrado obtiene automáticamente el rol admin
service.register("admin", "password123").await.unwrap();
let token = service.login("admin", "password123").await.unwrap();
```

## Verificar

```bash
cargo build
cargo test
```
