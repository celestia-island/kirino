# Démarrage Rapide

## Prérequis
- Rust (edition 2021, stable recommandé)
- Un projet pour intégrer kirino

## Ajouter la Dépendance

Ajoutez kirino à votre `Cargo.toml` :

```toml
[dependencies]
kirino = "0.1"
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
```

## Définir Vos Permissions

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

## Configurer le Moteur RBAC

```rust
use kirino::rbac::prelude::*;

async fn build_engine() -> RbacEngine<
    StringSubject,
    MyPermission,
    SimpleRole<MyPermission>,
    InMemoryAssignmentStore<StringSubject, SimpleRole<MyPermission>, MyPermission>,
> {
    // 1. Enregistrer toutes les permissions connues
    let perm_registry = StaticPermissionRegistry::from_set(
        [MyPermission::DocumentRead, MyPermission::DocumentWrite,
         MyPermission::UserManage, MyPermission::SystemAdmin].into()
    );

    // 2. Définir les rôles avec leurs ensembles de permissions
    let mut role_registry = StaticRoleRegistry::new();
    role_registry.register(SimpleRole::new("admin", [MyPermission::DocumentRead,
        MyPermission::DocumentWrite, MyPermission::UserManage, MyPermission::SystemAdmin].into()));
    role_registry.register(SimpleRole::new("editor", [MyPermission::DocumentRead,
        MyPermission::DocumentWrite].into()));
    role_registry.register(SimpleRole::new("viewer", [MyPermission::DocumentRead].into()));

    // 3. Créer les stockages en mémoire
    let assignment_store = InMemoryAssignmentStore::new();
    let role_store = InMemoryRoleStore::new();

    // 4. Construire le moteur
    RbacEngine::new(
        Arc::new(role_registry),
        Arc::new(perm_registry),
        Arc::new(assignment_store),
    )
}
```

## Vérifier les Permissions

```rust
#[tokio::main]
async fn main() {
    let engine = build_engine().await;

    // Assigner le rôle admin à un utilisateur
    let alice = StringSubject::new("alice");
    engine.assign_role(&alice, "admin").await.unwrap();

    // Vérifier la permission
    assert!(engine.check(&alice, &MyPermission::DocumentWrite).await);
    assert!(!engine.check(&alice, &MyPermission::SystemAdmin).await);
}
```

## Utiliser l'AuthService Intégré

Pour une configuration complète avec authentification, utilisez `AuthService` :

```rust
use kirino::service::login::{AuthService, build_default_engine};
use std::sync::Arc;

let engine = Arc::new(build_default_engine());
let service = AuthService::new(engine);

// Le premier utilisateur enregistré obtient automatiquement le rôle admin
service.register("admin", "password123").await.unwrap();
let token = service.login("admin", "password123").await.unwrap();
```

## Vérifier

```bash
cargo build
cargo test
```
