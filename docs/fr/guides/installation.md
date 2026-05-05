# Installation

## Cargo.toml

```toml
[dependencies]
kirino = "0.1"
```

## Drapeaux de Fonctionnalité

| Fonctionnalité | Description | Dépendances |
|---------|-------------|--------------|
| (par défaut) | Cœur RBAC + backends en mémoire | — |
| `rbac-core` | Traits et moteur RBAC uniquement | — |
| `rbac-inmemory` | Stockages d'assignation/rôles en mémoire | `rbac-core` |
| `rbac-hierarchy` | RBAC1 héritage hiérarchique des rôles | `rbac-core` |
| `rbac-constraints` | RBAC2 modèles de contraintes (SSD/DSD) | `rbac-core` |
| `rbac-sql` | Stockages persistants basés SQL | `sqlx` |
| `rbac-sea-orm` | Modèles d'entité SeaORM | `sea-orm` |
| `rbac-redis` | Cache de permissions basé Redis | `redis` |
| `rbac-full` | Toutes les fonctionnalités activées | tout ce qui précède |

### Exemple : Configuration complète

```toml
[dependencies]
kirino = { version = "0.1", features = ["rbac-full"] }
```

### Exemple : Configuration minimale

```toml
[dependencies]
kirino = { version = "0.1", default-features = false, features = ["rbac-core"] }
```

## Vérifier l'Installation

```bash
cargo build
cargo test
```

Tous les tests doivent passer sans erreur.

## Exigences

- Rust 1.75+ (edition 2021)
- Optionnel : PostgreSQL (pour `rbac-sql`), Redis (pour `rbac-redis`), SeaORM CLI (pour `rbac-sea-orm`)
