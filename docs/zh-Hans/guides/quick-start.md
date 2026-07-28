# 快速开始

## 前置条件
- Rust（edition 2021，推荐 stable）
- 一个需要集成 kirino 的项目

## 添加依赖

在 `Cargo.toml` 中添加 kirino：

```toml
[dependencies]
kirino = "0.1"
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
```

## 定义你的权限

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

## 搭建 RBAC 引擎

```rust
use kirino::rbac::prelude::*;

async fn build_engine() -> RbacEngine<
    StringSubject,
    MyPermission,
    SimpleRole<MyPermission>,
    InMemoryAssignmentStore<StringSubject, SimpleRole<MyPermission>, MyPermission>,
> {
    // 1. 注册所有已知权限
    let perm_registry = StaticPermissionRegistry::from_set(
        [MyPermission::DocumentRead, MyPermission::DocumentWrite,
         MyPermission::UserManage, MyPermission::SystemAdmin].into()
    );

    // 2. 定义角色及其权限集合
    let mut role_registry = StaticRoleRegistry::new();
    role_registry.register(SimpleRole::new("admin", [MyPermission::DocumentRead,
        MyPermission::DocumentWrite, MyPermission::UserManage, MyPermission::SystemAdmin].into()));
    role_registry.register(SimpleRole::new("editor", [MyPermission::DocumentRead,
        MyPermission::DocumentWrite].into()));
    role_registry.register(SimpleRole::new("viewer", [MyPermission::DocumentRead].into()));

    // 3. 创建内存存储
    let assignment_store = InMemoryAssignmentStore::new();
    let role_store = InMemoryRoleStore::new();

    // 4. 构建引擎
    RbacEngine::new(
        Arc::new(role_registry),
        Arc::new(perm_registry),
        Arc::new(assignment_store),
    )
}
```

## 检查权限

```rust
#[tokio::main]
async fn main() {
    let engine = build_engine().await;

    // 为用户分配 admin 角色
    let alice = StringSubject::new("alice");
    engine.assign_role(&alice, "admin").await.unwrap();

    // 检查权限
    assert!(engine.check(&alice, &MyPermission::DocumentWrite).await);
    assert!(!engine.check(&alice, &MyPermission::SystemAdmin).await);
}
```

## 使用内置 AuthService

如需完整的认证设置，可使用 `AuthService`：

```rust
use kirino::service::login::{AuthService, build_default_engine};
use std::sync::Arc;

let engine = Arc::new(build_default_engine());
let service = AuthService::new(engine);

// 第一个注册的用户自动获得 admin 角色
service.register("admin", "password123").await.unwrap();
let token = service.login("admin", "password123").await.unwrap();
```

## 验证

```bash
cargo build
cargo test
```
