# البدء السريع

## المتطلبات المسبقة
- لغة Rust (الإصدار 2021، يُنصح بالقناة المستقرة)
- مشروع تريد دمج kirino ضمنه

## إضافة التبعية

أضِف kirino إلى ملف `Cargo.toml` الخاص بك:

```toml
[dependencies]
kirino = "0.1"
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
```

## تعريف الصلاحيات الخاصة بك

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

## إعداد محرّك RBAC

```rust
use kirino::rbac::prelude::*;

async fn build_engine() -> RbacEngine<
    StringSubject,
    MyPermission,
    SimpleRole<MyPermission>,
    InMemoryAssignmentStore<StringSubject, SimpleRole<MyPermission>, MyPermission>,
> {
    // 1. تسجيل جميع الصلاحيات المعروفة
    let perm_registry = StaticPermissionRegistry::from_set(
        [MyPermission::DocumentRead, MyPermission::DocumentWrite,
         MyPermission::UserManage, MyPermission::SystemAdmin].into()
    );

    // 2. تعريف الأدوار مع مجموعات صلاحياتها
    let mut role_registry = StaticRoleRegistry::new();
    role_registry.register(SimpleRole::new("admin", [MyPermission::DocumentRead,
        MyPermission::DocumentWrite, MyPermission::UserManage, MyPermission::SystemAdmin].into()));
    role_registry.register(SimpleRole::new("editor", [MyPermission::DocumentRead,
        MyPermission::DocumentWrite].into()));
    role_registry.register(SimpleRole::new("viewer", [MyPermission::DocumentRead].into()));

    // 3. إنشاء المخازن في الذاكرة
    let assignment_store = InMemoryAssignmentStore::new();
    let role_store = InMemoryRoleStore::new();

    // 4. بناء المحرّك
    RbacEngine::new(
        Arc::new(role_registry),
        Arc::new(perm_registry),
        Arc::new(assignment_store),
    )
}
```

## التحقق من الصلاحيات

```rust
#[tokio::main]
async fn main() {
    let engine = build_engine().await;

    // إسناد دور المدير لأحد المستخدمين
    let alice = StringSubject::new("alice");
    engine.assign_role(&alice, "admin").await.unwrap();

    // التحقق من الصلاحية
    assert!(engine.check(&alice, &MyPermission::DocumentWrite).await);
    assert!(!engine.check(&alice, &MyPermission::SystemAdmin).await);
}
```

## استخدام AuthService المدمج

لإعداد كامل مع المصادقة، استخدم `AuthService`:

```rust
use kirino::service::login::{AuthService, build_default_engine};
use std::sync::Arc;

let engine = Arc::new(build_default_engine());
let service = AuthService::new(engine);

// يحصل أول مستخدم على دور المدير تلقائياً
service.register("admin", "password123").await.unwrap();
let token = service.login("admin", "password123").await.unwrap();
```

## التحقق

```bash
cargo build
cargo test
```
