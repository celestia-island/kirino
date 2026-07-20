use kirino::rbac::{
    prelude::*,
    store::registry::{SimpleRole, StaticPermissionRegistry, StaticRoleRegistry},
    traits::Permission as PermissionTrait,
};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum MyPermission {
    DocumentRead,
    DocumentWrite,
    UserManage,
}

impl PermissionTrait for MyPermission {
    fn name(&self) -> &str {
        match self {
            Self::DocumentRead => "document:read",
            Self::DocumentWrite => "document:write",
            Self::UserManage => "user:manage",
        }
    }

    fn domain(&self) -> &'static str {
        match self {
            Self::DocumentRead | Self::DocumentWrite => "document",
            Self::UserManage => "user",
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let mut role_reg = StaticRoleRegistry::new();
    role_reg.register(SimpleRole::new(
        "admin",
        [
            MyPermission::DocumentRead,
            MyPermission::DocumentWrite,
            MyPermission::UserManage,
        ]
        .into(),
    ));
    role_reg.register(SimpleRole::new(
        "viewer",
        [MyPermission::DocumentRead].into(),
    ));

    let perm_reg = StaticPermissionRegistry::new(
        [
            MyPermission::DocumentRead,
            MyPermission::DocumentWrite,
            MyPermission::UserManage,
        ]
        .into(),
    );

    let store = InMemoryAssignmentStore::new();
    let engine = RbacEngine::new(role_reg, perm_reg, store);

    let alice = StringSubject::new("alice");
    let bob = StringSubject::new("bob");

    engine
        .assignment_store()
        .assign_role(&alice, "admin")
        .await
        .unwrap();
    engine
        .assignment_store()
        .assign_role(&bob, "viewer")
        .await
        .unwrap();

    assert!(engine.check(&alice, &MyPermission::DocumentWrite).await);
    assert!(engine.check(&bob, &MyPermission::DocumentRead).await);
    assert!(!engine.check(&bob, &MyPermission::DocumentWrite).await);

    println!("Alice can write documents: true");
    println!("Bob can read documents:    true");
    println!("Bob can write documents:   false");
}
