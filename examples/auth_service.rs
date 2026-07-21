use kirino::{
    database::memory::InMemoryUserDatabase,
    rbac::permission::Permission,
    service::login::{build_default_engine, AuthService},
};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let db = InMemoryUserDatabase::new();
    let engine = build_default_engine();

    let service = AuthService::new(
        db,
        "my-jwt-secret-key-that-is-at-least-32-bytes-long",
        24,
        engine,
        "admin",
        "viewer",
    ).unwrap().with_auto_admin_first_user(true);

    let alice = service.register("alice", "SecureP@ss1", Some("Alice")).await.unwrap();
    let bob = service.register("bob", "AnotherP@ss2", None).await.unwrap();

    let login = service.login("alice", "SecureP@ss1").await.unwrap();
    let _claims = service.verify_token(&login.token).await.unwrap();

    let _ = service.check_permission(&alice.id.to_string(), &Permission::from_path("system.write").unwrap()).await;
    let _ = service.check_permission(&bob.id.to_string(), &Permission::from_path("system.write").unwrap()).await;
    let _ = service.check_permission(&bob.id.to_string(), &Permission::from_path("agent.read").unwrap()).await;
}
