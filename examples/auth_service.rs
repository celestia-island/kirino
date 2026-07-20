use kirino::{
    database::memory::InMemoryUserDatabase,
    rbac::permission::Permission as KirinoPermission,
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
    )
    .unwrap()
    .with_auto_admin_first_user(true);

    let alice = service
        .register("alice", "SecureP@ss1", Some("Alice"))
        .await
        .unwrap();
    println!("Registered: {} (id: {})", alice.username, alice.id);

    let bob = service.register("bob", "AnotherP@ss2", None).await.unwrap();
    println!("Registered: {} (id: {})", bob.username, bob.id);

    let login = service.login("alice", "SecureP@ss1").await.unwrap();
    println!("\nAlice logged in:");
    println!("  Token: {}...", &login.token[..50]);
    println!("  Roles: {:?}", login.roles);

    let claims = service.verify_token(&login.token).await.unwrap();
    println!("  Token verified for subject: {}", claims.sub);

    let can_manage = service
        .check_permission(&alice.id.to_string(), &KirinoPermission::SystemWrite)
        .await;
    println!("\nAlice can manage system: {can_manage}");

    let can_manage = service
        .check_permission(&bob.id.to_string(), &KirinoPermission::SystemWrite)
        .await;
    println!("Bob can manage system:   {can_manage}");

    let can_read = service
        .check_permission(&bob.id.to_string(), &KirinoPermission::AgentRead)
        .await;
    println!("Bob can read agents:     {can_read}");

    let users = service.list_users().await.unwrap();
    println!("\nAll users ({}):", users.len());
    for u in &users {
        println!("  - {} ({})", u.username, u.id);
    }
}
