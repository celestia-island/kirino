use crate::database::sql::InMemoryUserDatabase;
use crate::service::login::AuthService;
#[allow(deprecated)]
use crate::rbac::compat::{Permission, Role, RbacStore};

#[tokio::test]
async fn test_register_and_login() {
    let db = InMemoryUserDatabase::new();
    let auth = AuthService::new(db, "test-secret", 24);

    let user = auth.register("alice", "password123", Some("Alice")).await.unwrap();
    assert_eq!(user.username, "alice");
    assert_eq!(user.display_name, Some("Alice".to_string()));

    let result = auth.login("alice", "password123").await.unwrap();
    assert_eq!(result.username, "alice");
    assert!(!result.token.is_empty());

    let claims = auth.verify_token(&result.token).await.unwrap();
    assert_eq!(claims.sub, "alice");
}

#[tokio::test]
async fn test_first_user_is_admin() {
    let db = InMemoryUserDatabase::new();
    let auth = AuthService::new(db, "test-secret", 24);

    auth.register("admin", "password123", None).await.unwrap();
    assert!(auth.check_permission(
        &auth.login("admin", "password123").await.unwrap().user_id,
        Permission::SystemWrite
    ).await);
}

#[tokio::test]
async fn test_second_user_is_viewer() {
    let db = InMemoryUserDatabase::new();
    let auth = AuthService::new(db, "test-secret", 24);

    auth.register("admin", "password123", None).await.unwrap();
    auth.register("viewer", "password123", None).await.unwrap();

    let viewer_id = auth.login("viewer", "password123").await.unwrap().user_id;
    assert!(auth.check_permission(&viewer_id, Permission::AgentRead).await);
    assert!(!auth.check_permission(&viewer_id, Permission::SystemWrite).await);
}

#[tokio::test]
async fn test_wrong_password() {
    let db = InMemoryUserDatabase::new();
    let auth = AuthService::new(db, "test-secret", 24);

    auth.register("alice", "password123", None).await.unwrap();
    assert!(auth.login("alice", "wrong").await.is_err());
}

#[tokio::test]
async fn test_change_password() {
    let db = InMemoryUserDatabase::new();
    let auth = AuthService::new(db, "test-secret", 24);

    let user = auth.register("alice", "old_password", None).await.unwrap();
    auth.change_password(&user.id.to_string(), "old_password", "new_password")
        .await
        .unwrap();

    assert!(auth.login("alice", "old_password").await.is_err());
    assert!(auth.login("alice", "new_password").await.is_ok());
}

#[tokio::test]
async fn test_delete_user() {
    let db = InMemoryUserDatabase::new();
    let auth = AuthService::new(db, "test-secret", 24);

    let user = auth.register("alice", "password123", None).await.unwrap();
    assert!(auth.delete_user(&user.id.to_string()).await.unwrap());
    assert!(auth.login("alice", "password123").await.is_err());
}

#[tokio::test]
async fn test_duplicate_username() {
    let db = InMemoryUserDatabase::new();
    let auth = AuthService::new(db, "test-secret", 24);

    auth.register("alice", "password123", None).await.unwrap();
    assert!(auth.register("alice", "password456", None).await.is_err());
}

#[tokio::test]
async fn test_weak_password() {
    let db = InMemoryUserDatabase::new();
    let auth = AuthService::new(db, "test-secret", 24);

    assert!(auth.register("alice", "short", None).await.is_err());
    assert!(auth.register("", "password123", None).await.is_err());
}

#[tokio::test]
async fn test_list_users() {
    let db = InMemoryUserDatabase::new();
    let auth = AuthService::new(db, "test-secret", 24);

    auth.register("alice", "password123", None).await.unwrap();
    auth.register("bob", "password123", None).await.unwrap();

    let users = auth.list_users().await.unwrap();
    assert_eq!(users.len(), 2);
}

#[tokio::test]
async fn test_rbac_with_custom_store() {
    let db = InMemoryUserDatabase::new();
    let rbac: std::sync::Arc<tokio::sync::RwLock<RbacStore>> = std::sync::Arc::new(tokio::sync::RwLock::new(RbacStore::new()));
    let auth = AuthService::new(db, "test-secret", 24).with_rbac(rbac.clone());

    let user = auth.register("operator", "password123", None).await.unwrap();

    {
        let mut store = rbac.write().await;
        store.remove_role(&user.id.to_string(), &Role::Admin);
        store.assign_role(&user.id.to_string(), Role::Operator);
    }

    let uid = user.id.to_string();
    assert!(auth.check_permission(&uid, Permission::AgentWrite).await);
    assert!(!auth.check_permission(&uid, Permission::SystemWrite).await);
}
