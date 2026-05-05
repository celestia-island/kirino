#[cfg(test)]
mod tests {
    use crate::database::sql::InMemoryUserDatabase;
    use crate::rbac::store::memory::InMemoryAssignmentStore;
    use crate::rbac::store::registry::SimpleRole;
    use crate::rbac::subject::StringSubject;
    use crate::rbac::traits::AssignmentStore;
    use crate::service::login::{build_default_engine, AuthService, KirinoPermission};

    fn make_auth() -> AuthService<
        InMemoryUserDatabase,
        KirinoPermission,
        SimpleRole<KirinoPermission>,
        InMemoryAssignmentStore<StringSubject, KirinoPermission>,
    > {
        let db = InMemoryUserDatabase::new();
        let engine = build_default_engine();
        AuthService::new(db, "test-secret", 24, engine, "admin", "viewer")
    }

    #[tokio::test]
    async fn test_register_and_login() {
        let auth = make_auth();

        let user = auth
            .register("alice", "password123", Some("Alice"))
            .await
            .unwrap();
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
        let auth = make_auth();

        auth.register("admin", "password123", None).await.unwrap();
        assert!(
            auth.check_permission(
                &auth.login("admin", "password123").await.unwrap().user_id,
                &KirinoPermission::SystemWrite,
            )
            .await
        );
    }

    #[tokio::test]
    async fn test_second_user_is_viewer() {
        let auth = make_auth();

        auth.register("admin", "password123", None).await.unwrap();
        auth.register("viewer", "password123", None).await.unwrap();

        let viewer_id = auth.login("viewer", "password123").await.unwrap().user_id;
        assert!(
            auth.check_permission(&viewer_id, &KirinoPermission::AgentRead)
                .await
        );
        assert!(
            !auth
                .check_permission(&viewer_id, &KirinoPermission::SystemWrite)
                .await
        );
    }

    #[tokio::test]
    async fn test_wrong_password() {
        let auth = make_auth();

        auth.register("alice", "password123", None).await.unwrap();
        assert!(auth.login("alice", "wrong").await.is_err());
    }

    #[tokio::test]
    async fn test_change_password() {
        let auth = make_auth();

        let user = auth.register("alice", "old_password", None).await.unwrap();
        auth.change_password(&user.id.to_string(), "old_password", "new_password")
            .await
            .unwrap();

        assert!(auth.login("alice", "old_password").await.is_err());
        assert!(auth.login("alice", "new_password").await.is_ok());
    }

    #[tokio::test]
    async fn test_delete_user() {
        let auth = make_auth();

        let user = auth.register("alice", "password123", None).await.unwrap();
        assert!(auth.delete_user(&user.id.to_string()).await.unwrap());
        assert!(auth.login("alice", "password123").await.is_err());
    }

    #[tokio::test]
    async fn test_duplicate_username() {
        let auth = make_auth();

        auth.register("alice", "password123", None).await.unwrap();
        assert!(auth.register("alice", "password456", None).await.is_err());
    }

    #[tokio::test]
    async fn test_weak_password() {
        let auth = make_auth();

        assert!(auth.register("alice", "short", None).await.is_err());
        assert!(auth.register("", "password123", None).await.is_err());
    }

    #[tokio::test]
    async fn test_list_users() {
        let auth = make_auth();

        auth.register("alice", "password123", None).await.unwrap();
        auth.register("bob", "password123", None).await.unwrap();

        let users = auth.list_users().await.unwrap();
        assert_eq!(users.len(), 2);
    }

    #[tokio::test]
    async fn test_rbac_role_change() {
        let auth = make_auth();

        let user = auth
            .register("operator", "password123", None)
            .await
            .unwrap();

        let subject = StringSubject::new(user.id.to_string());
        let engine = auth.engine();
        engine
            .assignment_store()
            .revoke_role(&subject, "admin")
            .await
            .unwrap();
        engine
            .assignment_store()
            .assign_role(&subject, "operator")
            .await
            .unwrap();

        let uid = user.id.to_string();
        assert!(
            auth.check_permission(&uid, &KirinoPermission::AgentWrite)
                .await
        );
        assert!(
            !auth
                .check_permission(&uid, &KirinoPermission::SystemWrite)
                .await
        );
    }
}
