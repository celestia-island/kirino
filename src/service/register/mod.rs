#[cfg(test)]
mod tests {

    use crate::{
        database::sql::InMemoryUserDatabase,
        rbac::{
            store::{memory::InMemoryAssignmentStore, registry::SimpleRole},
            subject::StringSubject,
            traits::AssignmentStore,
        },
        service::login::{build_default_engine, AuthService, KirinoPermission, LoginRateLimiter},
    };

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
            .register("alice", "Password123!", Some("Alice"))
            .await
            .unwrap();
        assert_eq!(user.username, "alice");
        assert_eq!(user.display_name, Some("Alice".to_string()));

        let result = auth.login("alice", "Password123!").await.unwrap();
        assert_eq!(result.username, "alice");
        assert!(!result.token.is_empty());

        let claims = auth.verify_token(&result.token).await.unwrap();
        assert_eq!(claims.sub, "alice");
    }

    #[tokio::test]
    async fn test_first_user_is_admin() {
        let db = InMemoryUserDatabase::new();
        let engine = build_default_engine();
        let auth = AuthService::new(db, "test-secret", 24, engine, "admin", "viewer")
            .with_auto_admin_first_user(true);

        auth.register("admin", "Password123!", None).await.unwrap();
        assert!(
            auth.check_permission(
                &auth.login("admin", "Password123!").await.unwrap().user_id,
                &KirinoPermission::SystemWrite,
            )
            .await
        );
    }

    #[tokio::test]
    async fn test_first_user_is_not_admin_by_default() {
        let db = InMemoryUserDatabase::new();
        let engine = build_default_engine();
        let auth = AuthService::new(db, "test-secret", 24, engine, "admin", "viewer");

        auth.register("first", "Password123!", None).await.unwrap();
        assert!(
            !auth
                .check_permission(
                    &auth.login("first", "Password123!").await.unwrap().user_id,
                    &KirinoPermission::SystemWrite,
                )
                .await
        );
    }

    #[tokio::test]
    async fn test_second_user_is_viewer() {
        let auth = make_auth();

        auth.register("admin", "Password123!", None).await.unwrap();
        auth.register("viewer", "Password123!", None).await.unwrap();

        let viewer_id = auth.login("viewer", "Password123!").await.unwrap().user_id;
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

        auth.register("alice", "Password123!", None).await.unwrap();
        assert!(auth.login("alice", "wrong").await.is_err());
    }

    #[tokio::test]
    async fn test_change_password() {
        let auth = make_auth();

        let user = auth.register("alice", "Old_Pass123!", None).await.unwrap();
        auth.change_password(&user.id.to_string(), "Old_Pass123!", "New_Pass456!")
            .await
            .unwrap();

        assert!(auth.login("alice", "Old_Pass123!").await.is_err());
        assert!(auth.login("alice", "New_Pass456!").await.is_ok());
    }

    #[tokio::test]
    async fn test_delete_user() {
        let auth = make_auth();

        let user = auth.register("alice", "Password123!", None).await.unwrap();
        assert!(auth.delete_user(&user.id.to_string()).await.unwrap());
        assert!(auth.login("alice", "Password123!").await.is_err());
    }

    #[tokio::test]
    async fn test_duplicate_username() {
        let auth = make_auth();

        auth.register("alice", "Password123!", None).await.unwrap();
        assert!(auth
            .register("alice", "Other_Pass456!", None)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_weak_password() {
        let auth = make_auth();

        assert!(auth.register("alice", "short", None).await.is_err());
        assert!(auth.register("bob", "Password123!", None).await.is_ok());
        assert!(auth.register("alice2", "abc", None).await.is_err());
        assert!(auth
            .register("alice3", "simplepassword", None)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_invalid_username() {
        let auth = make_auth();

        assert!(auth.register("", "Password123!", None).await.is_err());
        assert!(auth.register("a", "Password123!", None).await.is_err());
        assert!(auth
            .register("alice@evil", "Password123!", None)
            .await
            .is_err());
        assert!(auth
            .register("alice hack", "Password123!", None)
            .await
            .is_err());
        assert!(auth
            .register(
                "a_very_long_username_that_exceeds_the_maximum_allowed_length_limit_here",
                "Password123!",
                None
            )
            .await
            .is_err());
        assert!(auth
            .register("alice_123", "Password123!", None)
            .await
            .is_ok());
        assert!(auth
            .register("alice.1-2", "Password123!", None)
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn test_list_users() {
        let auth = make_auth();

        auth.register("alice", "Password123!", None).await.unwrap();
        auth.register("bob", "Password123!", None).await.unwrap();

        let users = auth.list_users().await.unwrap();
        assert_eq!(users.len(), 2);
    }

    #[tokio::test]
    async fn test_rbac_role_change() {
        let auth = make_auth();

        let user = auth
            .register("operator", "Password123!", None)
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

    #[tokio::test]
    async fn test_login_rate_limiting() {
        let db = InMemoryUserDatabase::new();
        let engine = build_default_engine();
        let auth = AuthService::new(db, "test-secret", 24, engine, "admin", "viewer")
            .with_rate_limiter(LoginRateLimiter::new(3, 60, 60));

        auth.register("alice", "Password123!", None).await.unwrap();

        for _ in 0..3 {
            assert!(auth.login("alice", "wrong").await.is_err());
        }
        let result = auth.login("alice", "wrong").await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("too many login attempts"));
    }

    #[tokio::test]
    async fn test_rate_limit_resets_on_success() {
        let db = InMemoryUserDatabase::new();
        let engine = build_default_engine();
        let auth = AuthService::new(db, "test-secret", 24, engine, "admin", "viewer")
            .with_rate_limiter(LoginRateLimiter::new(3, 60, 60));

        auth.register("alice", "Password123!", None).await.unwrap();

        assert!(auth.login("alice", "wrong").await.is_err());
        assert!(auth.login("alice", "wrong").await.is_err());
        assert!(auth.login("alice", "Password123!").await.is_ok());
        assert!(auth.login("alice", "wrong").await.is_err());
        assert!(auth.login("alice", "wrong").await.is_err());
    }
}
