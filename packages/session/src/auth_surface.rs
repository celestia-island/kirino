//! The chest auth-surface contract, versioned here so every consumer
//! spells it identically.
//!
//! The cookie/header names below are owned by the chest server
//! (chest-auth/src/cookie.rs). They are mirrored here — and in
//! packages/web_ts/src/auth_surface.ts — so the desktop shell, the
//! webui and the server cannot drift apart silently: chest-auth pins
//! these constants back (contract tests), and GET /api/auth/surface
//! publishes the live values for startup drift detection.
//!
//! Renaming a cookie on the server MUST change the constants here and
//! in the TS mirror in the same PR, and MUST bump the surface version.

/// CSRF double-submit cookie name (chest-auth `CSRF_COOKIE_NAME`).
pub const AUTH_COOKIE_CSRF: &str = "csrf";
/// Header the client echoes the csrf nonce back on (`CSRF_HEADER_NAME`).
pub const AUTH_HEADER_CSRF: &str = "x-csrf-token";
/// Access-token cookie for WS upgrades and REST fallbacks (production
/// `__Secure-` prefixed; the plain-HTTP demo profile issues `wsat`).
pub const AUTH_COOKIE_WS: &str = "__Secure-wsat";
pub const AUTH_COOKIE_WS_DEV: &str = "wsat";
/// Refresh-token cookie (production `__Secure-` prefixed; demo `rt`).
pub const AUTH_COOKIE_RT: &str = "__Secure-rt";
pub const AUTH_COOKIE_RT_DEV: &str = "rt";

/// How an auth endpoint treats the double-submit pair and credentials.
/// The variants mirror chest-auth/src/csrf.rs guard functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthRequirement {
    /// No session check at all (public: /health, /auth/nonce).
    Public,
    /// Double-submit verified only when a csrf cookie is present; the
    /// no-cookie case passes (first login before any cookie was issued).
    CsrfWhenPresent,
    /// A missing/empty csrf cookie is itself a failure
    /// (`verify_csrf_required`).
    CsrfRequired,
    /// Requests carrying an Authorization header bypass the csrf check;
    /// cookie-session calls still verify it (`verify_csrf_unless_bearer`).
    CsrfUnlessBearer,
}

/// One auth-surface endpoint and its guard semantics.
#[derive(Debug, Clone, Copy)]
pub struct AuthEndpoint {
    pub path: &'static str,
    pub requirement: AuthRequirement,
}

/// The endpoint matrix as the server wires it today. The authoritative
/// runtime view is GET /api/auth/surface; this table is the compile-time
/// mirror the desktop boot probe checks against and may lag the server
/// by one surface change — drift surfaces through the boot probe, never
/// as a silent user-facing 403.
pub const AUTH_ENDPOINTS: &[AuthEndpoint] = &[
    AuthEndpoint { path: "/api/health", requirement: AuthRequirement::Public },
    AuthEndpoint { path: "/api/auth/nonce", requirement: AuthRequirement::Public },
    AuthEndpoint { path: "/api/auth/login-methods", requirement: AuthRequirement::Public },
    AuthEndpoint { path: "/api/auth/login/begin", requirement: AuthRequirement::CsrfWhenPresent },
    AuthEndpoint { path: "/api/auth/login", requirement: AuthRequirement::CsrfWhenPresent },
    AuthEndpoint { path: "/api/auth/org-login", requirement: AuthRequirement::CsrfWhenPresent },
    AuthEndpoint { path: "/api/auth/passkey/login", requirement: AuthRequirement::CsrfUnlessBearer },
    AuthEndpoint { path: "/api/auth/mfa/verify", requirement: AuthRequirement::CsrfWhenPresent },
    AuthEndpoint { path: "/api/auth/token", requirement: AuthRequirement::CsrfRequired },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn surface_literals_are_pinned() {
        assert_eq!(AUTH_COOKIE_CSRF, "csrf");
        assert_eq!(AUTH_HEADER_CSRF, "x-csrf-token");
        assert_eq!(AUTH_COOKIE_WS, "__Secure-wsat");
        assert_eq!(AUTH_COOKIE_WS_DEV, "wsat");
        assert_eq!(AUTH_COOKIE_RT, "__Secure-rt");
        assert_eq!(AUTH_COOKIE_RT_DEV, "rt");
    }

    #[test]
    fn endpoint_matrix_covers_the_login_lane() {
        let paths: Vec<_> = AUTH_ENDPOINTS.iter().map(|e| e.path).collect();
        for required in [
            "/api/auth/nonce",
            "/api/auth/login/begin",
            "/api/auth/login",
            "/api/auth/mfa/verify",
            "/api/auth/token",
        ] {
            assert!(
                paths.contains(&required),
                "auth surface matrix is missing {required}",
            );
        }
        let token = AUTH_ENDPOINTS
            .iter()
            .find(|e| e.path == "/api/auth/token")
            .unwrap();
        assert_eq!(token.requirement, AuthRequirement::CsrfRequired);
    }
}