/**
 * The chest auth-surface contract — TS mirror of the Rust
 * kirino-session `auth_surface` module, which is itself pinned to
 * chest-auth/src/cookie.rs by contract tests. Callers must consume
 * these constants instead of hand-typing cookie/header names:
 * a server-side rename lands here and in the Rust mirror in one PR.
 */

export const AUTH_COOKIE_CSRF = "csrf" as const;
export const AUTH_HEADER_CSRF = "x-csrf-token" as const;
export const AUTH_COOKIE_WS = "__Secure-wsat" as const;
export const AUTH_COOKIE_WS_DEV = "wsat" as const;
export const AUTH_COOKIE_RT = "__Secure-rt" as const;
export const AUTH_COOKIE_RT_DEV = "rt" as const;

export type AuthRequirement =
  | "public"
  | "csrf-when-present"
  | "csrf-required"
  | "csrf-unless-bearer";

export interface AuthEndpoint {
  path: string;
  requirement: AuthRequirement;
}

export const AUTH_ENDPOINTS: AuthEndpoint[] = [
  { path: "/api/health", requirement: "public" },
  { path: "/api/auth/nonce", requirement: "public" },
  { path: "/api/auth/login-methods", requirement: "public" },
  { path: "/api/auth/login/begin", requirement: "csrf-when-present" },
  { path: "/api/auth/login", requirement: "csrf-when-present" },
  { path: "/api/auth/org-login", requirement: "csrf-when-present" },
  { path: "/api/auth/passkey/login", requirement: "csrf-unless-bearer" },
  { path: "/api/auth/mfa/verify", requirement: "csrf-when-present" },
  { path: "/api/auth/token", requirement: "csrf-required" },
];