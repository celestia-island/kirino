import { describe, expect, it } from "vitest";

import {
  AUTH_COOKIE_CSRF,
  AUTH_COOKIE_RT,
  AUTH_COOKIE_WS,
  AUTH_ENDPOINTS,
  AUTH_HEADER_CSRF,
} from "../src/auth_surface";

// The literals are pinned: the server side (chest-auth/src/cookie.rs)
// owns them and its contract tests mirror these exact spellings. A
// rename must land in both places in one PR.
describe("auth surface contract", () => {
  it("pins the server cookie/header spellings", () => {
    expect(AUTH_COOKIE_CSRF).toBe("csrf");
    expect(AUTH_HEADER_CSRF).toBe("x-csrf-token");
    expect(AUTH_COOKIE_WS).toBe("__Secure-wsat");
    expect(AUTH_COOKIE_RT).toBe("__Secure-rt");
  });

  it("covers the login lane endpoints", () => {
    const paths = AUTH_ENDPOINTS.map((e) => e.path);
    for (const required of [
      "/api/auth/nonce",
      "/api/auth/login/begin",
      "/api/auth/login",
      "/api/auth/mfa/verify",
      "/api/auth/token",
    ]) {
      expect(paths).toContain(required);
    }
    expect(AUTH_ENDPOINTS.find((e) => e.path === "/api/auth/token")?.requirement).toBe(
      "csrf-required",
    );
  });
});