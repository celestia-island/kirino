import { describe, it, expect } from "vitest";
import { isJwtExpired } from "./index.js";

describe("isJwtExpired", () => {
  it("returns true for expired token", () => {
    const past = Math.floor(Date.now() / 1000) - 3600;
    const token = btoa(JSON.stringify({ alg: "HS256" })) + "." +
      btoa(JSON.stringify({ exp: past })) + ".sig";
    expect(isJwtExpired(token)).toBe(true);
  });

  it("returns false for valid token", () => {
    const future = Math.floor(Date.now() / 1000) + 3600;
    const token = btoa(JSON.stringify({ alg: "HS256" })) + "." +
      btoa(JSON.stringify({ exp: future })) + ".sig";
    expect(isJwtExpired(token)).toBe(false);
  });

  it("returns false for malformed token", () => {
    expect(isJwtExpired("not.a.jwt")).toBe(false);
    expect(isJwtExpired("")).toBe(false);
    expect(isJwtExpired("abc.def")).toBe(false);
  });

  it("returns false for token without exp", () => {
    const token = btoa(JSON.stringify({ alg: "HS256" })) + "." +
      btoa(JSON.stringify({ sub: "test" })) + ".sig";
    expect(isJwtExpired(token)).toBe(false);
  });

  it("handles edge expiration times", () => {
    const now = Math.floor(Date.now() / 1000);
    // Just expired (1 second ago)
    const justPast = btoa(JSON.stringify({})) + "." +
      btoa(JSON.stringify({ exp: now - 1 })) + ".sig";
    expect(isJwtExpired(justPast)).toBe(true);
    // Still valid (1 second from now)
    const justFuture = btoa(JSON.stringify({})) + "." +
      btoa(JSON.stringify({ exp: now + 1 })) + ".sig";
    expect(isJwtExpired(justFuture)).toBe(false);
  });
});
