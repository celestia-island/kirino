export function isJwtExpired(token: string): boolean {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return false;
    const payload = JSON.parse(atob(parts[1]));
    const exp = payload.exp;
    if (typeof exp === "number") return Date.now() / 1000 > exp;
    return false;
  } catch { return false; }
}

const TOKEN_KEY = "kirino:accessToken";

export function saveToken(token: string): void {
  try { sessionStorage.setItem(TOKEN_KEY, token); } catch {}
}

export function restoreToken(): string | null {
  try {
    const stored = sessionStorage.getItem(TOKEN_KEY);
    if (stored && !isJwtExpired(stored)) return stored;
    sessionStorage.removeItem(TOKEN_KEY);
  } catch {}
  return null;
}

export function clearToken(): void {
  try { sessionStorage.removeItem(TOKEN_KEY); } catch {}
}

export * from "./passkey";
export * from "./auth_surface";

// Wire-contract types, generated from the Rust declarations in
// `kirino::auth::mode` (`cargo test -p kirino --lib --features ts
// export_bindings`). Never edit `./generated/*` by hand — change the Rust
// side and regenerate.
export type { AuthMode } from "./generated/AuthMode";
export type { AuthMethod } from "./generated/AuthMethod";
export type { LoginMethodDescriptor } from "./generated/LoginMethodDescriptor";
export type { RelayDirective } from "./generated/RelayDirective";
export type { LoginPolicy } from "./generated/LoginPolicy";
export type { IdpCapabilities } from "./generated/IdpCapabilities";
