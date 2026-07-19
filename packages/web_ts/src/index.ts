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
