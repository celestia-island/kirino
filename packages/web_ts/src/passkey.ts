/**
 * WebAuthn/passkey browser-side ceremony helpers.
 *
 * Zero-dependency glue between the raw `navigator.credentials` DOM API and
 * the JSON wire shapes chest-core's `/api/auth/passkey/*` endpoints expect:
 * every binary field travels as base64url (RFC 4648, unpadded), exactly the
 * encoding produced by the Rust-side challenge store.
 */

/** Encode bytes as base64url without padding. */
export function bytesToBase64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Decode base64url (padding tolerated) into bytes. */
export function base64urlToBytes(value: string): Uint8Array {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(padded + "=".repeat((4 - (padded.length % 4)) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// ── Registration (create) ────────────────────────────────────────────────

/** DOM-facing descriptor from a base64url credential id. */
function toDescriptor(id_b64: string): PublicKeyCredentialDescriptor {
  return {
    type: "public-key",
    id: base64urlToBytes(id_b64) as unknown as BufferSource,
    transports: ["internal", "hybrid", "usb", "nfc", "ble"] as AuthenticatorTransport[],
  };
}

export interface ServerCreationOptions {
  rp_name?: string;
  rp_id: string;
  user_id_b64: string;
  username: string;
  display_name?: string;
  challenge_b64: string;
  exclude_credentials_b64?: string[];
  require_user_verification?: boolean;
}

export function prepareCreationOptions(
  server: ServerCreationOptions,
): PublicKeyCredentialCreationOptions {
  const exclude: PublicKeyCredentialDescriptor[] = (
    server.exclude_credentials_b64 ?? []
  ).map(toDescriptor);
  return {
    rp: { name: server.rp_name ?? server.rp_id, id: server.rp_id },
    user: {
      id: base64urlToBytes(server.user_id_b64) as unknown as BufferSource,
      name: server.username,
      displayName: server.display_name ?? server.username,
    },
    challenge: base64urlToBytes(server.challenge_b64) as unknown as BufferSource,
    pubKeyCredParams: [
      { type: "public-key", alg: -7 }, // ES256 — the only alg kirino verifies
    ],
    timeout: 120_000,
    excludeCredentials: exclude,
    authenticatorSelection: {
      residentKey: "preferred",
      userVerification: server.require_user_verification === true ? "required" : "preferred",
    },
    attestation: "none",
  };
}

export interface SerializedRegistration {
  id: string;
  raw_id_b64: string;
  transports: string[];
  attestation_object_b64: string;
  client_data_json_b64: string;
}

export function serializeRegistration(
  credential: PublicKeyCredential,
): SerializedRegistration {
  const response = credential.response as AuthenticatorAttestationResponse;
  const transports = typeof response.getTransports === "function"
    ? response.getTransports()
    : [];
  return {
    id: credential.id,
    raw_id_b64: bytesToBase64url(new Uint8Array(credential.rawId)),
    transports: transports ?? [],
    attestation_object_b64: bytesToBase64url(new Uint8Array(response.attestationObject)),
    client_data_json_b64: bytesToBase64url(new Uint8Array(response.clientDataJSON)),
  };
}

// ── Authentication (get) ─────────────────────────────────────────────────

export interface ServerRequestOptions {
  rp_id: string;
  challenge_b64: string;
  allow_credentials_b64?: string[];
  require_user_verification?: boolean;
}

export function prepareRequestOptions(
  server: ServerRequestOptions,
): PublicKeyCredentialRequestOptions {
  const allow: PublicKeyCredentialDescriptor[] = (
    server.allow_credentials_b64 ?? []
  ).map(toDescriptor);
  return {
    rpId: server.rp_id,
    challenge: base64urlToBytes(server.challenge_b64) as unknown as BufferSource,
    timeout: 120_000,
    // Empty allow-list = discoverable credential picker (usernameless).
    allowCredentials: allow,
    userVerification: server.require_user_verification === true ? "required" : "preferred",
  };
}

export interface SerializedAssertion {
  id: string;
  raw_id_b64: string;
  authenticator_data_b64: string;
  client_data_json_b64: string;
  signature_b64: string;
  user_handle_b64: string | null;
}

export function serializeAssertion(credential: PublicKeyCredential): SerializedAssertion {
  const response = credential.response as AuthenticatorAssertionResponse;
  return {
    id: credential.id,
    raw_id_b64: bytesToBase64url(new Uint8Array(credential.rawId)),
    authenticator_data_b64: bytesToBase64url(new Uint8Array(response.authenticatorData)),
    client_data_json_b64: bytesToBase64url(new Uint8Array(response.clientDataJSON)),
    signature_b64: bytesToBase64url(new Uint8Array(response.signature)),
    user_handle_b64: response.userHandle && response.userHandle.byteLength > 0
      ? bytesToBase64url(new Uint8Array(response.userHandle))
      : null,
  };
}

// ── Capability probe ──────────────────────────────────────────────────────

/** True when this environment can plausibly run WebAuthn ceremonies. */
export async function isPasskeyAvailable(): Promise<boolean> {
  if (typeof window === "undefined" || !("PublicKeyCredential" in window)) {
    return false;
  }
  try {
    const pkc = window.PublicKeyCredential as unknown as {
      isUserVerifyingPlatformAuthenticatorAvailable?: () => Promise<boolean>;
    };
    if (typeof pkc.isUserVerifyingPlatformAuthenticatorAvailable !== "function") {
      return true; // API present, platform detection unsupported → still try
    }
    return await pkc.isUserVerifyingPlatformAuthenticatorAvailable();
  } catch {
    return false;
  }
}
