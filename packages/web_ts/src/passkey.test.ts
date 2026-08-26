import { describe, expect, it } from "vitest";
import {
  base64urlToBytes,
  bytesToBase64url,
  prepareRequestOptions,
  serializeAssertion,
  serializeRegistration,
} from "./passkey";

describe("base64url codec", () => {
  it("round-trips all chunk shapes", () => {
    for (const case_ of [new Uint8Array(0), new Uint8Array([1]), new Uint8Array([1, 2]),
      new Uint8Array([1, 2, 3]), new Uint8Array([0xfb, 0xff])]) {
      expect(base64urlToBytes(bytesToBase64url(case_))).toEqual(case_);
    }
  });

  it("emits url-safe unpadded alphabet", () => {
    const s = bytesToBase64url(new Uint8Array([251, 255]));
    expect(s).toBe("-_8");
    expect(s).not.toMatch(/[+/=]/);
  });
});

describe("prepareRequestOptions", () => {
  it("builds discoverable (empty allow-list) options", () => {
    const opts = prepareRequestOptions({
      rp_id: "celestia.world",
      challenge_b64: "Zm9v",
    });
    expect(opts.rpId).toBe("celestia.world");
    expect(opts.allowCredentials).toEqual([]);
    expect([...(opts.challenge as Uint8Array)]).toEqual([...base64urlToBytes("Zm9v")]);
    expect(opts.userVerification).toBe("preferred");
  });
});

describe("serialize* wire shapes", () => {
  function b64(bytes: Uint8Array): string {
    return bytesToBase64url(bytes);
  }

  it("serializes a registration response into b64url fields", () => {
    const cred = {
      id: "abc",
      rawId: new Uint8Array([1, 2]).buffer,
      response: {
        attestationObject: new Uint8Array([3]).buffer,
        clientDataJSON: new Uint8Array([4]).buffer,
        getTransports: () => ["internal"],
      },
    } as unknown as PublicKeyCredential;
    const out = serializeRegistration(cred);
    expect(out).toMatchObject({
      id: "abc",
      raw_id_b64: b64(new Uint8Array([1, 2])),
      attestation_object_b64: b64(new Uint8Array([3])),
      client_data_json_b64: b64(new Uint8Array([4])),
      transports: ["internal"],
    });
  });

  it("serializes an assertion with null userHandle when absent", () => {
    const cred = {
      id: "xyz",
      rawId: new Uint8Array([9]).buffer,
      response: {
        authenticatorData: new Uint8Array([5]).buffer,
        clientDataJSON: new Uint8Array([6]).buffer,
        signature: new Uint8Array([7]).buffer,
        userHandle: new ArrayBuffer(0),
      },
    } as unknown as PublicKeyCredential;
    const out = serializeAssertion(cred);
    expect(out.user_handle_b64).toBeNull();
    expect(out.signature_b64).toBe(b64(new Uint8Array([7])));
  });
});
