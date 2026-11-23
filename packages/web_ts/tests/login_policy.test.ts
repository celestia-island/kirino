import { describe, expect, expectTypeOf, it } from "vitest";

import type { AuthMethod, AuthMode, LoginPolicy } from "../src/index.js";

// The three canonical documents from the Rust `kirino::auth::mode` docs,
// typed against the GENERATED bindings.
// MUT:wire-shape-typed — a binding that drifts from the wire shape the service
// serialises never typechecks here (a renamed field or a changed literal turns
// `pnpm run typecheck` red on exactly this file).
const local: LoginPolicy = { version: 1, mode: "local", password: true, methods: [] };

const federated: LoginPolicy = {
  version: 1,
  mode: "federated",
  password: true,
  methods: [
    { kind: "passkey", id: "passkey", label: "Passkey", href: "/api/auth/passkey/login" },
    {
      kind: "oauth",
      id: "example-idp",
      label: "Sign in with Example",
      href: "/api/auth/oauth/example-idp",
      provider: "example-idp",
      icon: "key",
    },
    { kind: "custom", id: "jump", label: "Jump", href: "/auth/jump" },
  ],
};

const relay: LoginPolicy = {
  version: 1,
  mode: "relay",
  password: false,
  methods: [],
  relay: { entry: "/api/auth/relay", return_param: "return_to" },
};

describe("login policy contract (generated)", () => {
  it("names the three modes and four auth methods", () => {
    expectTypeOf<AuthMode>().toEqualTypeOf<"local" | "federated" | "relay">();
    expectTypeOf<AuthMethod>().toEqualTypeOf<
      "password" | { oauth: { provider: string } } | "relay" | "passkey"
    >();
  });

  it("accepts the three canonical documents", () => {
    expect(local.mode).toBe("local");
    expect(federated.methods.map((method) => method.kind)).toEqual(["passkey", "oauth", "custom"]);
    expect(relay.relay?.entry).toBe("/api/auth/relay");
  });

  it("discriminates the method union on `kind`", () => {
    for (const method of federated.methods) {
      if (method.kind === "oauth") {
        expectTypeOf(method.provider).toEqualTypeOf<string>();
        expect(method.provider).toBe("example-idp");
      } else {
        expect("provider" in method).toBe(false);
      }
    }
  });
});
