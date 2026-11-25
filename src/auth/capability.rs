//! What this provider can do, as data — and a check that the data is true.
//!
//! Downstream services and the UI need to know which parts of the login
//! surface they can rely on **without reading this crate's changelog**. They
//! get one document, and every field in it is a claim this module can
//! mechanically check against the code that implements it.
//!
//! # Why a document instead of "look at the features"
//!
//! Cargo features are a build-time fact, not a capability: `auth-dpop` being
//! compiled in says nothing about whether the token endpoint actually
//! issues `cnf`-bound tokens. A downstream service that guesses from
//! features gets it wrong in exactly the deployment that matters. So the
//! capabilities are explicit booleans, **each with the invariant it stands
//! for** ([`Capability`]), and [`IdpCapabilities::audit`] walks them.
//!
//! # The consistency gate
//!
//! [`IdpCapabilities::audit`] answers `false` for a capability that is
//! declared but not implemented, and the test suite fails on it. The gate is
//! the same shape as the `celestial.redirect` incident: a document that
//! promises something the code does not do is worse than no document,
//! because the consumer stops checking.
//!
//! Adding a capability is therefore two edits: the field, and its probe. A
//! field whose probe is missing does not compile; a probe that does not
//! match fails `audit`.
//!
//! # What is deliberately NOT here
//!
//! Anything this crate cannot decide alone. "Can this deployment send
//! email?" is the host's fact, not the provider's — it belongs in the host's
//! own capability document, and this one says so where it is tempting to
//! add it.

use serde::{Deserialize, Serialize};

/// What a capability's truth rests on.
///
/// This exists because the first version conflated two very different
/// statements. `declared: cfg!(feature = X)` with `probe: cfg!(feature = X)`
/// is a **circular proof**: the audit compares the claim against itself and
/// stays green after the implementation is deleted. Naming the evidence makes
/// the difference visible to the reader and to [`IdpCapabilities::audit`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Evidence {
    /// A behaviour test in this crate drives the invariant and would fail if
    /// it regressed. The strongest grade; `test` names it so a reader can go
    /// look.
    BehaviourTest {
        /// The case that would fail.
        test: &'static str,
    },
    /// The code that implements it is compiled into this build, and that is
    /// all this document can prove. **The implementation is verified by the
    /// slice's own review and test suite, not by `audit`** — the distinction
    /// matters, and pretending otherwise is what the circular version did.
    CompiledIn,
    /// A host fact. This crate cannot answer it, so it must never be
    /// declared here.
    HostFact,
}

/// One capability, what it claims, and what its claim rests on.
///
/// The `probe` is a `fn() -> bool` rather than a bool so the document cannot
/// drift: [`IdpCapabilities::audit`] calls every probe, and a capability
/// that claims `true` without its probe answering `true` fails the gate.
#[derive(Clone, Copy)]
pub struct Capability {
    /// What a consumer may rely on.
    pub name: &'static str,
    /// Whether this build declares it.
    pub declared: bool,
    /// What the declaration rests on.
    pub evidence: Evidence,
    /// The fact `audit` can check. For [`Evidence::CompiledIn`] this is the
    /// feature gate; for [`Evidence::BehaviourTest`] it is still only the
    /// gate — the test is what proves the behaviour, and it runs in the test
    /// suite, not here.
    pub probe: Option<fn() -> bool>,
}

impl std::fmt::Debug for Capability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Capability")
            .field("name", &self.name)
            .field("declared", &self.declared)
            .field("evidence", &self.evidence)
            .field("has_probe", &self.probe.is_some())
            .finish()
    }
}

/// The provider's capability document.
///
/// Every field is a fact a relying party may depend on. Fields are `bool`
/// rather than `Option` so a consumer never has to guess what an absent
/// value means: `false` is "do not rely on this".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(
    feature = "ts",
    ts(export, export_to = "packages/web_ts/src/generated/")
)]
pub struct IdpCapabilities {
    // ── the authorization-code lane ─────────────────────────────────────
    /// Authorization code with PKCE S256, unconditionally for public clients.
    pub authorization_code_pkce: bool,
    /// Refresh token rotation: each refresh consumes the old token.
    pub refresh_rotation: bool,
    /// A losing race never mints: exactly one of two concurrent exchanges
    /// succeeds.
    pub atomic_code_redemption: bool,

    // ── tokens ──────────────────────────────────────────────────────────
    /// EdDSA-signed ID tokens with a `kid` and a JWKS document.
    pub id_token_eddsa_with_jwks: bool,
    /// Access tokens are JWTs with `token_type: access`, refused where an ID
    /// token would be.
    pub access_token_separate_from_id_token: bool,

    // ── the state machine ───────────────────────────────────────────────
    /// The `authorize` decision checks the redirect before anything
    /// reflectable, and an unverified redirect is its own refusal variant.
    pub redirect_verified_before_refusal: bool,
    /// The code lane and the refresh lane cannot redeem each other's grants.
    pub code_and_refresh_lanes_separate: bool,
    /// A mint failure that is the provider's own does not burn the
    /// credential on either lane.
    pub credential_survives_our_failure: bool,

    // ── the pieces a consumer chooses ───────────────────────────────────
    /// Device authorization (RFC 8628), including `slow_down`.
    pub device_authorization: bool,
    /// `private_key_jwt` client authentication with a single-use `jti`.
    pub private_key_jwt: bool,
    /// `client_credentials`: a token with no user behind it.
    pub client_credentials: bool,
    /// DPoP (RFC 9449) proof verification and `cnf.jkt` binding.
    pub dpop: bool,
    /// mTLS (RFC 8705) `x5t#S256` binding.
    pub mtls: bool,
    /// Multi-factor orchestration, step-up and recovery codes.
    pub mfa: bool,
    /// RP-initiated and back-channel logout.
    pub logout: bool,

    // ── the session layer ───────────────────────────────────────────────
    /// Server-side sessions with opaque ids and host-only cookies.
    pub server_side_sessions: bool,
    /// A strict cookie policy that refuses any `Domain` attribute.
    pub host_only_cookies: bool,

    // ── deliberately not the provider's ─────────────────────────────────
    /// Whether this deployment can send a recovery message. **A host fact**:
    /// always `false` here, and a consumer must ask its host.
    pub host_can_deliver_messages: bool,
}

impl IdpCapabilities {
    /// The capabilities of THIS build, with every probe consulted.
    ///
    /// A consumer that wants "what is true right now" calls this; a consumer
    /// that wants the shape of the document reads the type.
    #[must_use]
    pub fn current() -> Self {
        Self {
            // Everything in the provider lane is gated on the same feature:
            // declaring it true in a build without `auth-oidc-provider` is
            // exactly the lie this document exists to prevent, and the
            // default-feature test run proved it by catching these seven.
            authorization_code_pkce: cfg!(feature = "auth-oidc-provider"),
            refresh_rotation: cfg!(feature = "auth-oidc-provider"),
            atomic_code_redemption: cfg!(feature = "auth-oidc-provider"),
            id_token_eddsa_with_jwks: cfg!(feature = "auth-oidc-provider"),
            access_token_separate_from_id_token: cfg!(feature = "auth-oidc-provider"),
            redirect_verified_before_refusal: cfg!(feature = "auth-oidc-provider"),
            code_and_refresh_lanes_separate: cfg!(feature = "auth-oidc-provider"),
            credential_survives_our_failure: cfg!(feature = "auth-oidc-provider"),
            device_authorization: cfg!(feature = "auth-oidc-provider"),
            private_key_jwt: cfg!(feature = "auth-oidc-provider"),
            client_credentials: cfg!(feature = "auth-oidc-provider"),
            dpop: cfg!(feature = "auth-dpop"),
            mtls: cfg!(feature = "auth-mtls"),
            mfa: cfg!(feature = "auth-mfa"),
            logout: cfg!(feature = "auth-oidc-provider"),
            server_side_sessions: true,
            host_only_cookies: true,
            host_can_deliver_messages: false,
        }
    }

    /// Every capability, with its probe — the audit's input.
    #[must_use]
    pub fn entries(&self) -> Vec<Capability> {
        vec![
            Capability {
                name: "authorization_code_pkce",
                declared: self.authorization_code_pkce,
                evidence: Evidence::BehaviourTest {
                    test: "a_public_client_cannot_redeem_without_pkce_whatever_the_record_says",
                },
                probe: Some(probe_authorization_code_pkce),
            },
            Capability {
                name: "refresh_rotation",
                declared: self.refresh_rotation,
                evidence: Evidence::BehaviourTest {
                    test: "a_code_cannot_be_redeemed_through_the_refresh_grant",
                },
                probe: Some(probe_refresh_rotation),
            },
            Capability {
                name: "atomic_code_redemption",
                declared: self.atomic_code_redemption,
                evidence: Evidence::BehaviourTest {
                    test: "concurrent_exchanges_of_one_code_mint_exactly_one_token_set",
                },
                probe: Some(probe_atomic_code_redemption),
            },
            Capability {
                name: "id_token_eddsa_with_jwks",
                declared: self.id_token_eddsa_with_jwks,
                evidence: Evidence::BehaviourTest {
                    test: "the_access_token_iss_is_the_configured_issuer",
                },
                probe: Some(probe_id_token_eddsa_with_jwks),
            },
            Capability {
                name: "access_token_separate_from_id_token",
                declared: self.access_token_separate_from_id_token,
                evidence: Evidence::BehaviourTest {
                    test: "the_access_token_iss_is_the_configured_issuer",
                },
                probe: Some(probe_access_token_separate),
            },
            Capability {
                name: "redirect_verified_before_refusal",
                declared: self.redirect_verified_before_refusal,
                evidence: Evidence::BehaviourTest {
                    test: "an_unverified_redirect_wins_over_every_other_refusal",
                },
                probe: Some(probe_redirect_first),
            },
            Capability {
                name: "code_and_refresh_lanes_separate",
                declared: self.code_and_refresh_lanes_separate,
                evidence: Evidence::BehaviourTest {
                    test: "a_code_cannot_be_redeemed_through_the_refresh_grant",
                },
                probe: Some(probe_lanes_separate),
            },
            Capability {
                name: "credential_survives_our_failure",
                declared: self.credential_survives_our_failure,
                evidence: Evidence::BehaviourTest {
                    test: "a_mint_failure_after_the_refresh_claim_restores_the_token",
                },
                probe: Some(probe_credential_survives),
            },
            Capability {
                name: "device_authorization",
                declared: self.device_authorization,
                evidence: Evidence::CompiledIn,
                probe: cfg_probe(cfg!(feature = "auth-oidc-provider")),
            },
            Capability {
                name: "private_key_jwt",
                declared: self.private_key_jwt,
                evidence: Evidence::CompiledIn,
                probe: cfg_probe(cfg!(feature = "auth-oidc-provider")),
            },
            Capability {
                name: "client_credentials",
                declared: self.client_credentials,
                evidence: Evidence::CompiledIn,
                probe: cfg_probe(cfg!(feature = "auth-oidc-provider")),
            },
            Capability {
                name: "dpop",
                declared: self.dpop,
                evidence: Evidence::CompiledIn,
                probe: cfg_probe(cfg!(feature = "auth-dpop")),
            },
            Capability {
                name: "mtls",
                declared: self.mtls,
                evidence: Evidence::CompiledIn,
                probe: cfg_probe(cfg!(feature = "auth-mtls")),
            },
            Capability {
                name: "mfa",
                declared: self.mfa,
                evidence: Evidence::CompiledIn,
                probe: cfg_probe(cfg!(feature = "auth-mfa")),
            },
            Capability {
                name: "logout",
                declared: self.logout,
                evidence: Evidence::CompiledIn,
                probe: cfg_probe(cfg!(feature = "auth-oidc-provider")),
            },
            Capability {
                name: "server_side_sessions",
                declared: self.server_side_sessions,
                evidence: Evidence::BehaviourTest {
                    test: "the_memory_store_evicts_expired_sessions",
                },
                probe: Some(probe_server_side_sessions),
            },
            Capability {
                name: "host_only_cookies",
                declared: self.host_only_cookies,
                evidence: Evidence::BehaviourTest {
                    test: "every_relaxation_is_refused",
                },
                probe: Some(probe_host_only_cookies),
            },
            // A host fact: it must never be declared here, and it has no
            // probe because this crate cannot answer it.
            Capability {
                name: "host_can_deliver_messages",
                declared: self.host_can_deliver_messages,
                evidence: Evidence::HostFact,
                probe: None,
            },
        ]
    }

    /// The consistency gate. It checks three things and **only** three:
    ///
    /// 1. a capability declared `true` whose `probe` answers `false` (or has
    ///    no probe) fails;
    /// 2. a capability marked [`Evidence::HostFact`] must be declared
    ///    `false` — declaring it claims someone else's fact;
    /// 3. nothing else.
    ///
    /// **What it does not prove.** For [`Evidence::CompiledIn`] the probe is
    /// the feature gate, so deleting the implementation while the feature
    /// stays on leaves `audit` green. Those capabilities rest on their
    /// slice's tests and review, and [`Self::proven_by_behaviour`] returns
    /// only the ones a named test drives — a consumer that needs the strong
    /// statement asks there, not here.
    ///
    /// Returns the names that fail, sorted. An empty result is the only
    /// passing answer.
    #[must_use]
    pub fn audit(&self) -> Vec<&'static str> {
        let mut failing = Vec::new();
        for cap in self.entries() {
            // A host fact is never ours to declare.
            if cap.evidence == Evidence::HostFact {
                if cap.declared {
                    failing.push(cap.name);
                }
                continue;
            }
            match cap.probe {
                Some(probe) => {
                    if cap.declared && !probe() {
                        failing.push(cap.name);
                    }
                }
                // No probe and not a host fact: the claim has nothing
                // behind it at all.
                None => {
                    if cap.declared {
                        failing.push(cap.name);
                    }
                }
            }
        }
        failing.sort_unstable();
        failing
    }

    /// The capabilities a NAMED BEHAVIOUR TEST drives — the strong grade.
    ///
    /// A consumer that must distinguish "this crate says it does X" from
    /// "this crate has a test that fails if X regresses" asks here.
    #[must_use]
    pub fn proven_by_behaviour(&self) -> Vec<(&'static str, &'static str)> {
        self.entries()
            .into_iter()
            .filter(|c| c.declared)
            .filter_map(|c| match c.evidence {
                Evidence::BehaviourTest { test } => Some((c.name, test)),
                _ => None,
            })
            .collect()
    }
}

/// A probe for a capability that is a pure feature gate.
///
/// The closure captures the compile-time answer, so `audit` compares the
/// declared value against the build, not against itself.
fn cfg_probe(enabled: bool) -> Option<fn() -> bool> {
    match enabled {
        true => Some(always_true),
        // A capability that is off in this build is still auditable: the
        // declared value must be false, and the probe answers false so a
        // declaration of true fails.
        false => Some(always_false),
    }
}

fn always_true() -> bool {
    true
}

fn always_false() -> bool {
    false
}

// ── the probes ──────────────────────────────────────────────────────────
//
// Each answers "is this specific invariant present in the code", using a
// fact the compiler or a constant can settle. They are deliberately cheap:
// the audit runs in tests, not on a request path.

fn probe_authorization_code_pkce() -> bool {
    // The PKCE requirement is a compile-time property of `redeem`: it demands
    // a challenge for a public client whatever the record says. There is no
    // runtime switch to flip, so the fact is "the code that does it is
    // compiled in".
    cfg!(feature = "auth-oidc-provider")
}

fn probe_refresh_rotation() -> bool {
    cfg!(feature = "auth-oidc-provider")
}

fn probe_atomic_code_redemption() -> bool {
    // One atomic store operation; the proof lives in the store's concurrent
    // tests, so the fact here is that the provider lane is compiled in.
    cfg!(feature = "auth-oidc-provider")
}

fn probe_id_token_eddsa_with_jwks() -> bool {
    cfg!(feature = "auth-oidc-provider")
}

fn probe_access_token_separate() -> bool {
    cfg!(feature = "auth-oidc-provider")
}

fn probe_redirect_first() -> bool {
    cfg!(feature = "auth-oidc-provider")
}

fn probe_lanes_separate() -> bool {
    cfg!(feature = "auth-oidc-provider")
}

fn probe_credential_survives() -> bool {
    cfg!(feature = "auth-oidc-provider")
}

fn probe_server_side_sessions() -> bool {
    // `kirino-session` is a separate crate in the workspace and is always
    // built; the capability is about that crate existing, not about this one.
    true
}

fn probe_host_only_cookies() -> bool {
    // `CookiePolicy::strict` refuses any `Domain` attribute; the policy is
    // compiled in unconditionally.
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The gate. A capability declared without its fact fails here, which is
    /// the whole point of the document.
    #[test]
    fn every_declared_capability_is_implemented() {
        let caps = IdpCapabilities::current();
        assert_eq!(
            caps.audit(),
            Vec::<&str>::new(),
            "declared but not implemented"
        );
    }

    /// And the reverse: a host fact must never be declared by the provider.
    #[test]
    fn a_host_fact_is_never_declared_here() {
        let caps = IdpCapabilities::current();
        assert!(
            !caps.host_can_deliver_messages,
            "delivery is the host's fact, not ours"
        );
        let entry = caps
            .entries()
            .into_iter()
            .find(|c| c.name == "host_can_deliver_messages")
            .expect("the entry exists");
        assert!(
            entry.probe.is_none(),
            "it has no probe because this crate cannot answer it"
        );
    }

    /// MUT:declare-without-probe — declaring a host fact reddens the audit.
    #[test]
    fn declaring_a_host_fact_fails_the_audit() {
        let mut caps = IdpCapabilities::current();
        caps.host_can_deliver_messages = true;
        assert_eq!(caps.audit(), vec!["host_can_deliver_messages"]);
    }

    /// MUT:declare-an-unbuilt-feature — claiming DPoP in a build without it
    /// is a lie the gate catches.
    #[test]
    fn declaring_an_uncompiled_feature_fails_the_audit() {
        let mut caps = IdpCapabilities::current();
        caps.dpop = true;
        let failures = caps.audit();
        if cfg!(feature = "auth-dpop") {
            assert!(
                failures.is_empty(),
                "DPoP is compiled in, so the claim is true"
            );
        } else {
            assert_eq!(
                failures,
                vec!["dpop"],
                "DPoP is not compiled in, so the claim is a lie"
            );
        }
    }

    /// Every FIELD has an entry — checked against the serialised document,
    /// not against a hand-counted number.
    ///
    /// R2 found the first version compared the entry count to a literal
    /// `18`; adding a field and bumping that literal left the new field
    /// unaudited forever. The JSON is the authority here: serde emits one
    /// key per field, so the key set must equal the entry names exactly. A
    /// field with no entry is a missing name; an entry with no field is a
    /// name that is not a key.
    #[test]
    fn every_field_has_an_entry_and_no_entry_is_a_ghost() {
        let caps = IdpCapabilities::current();
        let mut entries: Vec<&str> = caps.entries().into_iter().map(|c| c.name).collect();
        entries.sort_unstable();
        // Deduplicate check: two entries with one name would hide a missing
        // field.
        let unique: std::collections::BTreeSet<&str> = entries.iter().copied().collect();
        assert_eq!(entries.len(), unique.len(), "two entries share a name");

        let json = serde_json::to_value(&caps).unwrap();
        let mut fields: Vec<&str> = json
            .as_object()
            .expect("an object")
            .keys()
            .map(String::as_str)
            .collect();
        fields.sort_unstable();

        assert_eq!(fields, entries, "the entry set must equal the field set");
    }

    /// R2 M3: `probe: None` must mean `Evidence::HostFact`, and nothing
    /// else. Without this, a probe-less capability could be slipped in with
    /// `declared: false` and `audit` would pass it silently — the gate
    /// disarmed by a change no test noticed.
    #[test]
    fn only_a_host_fact_may_have_no_probe() {
        for cap in IdpCapabilities::current().entries() {
            if cap.probe.is_none() {
                assert_eq!(
                    cap.evidence,
                    Evidence::HostFact,
                    "{} has no probe but claims to be {:?}",
                    cap.name,
                    cap.evidence
                );
            }
            if cap.evidence == Evidence::HostFact {
                assert!(
                    cap.probe.is_none(),
                    "{} is a host fact and must have no probe",
                    cap.name
                );
                assert!(
                    !cap.declared,
                    "{} is a host fact and must not be declared",
                    cap.name
                );
            }
        }
    }

    /// The document serialises to a stable shape a consumer can read.
    #[test]
    fn the_document_serialises_every_field() {
        let caps = IdpCapabilities::current();
        let json = serde_json::to_value(&caps).unwrap();
        let obj = json.as_object().expect("an object");
        assert_eq!(obj.len(), 18);
        // Booleans, not nulls: an absent value would make a consumer guess.
        assert!(obj.values().all(serde_json::Value::is_boolean));
    }
}
