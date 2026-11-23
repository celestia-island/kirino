//! The login-mode contract: which sign-in shapes a deployment offers.
//!
//! # Three modes
//!
//! Every service in the family that shows a login panel answers one question
//! the same way — "how may a visitor sign in here?" — with an
//! [`AuthMode`] plus the method list that goes with it:
//!
//! | Mode | Meaning | Login page | Local password | Identity storage |
//! | --- | --- | --- | --- | --- |
//! | [`Local`](AuthMode::Local) | Self-contained credentials, the shape of an independently deployed instance | yes | offered | local |
//! | [`Federated`](AuthMode::Federated) | Local credentials **plus** third-party providers; external identities are linked to local accounts | yes, with a channel picker | offered or refused, deployment's choice | local |
//! | [`Relay`](AuthMode::Relay) | One designated external login source: **no login page of its own**, the browser is sent to the central site with a return address, and the callback mints a local session | **no** | structurally refused | local session; the account comes from the callback |
//!
//! The mode is a *summary*, not a second source of truth: it must agree with
//! the method list, and [`LoginPolicy::validate`] refuses any document where
//! it does not. A capability document that advertises a channel the UI never
//! renders — or hides one it does — is the failure this module exists to
//! prevent, so the invariants are checked on the wire shape itself.
//!
//! # Deriving the mode
//!
//! [`AuthMode::derive`] folds two facts into a mode: a configured relay source
//! wins outright, otherwise any configured provider means `Federated`,
//! otherwise `Local`. The relay configuration is read from the environment by
//! the service (see the relay module); an incomplete relay configuration is a
//! start-up error there, never a silent fall back to `Local` — a production
//! instance that quietly re-exposes its local password form because one
//! variable went missing is exactly the drift this contract rules out.
//!
//! # The wire document
//!
//! [`LoginPolicy`] is what a service serialises at its login-method discovery
//! endpoint. It is declared here, in Rust, and the TypeScript binding is
//! generated from it (the optional `ts` feature); hosts extend it by embedding
//! and adding their own fields, never by editing this shape. Unknown fields
//! are ignored on deserialisation, so `validate` checks the fields this
//! version knows — a consumer that received a newer `version` must not trust
//! the rest of the document. `version` is bumped on any non-additive change.

use serde::{Deserialize, Serialize};

use crate::service::login::policy::PasswordLoginPolicy;

/// The wire version of [`LoginPolicy`]. Bumped on any non-additive change.
pub const LOGIN_POLICY_VERSION: u8 = 1;

/// Which sign-in shapes a deployment offers.
///
/// The summary of the method list; see the module docs for the table. `Local`
/// is the default so a service that never mentions the contract keeps the
/// historical behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(
    feature = "ts",
    ts(export, export_to = "packages/web_ts/src/generated/")
)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "ts", ts(rename_all = "snake_case"))]
pub enum AuthMode {
    /// Self-contained credentials; no external identity source.
    #[default]
    Local,
    /// Local credentials plus third-party providers, identities linked locally.
    Federated,
    /// One designated external login source; no login page of its own.
    Relay,
}

impl AuthMode {
    /// Parse a configuration value into a mode.
    ///
    /// Accepts the three mode names case-insensitively, after trimming
    /// surrounding whitespace. Every other value — the empty string included
    /// — yields `None`; treat that as a configuration error rather than a
    /// default (the same fail-closed contract as
    /// [`PasswordLoginPolicy::parse`]).
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "local" => Some(Self::Local),
            "federated" => Some(Self::Federated),
            "relay" => Some(Self::Relay),
            _ => None,
        }
    }

    /// The canonical spelling, for logs, config echo and round-tripping
    /// through [`parse`](Self::parse).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Federated => "federated",
            Self::Relay => "relay",
        }
    }

    /// Whether the local password method is offered under this mode.
    ///
    /// `Relay` refuses it — there is no login page to offer it on. `Local`
    /// and `Federated` leave the choice to the deployment, so the projection
    /// is the permissive `Enabled`; a `Federated` deployment that wants
    /// third-party sign-in only layers [`PasswordLoginPolicy::Disabled`] on
    /// top.
    ///
    /// The projection is a value for the host to **apply** (through
    /// `AuthService::with_password_login_policy`); that is what makes the
    /// refusal precede any credential lookup. Accounts of a relay deployment
    /// additionally carry the no-local-password sentinel, which refuses a
    /// password sign-in even on a host that forgot to apply the policy —
    /// defence in depth, not the primary gate.
    #[must_use]
    pub fn password_login_policy(self) -> PasswordLoginPolicy {
        match self {
            Self::Local | Self::Federated => PasswordLoginPolicy::Enabled,
            Self::Relay => PasswordLoginPolicy::Disabled,
        }
    }

    /// `true` for [`Relay`](Self::Relay): the service has no login page.
    #[must_use]
    pub fn is_relay(self) -> bool {
        matches!(self, Self::Relay)
    }

    /// Fold the two configuration facts into a mode.
    ///
    /// A configured relay source wins outright (the designated-source mode
    /// excludes every other entrance); otherwise any configured provider
    /// means `Federated`; otherwise `Local`. The caller is responsible for
    /// having validated the relay configuration before reporting it as
    /// configured.
    #[must_use]
    pub fn derive(relay_configured: bool, provider_count: usize) -> Self {
        if relay_configured {
            Self::Relay
        } else if provider_count > 0 {
            Self::Federated
        } else {
            Self::Local
        }
    }
}

/// How the presentee proved their identity on a sign-in.
///
/// Recorded on the login result by the service and meant for tokens and
/// audit rows, so a host can tell a password sign-in from an externally
/// proven one after the fact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(
    feature = "ts",
    ts(export, export_to = "packages/web_ts/src/generated/")
)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "ts", ts(rename_all = "snake_case"))]
pub enum AuthMethod {
    /// The local password (the historical sign-in).
    Password,
    /// A third-party provider vouched for the visitor.
    Oauth {
        /// The host's provider id.
        provider: String,
    },
    /// The designated central login source vouched for the visitor.
    Relay,
    /// A WebAuthn / passkey assertion.
    Passkey,
}

impl std::fmt::Display for AuthMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl AuthMethod {
    /// The canonical spelling (`"password"`, `"oauth"`, `"relay"`,
    /// `"passkey"`), for logs and audit rows.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::Oauth { .. } => "oauth",
            Self::Relay => "relay",
            Self::Passkey => "passkey",
        }
    }
}

/// One login method the browser can start.
///
/// A tagged union on the wire (`kind` discriminates), so the payload of each
/// kind sits flat beside the common fields instead of nested:
///
/// ```json
/// { "kind": "oauth", "id": "example-idp", "label": "…", "href": "/api/auth/oauth/example-idp", "provider": "example-idp" }
/// { "kind": "passkey", "id": "passkey", "label": "…", "href": "/api/auth/passkey/login" }
/// ```
///
/// The password card is not a method — it is the base card, announced by
/// the policy's `password` flag — so it has no variant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(
    feature = "ts",
    ts(export, export_to = "packages/web_ts/src/generated/")
)]
#[serde(rename_all = "snake_case", tag = "kind")]
#[cfg_attr(feature = "ts", ts(rename_all = "snake_case"))]
pub enum LoginMethodDescriptor {
    /// A third-party provider the browser is sent to, named by the host's
    /// provider id (`"github"`, an internal name, …).
    Oauth {
        /// Stable id, unique within the policy (the host names it).
        id: String,
        /// Display label. The host localises it; the contract carries it as data.
        label: String,
        /// Where the browser starts the method: a **same-origin absolute
        /// path** (`/api/auth/oauth/github`), never an external URL — the
        /// navigation target is checked when the policy is validated, so a
        /// tampered or misconfigured row cannot turn the login panel into an
        /// open redirect. Consumers use it as a **navigation** target
        /// (`location.href`, an `<a href>`); it is never a fetch or
        /// `Request` URL, whose base-URL rules differ.
        href: String,
        /// The host's provider id.
        provider: String,
        /// Optional icon reference (a URL, a symbol name — the host decides).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[cfg_attr(feature = "ts", ts(optional))]
        icon: Option<String>,
    },
    /// WebAuthn / passkey sign-in.
    Passkey {
        /// Stable id, unique within the policy.
        id: String,
        /// Display label.
        label: String,
        /// Where the browser starts the method (same-origin absolute path).
        href: String,
        /// Optional icon reference.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[cfg_attr(feature = "ts", ts(optional))]
        icon: Option<String>,
    },
    /// A host-specific entrance the host documents itself (for example a
    /// cross-realm jump row). Its `href` is a same-origin route like any
    /// other method.
    Custom {
        /// Stable id, unique within the policy.
        id: String,
        /// Display label.
        label: String,
        /// Where the browser starts the method (same-origin absolute path).
        href: String,
        /// Optional icon reference.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[cfg_attr(feature = "ts", ts(optional))]
        icon: Option<String>,
    },
}

impl LoginMethodDescriptor {
    /// The stable id, whatever the kind.
    #[must_use]
    pub fn id(&self) -> &str {
        match self {
            Self::Oauth { id, .. } | Self::Passkey { id, .. } | Self::Custom { id, .. } => id,
        }
    }

    /// The navigation target, whatever the kind.
    #[must_use]
    pub fn href(&self) -> &str {
        match self {
            Self::Oauth { href, .. } | Self::Passkey { href, .. } | Self::Custom { href, .. } => {
                href
            }
        }
    }

    /// The provider id when this is a provider entrance.
    #[must_use]
    pub fn provider(&self) -> Option<&str> {
        match self {
            Self::Oauth { provider, .. } => Some(provider),
            Self::Passkey { .. } | Self::Custom { .. } => None,
        }
    }

    /// A provider entrance with no icon.
    pub fn oauth(id: impl Into<String>, href: impl Into<String>, label: impl Into<String>) -> Self {
        let id = id.into();
        Self::Oauth {
            provider: id.clone(),
            id,
            label: label.into(),
            href: href.into(),
            icon: None,
        }
    }
}

/// How a relay-mode service is entered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(
    feature = "ts",
    ts(export, export_to = "packages/web_ts/src/generated/")
)]
pub struct RelayDirective {
    /// The service's **own** same-origin entry route (`/api/auth/relay`): the
    /// browser is sent there so the service can bind the return address into
    /// signed state before redirecting to the central site. Never the central
    /// site's URL directly.
    pub entry: String,
    /// The query parameter that carries the post-login return address
    /// (conventionally `return_to`).
    pub return_param: String,
}

/// The login-method discovery document a service serialises for its UI.
///
/// Declared in Rust; the TypeScript binding is generated from it. Hosts add
/// their own fields by embedding this struct, not by editing it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(
    feature = "ts",
    ts(export, export_to = "packages/web_ts/src/generated/")
)]
pub struct LoginPolicy {
    /// The wire version (currently `1`).
    pub version: u8,
    /// The mode — the summary of everything below.
    pub mode: AuthMode,
    /// Whether the local password card is offered. Must equal
    /// `mode.password_login_policy()` composed with the deployment's own
    /// password switch; `Relay` forbids `true`.
    pub password: bool,
    /// Every entrance other than the password card, in display order.
    pub methods: Vec<LoginMethodDescriptor>,
    /// Present if and only if `mode` is `Relay`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts", ts(optional))]
    pub relay: Option<RelayDirective>,
}

/// A [`LoginPolicy`] that disagrees with itself.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LoginPolicyViolation {
    /// `version` is not [`LOGIN_POLICY_VERSION`].
    #[error("unsupported login policy version {0}")]
    Version(u8),
    /// The relay directive is present outside `Relay` mode.
    #[error("relay directive present but mode is {0}")]
    RelayOutsideRelayMode(AuthMode),
    /// `Relay` mode without a relay directive — the UI would have nowhere to go.
    #[error("relay mode without a relay directive")]
    RelayWithoutDirective,
    /// `password` is offered in relay mode — a deployment with no login
    /// page cannot offer a password card.
    #[error("password is offered in relay mode")]
    PasswordInRelayMode,
    /// `password` is withheld in local mode — with no provider either, the
    /// deployment would have no way at all to sign in.
    #[error("local mode offers neither a password nor a provider")]
    PasswordMissingInLocalMode,
    /// `Local` mode advertising a provider, or `Federated` advertising none.
    #[error("mode {0} disagrees with the provider methods (found {1})")]
    ProviderCount(AuthMode, usize),
    /// Two methods share an id, or a method id is empty or padded.
    #[error("method id {0:?} is empty, padded or not unique")]
    MethodId(String),
    /// A method's label — for every kind, a row must have a visible name —
    /// or a provider entrance's provider id, is blank: the panel would
    /// render a nameless row, or the entrance would route nowhere.
    #[error("method {0:?} has a blank label or provider")]
    BlankMethod(String),
    /// A navigation target is not a same-origin absolute path.
    #[error("{0} is not a same-origin absolute path: {1:?}")]
    NotSameOriginPath(&'static str, String),
    /// The relay directive's return parameter is empty.
    #[error("relay return parameter is empty")]
    ReturnParam,
}

impl LoginPolicy {
    /// The policy of a plain self-contained deployment: password only.
    #[must_use]
    pub fn local() -> Self {
        Self {
            version: LOGIN_POLICY_VERSION,
            mode: AuthMode::Local,
            password: true,
            methods: Vec::new(),
            relay: None,
        }
    }

    /// The policy of a relay-mode deployment.
    #[must_use]
    pub fn relay(entry: impl Into<String>, return_param: impl Into<String>) -> Self {
        Self {
            version: LOGIN_POLICY_VERSION,
            mode: AuthMode::Relay,
            password: false,
            methods: Vec::new(),
            relay: Some(RelayDirective {
                entry: entry.into(),
                return_param: return_param.into(),
            }),
        }
    }

    /// Refuse a document that disagrees with itself.
    ///
    /// Invariants (all of them, so a UI can rely on each), in the order
    /// they are checked — the **first** violation is the one reported, so a
    /// host can rely on which invariant a given repair addresses:
    ///
    /// 1. `version` is the current one;
    /// 2. the relay directive is present exactly in `Relay` mode, and in
    ///    `Relay` mode its return parameter is non-blank and its entry a
    ///    same-origin absolute path;
    /// 3. `Relay` offers no password and `Local` offers one (a `Local`
    ///    deployment with no password and no provider would have no way at
    ///    all to sign in; `Federated` leaves the choice to the deployment);
    /// 4. `Local` and `Relay` list no provider and `Federated` lists at least
    ///    one (the designated source is the only provider entrance in relay
    ///    mode);
    /// 5. method ids are non-empty, unpadded (`" idp "` is refused) and
    ///    unique, and every label (and every provider id) is non-blank;
    /// 6. every method `href` is a same-origin absolute path (starts with a
    ///    single `/`), never an external or scheme-relative URL.
    ///
    /// # Errors
    ///
    /// The first violated invariant, as a [`LoginPolicyViolation`].
    pub fn validate(&self) -> Result<(), LoginPolicyViolation> {
        if self.version != LOGIN_POLICY_VERSION {
            return Err(LoginPolicyViolation::Version(self.version));
        }
        match (self.mode, &self.relay) {
            (AuthMode::Relay, None) => return Err(LoginPolicyViolation::RelayWithoutDirective),
            (AuthMode::Relay, Some(directive)) => {
                if directive.return_param.trim().is_empty() {
                    return Err(LoginPolicyViolation::ReturnParam);
                }
                check_same_origin_path("relay entry", &directive.entry)?;
            }
            (mode, Some(_)) => return Err(LoginPolicyViolation::RelayOutsideRelayMode(mode)),
            (_, None) => {}
        }
        match self.mode {
            AuthMode::Relay if self.password => {
                return Err(LoginPolicyViolation::PasswordInRelayMode);
            }
            AuthMode::Local if !self.password => {
                return Err(LoginPolicyViolation::PasswordMissingInLocalMode);
            }
            _ => {}
        }
        let providers = self
            .methods
            .iter()
            .filter(|method| method.provider().is_some())
            .count();
        match self.mode {
            AuthMode::Local if providers > 0 => {
                return Err(LoginPolicyViolation::ProviderCount(
                    AuthMode::Local,
                    providers,
                ));
            }
            AuthMode::Federated if providers == 0 => {
                return Err(LoginPolicyViolation::ProviderCount(
                    AuthMode::Federated,
                    providers,
                ));
            }
            // The designated source is the ONLY provider entrance in relay mode.
            AuthMode::Relay if providers > 0 => {
                return Err(LoginPolicyViolation::ProviderCount(
                    AuthMode::Relay,
                    providers,
                ));
            }
            _ => {}
        }
        // Ids first, then navigation targets: the documented order.
        let mut seen = std::collections::HashSet::new();
        for method in &self.methods {
            let id = method.id();
            // Padded ids are refused outright: `" idp "` and `"idp"` must not be
            // two methods, and a blank id names nothing.
            if id.is_empty() || id.trim() != id || !seen.insert(id) {
                return Err(LoginPolicyViolation::MethodId(id.to_owned()));
            }
            let blank_label = match method {
                LoginMethodDescriptor::Oauth { label, .. }
                | LoginMethodDescriptor::Passkey { label, .. }
                | LoginMethodDescriptor::Custom { label, .. } => label.trim().is_empty(),
            };
            let blank_provider = method
                .provider()
                .is_some_and(|provider| provider.trim().is_empty());
            if blank_label || blank_provider {
                return Err(LoginPolicyViolation::BlankMethod(id.to_owned()));
            }
        }
        for method in &self.methods {
            check_same_origin_path("method href", method.href())?;
        }
        Ok(())
    }
}

/// A navigation target must start with exactly one `/`: an absolute path on
/// the service's own origin. `//host` is scheme-relative (a foreign origin),
/// and anything without the leading slash is relative to the current page —
/// neither is a target the login panel was configured with.
fn check_same_origin_path(what: &'static str, raw: &str) -> Result<(), LoginPolicyViolation> {
    let same_origin = raw.starts_with('/') && !raw.starts_with("//") && raw != "/";
    if same_origin {
        Ok(())
    } else {
        Err(LoginPolicyViolation::NotSameOriginPath(
            what,
            raw.to_owned(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oauth(id: &str) -> LoginMethodDescriptor {
        LoginMethodDescriptor::oauth(id, format!("/api/auth/oauth/{id}"), id)
    }

    fn passkey() -> LoginMethodDescriptor {
        LoginMethodDescriptor::Passkey {
            id: "passkey".to_owned(),
            label: "Passkey".to_owned(),
            href: "/api/auth/passkey/login".to_owned(),
            icon: None,
        }
    }

    fn custom(id: &str, href: &str) -> LoginMethodDescriptor {
        LoginMethodDescriptor::Custom {
            id: id.to_owned(),
            label: "Jump".to_owned(),
            href: href.to_owned(),
            icon: None,
        }
    }

    fn federated(methods: Vec<LoginMethodDescriptor>) -> LoginPolicy {
        LoginPolicy {
            mode: AuthMode::Federated,
            methods,
            ..LoginPolicy::local()
        }
    }

    #[test]
    fn mode_names_round_trip_and_unknown_is_none() {
        for mode in [AuthMode::Local, AuthMode::Federated, AuthMode::Relay] {
            assert_eq!(AuthMode::parse(mode.as_str()), Some(mode));
            assert_eq!(
                AuthMode::parse(&format!("  {} \t", mode.as_str().to_uppercase())),
                Some(mode)
            );
            assert_eq!(mode.to_string(), mode.as_str());
        }
        assert_eq!(AuthMode::parse(""), None);
        assert_eq!(AuthMode::parse("sso"), None);
        assert_eq!(AuthMode::parse("relay "), Some(AuthMode::Relay));
    }

    #[test]
    fn default_is_local() {
        assert_eq!(AuthMode::default(), AuthMode::Local);
        assert_eq!(AuthMode::Local, AuthMode::default());
        let mode: AuthMode = serde_json::from_str("\"federated\"").expect("wire name deserialises");
        assert_eq!(mode, AuthMode::Federated);
        assert!(
            serde_json::from_str::<AuthMode>("\"sso\"").is_err(),
            "unknown wire name is refused"
        );
    }

    #[test]
    fn relay_refuses_password_structurally_and_others_leave_the_choice() {
        assert_eq!(
            AuthMode::Relay.password_login_policy(),
            PasswordLoginPolicy::Disabled
        );
        assert!(!AuthMode::Relay.password_login_policy().is_enabled());
        assert_eq!(
            AuthMode::Local.password_login_policy(),
            PasswordLoginPolicy::Enabled
        );
        assert_eq!(
            AuthMode::Federated.password_login_policy(),
            PasswordLoginPolicy::Enabled
        );
        assert!(AuthMode::Relay.is_relay());
        assert!(!AuthMode::Local.is_relay());
        assert!(!AuthMode::Federated.is_relay());
    }

    #[test]
    fn derive_prefers_relay_then_providers_then_local() {
        assert_eq!(AuthMode::derive(true, 7), AuthMode::Relay);
        assert_eq!(AuthMode::derive(true, 0), AuthMode::Relay);
        assert_eq!(AuthMode::derive(false, 1), AuthMode::Federated);
        assert_eq!(AuthMode::derive(false, 0), AuthMode::Local);
    }

    #[test]
    fn auth_method_names_are_canonical_and_externally_tagged() {
        let cases = [
            (AuthMethod::Password, serde_json::json!("password")),
            (AuthMethod::Relay, serde_json::json!("relay")),
            (AuthMethod::Passkey, serde_json::json!("passkey")),
            (
                AuthMethod::Oauth {
                    provider: "example-idp".to_owned(),
                },
                serde_json::json!({ "oauth": { "provider": "example-idp" } }),
            ),
        ];
        for (method, wire) in &cases {
            assert_eq!(serde_json::to_value(method).expect("serialises"), *wire);
            let back: AuthMethod = serde_json::from_value(wire.clone()).expect("round-trips");
            assert_eq!(&back, method);
        }
        assert_eq!(AuthMethod::Password.as_str(), "password");
        assert_eq!(
            AuthMethod::Oauth {
                provider: String::new()
            }
            .as_str(),
            "oauth"
        );
        assert_eq!(AuthMethod::Relay.as_str(), "relay");
        assert_eq!(AuthMethod::Passkey.as_str(), "passkey");
    }

    #[test]
    fn local_policy_is_valid_and_serialises_minimally() {
        let policy = LoginPolicy::local();
        policy.validate().expect("local policy is self-consistent");
        let json = serde_json::to_value(&policy).expect("serialises");
        assert_eq!(
            json,
            serde_json::json!({
                "version": 1,
                "mode": "local",
                "password": true,
                "methods": []
            })
        );
        let back: LoginPolicy = serde_json::from_value(json).expect("round-trips");
        assert_eq!(back, policy);
    }

    #[test]
    fn relay_policy_serialises_the_directive_and_nothing_else() {
        let policy = LoginPolicy::relay("/api/auth/relay", "return_to");
        policy.validate().expect("relay policy is self-consistent");
        let json = serde_json::to_value(&policy).expect("serialises");
        assert_eq!(
            json,
            serde_json::json!({
                "version": 1,
                "mode": "relay",
                "password": false,
                "methods": [],
                "relay": { "entry": "/api/auth/relay", "return_param": "return_to" }
            })
        );
        let back: LoginPolicy = serde_json::from_value(json).expect("round-trips");
        assert_eq!(back, policy);
    }

    #[test]
    fn federated_policy_carries_its_methods_flat() {
        let policy = federated(vec![passkey(), oauth("example-idp")]);
        policy
            .validate()
            .expect("federated policy is self-consistent");
        let json = serde_json::to_value(&policy).expect("serialises");
        assert_eq!(json["mode"], "federated");
        assert_eq!(
            json["methods"][0],
            serde_json::json!({
                "kind": "passkey", "id": "passkey", "label": "Passkey", "href": "/api/auth/passkey/login"
            })
        );
        // MUT:flat-payload — the provider sits beside the discriminator, not nested under it.
        assert_eq!(
            json["methods"][1],
            serde_json::json!({
                "kind": "oauth", "id": "example-idp", "label": "example-idp",
                "href": "/api/auth/oauth/example-idp", "provider": "example-idp"
            })
        );
        let back: LoginPolicy = serde_json::from_value(json).expect("round-trips");
        assert_eq!(back, policy);
        assert_eq!(back.methods[1].provider(), Some("example-idp"));
        assert_eq!(back.methods[0].provider(), None);
        assert_eq!(back.methods[0].id(), "passkey");
        assert_eq!(back.methods[0].href(), "/api/auth/passkey/login");
    }

    #[test]
    fn icon_is_omitted_when_absent_and_kept_when_present() {
        let with_icon = LoginMethodDescriptor::Oauth {
            id: "example-idp".to_owned(),
            label: "example-idp".to_owned(),
            href: "/api/auth/oauth/example-idp".to_owned(),
            provider: "example-idp".to_owned(),
            icon: Some("key".to_owned()),
        };
        let policy = federated(vec![oauth("example-idp"), with_icon.clone()]);
        assert_eq!(
            policy.validate(),
            Err(LoginPolicyViolation::MethodId("example-idp".to_owned())),
            "same id twice is refused"
        );
        let json = serde_json::to_value(&with_icon).expect("serialises");
        assert_eq!(json["icon"], "key");
        let json = serde_json::to_value(oauth("example-idp")).expect("serialises");
        assert!(json.get("icon").is_none(), "absent icon is omitted");
        let parsed: LoginMethodDescriptor = serde_json::from_value(json).expect("icon defaults");
        assert_eq!(parsed, oauth("example-idp"));
    }

    #[test]
    fn custom_kind_is_a_flat_tagged_payload() {
        let method = custom("jump", "/auth/jump");
        let json = serde_json::to_value(&method).expect("serialises");
        assert_eq!(
            json,
            serde_json::json!({ "kind": "custom", "id": "jump", "label": "Jump", "href": "/auth/jump" })
        );
    }

    #[test]
    fn validate_refuses_each_self_disagreement() {
        let base = LoginPolicy::local();

        let mut policy = base.clone();
        policy.version = 2;
        assert_eq!(policy.validate(), Err(LoginPolicyViolation::Version(2)));

        let mut policy = base.clone();
        policy.relay = Some(RelayDirective {
            entry: "/x".to_owned(),
            return_param: "r".to_owned(),
        });
        assert_eq!(
            policy.validate(),
            Err(LoginPolicyViolation::RelayOutsideRelayMode(AuthMode::Local))
        );

        let mut policy = LoginPolicy::relay("/x", "r");
        policy.relay = None;
        assert_eq!(
            policy.validate(),
            Err(LoginPolicyViolation::RelayWithoutDirective)
        );

        let mut policy = LoginPolicy::relay("/x", "r");
        policy.password = true;
        assert_eq!(
            policy.validate(),
            Err(LoginPolicyViolation::PasswordInRelayMode)
        );

        let policy = LoginPolicy::relay("/x", "");
        assert_eq!(policy.validate(), Err(LoginPolicyViolation::ReturnParam));

        let mut policy = base.clone();
        policy.methods = vec![oauth("example-idp")];
        assert_eq!(
            policy.validate(),
            Err(LoginPolicyViolation::ProviderCount(AuthMode::Local, 1))
        );

        let policy = federated(vec![]);
        assert_eq!(
            policy.validate(),
            Err(LoginPolicyViolation::ProviderCount(AuthMode::Federated, 0))
        );

        // MUT:relay-sole-source — a provider entrance beside the designated source is a contradiction.
        let mut policy = LoginPolicy::relay("/x", "r");
        policy.methods = vec![oauth("example-idp")];
        assert_eq!(
            policy.validate(),
            Err(LoginPolicyViolation::ProviderCount(AuthMode::Relay, 1))
        );

        let policy = federated(vec![oauth("same"), oauth("same")]);
        assert_eq!(
            policy.validate(),
            Err(LoginPolicyViolation::MethodId("same".to_owned()))
        );

        let policy = federated(vec![oauth("")]);
        assert_eq!(
            policy.validate(),
            Err(LoginPolicyViolation::MethodId(String::new()))
        );

        // MUT:blank-method-fields — a nameless row, or a provider entrance whose
        // provider routes nowhere, is refused rather than rendered empty.
        let mut policy = federated(vec![oauth("example-idp")]);
        policy.methods[0] = LoginMethodDescriptor::oauth("example-idp", "/ok", "   ");
        assert_eq!(
            policy.validate(),
            Err(LoginPolicyViolation::BlankMethod("example-idp".to_owned()))
        );
        let mut policy = federated(vec![oauth("example-idp")]);
        policy.methods[0] = LoginMethodDescriptor::Oauth {
            id: "example-idp".to_owned(),
            label: "Example".to_owned(),
            href: "/ok".to_owned(),
            provider: "  ".to_owned(),
            icon: None,
        };
        assert_eq!(
            policy.validate(),
            Err(LoginPolicyViolation::BlankMethod("example-idp".to_owned()))
        );
        let mut policy = LoginPolicy::local();
        policy.methods.push(passkey());
        policy.methods[0] = LoginMethodDescriptor::Passkey {
            id: "passkey".to_owned(),
            label: "\t".to_owned(),
            href: "/api/auth/passkey/login".to_owned(),
            icon: None,
        };
        assert_eq!(
            policy.validate(),
            Err(LoginPolicyViolation::BlankMethod("passkey".to_owned()))
        );

        // MUT:unpadded-ids — a padded id is refused, not silently kept as a second method.
        let policy = federated(vec![oauth(" idp ")]);
        assert_eq!(
            policy.validate(),
            Err(LoginPolicyViolation::MethodId(" idp ".to_owned()))
        );
        let policy = federated(vec![oauth("idp"), oauth(" idp ")]);
        assert_eq!(
            policy.validate(),
            Err(LoginPolicyViolation::MethodId(" idp ".to_owned()))
        );

        let policy = federated(vec![oauth("example-idp")]);
        let mut policy = policy;
        policy.methods[0] =
            LoginMethodDescriptor::oauth("example-idp", "https://evil.example/authorize", "x");
        assert_eq!(
            policy.validate(),
            Err(LoginPolicyViolation::NotSameOriginPath(
                "method href",
                "https://evil.example/authorize".to_owned()
            ))
        );
    }

    #[test]
    fn navigation_targets_must_be_same_origin_absolute_paths() {
        // MUT:relayed-nav-target — a scheme-relative or relative target would send the
        // browser to a foreign origin from the login panel; each of these must be refused.
        for bad in [
            "//evil.example/x",
            "auth/oauth",
            "https://evil.example",
            "/",
            "",
        ] {
            let mut policy = LoginPolicy::relay("/ok".to_owned(), "r".to_owned());
            policy.relay.as_mut().expect("directive").entry = bad.to_owned();
            assert_eq!(
                policy.validate(),
                Err(LoginPolicyViolation::NotSameOriginPath(
                    "relay entry",
                    bad.to_owned()
                )),
                "relay entry {bad:?} must be refused"
            );
            let mut policy = federated(vec![oauth("example-idp")]);
            policy.methods[0] = LoginMethodDescriptor::oauth("example-idp", bad, "x");
            assert_eq!(
                policy.validate(),
                Err(LoginPolicyViolation::NotSameOriginPath(
                    "method href",
                    bad.to_owned()
                )),
                "method href {bad:?} must be refused"
            );
        }
        // A path with a query and a fragment is still a same-origin path.
        let policy = LoginPolicy::relay("/api/auth/relay?x=1#f".to_owned(), "r".to_owned());
        policy.validate().expect("query and fragment are fine");
    }

    #[test]
    fn relay_mode_tolerates_non_provider_entrances() {
        // Passkey and custom entrances do not contradict "the designated source is
        // the only provider"; only a provider entrance does.
        let mut policy = LoginPolicy::relay("/api/auth/relay".to_owned(), "return_to".to_owned());
        policy.methods.push(custom("jump", "/auth/jump"));
        policy.methods.push(passkey());
        policy
            .validate()
            .expect("non-provider entrances are allowed in relay mode");
    }

    #[test]
    fn a_local_deployment_must_offer_its_password() {
        // MUT:local-needs-password — no password and no provider is a deployment
        // nobody can sign in to; the document must not validate.
        let mut policy = LoginPolicy::local();
        policy.password = false;
        assert_eq!(
            policy.validate(),
            Err(LoginPolicyViolation::PasswordMissingInLocalMode)
        );
        // Passkey and custom entrances do not substitute for the password card.
        policy.methods.push(passkey());
        assert_eq!(
            policy.validate(),
            Err(LoginPolicyViolation::PasswordMissingInLocalMode)
        );
        // A federated deployment MAY withhold the password (third-party only).
        let third_party_only = LoginPolicy {
            password: false,
            ..federated(vec![oauth("example-idp")])
        };
        third_party_only
            .validate()
            .expect("federated without password is consistent");
    }

    #[test]
    fn validate_reports_the_first_violation_in_document_order() {
        // 2. relay pair: the return parameter is checked before the entry path …
        let policy = LoginPolicy::relay("https://evil.example", "   ");
        assert_eq!(policy.validate(), Err(LoginPolicyViolation::ReturnParam));
        // … and both before the password ↔ mode rule (3).
        let mut policy = LoginPolicy::relay("https://evil.example", "r");
        policy.password = true;
        assert_eq!(
            policy.validate(),
            Err(LoginPolicyViolation::NotSameOriginPath(
                "relay entry",
                "https://evil.example".to_owned()
            ))
        );
        // 3 before 4: a Local document with neither password nor provider reports
        // the missing password, not the provider count.
        let mut policy = LoginPolicy::local();
        policy.password = false;
        assert_eq!(
            policy.validate(),
            Err(LoginPolicyViolation::PasswordMissingInLocalMode)
        );
        // 5 before 6: a later method's bad id outranks an earlier method's bad href.
        let mut policy = LoginPolicy {
            mode: AuthMode::Federated,
            methods: vec![oauth("example-idp"), oauth("")],
            ..LoginPolicy::local()
        };
        policy.methods[0] =
            LoginMethodDescriptor::oauth("example-idp", "https://evil.example", "x");
        assert_eq!(
            policy.validate(),
            Err(LoginPolicyViolation::MethodId(String::new())),
            "ids are checked before hrefs"
        );
        // 6: with every id sound, the href is reported.
        let mut policy = LoginPolicy {
            mode: AuthMode::Federated,
            methods: vec![
                LoginMethodDescriptor::oauth("example-idp", "/ok", "x"),
                oauth("other"),
            ],
            ..LoginPolicy::local()
        };
        policy.methods[1] = LoginMethodDescriptor::oauth("other", "//evil.example", "x");
        assert_eq!(
            policy.validate(),
            Err(LoginPolicyViolation::NotSameOriginPath(
                "method href",
                "//evil.example".to_owned()
            ))
        );
    }

    #[test]
    fn a_local_deployment_may_still_offer_passkey_and_custom_entrances() {
        let mut policy = LoginPolicy::local();
        policy.methods.push(passkey());
        policy.methods.push(custom("jump", "/auth/jump"));
        policy
            .validate()
            .expect("local mode with non-provider entrances is consistent");
    }
}
