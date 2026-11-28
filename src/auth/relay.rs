//! Relay mode (a designated external login source) as configuration.
//!
//! Relay mode is a **deployment shape**, so it is read from the environment
//! (workspace rule: bootstrap configuration never lives in a database), with
//! family-wide names and no service prefix:
//!
//! | Variable | Meaning |
//! | --- | --- |
//! | `AUTH_RELAY_ISSUER` | The central login site |
//! | `AUTH_RELAY_CLIENT_ID` | This service's registered client id |
//! | `AUTH_RELAY_CLIENT_SECRET` | Optional; absent = public client (PKCE is then the only proof) |
//! | `AUTH_RELAY_REDIRECT_URL` | This service's callback, whose path ends in `/callback` |
//! | `AUTH_RELAY_AUTHORIZE_URL` / `_TOKEN_URL` / `_USERINFO_URL` | Optional endpoint overrides; otherwise resolved from OIDC discovery |
//! | `AUTH_RELAY_SCOPES` | Space-separated, default `openid profile email` |
//! | `AUTH_RELAY_RETURN_PARAM` | Default `return_to` |
//! | `AUTH_RELAY_RETURN_ORIGINS` | Comma-separated exact origins a return address may name; never empty |
//! | `AUTH_RELAY_BREAK_GLASS` | The only switch that lets a host expose a local login in relay mode |
//! | `AUTH_MODE` | Optional; must agree with the relay configuration |
//!
//! # Fail closed
//!
//! [`RelayConfig::from_env`] answers `Ok(None)` when **no** relay variable is
//! set, and an `Err` naming the variable when the set is incomplete or
//! malformed. It never falls back to a local login: a production instance
//! that quietly re-exposed its password form because one variable went
//! missing is exactly the drift this module exists to rule out. The same
//! holds for [`mode_from_env`]: an explicit `AUTH_MODE` that contradicts the
//! configuration is an error, not a tie-break.
//!
//! The protocol side (PKCE, state, the token exchange) lives in
//! [`crate::auth::passport::oauth`] behind the `auth-oauth` feature; this
//! module is always compiled so every deployment can read its mode at boot.

use anyhow::Result;
use url::Url;

use zeroize::Zeroizing;

use crate::auth::mode::{AuthMode, LoginPolicy};

/// Explicit mode override; must agree with the relay configuration.
pub const AUTH_MODE_ENV: &str = "AUTH_MODE";
/// The central login site.
pub const RELAY_ISSUER_ENV: &str = "AUTH_RELAY_ISSUER";
/// Optional authorization-endpoint override.
pub const RELAY_AUTHORIZE_URL_ENV: &str = "AUTH_RELAY_AUTHORIZE_URL";
/// Optional token-endpoint override.
pub const RELAY_TOKEN_URL_ENV: &str = "AUTH_RELAY_TOKEN_URL";
/// Optional userinfo-endpoint override.
pub const RELAY_USERINFO_URL_ENV: &str = "AUTH_RELAY_USERINFO_URL";
/// This service's registered client id.
pub const RELAY_CLIENT_ID_ENV: &str = "AUTH_RELAY_CLIENT_ID";
/// Optional client secret; absent means a public client.
pub const RELAY_CLIENT_SECRET_ENV: &str = "AUTH_RELAY_CLIENT_SECRET";
/// This service's callback URL; its path ends in `/callback`.
pub const RELAY_REDIRECT_URL_ENV: &str = "AUTH_RELAY_REDIRECT_URL";
/// Space-separated scopes.
pub const RELAY_SCOPES_ENV: &str = "AUTH_RELAY_SCOPES";
/// The query parameter carrying the return address.
pub const RELAY_RETURN_PARAM_ENV: &str = "AUTH_RELAY_RETURN_PARAM";
/// Comma-separated exact origins a return address may name.
pub const RELAY_RETURN_ORIGINS_ENV: &str = "AUTH_RELAY_RETURN_ORIGINS";
/// Opt-in that lets a host expose a local login while in relay mode.
pub const RELAY_BREAK_GLASS_ENV: &str = "AUTH_RELAY_BREAK_GLASS";

/// Every relay variable; a deployment sets none of them or a complete set.
pub const RELAY_ENV_VARS: &[&str] = &[
    RELAY_ISSUER_ENV,
    RELAY_AUTHORIZE_URL_ENV,
    RELAY_TOKEN_URL_ENV,
    RELAY_USERINFO_URL_ENV,
    RELAY_CLIENT_ID_ENV,
    RELAY_CLIENT_SECRET_ENV,
    RELAY_REDIRECT_URL_ENV,
    RELAY_SCOPES_ENV,
    RELAY_RETURN_PARAM_ENV,
    RELAY_RETURN_ORIGINS_ENV,
    RELAY_BREAK_GLASS_ENV,
];

const DEFAULT_SCOPES: &[&str] = &["openid", "profile", "email"];
const DEFAULT_RETURN_PARAM: &str = "return_to";
/// The callback path convention: the entry route is the callback path
/// without this suffix.
const CALLBACK_SUFFIX: &str = "/callback";

/// A relay deployment's configuration.
#[derive(Clone, Debug)]
pub struct RelayConfig {
    pub issuer: Url,
    pub authorize_url: Option<Url>,
    pub token_url: Option<Url>,
    pub userinfo_url: Option<Url>,
    pub client_id: String,
    /// `None` for a public client.
    pub client_secret: Option<Zeroizing<String>>,
    pub redirect_url: Url,
    pub scopes: Vec<String>,
    pub return_param: String,
    /// Exact `scheme://host[:port]` origins; never empty.
    pub allowed_return_origins: Vec<String>,
    pub break_glass: bool,
}

/// A relay configuration that cannot be honoured.
#[derive(Debug, thiserror::Error)]
pub enum RelayConfigError {
    #[error("relay mode needs {0}")]
    Missing(&'static str),
    #[error("{0} is not a valid URL: {1}")]
    InvalidUrl(&'static str, url::ParseError),
    #[error("{0} must be https (http is allowed only for a loopback host)")]
    NotHttps(&'static str),
    #[error("{0} lists no origin")]
    NoReturnOrigins(&'static str),
    #[error("{0} entry {1:?} is not an exact origin")]
    BadOrigin(&'static str, String),
    #[error("the path of {0} must end with {CALLBACK_SUFFIX} (got {1:?})")]
    RedirectPath(&'static str, String),
    #[error("{0} names no scopes")]
    BlankScopes(&'static str),
    #[error("{0} is blank")]
    Blank(&'static str),
    #[error("{AUTH_MODE_ENV} must name local, federated or relay (got {0:?})")]
    UnknownMode(String),
    #[error("{AUTH_MODE_ENV} is {0} while a relay source is configured; remove one of them")]
    ModeConflicts(String),
    #[error("{AUTH_MODE_ENV} says relay but no relay source is configured")]
    RelayNotConfigured,
    #[error("discovery document: {0}")]
    Discovery(&'static str),
}

fn is_truthy(raw: &str) -> bool {
    matches!(
        raw.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "on" | "yes"
    )
}

fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

fn parse_url(raw: &str, name: &'static str) -> Result<Url, RelayConfigError> {
    let url = Url::parse(raw.trim()).map_err(|error| RelayConfigError::InvalidUrl(name, error))?;
    let secure = url.scheme() == "https" || (url.scheme() == "http" && is_loopback(&url));
    if !secure || url.host().is_none() {
        return Err(RelayConfigError::NotHttps(name));
    }
    Ok(url)
}

/// Characters a navigation target must never contain: a backslash (browsers
/// read it as a slash, so `/` + backslash + host leaves the origin), control
/// characters, the line/paragraph separators, and the format characters that
/// reshape how a path is displayed or ordered.
pub(crate) fn is_unsafe_in_a_location(c: char) -> bool {
    c == '\\'
        || c.is_control()
        || matches!(
            c,
            '\u{2028}'
                | '\u{2029}'
                | '\u{00AD}'
                | '\u{200B}'..='\u{200F}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2066}'..='\u{2069}'
                | '\u{FEFF}'
        )
}

/// `scheme://host[:port]` of a URL, the form an allow-list entry takes.
#[must_use]
pub fn origin_of(url: &Url) -> String {
    let port = url.port().map(|p| format!(":{p}")).unwrap_or_default();
    format!(
        "{}://{}{}",
        url.scheme(),
        url.host_str().unwrap_or_default(),
        port
    )
}

/// Normalise a return address the browser asked for.
///
/// `Some(path)` for a same-origin absolute path (`/inbox?x=1`, never `//host`,
/// a backslash, control or format characters, `/`, blank) or for an absolute
/// URL whose origin is on the allow-list (reduced to its path, query and
/// fragment). `None` for anything else — a foreign origin is never
/// forwarded. The result is what the host carries through its signed state
/// (the host's job — nothing here signs) and where the browser lands
/// afterwards.
#[must_use]
pub fn safe_return_path(raw: &str, allowed_origins: &[String]) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    if let Some(path) = raw.strip_prefix('/') {
        // A single leading slash is a same-origin path; `//host` is
        // scheme-relative and names a foreign origin. A backslash is refused
        // too: browsers normalise a backslash to `/` in URLs, so a path that
        // starts `/` + backslash + host would be followed as `//host`. Control
        // characters, the Unicode line separators and the format characters
        // that reshape display (soft hyphen, zero-width marks, bidi
        // controls, BOM) are refused as well: the value ends up in a
        // `Location` header and may be shown to a user.
        if path.is_empty() || path.starts_with('/') {
            return None;
        }
        if raw.chars().any(is_unsafe_in_a_location) {
            return None;
        }
        return Some(raw.to_owned());
    }
    let url = Url::parse(raw).ok()?;
    let origin = origin_of(&url);
    if !allowed_origins.iter().any(|allowed| allowed == &origin) {
        return None;
    }
    let mut path = url.path().to_owned();
    if path == "/" {
        return None;
    }
    if let Some(query) = url.query() {
        path.push('?');
        path.push_str(query);
    }
    if let Some(fragment) = url.fragment() {
        path.push('#');
        path.push_str(fragment);
    }
    Some(path)
}

impl RelayConfig {
    /// Read the configuration from the process environment.
    ///
    /// # Errors
    ///
    /// As [`from_env_with`](Self::from_env_with).
    pub fn from_env() -> Result<Option<Self>, RelayConfigError> {
        Self::from_env_with(|name| std::env::var(name).ok())
    }

    /// Read the configuration through `read`.
    ///
    /// `Ok(None)` when no relay variable is set at all; otherwise every
    /// required variable must be present and well-formed.
    ///
    /// # Errors
    ///
    /// [`RelayConfigError`] naming the first offending variable.
    pub fn from_env_with(
        read: impl Fn(&str) -> Option<String>,
    ) -> Result<Option<Self>, RelayConfigError> {
        let value = |name: &'static str| -> Option<String> {
            read(name)
                .map(|raw| raw.trim().to_owned())
                .filter(|raw| !raw.is_empty())
        };
        // Fail closed on *presence*, not on content: a relay variable that is
        // set but blank means "relay was intended", never "no relay" — a
        // template that sets only a secret must not start up as a local
        // deployment. (MUT:presence-not-content)
        if RELAY_ENV_VARS.iter().all(|name| read(name).is_none()) {
            return Ok(None);
        }
        let issuer = value(RELAY_ISSUER_ENV)
            .ok_or(RelayConfigError::Missing(RELAY_ISSUER_ENV))
            .and_then(|raw| parse_url(&raw, RELAY_ISSUER_ENV))?;
        let client_id =
            value(RELAY_CLIENT_ID_ENV).ok_or(RelayConfigError::Missing(RELAY_CLIENT_ID_ENV))?;
        let redirect_url = value(RELAY_REDIRECT_URL_ENV)
            .ok_or(RelayConfigError::Missing(RELAY_REDIRECT_URL_ENV))
            .and_then(|raw| parse_url(&raw, RELAY_REDIRECT_URL_ENV))?;
        let redirect_path = redirect_url.path().to_owned();
        if !redirect_path.ends_with(CALLBACK_SUFFIX) {
            return Err(RelayConfigError::RedirectPath(
                RELAY_REDIRECT_URL_ENV,
                redirect_path,
            ));
        }
        let authorize_url = match value(RELAY_AUTHORIZE_URL_ENV) {
            Some(raw) => Some(parse_url(&raw, RELAY_AUTHORIZE_URL_ENV)?),
            None => None,
        };
        let token_url = match value(RELAY_TOKEN_URL_ENV) {
            Some(raw) => Some(parse_url(&raw, RELAY_TOKEN_URL_ENV)?),
            None => None,
        };
        let userinfo_url = match value(RELAY_USERINFO_URL_ENV) {
            Some(raw) => Some(parse_url(&raw, RELAY_USERINFO_URL_ENV)?),
            None => None,
        };
        let scopes = match value(RELAY_SCOPES_ENV) {
            Some(raw) => raw
                .split_whitespace()
                .map(str::to_owned)
                .collect::<Vec<_>>(),
            None => DEFAULT_SCOPES.iter().map(|s| (*s).to_owned()).collect(),
        };
        if scopes.is_empty() {
            return Err(RelayConfigError::BlankScopes(RELAY_SCOPES_ENV));
        }
        let return_param =
            value(RELAY_RETURN_PARAM_ENV).unwrap_or_else(|| DEFAULT_RETURN_PARAM.to_owned());
        if return_param.trim().is_empty() {
            return Err(RelayConfigError::Blank(RELAY_RETURN_PARAM_ENV));
        }
        let mut allowed_return_origins = Vec::new();
        {
            let raw = value(RELAY_RETURN_ORIGINS_ENV)
                .ok_or(RelayConfigError::Missing(RELAY_RETURN_ORIGINS_ENV))?;
            for entry in raw.split(',') {
                let entry = entry.trim();
                if entry.is_empty() {
                    continue;
                }
                let parsed = Url::parse(entry).map_err(|error| {
                    RelayConfigError::InvalidUrl(RELAY_RETURN_ORIGINS_ENV, error)
                })?;
                let secure = parsed.scheme() == "https"
                    || (parsed.scheme() == "http" && is_loopback(&parsed));
                let bare =
                    parsed.path() == "/" && parsed.query().is_none() && parsed.fragment().is_none();
                if !secure || parsed.host().is_none() || !bare {
                    return Err(RelayConfigError::BadOrigin(
                        RELAY_RETURN_ORIGINS_ENV,
                        entry.to_owned(),
                    ));
                }
                let origin = origin_of(&parsed);
                if !allowed_return_origins.contains(&origin) {
                    allowed_return_origins.push(origin);
                }
            }
        }
        if allowed_return_origins.is_empty() {
            return Err(RelayConfigError::NoReturnOrigins(RELAY_RETURN_ORIGINS_ENV));
        }
        let client_secret = value(RELAY_CLIENT_SECRET_ENV).map(Zeroizing::new);
        let break_glass = value(RELAY_BREAK_GLASS_ENV).is_some_and(|raw| is_truthy(&raw));
        Ok(Some(Self {
            issuer,
            authorize_url,
            token_url,
            userinfo_url,
            client_id,
            client_secret,
            redirect_url,
            scopes,
            return_param,
            allowed_return_origins,
            break_glass,
        }))
    }

    /// Fill the endpoints that were not set explicitly from an OIDC
    /// discovery document.
    ///
    /// # Errors
    ///
    /// [`RelayConfigError::Discovery`] when an endpoint is missing or
    /// unreadable, or names an origin other than the issuer's.
    pub fn with_discovery(
        mut self,
        document: &serde_json::Value,
    ) -> Result<Self, RelayConfigError> {
        let endpoint = |key: &'static str| -> Result<Option<Url>, RelayConfigError> {
            match document.get(key) {
                None | Some(serde_json::Value::Null) => Ok(None),
                Some(serde_json::Value::String(raw)) => {
                    let url = Url::parse(raw).map_err(|_| RelayConfigError::Discovery(key))?;
                    if origin_of(&url) != origin_of(&self.issuer) {
                        return Err(RelayConfigError::Discovery(key));
                    }
                    Ok(Some(url))
                }
                Some(_) => Err(RelayConfigError::Discovery(key)),
            }
        };
        if self.authorize_url.is_none() {
            self.authorize_url = endpoint("authorization_endpoint")?;
        }
        if self.token_url.is_none() {
            self.token_url = endpoint("token_endpoint")?;
        }
        if self.userinfo_url.is_none() {
            self.userinfo_url = endpoint("userinfo_endpoint")?;
        }
        Ok(self)
    }

    /// The service's own entry route, derived from the callback path by
    /// convention: `/api/auth/relay/callback` → `/api/auth/relay`.
    #[must_use]
    pub fn relay_entry(&self) -> String {
        let path = self.redirect_url.path();
        path.strip_suffix(CALLBACK_SUFFIX)
            .unwrap_or(path)
            .to_owned()
    }

    /// The discovery document a relay-mode service publishes.
    #[must_use]
    pub fn login_policy(&self) -> LoginPolicy {
        LoginPolicy::relay(self.relay_entry(), self.return_param.clone())
    }

    /// The central site's OIDC discovery URL.
    #[must_use]
    pub fn discovery_url(&self) -> Url {
        let base = self.issuer.as_str().trim_end_matches('/');
        Url::parse(&format!("{base}/.well-known/openid-configuration"))
            .unwrap_or_else(|_| self.issuer.clone())
    }

    /// Endpoints and encoding for the relying-party core; `None` until both
    /// the authorization and the token endpoint are known.
    #[cfg(feature = "auth-oauth")]
    #[must_use]
    pub fn provider_metadata(&self) -> Option<crate::auth::passport::oauth::ProviderMetadata> {
        use crate::auth::passport::oauth::ProviderMetadata;
        let metadata = ProviderMetadata::new(
            self.provider_id(),
            self.authorize_url.clone()?,
            self.token_url.clone()?,
        )
        .with_issuer(self.issuer.to_string().trim_end_matches('/').to_owned())
        .with_scopes(self.scopes.iter().cloned());
        // The relay source is an OIDC provider: form-encoded token body,
        // UserInfo when it has one, and a top-level token answer. A provider
        // that wraps its answer in an envelope is described by its own
        // metadata, never by the relay.
        Some(match self.userinfo_url.clone() {
            Some(userinfo_url) => metadata.with_userinfo_url(userinfo_url),
            None => metadata,
        })
    }

    /// The provider id recorded on relay identities: the issuer host.
    #[must_use]
    pub fn provider_id(&self) -> String {
        self.issuer
            .host_str()
            .map(str::to_owned)
            .unwrap_or_else(|| self.issuer.to_string())
    }

    /// How this service authenticates at the token endpoint.
    #[cfg(feature = "auth-oauth")]
    #[must_use]
    pub fn client_auth(&self) -> crate::auth::passport::oauth::ClientAuth {
        use crate::auth::passport::oauth::ClientAuth;
        match &self.client_secret {
            None => ClientAuth::Public {
                client_id: self.client_id.clone(),
            },
            Some(secret) => ClientAuth::Confidential {
                client_id: self.client_id.clone(),
                client_secret: secret.clone(),
            },
        }
    }
}

/// Resolve the deployment's login mode from the environment.
///
/// A configured relay source means [`AuthMode::Relay`]; otherwise an
/// explicit `AUTH_MODE` (`federated` or `local`) is honoured and defaults
/// to [`AuthMode::Local`]. The two never override each other silently.
///
/// # Errors
///
/// Every [`RelayConfigError`] the configuration can produce, plus a
/// contradictory, unknown or relay-without-source `AUTH_MODE`.
pub fn mode_from_env() -> Result<AuthMode, RelayConfigError> {
    mode_from_env_with(|name| std::env::var(name).ok())
}

/// [`mode_from_env`] through `read`.
///
/// # Errors
///
/// As [`mode_from_env`].
pub fn mode_from_env_with(
    read: impl Fn(&str) -> Option<String>,
) -> Result<AuthMode, RelayConfigError> {
    let relay = RelayConfig::from_env_with(&read)?;
    let explicit = read(AUTH_MODE_ENV)
        .map(|raw| raw.trim().to_owned())
        .filter(|raw| !raw.is_empty());
    let explicit = match explicit {
        Some(raw) => Some(AuthMode::parse(&raw).ok_or(RelayConfigError::UnknownMode(raw.clone()))?),
        None => None,
    };
    match (relay.is_some(), explicit) {
        (true, None | Some(AuthMode::Relay)) => Ok(AuthMode::Relay),
        (true, Some(mode)) => Err(RelayConfigError::ModeConflicts(mode.as_str().to_owned())),
        (false, Some(AuthMode::Relay)) => Err(RelayConfigError::RelayNotConfigured),
        (false, Some(mode)) => Ok(mode),
        (false, None) => Ok(AuthMode::Local),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Env = std::collections::HashMap<&'static str, String>;

    fn complete() -> Env {
        [
            (RELAY_ISSUER_ENV, "https://auth.example"),
            (RELAY_CLIENT_ID_ENV, "cid"),
            (
                RELAY_REDIRECT_URL_ENV,
                "https://app.example/api/auth/relay/callback",
            ),
            (RELAY_RETURN_ORIGINS_ENV, "https://app.example"),
        ]
        .into_iter()
        .map(|(k, v)| (k, v.to_owned()))
        .collect()
    }

    fn read(env: &Env) -> impl Fn(&str) -> Option<String> + '_ {
        move |name| env.get(name).cloned()
    }

    #[test]
    fn no_relay_variables_means_local_and_no_config() {
        assert!(RelayConfig::from_env_with(read(&Env::new()))
            .expect("ok")
            .is_none());
        assert_eq!(
            mode_from_env_with(read(&Env::new())).expect("ok"),
            AuthMode::Local
        );
    }

    #[test]
    fn a_complete_set_parses_with_family_defaults() {
        let cfg = RelayConfig::from_env_with(read(&complete()))
            .expect("ok")
            .expect("configured");
        assert_eq!(cfg.client_id, "cid");
        assert!(cfg.client_secret.is_none(), "absent secret = public client");
        assert_eq!(cfg.scopes, ["openid", "profile", "email"]);
        assert_eq!(cfg.return_param, "return_to");
        assert_eq!(cfg.allowed_return_origins, ["https://app.example"]);
        assert!(!cfg.break_glass, "break-glass is opt-in");
        assert_eq!(cfg.relay_entry(), "/api/auth/relay");
        // MUT:policy-round-trip — the published document must validate.
        cfg.login_policy()
            .validate()
            .expect("relay policy validates");
        assert_eq!(
            cfg.login_policy().relay.as_ref().map(|r| r.entry.as_str()),
            Some("/api/auth/relay")
        );
        assert_eq!(
            cfg.discovery_url().as_str(),
            "https://auth.example/.well-known/openid-configuration"
        );
        let explicit = {
            let mut env = complete();
            env.insert(RELAY_SCOPES_ENV, "openid  email ".to_owned());
            env.insert(RELAY_RETURN_PARAM_ENV, "next".to_owned());
            env.insert(RELAY_CLIENT_SECRET_ENV, "s".to_owned());
            env.insert(RELAY_BREAK_GLASS_ENV, "true".to_owned());
            env
        };
        let cfg = RelayConfig::from_env_with(read(&explicit))
            .expect("ok")
            .expect("configured");
        assert_eq!(cfg.scopes, ["openid", "email"]);
        assert_eq!(cfg.return_param, "next");
        assert!(cfg.client_secret.is_some() && cfg.break_glass);
    }

    #[test]
    fn an_incomplete_set_is_an_error_naming_the_variable() {
        // MUT:fail-closed — a partial configuration must never read as "no relay".
        for missing in [
            RELAY_ISSUER_ENV,
            RELAY_CLIENT_ID_ENV,
            RELAY_REDIRECT_URL_ENV,
            RELAY_RETURN_ORIGINS_ENV,
        ] {
            let mut env = complete();
            env.remove(missing);
            let err = RelayConfig::from_env_with(read(&env)).expect_err("partial set refused");
            assert!(
                matches!(err, RelayConfigError::Missing(name) if name == missing),
                "{missing}: {err}"
            );
        }
        let mut env = complete();
        env.insert(RELAY_RETURN_ORIGINS_ENV, " , ".to_owned());
        assert!(matches!(
            RelayConfig::from_env_with(read(&env)).unwrap_err(),
            RelayConfigError::NoReturnOrigins(RELAY_RETURN_ORIGINS_ENV)
        ));
    }

    #[test]
    fn urls_must_be_https_unless_loopback_and_the_callback_path_is_a_convention() {
        for (name, bad) in [
            (RELAY_ISSUER_ENV, "http://auth.example"),
            (
                RELAY_REDIRECT_URL_ENV,
                "http://app.example/api/auth/relay/callback",
            ),
            (RELAY_TOKEN_URL_ENV, "ftp://auth.example/token"),
        ] {
            let mut env = complete();
            env.insert(name, bad.to_owned());
            assert!(
                matches!(
                    RelayConfig::from_env_with(read(&env)).unwrap_err(),
                    RelayConfigError::NotHttps(n) if n == name
                ),
                "{name}"
            );
        }
        let mut env = complete();
        env.insert(RELAY_ISSUER_ENV, "http://localhost:8080".to_owned());
        env.insert(
            RELAY_REDIRECT_URL_ENV,
            "http://127.0.0.1:3000/auth/relay/callback".to_owned(),
        );
        env.insert(RELAY_RETURN_ORIGINS_ENV, "http://127.0.0.1:3000".to_owned());
        assert!(RelayConfig::from_env_with(read(&env))
            .expect("loopback is allowed")
            .is_some());

        let mut env = complete();
        env.insert(
            RELAY_REDIRECT_URL_ENV,
            "https://app.example/api/auth/relay".to_owned(),
        );
        assert!(matches!(
            RelayConfig::from_env_with(read(&env)).unwrap_err(),
            RelayConfigError::RedirectPath(RELAY_REDIRECT_URL_ENV, _)
        ));
        for bad in [
            "https://app.example/path",
            "https://app.example/?x=1",
            "app.example",
            "https://app.example/#f",
        ] {
            let mut env = complete();
            env.insert(RELAY_RETURN_ORIGINS_ENV, bad.to_owned());
            assert!(
                matches!(
                    RelayConfig::from_env_with(read(&env)).unwrap_err(),
                    RelayConfigError::BadOrigin(RELAY_RETURN_ORIGINS_ENV, _)
                        | RelayConfigError::InvalidUrl(RELAY_RETURN_ORIGINS_ENV, _)
                ),
                "{bad}"
            );
        }
    }

    #[test]
    fn discovery_fills_only_what_was_not_set_and_refuses_foreign_origins() {
        let cfg = RelayConfig::from_env_with(read(&complete()))
            .expect("ok")
            .expect("configured");
        let doc = serde_json::json!({
            "issuer": "https://auth.example",
            "authorization_endpoint": "https://auth.example/oauth/authorize",
            "token_endpoint": "https://auth.example/oauth/token",
            "userinfo_endpoint": "https://auth.example/oauth/userinfo"
        });
        let filled = cfg.clone().with_discovery(&doc).expect("discovery");
        assert_eq!(
            filled.authorize_url.as_ref().map(Url::as_str),
            Some("https://auth.example/oauth/authorize")
        );
        assert_eq!(
            filled.userinfo_url.as_ref().map(Url::as_str),
            Some("https://auth.example/oauth/userinfo")
        );
        let mut foreign = doc.clone();
        foreign["token_endpoint"] = serde_json::json!("https://evil.example/token");
        // MUT:discovery-same-origin — an endpoint on another origin is refused.
        assert!(matches!(
            cfg.clone().with_discovery(&foreign).unwrap_err(),
            RelayConfigError::Discovery("token_endpoint")
        ));
        let mut env = complete();
        env.insert(
            RELAY_TOKEN_URL_ENV,
            "https://auth.example/custom/token".to_owned(),
        );
        let explicit = RelayConfig::from_env_with(read(&env))
            .expect("ok")
            .expect("configured");
        let kept = explicit.with_discovery(&doc).expect("discovery");
        assert_eq!(
            kept.token_url.as_ref().map(Url::as_str),
            Some("https://auth.example/custom/token"),
            "an explicit endpoint wins"
        );
    }

    #[test]
    fn a_present_but_blank_relay_variable_still_means_relay() {
        // MUT:presence-not-content — a blank secret in a template must not read
        // as "no relay": the rest of the set is then missing and named.
        let env = [(RELAY_CLIENT_SECRET_ENV, "   ".to_owned())]
            .into_iter()
            .collect();
        assert!(matches!(
            RelayConfig::from_env_with(read(&env)).unwrap_err(),
            RelayConfigError::Missing(RELAY_ISSUER_ENV)
        ));
        let env = [(RELAY_BREAK_GLASS_ENV, String::new())]
            .into_iter()
            .collect();
        assert!(matches!(
            mode_from_env_with(read(&env)).unwrap_err(),
            RelayConfigError::Missing(RELAY_ISSUER_ENV)
        ));
    }

    #[test]
    fn return_addresses_are_same_origin_or_allow_listed() {
        let allowed = ["https://app.example".to_owned()];
        for (raw, expected) in [
            ("/inbox", Some("/inbox")),
            ("/inbox?x=1#f", Some("/inbox?x=1#f")),
            ("https://app.example/inbox?tab=a", Some("/inbox?tab=a")),
            ("//evil.example/x", None),
            ("https://evil.example/x", None),
            ("/", None),
            ("", None),
            ("inbox", None),
            ("https://app.example/", None),
            // MUT:no-backslash — browsers turn `/\host` into `//host`.
            ("/\\evil.example/x", None),
            ("/\nevil", None),
            ("/\u{2028}inbox", None),
            ("/in\u{007f}box", None),
            // MUT:no-format-chars — zero-width and bidi marks reshape a shown path.
            ("/in\u{200b}box", None),
            ("/\u{202e}xp", None),
            ("/in\u{feff}box", None),
        ] {
            assert_eq!(
                safe_return_path(raw, &allowed).as_deref(),
                expected,
                "{raw:?}"
            );
        }
    }

    #[test]
    fn the_explicit_mode_must_agree_with_the_configuration() {
        let mut env = complete();
        env.insert(AUTH_MODE_ENV, "relay".to_owned());
        assert_eq!(mode_from_env_with(read(&env)).expect("ok"), AuthMode::Relay);
        env.insert(AUTH_MODE_ENV, "local".to_owned());
        assert!(matches!(
            mode_from_env_with(read(&env)).unwrap_err(),
            RelayConfigError::ModeConflicts(_)
        ));
        let mut env = Env::new();
        env.insert(AUTH_MODE_ENV, "federated".to_owned());
        assert_eq!(
            mode_from_env_with(read(&env)).expect("ok"),
            AuthMode::Federated
        );
        env.insert(AUTH_MODE_ENV, "relay".to_owned());
        assert!(matches!(
            mode_from_env_with(read(&env)).unwrap_err(),
            RelayConfigError::RelayNotConfigured
        ));
        env.insert(AUTH_MODE_ENV, "sso".to_owned());
        assert!(matches!(
            mode_from_env_with(read(&env)).unwrap_err(),
            RelayConfigError::UnknownMode(_)
        ));
    }
}
