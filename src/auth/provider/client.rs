//! Registered clients: who may ask, where they may be sent back, and how
//! they authenticate.
//!
//! A [`ClientRegistry`] is the host's storage; the shapes here are the
//! **policy** a client carries. Three fields are load-bearing for security
//! and none of them has a permissive default:
//!
//! - [`redirect_uris`](ClientRecord::redirect_uris) are matched **exactly**.
//!   OAuth forbids partial matching for good reason: a prefix match on
//!   `https://app.example/` accepts `https://app.example/../../evil`, and a
//!   host that normalises before comparing has been the root cause of more
//!   than one real-world code theft.
//! - [`auth_method`](ClientRecord::auth_method): a confidential client
//!   presents a secret at the token endpoint; a public client (a native app,
//!   a SPA without a backend) presents nothing and relies on PKCE alone —
//!   and is therefore **required** to use PKCE, by construction rather than
//!   by configuration.
//! - [`require_pkce`](ClientRecord::require_pkce) is `true` unless the host
//!   says the client predates PKCE. The escape hatch exists for migration
//!   and is named so a reviewer can grep for every use of it.

use async_trait::async_trait;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::{ProtocolError, ProviderError};

/// How a client authenticates at the token endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientAuthMethod {
    /// `client_secret` in the body (this provider does not do HTTP Basic:
    /// it is the same credential with a worse audit trail). Compared in
    /// constant time against the stored hash.
    ClientSecret,
    /// No secret. PKCE is the only proof, so it is mandatory.
    None,
}

/// A grant the client is allowed to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantType {
    AuthorizationCode,
    RefreshToken,
    /// RFC 8628: the device authorization grant.
    DeviceCode,
    /// `client_credentials` (RFC 6749 §4.4).
    ClientCredentials,
}

/// Result of matching a requested redirect against the registration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedirectMatch {
    /// Exactly one registered URI.
    Registered,
    /// Not in the registration. Not reflected — there is no verified place
    /// to send an error.
    NotRegistered,
}

/// One registered client. Secrets are stored **hashed**: the registry never
/// needs the plaintext, and a leaked table is then useless for impersonating
/// the client at the token endpoint.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ClientRecord {
    pub client_id: String,
    /// Exact strings. The host supplies them; no normalisation happens here.
    pub redirect_uris: Vec<String>,
    pub auth_method: ClientAuthMethod,
    /// SHA-256 hex of the secret (lowercase). `None` for a public client.
    pub client_secret_hash: Option<String>,
    pub allowed_grants: Vec<GrantType>,
    /// `true` unless the client predates PKCE. See the module docs.
    ///
    /// **Not independently settable**: a public client has no secret, so
    /// PKCE is the only proof it can offer, and exempting one would let a
    /// bare `authorization_code` exchange mint tokens. Change it with
    /// [`ClientRecord::exempt_from_pkce`], which refuses for a public client.
    pub(crate) require_pkce: bool,
    /// Scopes this client may be granted; empty = the known set.
    pub allowed_scopes: Vec<String>,
}

impl ClientRecord {
    /// A confidential client that must use PKCE and may use both grants.
    #[must_use]
    pub fn confidential(
        client_id: impl Into<String>,
        redirect_uris: Vec<String>,
        secret: &str,
    ) -> Self {
        Self {
            client_id: client_id.into(),
            redirect_uris,
            auth_method: ClientAuthMethod::ClientSecret,
            client_secret_hash: Some(hash_secret(secret)),
            allowed_grants: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
            require_pkce: true,
            allowed_scopes: Vec::new(),
        }
    }

    /// A public client: no secret, PKCE mandatory by construction.
    #[must_use]
    pub fn public(client_id: impl Into<String>, redirect_uris: Vec<String>) -> Self {
        Self {
            client_id: client_id.into(),
            redirect_uris,
            auth_method: ClientAuthMethod::None,
            client_secret_hash: None,
            allowed_grants: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
            require_pkce: true,
            allowed_scopes: Vec::new(),
        }
    }

    /// Whether the client must present a PKCE challenge.
    #[must_use]
    pub fn require_pkce(&self) -> bool {
        self.require_pkce
    }

    /// Mark a confidential client as predating PKCE. **Refused for a public
    /// client**: with no secret to present, PKCE is its only proof at the
    /// token endpoint, and a public client without it is an open mint.
    ///
    /// # Errors
    ///
    /// [`ProviderError::Policy`] when the client is public.
    pub fn exempt_from_pkce(&mut self) -> Result<(), ProviderError> {
        if self.auth_method == ClientAuthMethod::None {
            return Err(ProviderError::Policy(
                "a public client cannot be exempted from PKCE: it has no other proof".into(),
            ));
        }
        self.require_pkce = false;
        Ok(())
    }

    /// Exact match against the registered redirect URIs.
    #[must_use]
    pub fn matches_redirect(&self, requested: &str) -> RedirectMatch {
        if self.redirect_uris.iter().any(|uri| uri == requested) {
            RedirectMatch::Registered
        } else {
            RedirectMatch::NotRegistered
        }
    }

    /// Verify a presented secret in constant time against the stored hash.
    /// A public client verifies **nothing** — callers must branch on
    /// [`auth_method`](Self::auth_method) first, so that a public client
    /// "authenticating" with an arbitrary secret is a protocol error rather
    /// than a pass.
    #[must_use]
    pub fn verify_secret(&self, presented: &str) -> bool {
        let Some(stored) = &self.client_secret_hash else {
            // No stored hash means no secret to check — answer false; the
            // caller should not have asked.
            return false;
        };
        let candidate = hash_secret(presented);
        candidate.as_bytes().ct_eq(stored.as_bytes()).into()
    }

    /// Whether the client may use `grant`.
    #[must_use]
    pub fn allows_grant(&self, grant: GrantType) -> bool {
        self.allowed_grants.contains(&grant)
    }

    /// Whether every token of `scope` is within this client's allowance.
    ///
    /// An empty allowance means **the known set**, as the field documents —
    /// not "any token at all" (R2: the old reading told a caller that
    /// `admin:everything` was allowed). `authorize` validates against the
    /// known set first, so no request reached the permissive path, but the
    /// method's own contract has to hold.
    #[must_use]
    pub fn allows_scope(&self, scope: &str) -> bool {
        scope.split_whitespace().all(|token| {
            if self.allowed_scopes.is_empty() {
                super::KNOWN_SCOPES.contains(&token)
            } else {
                self.allowed_scopes.iter().any(|s| s == token)
            }
        })
    }
}

/// Lowercase hex SHA-256 of a client secret.
///
/// Client secrets are high-entropy random strings, so a fast hash is right
/// (unlike user passwords, which go through Argon2 elsewhere in this crate).
#[must_use]
pub fn hash_secret(secret: &str) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(secret.as_bytes()))
}

/// Host-backed client storage.
///
/// Lookups are by `client_id` alone — the secret check is a separate step on
/// the returned record, so a host can cache records and never cache a
/// verification result.
#[async_trait]
pub trait ClientRegistry: Send + Sync {
    /// The record for `client_id`, or `None` for an unknown client.
    ///
    /// # Errors
    ///
    /// Storage failures. These must surface as [`ProviderError::Storage`],
    /// never as `Ok(None)`: an unreachable store answering "unknown client"
    /// would make every client look unregistered during an outage.
    async fn lookup(&self, client_id: &str) -> Result<Option<ClientRecord>, ProviderError>;
}

/// An in-memory registry: the reference implementation and the test double.
#[derive(Debug, Clone, Default)]
pub struct InMemoryClientRegistry {
    clients: std::sync::Arc<tokio::sync::RwLock<Vec<ClientRecord>>>,
}

impl InMemoryClientRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register (or replace) a client.
    pub async fn register(&self, record: ClientRecord) {
        let mut clients = self.clients.write().await;
        clients.retain(|c| c.client_id != record.client_id);
        clients.push(record);
    }
}

#[async_trait]
impl ClientRegistry for InMemoryClientRegistry {
    async fn lookup(&self, client_id: &str) -> Result<Option<ClientRecord>, ProviderError> {
        Ok(self
            .clients
            .read()
            .await
            .iter()
            .find(|c| c.client_id == client_id)
            .cloned())
    }
}

/// Verify a client at the token endpoint: lookup, method match, secret.
///
/// A public client presenting a secret is refused — the secret proves
/// nothing and accepting it would let a caller believe it holds a stronger
/// credential than it does. A confidential client presenting none is
/// refused.
///
/// # Errors
///
/// [`ProviderError::Storage`] when the registry is unreachable (never
/// `InvalidClient` for an outage); [`ProviderError::InvalidClient`] when the
/// client is unknown, the method does not match, or the secret is wrong.
pub async fn authenticate_client(
    registry: &dyn ClientRegistry,
    client_id: &str,
    presented_secret: Option<&str>,
) -> Result<ClientRecord, ProviderError> {
    let record = registry
        .lookup(client_id)
        .await?
        .ok_or(ProviderError::InvalidClient)?;
    match (record.auth_method, presented_secret) {
        (ClientAuthMethod::None, None) => Ok(record),
        (ClientAuthMethod::None, Some(_)) => {
            // A public client has no secret to present; one showing up means
            // the caller is confused or probing. Refuse rather than ignore.
            Err(ProviderError::InvalidClient)
        }
        (ClientAuthMethod::ClientSecret, Some(secret)) => {
            let secret = Zeroizing::new(secret.to_owned());
            if record.verify_secret(&secret) {
                Ok(record)
            } else {
                Err(ProviderError::InvalidClient)
            }
        }
        (ClientAuthMethod::ClientSecret, None) => Err(ProviderError::InvalidClient),
    }
}

/// Convenience for the authorize endpoint: the redirect must be registered
/// for the client, or the request is refused *without* a redirect target.
///
/// # Errors
///
/// [`ProviderError::UnauthorizedClient`] for an unknown client or an
/// unregistered redirect (the same error for both — telling them apart lets
/// an attacker enumerate client ids); [`ProviderError::Storage`] for an
/// unreachable registry.
pub async fn resolve_redirect(
    registry: &dyn ClientRegistry,
    client_id: &str,
    redirect_uri: &str,
) -> Result<ClientRecord, ProviderError> {
    let record = registry
        .lookup(client_id)
        .await?
        .ok_or(ProviderError::UnauthorizedClient)?;
    match record.matches_redirect(redirect_uri) {
        RedirectMatch::Registered => Ok(record),
        RedirectMatch::NotRegistered => Err(ProviderError::UnauthorizedClient),
    }
}

/// Normalize the `state` the client sent: it is echoed back verbatim and
/// **never** trusted — this provider does not sign it, does not bind
/// anything to it, and the client must not rely on it for correctness. The
/// only thing done here is a sanity bound, so a megabyte of `state` cannot
/// be reflected back into a URL.
///
/// # Errors
///
/// [`ProviderError::Redirectable`] with `invalid_request` when `state` is
/// longer than 1024 bytes or carries control characters (which cannot ride
/// a query string safely).
pub fn check_state(state: Option<&str>) -> Result<(), ProviderError> {
    let Some(state) = state else {
        return Ok(());
    };
    if state.len() > 1024 || state.chars().any(char::is_control) {
        return Err(ProviderError::Redirectable {
            error: ProtocolError::InvalidRequest,
            description: "state is too long or carries control characters".into(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client() -> ClientRecord {
        ClientRecord::confidential(
            "erp-admin",
            vec!["https://admin.example/api/auth/relay/callback".into()],
            "s3cret",
        )
    }

    #[test]
    fn redirect_matching_is_exact() {
        let c = client();
        assert_eq!(
            c.matches_redirect("https://admin.example/api/auth/relay/callback"),
            RedirectMatch::Registered
        );
        // MUT:redirect-prefix — a prefix match would accept each of these.
        for bad in [
            "https://admin.example/api/auth/relay/callback/",
            "https://admin.example/api/auth/relay/callback?x=1",
            "https://admin.example/",
            "https://admin.example/api/auth/relay/callback/../../evil",
            "http://admin.example/api/auth/relay/callback",
            "https://admin.example.evil/api/auth/relay/callback",
            "https://evil.example/api/auth/relay/callback",
        ] {
            assert_eq!(
                c.matches_redirect(bad),
                RedirectMatch::NotRegistered,
                "{bad}"
            );
        }
    }

    #[test]
    fn a_confidential_client_verifies_its_secret_and_nothing_else() {
        let c = client();
        assert!(c.verify_secret("s3cret"));
        assert!(!c.verify_secret("s3creT"));
        assert!(!c.verify_secret(""));
        // The stored form is a hash, never the secret.
        assert_eq!(
            c.client_secret_hash.as_deref(),
            Some(hash_secret("s3cret").as_str())
        );
        assert!(!c.client_secret_hash.as_deref().unwrap().contains("s3cret"));
    }

    #[test]
    fn a_public_client_verifies_nothing() {
        let c = ClientRecord::public("cli", vec!["http://127.0.0.1:1/cb".into()]);
        assert_eq!(c.auth_method, ClientAuthMethod::None);
        assert!(c.client_secret_hash.is_none());
        // There is no secret, so there is nothing a presented one can match.
        assert!(!c.verify_secret(""));
        assert!(!c.verify_secret("anything"));
        // And PKCE is mandatory for it by construction.
        assert!(c.require_pkce);
    }

    #[test]
    fn a_public_client_cannot_be_exempted_from_pkce() {
        let mut c = ClientRecord::public("cli", vec!["http://127.0.0.1:1/cb".into()]);
        let err = c.exempt_from_pkce().unwrap_err();
        assert!(matches!(err, ProviderError::Policy(_)), "{err}");
        assert!(c.require_pkce(), "still required after the refusal");
        // A confidential client may be exempted.
        let mut c = client();
        c.exempt_from_pkce().unwrap();
        assert!(!c.require_pkce());
    }

    #[tokio::test]
    async fn authentication_requires_the_right_method_and_secret() {
        let reg = InMemoryClientRegistry::new();
        reg.register(client()).await;
        reg.register(ClientRecord::public(
            "cli",
            vec!["http://127.0.0.1:1/cb".into()],
        ))
        .await;

        assert!(authenticate_client(&reg, "erp-admin", Some("s3cret"))
            .await
            .is_ok());
        // Confidential without a secret.
        assert_eq!(
            authenticate_client(&reg, "erp-admin", None)
                .await
                .unwrap_err(),
            ProviderError::InvalidClient
        );
        // Wrong secret.
        assert_eq!(
            authenticate_client(&reg, "erp-admin", Some("nope"))
                .await
                .unwrap_err(),
            ProviderError::InvalidClient
        );
        // Public with a secret: refused, not ignored.
        assert_eq!(
            authenticate_client(&reg, "cli", Some("x"))
                .await
                .unwrap_err(),
            ProviderError::InvalidClient
        );
        assert!(authenticate_client(&reg, "cli", None).await.is_ok());
        // Unknown.
        assert_eq!(
            authenticate_client(&reg, "ghost", None).await.unwrap_err(),
            ProviderError::InvalidClient
        );
    }

    #[tokio::test]
    async fn resolve_redirect_refuses_an_unregistered_target_without_a_redirect() {
        let reg = InMemoryClientRegistry::new();
        reg.register(client()).await;
        assert!(resolve_redirect(
            &reg,
            "erp-admin",
            "https://admin.example/api/auth/relay/callback"
        )
        .await
        .is_ok());
        // Unknown client and unregistered redirect answer identically: the
        // difference would let an attacker enumerate client ids.
        let unknown = resolve_redirect(
            &reg,
            "ghost",
            "https://admin.example/api/auth/relay/callback",
        )
        .await
        .unwrap_err();
        let unregistered = resolve_redirect(&reg, "erp-admin", "https://evil.example/cb")
            .await
            .unwrap_err();
        assert_eq!(unknown, ProviderError::UnauthorizedClient);
        assert_eq!(unregistered, ProviderError::UnauthorizedClient);
        assert_eq!(unknown.redirectable(), None);
    }

    #[test]
    fn state_is_bounded_and_control_free() {
        assert_eq!(check_state(None), Ok(()));
        assert_eq!(check_state(Some("abc-123")), Ok(()));
        assert_eq!(check_state(Some(&"x".repeat(1024))), Ok(()));
        let long = "x".repeat(1025);
        assert_eq!(
            check_state(Some(&long)).unwrap_err().redirectable(),
            Some(ProtocolError::InvalidRequest)
        );
        assert!(check_state(Some("a\nb")).is_err());
        assert!(check_state(Some("a\u{0}b")).is_err());
    }

    #[test]
    fn grant_and_scope_allowances() {
        let c = client();
        assert!(c.allows_grant(GrantType::AuthorizationCode));
        assert!(c.allows_grant(GrantType::RefreshToken));
        // Empty allowance = the known set.
        assert!(c.allows_scope("openid profile email"));
        // MUT:empty-allowance — "empty = anything" would pass this.
        assert!(
            !c.allows_scope("admin:everything"),
            "empty allowance is the KNOWN set, not any token"
        );
        assert!(!c.allows_scope("openid admin:everything"));
        let mut scoped = client();
        scoped.allowed_scopes = vec!["openid".into()];
        assert!(scoped.allows_scope("openid"));
        assert!(!scoped.allows_scope("openid email"));
    }
}
