//! The two documents a provider publishes so nobody configures it by hand:
//! OIDC discovery and the JWKS.
//!
//! Discovery is what lets a relying party configure from **one URL**. Every
//! downstream service today hard-codes three endpoint URLs (authorize, token,
//! userinfo) into its config — which is why changing the provider's host
//! name is a coordinated change across every consumer. With this document,
//! it is one URL per consumer and the provider decides the rest.
//!
//! Every endpoint the document names **must** share the issuer's origin: a
//! discovery document that points clients at another host is how a tampered
//! or misconfigured document turns into a token-exchange redirect. The
//! relying-party core already refuses such a document on its side
//! (`RelayConfig::with_discovery`); this module refuses to *produce* one.

use serde::{Deserialize, Serialize};

use super::ProviderError;

/// `/.well-known/openid-configuration`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryDocument {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub userinfo_endpoint: Option<String>,
    pub jwks_uri: String,
    /// The response types this provider supports: exactly `code`.
    pub response_types_supported: Vec<String>,
    /// `code` only; no implicit, no hybrid. Tokens never ride a fragment.
    pub response_modes_supported: Vec<String>,
    pub grant_types_supported: Vec<String>,
    pub subject_types_supported: Vec<String>,
    /// EdDSA only — the one algorithm [`IdTokenSigner`](super::id_token::IdTokenSigner) signs with.
    pub id_token_signing_alg_values_supported: Vec<String>,
    pub scopes_supported: Vec<String>,
    /// PKCE S256 is the only method; `plain` is refused everywhere.
    pub code_challenge_methods_supported: Vec<String>,
    /// Client authentication at the token endpoint: secret in the body, or
    /// none (public client + PKCE). Not `client_secret_basic` — this
    /// provider does not read the Authorization header.
    pub token_endpoint_auth_methods_supported: Vec<String>,
}

impl DiscoveryDocument {
    /// Build the document for `issuer`, placing every endpoint under it.
    ///
    /// The issuer is the one input; the paths are this provider's contract:
    ///
    /// ```text
    /// {issuer}/oauth/authorize        (the host's SPA route)
    /// {issuer}/api/oauth/token
    /// {issuer}/api/oauth/userinfo
    /// {issuer}/api/oauth/jwks
    /// ```
    ///
    /// # Errors
    ///
    /// [`ProviderError::Policy`] when `issuer` is not an `https` URL without
    /// a path, query or fragment — an issuer must be a bare origin (OIDC
    /// Core §2: the `iss` value is compared as an exact string, and a
    /// trailing slash on one side and not the other breaks every check).
    pub fn for_issuer(issuer: &str) -> Result<Self, ProviderError> {
        let issuer = normalise_issuer(issuer)?;
        let base = issuer.trim_end_matches('/');
        Ok(Self {
            issuer: issuer.clone(),
            authorization_endpoint: format!("{base}/oauth/authorize"),
            token_endpoint: format!("{base}/api/oauth/token"),
            userinfo_endpoint: Some(format!("{base}/api/oauth/userinfo")),
            jwks_uri: format!("{base}/api/oauth/jwks"),
            response_types_supported: vec!["code".into()],
            response_modes_supported: vec!["query".into()],
            grant_types_supported: vec!["authorization_code".into(), "refresh_token".into()],
            subject_types_supported: vec!["public".into()],
            id_token_signing_alg_values_supported: vec!["EdDSA".into()],
            scopes_supported: super::KNOWN_SCOPES
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
            code_challenge_methods_supported: vec!["S256".into()],
            token_endpoint_auth_methods_supported: vec!["client_secret_post".into(), "none".into()],
        })
    }

    /// Every advertised endpoint is on the issuer's origin — the invariant
    /// the relying-party side enforces on receipt. A document that fails
    /// this must never be served.
    ///
    /// # Errors
    ///
    /// [`ProviderError::Policy`] naming the first offending field.
    pub fn validate(&self) -> Result<(), ProviderError> {
        // Re-normalise: this type is `Deserialize`, so a document can arrive
        // from config or a database rather than `for_issuer`. R2: an issuer
        // with a path passed `validate` untouched — exactly the shape
        // `for_issuer` refuses because it breaks every `iss` comparison.
        let normalised = normalise_issuer(&self.issuer)?;
        if normalised != self.issuer {
            return Err(ProviderError::Policy(format!(
                "issuer {:?} is not in normalised form (expected {normalised:?})",
                self.issuer
            )));
        }
        let origin = origin_of(&self.issuer).ok_or_else(|| {
            ProviderError::Policy(format!("issuer {:?} is not a URL", self.issuer))
        })?;
        for (field, url) in [
            ("authorization_endpoint", &self.authorization_endpoint),
            ("token_endpoint", &self.token_endpoint),
            ("jwks_uri", &self.jwks_uri),
        ] {
            check_same_origin(field, url, &origin)?;
        }
        if let Some(url) = &self.userinfo_endpoint {
            check_same_origin("userinfo_endpoint", url, &origin)?;
        }
        if self.response_types_supported != ["code"] {
            return Err(ProviderError::Policy(
                "response_types_supported must be exactly [\"code\"]".into(),
            ));
        }
        if self.code_challenge_methods_supported != ["S256"] {
            return Err(ProviderError::Policy(
                "code_challenge_methods_supported must be exactly [\"S256\"]".into(),
            ));
        }
        if self.id_token_signing_alg_values_supported != ["EdDSA"] {
            return Err(ProviderError::Policy(
                "id_token_signing_alg_values_supported must be exactly [\"EdDSA\"]".into(),
            ));
        }
        Ok(())
    }
}

/// The JWKS document (RFC 7517): the public verifying keys, by `kid`.
///
/// Only public material. A symmetric key has no place here at all — the
/// provider signs ID tokens with Ed25519 precisely so that *publishing* the
/// verifying key is safe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JwksDocument {
    pub keys: Vec<serde_json::Value>,
}

impl JwksDocument {
    /// A document with the given JWKs.
    #[must_use]
    pub fn new(keys: Vec<serde_json::Value>) -> Self {
        Self { keys }
    }

    /// A document with **no** keys. Served when the provider has not loaded
    /// a signing key: an empty `keys` array is the honest document, and a
    /// client that fetches it will refuse to trust anything rather than
    /// fall back to some other key.
    #[must_use]
    pub fn empty() -> Self {
        Self { keys: Vec::new() }
    }

    /// Refuse a document that would publish private material or a key
    /// without a `kid` (a rotating verifier selects by `kid`).
    ///
    /// # Errors
    ///
    /// [`ProviderError::Policy`] naming the offending key.
    pub fn validate(&self) -> Result<(), ProviderError> {
        for (i, key) in self.keys.iter().enumerate() {
            if key.get("d").is_some() {
                return Err(ProviderError::Policy(format!(
                    "key #{i} carries a private component (\"d\"); a JWKS publishes public keys only"
                )));
            }
            if key
                .get("kid")
                .and_then(|k| k.as_str())
                .is_none_or(str::is_empty)
            {
                return Err(ProviderError::Policy(format!(
                    "key #{i} has no kid; a rotating verifier selects by kid"
                )));
            }
            // The error text says Ed25519, so check everything that makes
            // it one (R2: a key-agreement `X25519` key, or an Ed25519 key
            // with no `x`, passed).
            if key.get("kty").and_then(|k| k.as_str()) != Some("OKP")
                || key.get("crv").and_then(|k| k.as_str()) != Some("Ed25519")
            {
                return Err(ProviderError::Policy(format!(
                    "key #{i} is not an OKP/Ed25519 key"
                )));
            }
            if key
                .get("alg")
                .and_then(|k| k.as_str())
                .is_some_and(|a| a != "EdDSA")
            {
                return Err(ProviderError::Policy(format!(
                    "key #{i} names an algorithm other than EdDSA"
                )));
            }
            let x = key.get("x").and_then(|k| k.as_str()).unwrap_or_default();
            if x.len() != 43 {
                return Err(ProviderError::Policy(format!(
                    "key #{i} has no usable `x` (expected 43 base64url chars, got {})",
                    x.len()
                )));
            }
        }
        Ok(())
    }
}

/// Normalise an issuer: `https`, a host, no path/query/fragment, no
/// trailing slash.
fn normalise_issuer(raw: &str) -> Result<String, ProviderError> {
    let url = url::Url::parse(raw.trim())
        .map_err(|_| ProviderError::Policy(format!("issuer {raw:?} is not a URL")))?;
    // A trailing dot is a different string from what any RP will be
    // configured with, so `iss` would never match (R2).
    let trailing_dot = url.host_str().is_some_and(|h| h.ends_with('.'));
    let ok = url.scheme() == "https"
        && !trailing_dot
        && url.host_str().is_some()
        && url.path() == "/"
        && url.query().is_none()
        && url.fragment().is_none()
        // Credentials in an issuer are nonsense and would leak into `iss`.
        && url.username().is_empty()
        && url.password().is_none();
    if !ok {
        return Err(ProviderError::Policy(format!(
            "issuer {raw:?} must be a bare https origin (no path, query, fragment or credentials)"
        )));
    }
    Ok(url.origin().ascii_serialization())
}

fn origin_of(raw: &str) -> Option<String> {
    url::Url::parse(raw)
        .ok()
        .map(|u| u.origin().ascii_serialization())
}

fn check_same_origin(field: &'static str, value: &str, origin: &str) -> Result<(), ProviderError> {
    if origin_of(value).as_deref() != Some(origin) {
        return Err(ProviderError::Policy(format!(
            "{field} {value:?} is not on the issuer's origin {origin}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_for_a_bare_issuer_names_every_endpoint_under_it() {
        let d = DiscoveryDocument::for_issuer("https://auth.example").unwrap();
        d.validate().unwrap();
        assert_eq!(d.issuer, "https://auth.example");
        assert_eq!(
            d.authorization_endpoint,
            "https://auth.example/oauth/authorize"
        );
        assert_eq!(d.token_endpoint, "https://auth.example/api/oauth/token");
        assert_eq!(d.jwks_uri, "https://auth.example/api/oauth/jwks");
        assert_eq!(
            d.userinfo_endpoint.as_deref(),
            Some("https://auth.example/api/oauth/userinfo")
        );
        assert_eq!(d.response_types_supported, ["code"]);
        assert_eq!(d.code_challenge_methods_supported, ["S256"]);
        assert_eq!(d.id_token_signing_alg_values_supported, ["EdDSA"]);
        assert_eq!(d.scopes_supported, ["openid", "profile", "email"]);
        // The document is what the RP core's discovery reader consumes.
        let v = serde_json::to_value(&d).unwrap();
        assert_eq!(v["issuer"], "https://auth.example");
        assert_eq!(
            v["token_endpoint_auth_methods_supported"][0],
            "client_secret_post"
        );
    }

    /// The issuer is normalised: a trailing slash is removed, so the `iss`
    /// the provider writes matches the `iss` the RP was configured with.
    #[test]
    fn a_trailing_slash_on_the_issuer_is_removed() {
        let d = DiscoveryDocument::for_issuer("https://auth.example/").unwrap();
        assert_eq!(d.issuer, "https://auth.example");
        assert_eq!(
            d.authorization_endpoint,
            "https://auth.example/oauth/authorize"
        );
    }

    /// An issuer that is not a bare https origin is refused — the RP compares
    /// `iss` as an exact string, and a path or a stray query would make every
    /// token it issues look foreign.
    #[test]
    fn a_non_origin_issuer_is_refused() {
        for bad in [
            "http://auth.example",      // not https
            "https://auth.example/idp", // a path
            "https://auth.example?x=1", // a query
            "https://auth.example#f",   // a fragment
            "https://u:p@auth.example", // credentials
            "auth.example",             // no scheme
            "",                         // empty
        ] {
            let err = DiscoveryDocument::for_issuer(bad).unwrap_err();
            assert!(matches!(err, ProviderError::Policy(_)), "{bad}: {err}");
        }
    }

    /// The invariant, in its failing direction: a document that points a
    /// client at another host is refused by `validate` and must never be
    /// served. This is the mirror of the RP's own `MUT:discovery-same-origin`.
    #[test]
    fn validate_refuses_an_endpoint_on_another_origin() {
        let mut d = DiscoveryDocument::for_issuer("https://auth.example").unwrap();
        d.token_endpoint = "https://evil.example/api/oauth/token".into();
        let err = d.validate().unwrap_err();
        assert!(err.to_string().contains("token_endpoint"), "{err}");
        assert!(err.to_string().contains("evil.example"));
        // Each field on its own.
        let mut d = DiscoveryDocument::for_issuer("https://auth.example").unwrap();
        d.jwks_uri = "https://evil.example/jwks".into();
        assert!(d.validate().is_err());
        let mut d = DiscoveryDocument::for_issuer("https://auth.example").unwrap();
        d.userinfo_endpoint = Some("https://evil.example/userinfo".into());
        assert!(d.validate().is_err());
    }

    /// The document may not advertise what the provider does not do.
    #[test]
    fn validate_refuses_advertising_the_implicit_flow_or_plain_pkce() {
        let mut d = DiscoveryDocument::for_issuer("https://auth.example").unwrap();
        d.response_types_supported = vec!["code".into(), "token".into()];
        assert!(d.validate().is_err());
        let mut d = DiscoveryDocument::for_issuer("https://auth.example").unwrap();
        d.code_challenge_methods_supported = vec!["S256".into(), "plain".into()];
        assert!(d.validate().is_err());
        let mut d = DiscoveryDocument::for_issuer("https://auth.example").unwrap();
        d.id_token_signing_alg_values_supported = vec!["HS256".into()];
        assert!(d.validate().is_err());
    }

    #[test]
    fn jwks_publishes_public_keys_only_and_requires_a_kid() {
        let ok = JwksDocument::new(vec![serde_json::json!({
            "kty": "OKP", "crv": "Ed25519", "x": "a".repeat(43), "alg": "EdDSA", "use": "sig", "kid": "k1"
        })]);
        ok.validate().unwrap();
        // MUT:jwks-private — a private component in a published JWKS is the
        // one mistake that cannot be undone; it is refused here.
        let mut leaky = ok.clone();
        leaky.keys[0]["d"] = serde_json::json!("secret");
        let err = leaky.validate().unwrap_err();
        assert!(err.to_string().contains("private component"), "{err}");
        // No kid.
        let mut no_kid = ok.clone();
        no_kid.keys[0].as_object_mut().unwrap().remove("kid");
        assert!(no_kid.validate().unwrap_err().to_string().contains("kid"));
        // Not an OKP key.
        let mut rsa = ok.clone();
        rsa.keys[0]["kty"] = serde_json::json!("RSA");
        assert!(rsa.validate().is_err());
        // An empty document is valid and honest.
        JwksDocument::empty().validate().unwrap();
        assert_eq!(
            serde_json::to_value(JwksDocument::empty()).unwrap(),
            serde_json::json!({ "keys": [] })
        );
    }

    /// `validate` re-normalises: a deserialized document with a path on its
    /// issuer is refused even though its endpoints share that origin.
    #[test]
    fn validate_refuses_a_non_normalised_issuer_from_config() {
        let mut d = DiscoveryDocument::for_issuer("https://auth.example").unwrap();
        d.issuer = "https://auth.example/idp".into();
        d.authorization_endpoint = "https://auth.example/idp/oauth/authorize".into();
        d.token_endpoint = "https://auth.example/idp/api/oauth/token".into();
        d.jwks_uri = "https://auth.example/idp/api/oauth/jwks".into();
        d.userinfo_endpoint = Some("https://auth.example/idp/api/oauth/userinfo".into());
        // `normalise_issuer` refuses a path outright — the re-check is what
        // catches a document nobody built through `for_issuer`.
        let err = d.validate().unwrap_err();
        assert!(err.to_string().contains("bare https origin"), "{err}");
        // A trailing slash normalises fine but to a *different* string: the
        // equality check is what refuses it.
        let mut d = DiscoveryDocument::for_issuer("https://auth.example").unwrap();
        d.issuer = "https://auth.example/".into();
        d.authorization_endpoint = "https://auth.example//oauth/authorize".into();
        d.token_endpoint = "https://auth.example//api/oauth/token".into();
        d.jwks_uri = "https://auth.example//api/oauth/jwks".into();
        d.userinfo_endpoint = Some("https://auth.example//api/oauth/userinfo".into());
        let err = d.validate().unwrap_err();
        assert!(err.to_string().contains("normalised form"), "{err}");
    }

    #[test]
    fn a_trailing_dot_on_the_issuer_host_is_refused() {
        for bad in ["https://auth.example.", "https://auth.example%2e"] {
            assert!(DiscoveryDocument::for_issuer(bad).is_err(), "{bad}");
        }
        // The default port IS normalised away (R2 confirmed this is right).
        let d = DiscoveryDocument::for_issuer("https://auth.example:443").unwrap();
        assert_eq!(d.issuer, "https://auth.example");
    }

    #[test]
    fn jwks_refuses_keys_that_are_not_verifiable_ed25519() {
        let good = serde_json::json!({
            "kty": "OKP", "crv": "Ed25519", "x": "a".repeat(43), "alg": "EdDSA", "use": "sig", "kid": "k1"
        });
        JwksDocument::new(vec![good.clone()]).validate().unwrap();
        let mut k = good.clone();
        k["crv"] = serde_json::json!("X25519");
        assert!(JwksDocument::new(vec![k]).validate().is_err());
        let mut k = good.clone();
        k.as_object_mut().unwrap().remove("x");
        assert!(JwksDocument::new(vec![k]).validate().is_err());
        let mut k = good.clone();
        k["x"] = serde_json::json!("abc");
        assert!(JwksDocument::new(vec![k]).validate().is_err());
        let mut k = good.clone();
        k["alg"] = serde_json::json!("HS256");
        assert!(JwksDocument::new(vec![k]).validate().is_err());
    }

    /// Discovery for the real target round-trips through serde untouched.
    #[test]
    fn the_document_round_trips() {
        let d = DiscoveryDocument::for_issuer("https://auth.celestia.world").unwrap();
        let text = serde_json::to_string(&d).unwrap();
        let back: DiscoveryDocument = serde_json::from_str(&text).unwrap();
        assert_eq!(d, back);
        back.validate().unwrap();
    }
}
