//! The OIDC ID token: the claims it carries and the signer that mints it.
//!
//! This is the mirror of [`IdTokenVerifier`](crate::auth::passport::oauth::IdTokenVerifier)
//! on the relying-party side, and the two are tested against each other
//! (see the round-trip case below): whatever this module signs, the RP core
//! must accept — and anything the RP core refuses, this module must never
//! produce.
//!
//! # Claims the spec requires and what they mean here
//!
//! | claim | value | why it is load-bearing |
//! |---|---|---|
//! | `iss` | the provider's issuer URL, exactly | the RP checks it byte-for-byte |
//! | `sub` | the subject's stable id | **pairwise per client is the host's business**; this module writes what it is given |
//! | `aud` | the client id, as a single string | an RP that expects an array will not match; OIDC Core §2 allows either, and the kirino RP expects the string form |
//! | `exp`/`iat` | issue time + TTL | 60 s leeway on the RP side |
//! | `nonce` | the request's nonce, **required when `openid` was granted** | the RP refuses an ID token that omits an expected nonce |
//! | `auth_time` | when the user authenticated | lets an RP demand a fresh login |
//! | `amr`/`acr` | how, and at what class | carried verbatim from the grant |
//! | `azp` | the client id, when `aud` could have been an array | always written here, for the rare RP that checks it |
//!
//! # Signing
//!
//! EdDSA (Ed25519) only, for now. The signing key is a PEM the host loads;
//! the `kid` is stamped into the JOSE header so a key rotation can keep two
//! verification keys live at once. **Symmetric keys are refused by
//! construction**: an ID token is verified by *other* parties, and a
//! provider that signs with a shared secret has published that secret to
//! every client the first time it hands out a JWKS.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use zeroize::Zeroizing;

use super::ProviderError;

/// Default ID-token lifetime. Short: the token is consumed immediately by
/// the client and only needs to survive the one redirect.
pub const DEFAULT_ID_TOKEN_TTL_SECS: i64 = 300;

/// The claims of an ID token this provider issues.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    /// Present when the authorization carried one; `skip` so a token for a
    /// pure-OAuth client (no `openid`) carries no empty nonce.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    pub auth_time: i64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub amr: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
    /// The authorised party. Written whenever `aud` is set, since `aud` is
    /// a single string here and a client that checks `azp` must find it.
    pub azp: String,
    // `at_hash` is deliberately absent: the access token this provider
    // mints is a JWT with its own `aud`, and the RP core does not check
    // `at_hash`. Writing one would be a claim nobody verifies.
}

impl IdTokenClaims {
    /// Build the claims from a redeemed grant and the client.
    ///
    /// # Errors
    ///
    /// [`ProviderError::Policy`] when the grant has `openid` scope but no
    /// nonce — the authorize step already refuses that, so reaching this
    /// means the grant was minted through another path.
    pub fn from_grant(
        issuer: &str,
        grant: &super::code::CodeGrant,
        now: DateTime<Utc>,
        ttl_secs: Option<i64>,
    ) -> Result<Self, ProviderError> {
        if super::scope_granted(&grant.scope, "openid")
            && grant.nonce.as_deref().is_none_or(str::is_empty)
        {
            return Err(ProviderError::Policy(
                "openid scope without a nonce: the grant cannot yield an ID token".into(),
            ));
        }
        let iat = now.timestamp();
        Ok(Self {
            iss: issuer.to_owned(),
            sub: grant.sub.clone(),
            aud: grant.client_id.clone(),
            exp: iat + ttl_secs.unwrap_or(DEFAULT_ID_TOKEN_TTL_SECS),
            iat,
            nonce: grant.nonce.clone(),
            auth_time: grant.auth_time.timestamp(),
            amr: grant.amr.clone(),
            acr: grant.acr.clone(),
            azp: grant.client_id.clone(),
        })
    }

    /// Whether these claims grant `scope`.
    #[must_use]
    pub fn has_scope_claim(&self, _scope: &str) -> bool {
        // ID tokens carry no `scope` claim in OIDC Core; the scope lives on
        // the access token and the grant. Present so a host that reaches for
        // it does not invent one.
        false
    }
}

/// Signs ID tokens with an Ed25519 key and stamps a `kid`.
///
/// Construct once, share via `Arc`. The key is zeroised on drop.
pub struct IdTokenSigner {
    encoding: EncodingKey,
    kid: String,
}

impl std::fmt::Debug for IdTokenSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdTokenSigner")
            .field("kid", &self.kid)
            .finish()
    }
}

impl IdTokenSigner {
    /// Load an Ed25519 signing key from a PKCS#8 PEM.
    ///
    /// # Errors
    ///
    /// [`ProviderError::SigningUnavailable`] when the PEM cannot be read as
    /// an Ed25519 private key. There is no "insecure fallback" path: a
    /// provider that cannot sign does not mint ID tokens.
    pub fn from_ed25519_pem(pem: &str, kid: impl Into<String>) -> Result<Self, ProviderError> {
        let pem = Zeroizing::new(pem.to_owned());
        let encoding = EncodingKey::from_ed_pem(pem.as_bytes())
            .map_err(|e| ProviderError::SigningUnavailable(format!("Ed25519 PEM rejected: {e}")))?;
        Ok(Self {
            encoding,
            kid: kid.into(),
        })
    }

    /// Sign `claims` into a compact JWS (`alg: EdDSA`, `kid` set).
    ///
    /// # Errors
    ///
    /// [`ProviderError::SigningUnavailable`] when the key cannot sign.
    pub fn sign(&self, claims: &IdTokenClaims) -> Result<String, ProviderError> {
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(self.kid.clone());
        jsonwebtoken::encode(&header, claims, &self.encoding)
            .map_err(|e| ProviderError::SigningUnavailable(format!("sign failed: {e}")))
    }

    /// Sign a back-channel **logout token** (OIDC Back-Channel Logout §2.4)
    /// with the same key and `kid`.
    ///
    /// `typ` is `logout+jwt` (the spec RECOMMENDS it; an RP may refuse a
    /// token without it) — a header this signer would otherwise never set,
    /// which is why this is a separate method and not `sign` with a flag:
    /// an ID token and a logout token are different things and must not be
    /// interchangeable in either direction.
    ///
    /// # Errors
    ///
    /// [`ProviderError::SigningUnavailable`] when the key cannot sign.
    pub fn sign_logout_token(
        &self,
        claims: &super::logout::LogoutTokenClaims,
    ) -> Result<String, ProviderError> {
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(self.kid.clone());
        header.typ = Some("logout+jwt".to_owned());
        jsonwebtoken::encode(&header, claims, &self.encoding)
            .map_err(|e| ProviderError::SigningUnavailable(format!("logout sign failed: {e}")))
    }

    /// The `kid` this signer stamps — what the JWKS must advertise.
    #[must_use]
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// The `OKP` JWK for an Ed25519 **public** PEM (SubjectPublicKeyInfo).
    ///
    /// An Ed25519 SPKI is a fixed 44-byte DER body with a constant 12-byte
    /// prefix, so extracting the key is a shape check plus a slice — the
    /// same derivation `kirino-session` uses for its own JWKS export. The
    /// verifying key is first loaded through `jsonwebtoken` so a malformed
    /// PEM is refused before any bytes are trusted.
    ///
    /// # Errors
    ///
    /// [`ProviderError::SigningUnavailable`] when the PEM is not an Ed25519
    /// public key in SPKI form.
    pub fn public_jwk_from_pem(
        public_pem: &str,
        kid: &str,
    ) -> Result<serde_json::Value, ProviderError> {
        jsonwebtoken::DecodingKey::from_ed_pem(public_pem.as_bytes()).map_err(|e| {
            ProviderError::SigningUnavailable(format!("Ed25519 public PEM rejected: {e}"))
        })?;
        let raw = ed25519_spki_raw32(public_pem).ok_or_else(|| {
            ProviderError::SigningUnavailable("PEM is not an Ed25519 SubjectPublicKeyInfo".into())
        })?;
        Ok(serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": crate::utils::base64url::encode(&raw),
            "alg": "EdDSA",
            "use": "sig",
            "kid": kid,
        }))
    }
}

/// The raw 32 bytes of an Ed25519 public key from its SPKI PEM.
fn ed25519_spki_raw32(pem: &str) -> Option<[u8; 32]> {
    use base64::Engine;
    let mut lines = pem.lines();
    if !lines.next()?.contains("BEGIN PUBLIC KEY") {
        return None;
    }
    let body: String = lines
        .take_while(|l| !l.contains("END PUBLIC KEY"))
        .filter(|l| !l.trim().is_empty())
        .collect();
    const ED25519_SPKI_PREFIX: [u8; 12] = [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    let der = base64::engine::general_purpose::STANDARD
        .decode(body)
        .ok()?;
    if der.len() != 44 || der[..12] != ED25519_SPKI_PREFIX {
        return None;
    }
    let mut raw = [0u8; 32];
    raw.copy_from_slice(&der[12..]);
    Some(raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::passport::oauth::IdTokenVerifier;
    use crate::auth::provider::code::{CodeGrant, GrantKind};

    /// A throwaway keypair for tests only (never a deployment key).
    const PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEID3zTmAP9MdPuN/YdS5wbUXgOWWRd4LYu6lNdo/eBgZn
-----END PRIVATE KEY-----";
    const PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAPH53IpxGc7yhGj/Hb6390oc/ij0hPzepMo9gsUIKRXU=
-----END PUBLIC KEY-----";

    fn grant() -> CodeGrant {
        CodeGrant {
            kind: GrantKind::Code,
            client_id: "erp-admin".into(),
            redirect_uri: "https://admin.example/cb".into(),
            scope: "openid profile".into(),
            sub: "user-1".into(),
            auth_time: Utc::now() - chrono::Duration::seconds(5),
            amr: vec!["pwd".into(), "otp".into()],
            acr: Some("mfa".into()),
            nonce: Some("n-1".into()),
            code_challenge: None,
            authenticated_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::seconds(300),
        }
    }

    #[test]
    fn claims_from_a_grant_carry_every_required_field() {
        let now = Utc::now();
        let c = IdTokenClaims::from_grant("https://auth.example", &grant(), now, None).unwrap();
        assert_eq!(c.iss, "https://auth.example");
        assert_eq!(c.sub, "user-1");
        assert_eq!(c.aud, "erp-admin");
        assert_eq!(c.azp, "erp-admin");
        assert_eq!(c.nonce.as_deref(), Some("n-1"));
        assert_eq!(c.amr, vec!["pwd", "otp"]);
        assert_eq!(c.acr.as_deref(), Some("mfa"));
        assert_eq!(c.exp - c.iat, DEFAULT_ID_TOKEN_TTL_SECS);
        assert_eq!(c.auth_time, grant().auth_time.timestamp());
        // Serialised shape: `nonce` present, no empty `acr`, no stray fields.
        let v = serde_json::to_value(&c).unwrap();
        assert!(v.get("nonce").is_some());
        assert!(v.get("azp").is_some());
        assert!(v.get("at_hash").is_none());
    }

    #[test]
    fn openid_scope_without_a_nonce_is_a_policy_error() {
        let mut g = grant();
        g.nonce = None;
        let err =
            IdTokenClaims::from_grant("https://auth.example", &g, Utc::now(), None).unwrap_err();
        assert!(matches!(err, ProviderError::Policy(_)));
        // A pure-OAuth grant (no openid) may omit the nonce.
        g.scope = "profile".into();
        let c = IdTokenClaims::from_grant("https://auth.example", &g, Utc::now(), None).unwrap();
        assert!(c.nonce.is_none());
    }

    /// The round trip with the relying-party verifier: what this module
    /// signs, the RP core accepts, with the exact issuer/audience/nonce.
    #[test]
    fn the_rp_core_accepts_what_this_signs() {
        let signer = IdTokenSigner::from_ed25519_pem(PRIVATE_PEM, "k1").unwrap();
        let claims =
            IdTokenClaims::from_grant("https://auth.example", &grant(), Utc::now(), None).unwrap();
        let token = signer.sign(&claims).unwrap();
        let key = jsonwebtoken::DecodingKey::from_ed_pem(PUBLIC_PEM.as_bytes()).unwrap();
        let verifier = IdTokenVerifier::new(vec![key], "https://auth.example", "erp-admin");
        let back = verifier
            .verify(&token, Some("n-1"))
            .expect("the RP accepts it");
        assert_eq!(back["sub"], "user-1");
        assert_eq!(back["nonce"], "n-1");
        // Wrong audience, issuer or nonce → refused by the RP.
        let wrong_aud = IdTokenVerifier::new(
            vec![jsonwebtoken::DecodingKey::from_ed_pem(PUBLIC_PEM.as_bytes()).unwrap()],
            "https://auth.example",
            "other-client",
        );
        assert!(wrong_aud.verify(&token, Some("n-1")).is_err());
        let wrong_nonce = verifier.verify(&token, Some("n-2"));
        assert!(wrong_nonce.is_err());
        assert!(
            verifier.verify(&token, None).is_ok(),
            "no expected nonce = no check"
        );
        // An ID token that *omits* the nonce is refused when one is expected
        // (R2: the old case re-ran the success assertion under this name).
        let mut no_nonce = claims.clone();
        no_nonce.nonce = None;
        let bare = signer.sign(&no_nonce).unwrap();
        assert!(
            verifier.verify(&bare, Some("n-1")).is_err(),
            "a missing nonce must be refused"
        );
    }

    /// The JOSE header carries `alg: EdDSA` and the `kid` — the two things
    /// a rotating verifier selects on.
    #[test]
    fn the_jose_header_names_the_algorithm_and_kid() {
        let signer = IdTokenSigner::from_ed25519_pem(PRIVATE_PEM, "2026-11").unwrap();
        let claims =
            IdTokenClaims::from_grant("https://auth.example", &grant(), Utc::now(), None).unwrap();
        let token = signer.sign(&claims).unwrap();
        let header = jsonwebtoken::decode_header(&token).unwrap();
        assert_eq!(header.alg, Algorithm::EdDSA);
        assert_eq!(header.kid.as_deref(), Some("2026-11"));
        assert_eq!(signer.kid(), "2026-11");
    }

    #[test]
    fn a_bad_pem_is_refused_with_no_fallback() {
        let err = IdTokenSigner::from_ed25519_pem("not a pem", "k").unwrap_err();
        assert!(matches!(err, ProviderError::SigningUnavailable(_)));
        // A symmetric secret is not an Ed25519 key, so it is refused here —
        // there is no HS256 path to fall into.
        assert!(IdTokenSigner::from_ed25519_pem(
            "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----",
            "k"
        )
        .is_err());
    }

    #[test]
    fn the_public_jwk_is_the_okp_form_with_the_kid() {
        let jwk = IdTokenSigner::public_jwk_from_pem(PUBLIC_PEM, "k1").unwrap();
        assert_eq!(jwk["kty"], "OKP");
        assert_eq!(jwk["crv"], "Ed25519");
        assert_eq!(jwk["alg"], "EdDSA");
        assert_eq!(jwk["use"], "sig");
        assert_eq!(jwk["kid"], "k1");
        assert_eq!(jwk["x"].as_str().unwrap().len(), 43, "32 bytes base64url");
        // No private material in a published JWK.
        assert!(jwk.get("d").is_none());
        // The derive-without-PEM path is an error, never an empty JWK.
        assert!(IdTokenSigner::public_jwk_from_pem("garbage", "k").is_err());
    }

    /// The signer's `Debug` shows the kid and nothing else.
    #[test]
    fn the_signer_debug_prints_no_key_material() {
        let signer = IdTokenSigner::from_ed25519_pem(PRIVATE_PEM, "k1").unwrap();
        let rendered = format!("{signer:?}");
        assert!(rendered.contains("k1"));
        assert!(!rendered.contains("MC4CAQAw"));
    }
}
