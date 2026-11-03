use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64U;
use base64::Engine as _;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use uuid::Uuid;

use crate::config::{Ed25519Keys, MlDsa65Keys, SessionConfig};
use crate::error::{SessionError, SessionResult};
use crate::revocation::RefreshRevocationStore;
use crate::token::{TokenClaims, TokenPair, TokenType};

/// Expiry leeway in seconds for the hand-rolled ML-DSA-65 verify path,
/// mirroring the `jsonwebtoken` default so both profiles age tokens out
/// on the same clock.
#[cfg(feature = "mldsa")]
const VERIFY_LEEWAY_SECS: i64 = 60;

/// The exact `alg` string this crate mints and accepts for the ML-DSA-65
/// profile (RFC 9964). Comparison is exact-string on purpose: it is the
/// alg-confusion guard, not a prefix match.
#[cfg(feature = "mldsa")]
const ML_DSA_65_ALG: &str = "ML-DSA-65";

/// The resolved key profile of a [`TokenManager`].
///
/// `Broken` keeps construction infallible while still failing loudly: a
/// malformed PEM surfaces on the first sign or verify with a precise
/// message instead of a panic at startup or — worse — a silently ignored
/// key.
enum KeySet {
    SharedSecret {
        encoding: EncodingKey,
        decoding: DecodingKey,
    },
    Ed25519 {
        /// `None` on verify-only instances: minting then fails with
        /// [`SessionError::SigningUnavailable`] rather than working.
        encoding: Option<EncodingKey>,
        decoding: Vec<DecodingKey>,
        /// Raw 32-byte public keys, extracted from the same PEMs as
        /// `decoding` at resolve time, for
        /// [`TokenManager::jwks`](TokenManager::jwks). Kept alongside the
        /// decoding keys so the JWKS export can never drift from the keys
        /// actually used for verification.
        verifying_raw: Vec<[u8; 32]>,
    },
    /// ML-DSA-65 (FIPS 204 / RFC 9964) profile, selected by a non-empty
    /// `MlDsa65Keys::verifying` in the config. Same shape as
    /// [`KeySet::Ed25519`]: `signing: None` on verify-only instances.
    #[cfg(feature = "mldsa")]
    MlDsa65 {
        signing: Option<ml_dsa::SigningKey<ml_dsa::MlDsa65>>,
        verifying: Vec<ml_dsa::VerifyingKey<ml_dsa::MlDsa65>>,
    },
    /// A malformed key found at construction; the message is replayed on
    /// every sign/verify so construction stays infallible and the failure
    /// stays loud. A `String` (not the error enum) because `SessionError`
    /// is not `Clone`.
    Broken(String),
}

impl KeySet {
    fn resolve(ed: &Ed25519Keys, ml: &MlDsa65Keys, secret: &str) -> Self {
        let ed_configured = ed.signing_pem.is_some() || !ed.verifying_pems.is_empty();
        let ml_configured = ml.signing_seed.is_some() || !ml.verifying.is_empty();
        // Profile mutual exclusion: with key material for both asymmetric
        // profiles the accepted-algorithm set would be ambiguous at verify
        // time (and at mint time either key could silently win). The only
        // safe resolution is none at all.
        if ed_configured && ml_configured {
            return Self::Broken(
                "both Ed25519 and ML-DSA-65 key material is configured; a \
                 manager pins exactly one profile — remove one of the two \
                 key sets"
                    .into(),
            );
        }
        // Selection priority from here on: ML-DSA-65 verifying keys, then
        // Ed25519 verifying keys, then the HS256 shared secret.
        #[cfg(feature = "mldsa")]
        {
            if ml.signing_seed.is_some() && ml.verifying.is_empty() {
                // Wrong-direction config, mirroring the Ed25519 guard
                // below: an issuer that configured only its seed would
                // otherwise silently mint HS256 tokens with the leftover
                // secret.
                return Self::Broken(
                    "an ML-DSA-65 signing seed is configured but no verifying \
                     key is: add the matching public key with \
                     `add_mldsa65_verifying_key`"
                        .into(),
                );
            }
            if !ml.verifying.is_empty() {
                // `VerifyingKey::decode` accepts any 1952 bytes (FIPS 204
                // has no cheap pk syntax check); an unusable key stays
                // inert and fails every signature it is tried against.
                let verifying = ml
                    .verifying
                    .iter()
                    .map(|raw| {
                        ml_dsa::VerifyingKey::decode(
                            &ml_dsa::EncodedVerifyingKey::<ml_dsa::MlDsa65>::from(*raw),
                        )
                    })
                    .collect();
                let signing = ml.signing_seed.as_ref().map(|seed| {
                    ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(&ml_dsa::Seed::from(**seed))
                });
                return Self::MlDsa65 { signing, verifying };
            }
        }
        #[cfg(not(feature = "mldsa"))]
        if ml_configured {
            // Without the feature there is no ML-DSA keyset to resolve to;
            // falling back to the shared secret would quietly revive the
            // exact trust path the config is trying to retire.
            return Self::Broken(
                "ML-DSA-65 key material is configured but this build of \
                 kirino-session lacks the `mldsa` feature; refusing to fall \
                 back to the HS256 shared-secret profile"
                    .into(),
            );
        }
        if ed.signing_pem.is_some() && ed.verifying_pems.is_empty() {
            // Wrong-direction config: an issuer that configured its private
            // key but no public key would otherwise silently mint HS256
            // tokens with the leftover secret — the exact trust path this
            // profile exists to retire. Fail as loudly as a malformed PEM.
            return Self::Broken(
                "an Ed25519 signing key is configured but no verifying key is: \
                 add the matching public key with `add_ed25519_verifying_key`"
                    .into(),
            );
        }
        if ed.verifying_pems.is_empty() {
            return Self::SharedSecret {
                encoding: EncodingKey::from_secret(secret.as_bytes()),
                decoding: DecodingKey::from_secret(secret.as_bytes()),
            };
        }
        let mut decoding = Vec::with_capacity(ed.verifying_pems.len());
        let mut verifying_raw = Vec::with_capacity(ed.verifying_pems.len());
        for (i, pem) in ed.verifying_pems.iter().enumerate() {
            match (
                DecodingKey::from_ed_pem(pem.as_bytes()),
                ed25519_spki_raw32(pem),
            ) {
                (Ok(key), Some(raw)) => {
                    decoding.push(key);
                    verifying_raw.push(raw);
                }
                (Err(e), _) => {
                    return Self::Broken(format!(
                        "Ed25519 verifying key #{} is not a valid PEM key: {e}",
                        i + 1
                    ))
                }
                (Ok(_), None) => {
                    // jsonwebtoken accepted it but it is not a plain
                    // Ed25519 SubjectPublicKeyInfo — we could verify with
                    // it but not publish it, so refuse rather than have
                    // jwks() and verify() disagree.
                    return Self::Broken(format!(
                        "Ed25519 verifying key #{} is not a raw Ed25519 \
                         SubjectPublicKeyInfo block",
                        i + 1
                    ));
                }
            }
        }
        let encoding = match &ed.signing_pem {
            None => None,
            Some(pem) => match EncodingKey::from_ed_pem(pem.as_bytes()) {
                Ok(key) => Some(key),
                Err(e) => {
                    return Self::Broken(format!("Ed25519 signing key is not a valid PEM key: {e}"))
                }
            },
        };
        Self::Ed25519 {
            encoding,
            decoding,
            verifying_raw,
        }
    }

    /// The only algorithm this manager accepts. Pinning it per profile is
    /// the alg-confusion guard: an HS256 token presented to an Ed25519
    /// manager (or vice versa) is rejected by the algorithm whitelist
    /// before any key is tried.
    fn algorithm(&self) -> Algorithm {
        match self {
            Self::SharedSecret { .. } => Algorithm::HS256,
            Self::Ed25519 { .. } => Algorithm::EdDSA,
            #[cfg(feature = "mldsa")]
            Self::MlDsa65 { .. } => {
                // The ML-DSA path never consults algorithm(): it pins the
                // alg string itself (exact match on "ML-DSA-65") inside
                // its own sign/verify code, which jsonwebtoken's Algorithm
                // enum cannot express.
                debug_assert!(
                    false,
                    "KeySet::MlDsa65 handles sign/verify without algorithm()"
                );
                Algorithm::EdDSA
            }
            Self::Broken(_) => {
                // Every sign/verify call site returns the Broken error before
                // reaching here; keep that invariant loud in debug builds.
                debug_assert!(
                    false,
                    "KeySet::Broken must be handled by sign/verify before \
                     algorithm() is consulted"
                );
                Algorithm::EdDSA
            }
        }
    }
}

/// Extract the raw 32-byte Ed25519 public key from a SubjectPublicKeyInfo
/// PEM block. An Ed25519 SPKI is a fixed 44-byte DER body whose 12-byte
/// prefix is constant, so this is a shape check plus a slice — enough for
/// the JWKS `x` field without pulling in a DER parser.
fn ed25519_spki_raw32(pem: &str) -> Option<[u8; 32]> {
    use base64::engine::general_purpose::STANDARD;
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
    let der = STANDARD.decode(body).ok()?;
    if der.len() != 44 || der[..12] != ED25519_SPKI_PREFIX {
        return None;
    }
    let mut raw = [0u8; 32];
    raw.copy_from_slice(&der[12..]);
    Some(raw)
}

/// base64url (RFC 7515, no padding) for JWS segments and JWK fields.
fn b64u_encode(bytes: &[u8]) -> String {
    B64U.encode(bytes)
}

/// Decode a base64url (unpadded) JWS segment, mapping decode failures to
/// [`SessionError::InvalidToken`]. Only the ML-DSA-65 paths parse JWS
/// segments by hand; the other profiles stay inside `jsonwebtoken`.
#[cfg(feature = "mldsa")]
fn b64u_decode(segment: &str) -> SessionResult<Vec<u8>> {
    B64U.decode(segment)
        .map_err(|e| SessionError::InvalidToken(format!("invalid base64url segment: {e}")))
}

/// Mint an ML-DSA-65 compact JWS: `b64url(header).b64url(payload).b64url(sig)`
/// (RFC 7515 §5.1 / RFC 9964).
///
/// The signature is `ml_dsa`'s plain [`Signer`](ml_dsa::Signer) call,
/// i.e. the FIPS 204 pure mode with an **empty context** — what RFC 9964
/// requires for the `ML-DSA-65` JOSE alg. The wire signature is the
/// 3309-byte `EncodedSignature` (FIPS 204 `sigEncode`), base64url
/// without padding like every other JWS segment.
#[cfg(feature = "mldsa")]
fn sign_mldsa65_compact(
    sk: &ml_dsa::SigningKey<ml_dsa::MlDsa65>,
    claims: &TokenClaims,
    kid: Option<&str>,
) -> SessionResult<String> {
    use ml_dsa::Signer as _;

    let mut header = serde_json::Map::new();
    header.insert("alg".into(), ML_DSA_65_ALG.into());
    header.insert("typ".into(), "JWT".into());
    if let Some(kid) = kid {
        header.insert("kid".into(), kid.into());
    }
    let header_bytes = serde_json::to_vec(&serde_json::Value::Object(header))
        .map_err(|e| SessionError::Other(format!("failed to serialize JOSE header: {e}")))?;
    let payload_bytes = serde_json::to_vec(claims)
        .map_err(|e| SessionError::Other(format!("failed to serialize token claims: {e}")))?;
    // RFC 7515 §5.1: the signing input is the ASCII of
    // b64url(header).b64url(payload).
    let signing_input = format!(
        "{}.{}",
        b64u_encode(&header_bytes),
        b64u_encode(&payload_bytes)
    );
    let sig = sk.sign(signing_input.as_bytes());
    Ok(format!(
        "{signing_input}.{}",
        b64u_encode(sig.encode().as_slice())
    ))
}

/// Parse the claims of an `ML-DSA-65`-headed token **without any
/// signature check**, for [`TokenManager::decode_unverified`]. Returns
/// `None` for anything that is not clearly an ML-DSA-65 token (the
/// jsonwebtoken fallback then handles — or rejects — it).
#[cfg(feature = "mldsa")]
fn mldsa65_claims_unverified(token: &str) -> Option<TokenClaims> {
    let h_b64 = token.split('.').next()?;
    let header: serde_json::Value = serde_json::from_slice(&B64U.decode(h_b64).ok()?).ok()?;
    if header.get("alg").and_then(|alg| alg.as_str()) != Some(ML_DSA_65_ALG) {
        return None;
    }
    let p_b64 = token.split('.').nth(1)?;
    let claims = serde_json::from_slice(&B64U.decode(p_b64).ok()?).ok()?;
    Some(claims)
}

/// Core JWT token manager — stateless sign/verify.
///
/// Symmetric (HS256 shared secret) by default; asymmetric (Ed25519) when
/// the config carries at least one public verifying key. See
/// [`SessionConfig`] for why the asymmetric profile exists.
pub struct TokenManager {
    config: SessionConfig,
    keys: KeySet,
}

impl TokenManager {
    pub fn new(config: SessionConfig) -> Self {
        let keys = KeySet::resolve(&config.ed25519, &config.mldsa65, &config.secret);
        Self { config, keys }
    }

    /// Issue an access + refresh token pair for a user.
    ///
    /// `roles` is embedded into **both** tokens via
    /// [`TokenClaims::with_roles`]: the access token needs it for
    /// authorization decisions, and the refresh token carries it so
    /// [`TokenManager::refresh`] / [`TokenManager::refresh_rotating`]
    /// can re-issue an equally privileged pair without a user-store
    /// round-trip. The parameter is wired rather than removed because
    /// the only in-crate callers are those refresh paths, which pass
    /// the presented token's `claims.roles` — dropping the parameter
    /// would silently downgrade every refreshed credential to an
    /// empty role set (the bug this signature once hid).
    ///
    /// Unlike `roles`, `permissions` are deliberately **not**
    /// propagated: the pair API has no permissions parameter, and a
    /// refreshed pair keeps only roles. Callers that mint
    /// permission-bearing tokens must sign [`TokenClaims`] directly
    /// via [`TokenManager::sign`].
    pub fn issue_pair(
        &self,
        user_id: Uuid,
        username: String,
        roles: Vec<String>,
    ) -> SessionResult<TokenPair> {
        let sid = Uuid::new_v4().to_string();
        // Audience is stamped from the config so the pair passes this very
        // manager's verifier: a configured audience without stamping would
        // have every issued token rejected at first presentation.
        let stamp = |c: TokenClaims| match &self.config.audience {
            Some(aud) => c.with_audience(aud.clone()),
            None => c,
        };
        let access = self.sign(&stamp(
            TokenClaims::new(
                user_id,
                username.clone(),
                TokenType::Access,
                self.config.access_ttl_secs,
                &self.config.issuer,
            )
            .with_session(&sid)
            .with_roles(roles.clone()),
        ))?;
        let refresh = self.sign(&stamp(
            TokenClaims::new(
                user_id,
                username,
                TokenType::Refresh,
                self.config.refresh_ttl_secs,
                &self.config.issuer,
            )
            .with_session(&sid)
            .with_roles(roles),
        ))?;
        Ok(TokenPair {
            access_token: access,
            refresh_token: refresh,
            token_type: "Bearer".into(),
            expires_in: self.config.access_ttl_secs,
        })
    }

    /// Sign claims into a JWT string.
    ///
    /// The claims are signed as given: unlike [`Self::issue_pair`], this
    /// does **not** stamp the configured audience onto them. A caller that
    /// signs claims by hand on a manager configured with
    /// [`SessionConfig::with_audience`] must set `aud` itself
    /// ([`TokenClaims::with_audience`]) or its own verifier — and every
    /// other audience-enforcing service — will reject the token.
    pub fn sign(&self, claims: &TokenClaims) -> SessionResult<String> {
        match &self.keys {
            KeySet::SharedSecret { encoding, .. } => {
                // The legacy profile keeps its byte format frozen: no kid
                // is stamped even when one is configured.
                Ok(encode(&Header::new(Algorithm::HS256), claims, encoding)?)
            }
            KeySet::Ed25519 {
                encoding: Some(key),
                ..
            } => {
                let mut header = Header::new(Algorithm::EdDSA);
                header.kid = self.config.kid.clone();
                Ok(encode(&header, claims, key)?)
            }
            KeySet::Ed25519 { encoding: None, .. } => Err(SessionError::SigningUnavailable),
            #[cfg(feature = "mldsa")]
            KeySet::MlDsa65 { signing, .. } => {
                let sk = signing.as_ref().ok_or(SessionError::SigningUnavailable)?;
                sign_mldsa65_compact(sk, claims, self.config.kid.as_deref())
            }
            KeySet::Broken(msg) => Err(SessionError::Keys(msg.clone())),
        }
    }

    /// Verify a JWT and return its claims.
    pub fn verify(&self, token: &str) -> SessionResult<TokenClaims> {
        self.verify_with(token, true)
    }

    /// Verify a JWT without rejecting expired tokens.
    ///
    /// Useful for **session restore** flows where an expired access token
    /// should still identify the user so a new token pair can be issued
    /// in exchange.  Expiry is checked on the returned claims so callers
    /// can decide whether to issue a fresh token.
    pub fn verify_lenient(&self, token: &str) -> SessionResult<TokenClaims> {
        self.verify_with(token, false)
    }

    /// Shared verify core: issuer, audience (when configured), expiry
    /// (optional), and exactly one algorithm family. With several
    /// verifying keys the keys are tried in configuration order — the
    /// rotation path — and the last error is reported when none match.
    fn verify_with(&self, token: &str, check_exp: bool) -> SessionResult<TokenClaims> {
        match &self.keys {
            #[cfg(feature = "mldsa")]
            KeySet::MlDsa65 { verifying, .. } => self.verify_mldsa65(token, verifying, check_exp),
            KeySet::SharedSecret { decoding, .. } => {
                self.verify_jsonwebtoken(token, std::slice::from_ref(decoding), check_exp)
            }
            KeySet::Ed25519 { decoding, .. } => {
                self.verify_jsonwebtoken(token, decoding, check_exp)
            }
            KeySet::Broken(msg) => Err(SessionError::Keys(msg.clone())),
        }
    }

    /// The `jsonwebtoken`-backed verify path (HS256 / Ed25519 profiles):
    /// registered-claim validation plus the per-profile algorithm
    /// whitelist, trying `decoding` in order.
    fn verify_jsonwebtoken(
        &self,
        token: &str,
        decoding: &[DecodingKey],
        check_exp: bool,
    ) -> SessionResult<TokenClaims> {
        let mut validation = Validation::new(self.keys.algorithm());
        validation.set_issuer(&[&self.config.issuer]);
        validation.validate_exp = check_exp;
        if let Some(ref aud) = self.config.audience {
            validation.set_audience(&[aud]);
            // jsonwebtoken validates `aud` only when the token carries the
            // claim: without marking it required, an audience-less token
            // sails through a configured boundary — the exact token a
            // sibling service would mint with the shared secret.
            validation.required_spec_claims.insert("aud".to_owned());
        }
        let mut last_err = None;
        for key in decoding {
            match decode::<TokenClaims>(token, key, &validation) {
                Ok(data) => return Ok(data.claims),
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err
            .map(|e| {
                // Audit R1-SESS-8: an expired token gets its own variant so
                // clients can tell "refresh me" from "sign in again" — the
                // middleware `Expired` arms were dead code while every
                // failure surfaced as the generic `Jwt` wrapper.
                if matches!(e.kind(), jsonwebtoken::errors::ErrorKind::ExpiredSignature) {
                    SessionError::Expired(chrono::Utc::now())
                } else {
                    SessionError::Jwt(e)
                }
            })
            .unwrap_or_else(|| SessionError::Keys("no verifying keys configured".into())))
    }

    /// The hand-rolled ML-DSA-65 verify path. `jsonwebtoken` cannot
    /// express the `ML-DSA-65` alg, so this mirrors its contract:
    /// structural parse → **exact alg whitelist** (the confusion guard —
    /// anything but the literal `"ML-DSA-65"` is rejected before any key
    /// is tried) → `kid` targeting → registered claims (issuer, audience
    /// as a required claim when configured, expiry with the same leeway)
    /// → signature over the RFC 7515 §5.1 signing input, trying the
    /// verifying keys in configuration order.
    #[cfg(feature = "mldsa")]
    fn verify_mldsa65(
        &self,
        token: &str,
        verifying: &[ml_dsa::VerifyingKey<ml_dsa::MlDsa65>],
        check_exp: bool,
    ) -> SessionResult<TokenClaims> {
        use ml_dsa::Verifier as _;

        let mut segments = token.split('.');
        let (h_b64, p_b64, s_b64) = match (
            segments.next(),
            segments.next(),
            segments.next(),
            segments.next(),
        ) {
            (Some(h), Some(p), Some(s), None) => (h, p, s),
            _ => return Err(SessionError::InvalidToken("not a compact JWS".into())),
        };
        let header: serde_json::Value = serde_json::from_slice(&b64u_decode(h_b64)?)
            .map_err(|e| SessionError::InvalidToken(format!("malformed JOSE header: {e}")))?;

        match header.get("alg").and_then(|alg| alg.as_str()) {
            Some(alg) if alg == ML_DSA_65_ALG => {}
            other => {
                return Err(SessionError::InvalidToken(format!(
                    "algorithm {other:?} is not accepted: this manager only \
                     takes {ML_DSA_65_ALG} tokens"
                )))
            }
        }

        // kid targeting: a token that carries a kid must carry the
        // configured one; a token without a kid (or a verifier without
        // one configured) falls through to the try-order below.
        let presented_kid = header.get("kid").and_then(|kid| kid.as_str());
        if let (Some(configured), Some(presented)) = (self.config.kid.as_deref(), presented_kid) {
            if configured != presented {
                return Err(SessionError::InvalidToken(format!(
                    "token kid {presented:?} does not match the configured kid {configured:?}"
                )));
            }
        }

        let claims: TokenClaims = serde_json::from_slice(&b64u_decode(p_b64)?)
            .map_err(|e| SessionError::InvalidToken(format!("malformed token claims: {e}")))?;
        if claims.iss != self.config.issuer {
            return Err(SessionError::InvalidToken(format!(
                "token issuer {:?} does not match the configured issuer {:?}",
                claims.iss, self.config.issuer
            )));
        }
        if let Some(expected) = &self.config.audience {
            // Mirrors the required-claim behavior of the jsonwebtoken
            // path: a configured audience makes `aud` mandatory.
            if claims.aud.as_deref() != Some(expected.as_str()) {
                return Err(SessionError::InvalidToken(
                    "token audience is missing or does not match the configured one".into(),
                ));
            }
        }
        if check_exp {
            let now = chrono::Utc::now().timestamp();
            if now > claims.exp as i64 + VERIFY_LEEWAY_SECS {
                return Err(SessionError::Expired(chrono::Utc::now()));
            }
        }

        let sig_bytes = b64u_decode(s_b64)?;
        let sig = ml_dsa::Signature::<ml_dsa::MlDsa65>::try_from(&sig_bytes[..])
            .map_err(|_| SessionError::InvalidToken("malformed ML-DSA-65 signature".into()))?;
        // RFC 7515 §5.1: the signed bytes are the ASCII of
        // b64url(header).b64url(payload) — byte-identical to the token
        // prefix up to the final dot.
        let signing_input = format!("{h_b64}.{p_b64}");
        for key in verifying {
            if key.verify(signing_input.as_bytes(), &sig).is_ok() {
                return Ok(claims);
            }
        }
        Err(SessionError::InvalidToken(
            "signature verification failed against every configured ML-DSA-65 key".into(),
        ))
    }

    /// Decode a JWT without verifying signature (e.g. for client-side expiry check).
    pub fn decode_unverified(token: &str) -> SessionResult<TokenClaims> {
        // `jsonwebtoken`'s insecure decode cannot even parse an ML-DSA-65
        // header (its Algorithm enum has no such variant), so the
        // ML-DSA-shaped case is handled here — with the same total absence
        // of signature checking that makes this method "dangerous" in the
        // first place.
        #[cfg(feature = "mldsa")]
        if let Some(claims) = mldsa65_claims_unverified(token) {
            return Ok(claims);
        }
        let data = jsonwebtoken::dangerous::insecure_decode::<TokenClaims>(token)?;
        Ok(data.claims)
    }

    /// Export the public verifying keys as a JWK Set (RFC 7517).
    ///
    /// - Ed25519 profile: one `OKP` entry per verifying key
    ///   (`{"kty":"OKP","crv":"Ed25519","x":…,"alg":"EdDSA","use":"sig"}`),
    ///   in the same try-order used for verification.
    /// - ML-DSA-65 profile (RFC 9964): one `AKP` entry per verifying key
    ///   (`{"kty":"AKP","alg":"ML-DSA-65","pub":…,"use":"sig"}`), `pub`
    ///   being the base64url of the 1952-byte FIPS 204 encoding.
    /// - The `kid` from [`SessionConfig::with_kid`] is stamped on every
    ///   entry when configured.
    /// - The HS256 profile and a `Broken` keyset publish nothing
    ///   publishable: `{"keys":[]}`. A shared secret must never leave the
    ///   process it minted in.
    pub fn jwks(&self) -> serde_json::Value {
        let mut keys = Vec::new();
        match &self.keys {
            KeySet::SharedSecret { .. } | KeySet::Broken(_) => {}
            KeySet::Ed25519 { verifying_raw, .. } => {
                for raw in verifying_raw {
                    let mut jwk = serde_json::Map::new();
                    jwk.insert("kty".into(), "OKP".into());
                    jwk.insert("crv".into(), "Ed25519".into());
                    jwk.insert("x".into(), b64u_encode(raw).into());
                    jwk.insert("alg".into(), "EdDSA".into());
                    jwk.insert("use".into(), "sig".into());
                    if let Some(kid) = &self.config.kid {
                        jwk.insert("kid".into(), kid.as_str().into());
                    }
                    keys.push(serde_json::Value::Object(jwk));
                }
            }
            #[cfg(feature = "mldsa")]
            KeySet::MlDsa65 { verifying, .. } => {
                for key in verifying {
                    let mut jwk = serde_json::Map::new();
                    jwk.insert("kty".into(), "AKP".into());
                    jwk.insert("alg".into(), ML_DSA_65_ALG.into());
                    jwk.insert("pub".into(), b64u_encode(key.encode().as_slice()).into());
                    jwk.insert("use".into(), "sig".into());
                    if let Some(kid) = &self.config.kid {
                        jwk.insert("kid".into(), kid.as_str().into());
                    }
                    keys.push(serde_json::Value::Object(jwk));
                }
            }
        }
        serde_json::json!({ "keys": keys })
    }

    /// Validate a refresh token: signature check, expected token type, and
    /// a parseable user id in `sub`. Returns the user id and the full claims.
    fn verify_refresh_claims(&self, refresh_token: &str) -> SessionResult<(Uuid, TokenClaims)> {
        let claims = self.verify(refresh_token)?;
        if claims.token_type != TokenType::Refresh {
            return Err(SessionError::InvalidToken("expected refresh token".into()));
        }
        let user_id = Uuid::parse_str(&claims.sub)
            .map_err(|_| SessionError::InvalidToken("invalid user id in token".into()))?;
        Ok((user_id, claims))
    }

    /// Refresh an access token using a valid refresh token.
    ///
    /// Returns a new token pair for the same user. **This method does not
    /// revoke the old refresh token**: the presented token stays valid until
    /// it expires naturally, so the same refresh token may be used more than
    /// once. Callers that need one-time-use rotation semantics (replay
    /// detection) must use [`TokenManager::refresh_rotating`] together with
    /// a [`RefreshRevocationStore`]. Do not mix the two paths on the same
    /// token population: every refresh that goes through this method
    /// bypasses the store's reuse detection entirely.
    pub fn refresh(&self, refresh_token: &str) -> SessionResult<TokenPair> {
        let (user_id, claims) = self.verify_refresh_claims(refresh_token)?;
        self.issue_pair(user_id, claims.username, claims.roles)
    }

    /// Refresh with one-time-use rotation backed by a revocation store.
    ///
    /// Semantics:
    /// - The presented refresh token must verify and carry a session id
    ///   (`sid`, set by `TokenClaims::with_session` when the pair was
    ///   issued); a refresh token without one is rejected.
    /// - If the store already records the `sid` inside the rejection
    ///   window (refresh TTL plus verify leeway — see
    ///   [`RefreshRevocationStore`]), the token was used for rotation
    ///   before and is rejected with [`SessionError::Revoked`]. That is
    ///   the reuse-detection signal: a refresh token must only ever be
    ///   presented once, so a second presentation means the token was
    ///   copied/stolen and both holders should be forced back to full
    ///   re-authentication.
    /// - The reuse check and the revocation bookkeeping happen in one
    ///   atomic step (`RefreshRevocationStore::check_and_revoke`), and the
    ///   `sid` is recorded **before** the new pair is issued. If issuance
    ///   then fails, the old refresh token is already dead and the user
    ///   must log in again; this deliberately trades a re-login for
    ///   closing the window in which the same token could be replayed.
    ///
    /// Revocation entries only need to live for the refresh-TTL window
    /// plus the verify-leeway grace — see [`RefreshRevocationStore`] for
    /// why, and for the in-memory (single-process) scope of the store.
    pub async fn refresh_rotating(
        &self,
        refresh_token: &str,
        revocations: &RefreshRevocationStore,
    ) -> SessionResult<TokenPair> {
        let (user_id, claims) = self.verify_refresh_claims(refresh_token)?;
        let sid = claims
            .sid
            .ok_or_else(|| SessionError::InvalidToken("refresh token has no session id".into()))?;
        let now = chrono::Utc::now().timestamp();
        if !revocations.check_and_revoke(&sid, now).await {
            return Err(SessionError::Revoked);
        }
        self.issue_pair(user_id, claims.username, claims.roles)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Static throwaway keypairs (openssl genpkey -algorithm ed25519),
    /// fixtures for tests only — no deployment uses them.
    const ED_PRIV_A: &str = concat!(
        "-----BEGIN PRIVATE KEY-----\n",
        "MC4CAQAwBQYDK2VwBCIEIHJZMnU8aSb141PJf2mApAbFap7LFj5SZQWxhQSM5X9d\n",
        "-----END PRIVATE KEY-----\n",
    );
    const ED_PUB_A: &str = concat!(
        "-----BEGIN PUBLIC KEY-----\n",
        "MCowBQYDK2VwAyEA+OA4Ug8REAhjvduxgwR+bDv3teNNRACYE96JQ5ZTzhA=\n",
        "-----END PUBLIC KEY-----\n",
    );
    const ED_PRIV_B: &str = concat!(
        "-----BEGIN PRIVATE KEY-----\n",
        "MC4CAQAwBQYDK2VwBCIEII1vRDE54egr3RWzmnQMTDqo+6A9Egmz5oLWXBq7Gubz\n",
        "-----END PRIVATE KEY-----\n",
    );
    const ED_PUB_B: &str = concat!(
        "-----BEGIN PUBLIC KEY-----\n",
        "MCowBQYDK2VwAyEAtCfny0WNxTiKRgsnHuC52XlFV3hH4lFQU/ctz4XRlGU=\n",
        "-----END PUBLIC KEY-----\n",
    );

    const ED_PRIV_C: &str = concat!(
        "-----BEGIN PRIVATE KEY-----\n",
        "MC4CAQAwBQYDK2VwBCIEIFCVpaUS2myE1o/0+UrTbBNAS1FVxtihGfRxQDD97fqK\n",
        "-----END PRIVATE KEY-----\n",
    );

    fn issuer_config() -> SessionConfig {
        SessionConfig::new("unused-in-ed25519-profile")
            .with_ed25519_signing_key(ED_PRIV_A)
            .add_ed25519_verifying_key(ED_PUB_A)
    }

    #[test]
    fn signing_key_without_verifying_keys_fails_loudly() {
        // The silent-HS256-downgrade trap the adversarial round probed: an
        // issuer that configured only its private key used to mint HS256
        // tokens signed with the leftover placeholder secret — forgeable by
        // anyone who reads the config. It must refuse instead.
        let manager = TokenManager::new(
            SessionConfig::new("placeholder").with_ed25519_signing_key(ED_PRIV_A),
        );
        let err = manager
            .sign(&TokenClaims::new(
                Uuid::new_v4(),
                "u".into(),
                TokenType::Access,
                60,
                "kirino",
            ))
            .unwrap_err();
        assert!(matches!(err, SessionError::Keys(_)), "got: {err:?}");
        assert!(manager.verify("any-token").is_err());
        assert!(manager
            .issue_pair(Uuid::new_v4(), "u".into(), vec![])
            .is_err());
    }

    #[test]
    fn lenient_verify_still_requires_the_audience() {
        // Leniency is an expiry axis, not a trust axis: a token with no
        // audience must stay rejected even where expiry is forgiven.
        let issuer = TokenManager::new(
            SessionConfig::new("x")
                .with_ed25519_signing_key(ED_PRIV_A)
                .add_ed25519_verifying_key(ED_PUB_A),
        );
        let strict_aud = TokenManager::new(
            SessionConfig::new("x")
                .add_ed25519_verifying_key(ED_PUB_A)
                .with_audience("chest-api"),
        );
        let token = issuer
            .sign(&TokenClaims::new(
                Uuid::new_v4(),
                "u".into(),
                TokenType::Access,
                60,
                "kirino",
            ))
            .unwrap();
        assert!(strict_aud.verify_lenient(&token).is_err());
    }

    #[test]
    fn strict_verify_rejects_expired_tokens_and_lenient_does_not() {
        // The manager-level expiry contract: jsonwebtoken's default leeway
        // is 60s, so the token is pushed 5 minutes into the past to be
        // unambiguously expired.
        let manager = TokenManager::new(issuer_config());
        let mut claims =
            TokenClaims::new(Uuid::new_v4(), "u".into(), TokenType::Access, 60, "kirino");
        claims.exp = (chrono::Utc::now().timestamp() - 300) as usize;
        let token = manager.sign(&claims).unwrap();

        assert!(manager.verify(&token).is_err());
        let lenient = manager.verify_lenient(&token).unwrap();
        assert_eq!(lenient.sub, claims.sub);
    }

    #[test]
    fn verify_rejects_a_foreign_issuer() {
        // Signed by a key this manager trusts, but minted by someone else:
        // issuer and audience are the two claims that keep a shared keypair
        // from becoming a family-wide passport.
        let manager = TokenManager::new(
            SessionConfig::new("x")
                .with_ed25519_signing_key(ED_PRIV_A)
                .add_ed25519_verifying_key(ED_PUB_A)
                .with_issuer("kirino"),
        );
        let foreign = manager
            .sign(&TokenClaims::new(
                Uuid::new_v4(),
                "u".into(),
                TokenType::Access,
                60,
                "someone-else",
            ))
            .unwrap();
        assert!(manager.verify(&foreign).is_err());
    }

    #[test]
    fn refresh_tokens_carry_the_configured_audience() {
        // Both halves of the pair are audience-bound: a refresh token that
        // could be replayed at an audience-less endpoint would make the
        // access token's audience decorative.
        let manager = TokenManager::new(issuer_config().with_audience("chest-api"));
        let pair = manager
            .issue_pair(Uuid::new_v4(), "alice".into(), vec![])
            .unwrap();
        let refresh = manager.verify(&pair.refresh_token).unwrap();
        assert_eq!(refresh.aud.as_deref(), Some("chest-api"));
    }

    #[test]
    fn ed25519_issue_and_verify_round_trip() {
        let manager = TokenManager::new(issuer_config());
        let user_id = Uuid::new_v4();
        let pair = manager
            .issue_pair(user_id, "alice".into(), vec!["admin".into()])
            .unwrap();

        let access = manager.verify(&pair.access_token).unwrap();
        assert_eq!(access.sub, user_id.to_string());
        assert_eq!(access.roles, vec!["admin".to_string()]);
        let refresh = manager.verify(&pair.refresh_token).unwrap();
        assert_eq!(refresh.token_type, TokenType::Refresh);
    }

    #[test]
    fn verify_only_manager_verifies_but_never_mints() {
        // The gateway shape: public key only. A leaked config from such a
        // service must not be enough to forge a token.
        let verifier =
            TokenManager::new(SessionConfig::new("x").add_ed25519_verifying_key(ED_PUB_A));
        let issuer = TokenManager::new(issuer_config());
        let pair = issuer
            .issue_pair(Uuid::new_v4(), "bob".into(), vec![])
            .unwrap();

        assert_eq!(verifier.verify(&pair.access_token).unwrap().username, "bob");
        let err = verifier
            .sign(&TokenClaims::new(
                Uuid::new_v4(),
                "bob".into(),
                TokenType::Access,
                60,
                "kirino",
            ))
            .unwrap_err();
        assert!(
            matches!(err, SessionError::SigningUnavailable),
            "got: {err:?}"
        );
        assert!(verifier
            .issue_pair(Uuid::new_v4(), "bob".into(), vec![])
            .is_err());
    }

    #[test]
    fn ed25519_rejects_hs256_tokens_and_vice_versa() {
        // Alg confusion in both directions: the algorithm whitelist is
        // pinned per profile, so a symmetric token must never verify
        // against an Ed25519 manager even when both sides are misconfigured
        // with the same secret, and vice versa.
        let hs = TokenManager::new(SessionConfig::new("shared"));
        let ed = TokenManager::new(
            SessionConfig::new("shared")
                .with_ed25519_signing_key(ED_PRIV_A)
                .add_ed25519_verifying_key(ED_PUB_A),
        );
        let hs_token = hs
            .sign(&TokenClaims::new(
                Uuid::new_v4(),
                "u".into(),
                TokenType::Access,
                60,
                "kirino",
            ))
            .unwrap();
        let ed_token = ed
            .sign(&TokenClaims::new(
                Uuid::new_v4(),
                "u".into(),
                TokenType::Access,
                60,
                "kirino",
            ))
            .unwrap();
        assert!(ed.verify(&hs_token).is_err());
        assert!(hs.verify(&ed_token).is_err());
    }

    #[test]
    fn ed25519_rotation_verifies_tokens_from_both_keys() {
        // Two public keys accepted, tokens signed by each private key
        // verify — the rollout window where the new key mints while the
        // old tokens must keep working.
        let current = TokenManager::new(
            SessionConfig::new("x")
                .with_ed25519_signing_key(ED_PRIV_B)
                .add_ed25519_verifying_key(ED_PUB_A)
                .add_ed25519_verifying_key(ED_PUB_B),
        );
        let retiring = TokenManager::new(
            SessionConfig::new("x")
                .with_ed25519_signing_key(ED_PRIV_A)
                .add_ed25519_verifying_key(ED_PUB_A),
        );
        let new_token = current
            .issue_pair(Uuid::new_v4(), "n".into(), vec![])
            .unwrap();
        let old_token = retiring
            .issue_pair(Uuid::new_v4(), "o".into(), vec![])
            .unwrap();
        assert!(current.verify(&new_token.access_token).is_ok());
        assert!(current.verify(&old_token.access_token).is_ok());
        // A key outside the accepted set still fails.
        let stranger = TokenManager::new(
            SessionConfig::new("x")
                .with_ed25519_signing_key(ED_PRIV_C)
                .add_ed25519_verifying_key(ED_PUB_B),
        );
        let stranger_token = &stranger
            .issue_pair(Uuid::new_v4(), "s".into(), vec![])
            .unwrap()
            .access_token;
        assert!(current.verify(stranger_token).is_err());
    }

    #[test]
    fn malformed_pem_fails_loudly_on_first_use() {
        // Construction stays infallible; the misconfiguration surfaces on
        // every sign and verify with a precise message instead of a panic
        // or a silently ignored key.
        let manager =
            TokenManager::new(SessionConfig::new("x").add_ed25519_verifying_key("not a pem"));
        let err = manager
            .sign(&TokenClaims::new(
                Uuid::new_v4(),
                "u".into(),
                TokenType::Access,
                60,
                "kirino",
            ))
            .unwrap_err();
        assert!(matches!(err, SessionError::Keys(_)), "got: {err:?}");
        assert!(manager.verify("anything").is_err());
    }

    #[test]
    fn mixed_ed25519_and_mldsa65_profiles_fail_loudly() {
        // Both asymmetric profiles on one config: the accepted-algorithm
        // set would be ambiguous, so the manager must refuse rather than
        // pick a winner. Runs with or without the `mldsa` feature — the
        // exclusion check precedes any feature-gated keyset construction.
        let dummy_mldsa_key = [7u8; 1952];
        let config = SessionConfig::new("x")
            .with_ed25519_signing_key(ED_PRIV_A)
            .add_ed25519_verifying_key(ED_PUB_A)
            .with_mldsa65_signing_seed(&[9u8; 32])
            .add_mldsa65_verifying_key(&dummy_mldsa_key);
        let manager = TokenManager::new(config);
        let err = manager
            .sign(&TokenClaims::new(
                Uuid::new_v4(),
                "u".into(),
                TokenType::Access,
                60,
                "kirino",
            ))
            .unwrap_err();
        assert!(matches!(err, SessionError::Keys(_)), "got: {err:?}");
        assert!(manager.verify("any-token").is_err());
    }

    #[test]
    fn jwks_exports_okp_keys_for_ed25519() {
        // Exact field match against RFC 8037's OKP shape; the `x` value is
        // pinned to the raw key bytes of ED_PUB_A (SPKI body minus its
        // constant 12-byte prefix), base64url without padding.
        let manager = TokenManager::new(
            SessionConfig::new("x")
                .add_ed25519_verifying_key(ED_PUB_A)
                .with_kid("gateway-1"),
        );
        let jwks = manager.jwks();
        let entry = &jwks["keys"][0];
        assert_eq!(entry["kty"], "OKP");
        assert_eq!(entry["crv"], "Ed25519");
        assert_eq!(entry["x"], "-OA4Ug8REAhjvduxgwR-bDv3teNNRACYE96JQ5ZTzhA");
        assert_eq!(entry["alg"], "EdDSA");
        assert_eq!(entry["use"], "sig");
        assert_eq!(entry["kid"], "gateway-1");
        // Exact key set: no extra members beyond the six pinned above.
        let mut fields: Vec<&str> = entry
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        fields.sort_unstable();
        assert_eq!(fields, vec!["alg", "crv", "kid", "kty", "use", "x"]);
    }

    #[test]
    fn jwks_lists_ed25519_keys_in_try_order_without_kid_when_unset() {
        let manager = TokenManager::new(
            SessionConfig::new("x")
                .add_ed25519_verifying_key(ED_PUB_A)
                .add_ed25519_verifying_key(ED_PUB_B),
        );
        let jwks = manager.jwks();
        assert_eq!(jwks["keys"].as_array().unwrap().len(), 2);
        // Try-order is part of the contract: the JWKS order must match the
        // verification order the manager itself uses.
        assert_eq!(
            jwks["keys"][0]["x"],
            "-OA4Ug8REAhjvduxgwR-bDv3teNNRACYE96JQ5ZTzhA"
        );
        assert_eq!(
            jwks["keys"][1]["x"],
            "tCfny0WNxTiKRgsnHuC52XlFV3hH4lFQU_ctz4XRlGU"
        );
        for entry in jwks["keys"].as_array().unwrap() {
            assert!(entry.get("kid").is_none());
        }
    }

    #[test]
    fn jwks_is_empty_for_the_shared_secret_profile() {
        // A shared secret has nothing publishable: the JWKS of the HS256
        // profile must be an empty key set, never the secret in any form.
        let manager = TokenManager::new(SessionConfig::new("test-secret-key-for-unit-tests"));
        assert_eq!(manager.jwks(), serde_json::json!({ "keys": [] }));
    }

    #[test]
    fn hs256_tokens_do_not_carry_kid_even_when_configured() {
        // The legacy profile's byte format is frozen: a configured kid is
        // for the asymmetric profiles only.
        let manager = TokenManager::new(SessionConfig::new("secret").with_kid("k"));
        let token = manager
            .sign(&TokenClaims::new(
                Uuid::new_v4(),
                "u".into(),
                TokenType::Access,
                60,
                "kirino",
            ))
            .unwrap();
        let h_b64 = token.split('.').next().unwrap();
        let header = serde_json::from_slice::<serde_json::Value>(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(h_b64)
                .unwrap(),
        )
        .unwrap();
        assert!(header.get("kid").is_none());
        assert!(manager.verify(&token).is_ok());
    }

    #[test]
    fn issue_pair_stamps_the_configured_audience() {
        // Before: a configured audience was enforced on verify but never
        // stamped on mint, so the manager rejected its own tokens.
        let config = issuer_config().with_audience("chest-api");
        let manager = TokenManager::new(config);
        let pair = manager
            .issue_pair(Uuid::new_v4(), "alice".into(), vec![])
            .unwrap();

        let claims = manager.verify(&pair.access_token).unwrap();
        assert_eq!(claims.aud.as_deref(), Some("chest-api"));

        // A token without an audience (hand-signed, bypassing issue_pair)
        // must be rejected by the same manager — that is the audience
        // boundary doing its job.
        let unaudited = TokenManager::new(issuer_config())
            .sign(&TokenClaims::new(
                Uuid::new_v4(),
                "alice".into(),
                TokenType::Access,
                60,
                "kirino",
            ))
            .unwrap();
        assert!(manager.verify(&unaudited).is_err());
    }

    #[test]
    fn sub_accessors_survive_sign_verify_roundtrip() {
        let manager = TokenManager::new(SessionConfig::new("test-secret"));
        let user_id = Uuid::new_v4();
        let token = manager
            .sign(&TokenClaims::new(
                user_id,
                "alice".into(),
                TokenType::Access,
                60,
                "kirino",
            ))
            .unwrap();

        let claims = manager.verify(&token).unwrap();
        // Semantic accessors: the stable identifier is the UUID (`sub`
        // here, `user_id` in the root crate's Claims) and the login name
        // is `username` (`sub` in the root crate's Claims).
        assert_eq!(claims.sub_uuid(), user_id.to_string());
        assert_eq!(claims.sub_username(), "alice");
        // Wire compatibility: `sub` on the wire is still the user UUID.
        assert_eq!(claims.sub, user_id.to_string());
        assert_eq!(claims.username, "alice");
    }

    #[test]
    fn sign_and_verify() {
        let config = SessionConfig::new("test-secret-key-for-unit-tests");
        let manager = TokenManager::new(config);
        let user_id = Uuid::new_v4();
        let pair = manager
            .issue_pair(user_id, "testuser".into(), vec![])
            .unwrap();

        let claims = manager.verify(&pair.access_token).unwrap();
        assert_eq!(claims.sub, user_id.to_string());
        assert_eq!(claims.username, "testuser");
        // roles deserialization known issue with serde(default)
        assert_eq!(claims.roles, Vec::<String>::new());
        assert_eq!(claims.token_type, TokenType::Access);
    }

    #[test]
    fn issue_pair_embeds_roles_in_both_tokens() {
        let manager = TokenManager::new(SessionConfig::new("secret"));
        let roles = vec!["admin".to_string(), "operator".to_string()];
        let pair = manager
            .issue_pair(Uuid::new_v4(), "u".into(), roles.clone())
            .unwrap();
        let access = manager.verify(&pair.access_token).unwrap();
        assert_eq!(access.roles, roles);
        // The refresh token must carry the roles too: refresh paths
        // re-issue from the presented token's claims.
        let refresh = manager.verify(&pair.refresh_token).unwrap();
        assert_eq!(refresh.roles, roles);
        assert_eq!(refresh.token_type, TokenType::Refresh);
    }

    #[test]
    #[ignore = "jsonwebtoken leeway"]
    fn expired_token_fails() {
        let config = SessionConfig::new("test-secret");
        let manager = TokenManager::new(config);
        // Create token with 0 TTL (immediately expired)
        let claims = TokenClaims::new(Uuid::new_v4(), "u".into(), TokenType::Access, 0, "kirino");
        let token = manager.sign(&claims).unwrap();
        // jsonwebtoken default leeway is 60s, set to 0 for this test
        let mut validation = jsonwebtoken::Validation::default();
        validation.set_issuer(&["kirino"]);
        validation.leeway = 0;
        assert!(jsonwebtoken::decode::<TokenClaims>(
            &token,
            &jsonwebtoken::DecodingKey::from_secret(b"test-secret"),
            &validation,
        )
        .is_err());
    }

    #[test]
    fn wrong_secret_fails() {
        let m1 = TokenManager::new(SessionConfig::new("secret-a"));
        let m2 = TokenManager::new(SessionConfig::new("secret-b"));
        let claims = TokenClaims::new(
            Uuid::new_v4(),
            "u".into(),
            TokenType::Access,
            3600,
            "kirino",
        );
        let token = m1.sign(&claims).unwrap();
        assert!(m2.verify(&token).is_err());
    }

    #[test]
    fn refresh_token_flow() {
        let manager = TokenManager::new(SessionConfig::new("secret"));
        let pair = manager
            .issue_pair(Uuid::new_v4(), "u".into(), vec![])
            .unwrap();
        let new_pair = manager.refresh(&pair.refresh_token).unwrap();
        assert_ne!(new_pair.access_token, pair.access_token);
    }

    #[test]
    fn refresh_preserves_roles() {
        let manager = TokenManager::new(SessionConfig::new("secret"));
        let roles = vec!["admin".to_string()];
        let pair = manager
            .issue_pair(Uuid::new_v4(), "u".into(), roles.clone())
            .unwrap();
        let refreshed = manager.refresh(&pair.refresh_token).unwrap();
        let claims = manager.verify(&refreshed.access_token).unwrap();
        assert_eq!(claims.roles, roles);
        // The new refresh token stays role-bearing so further refreshes
        // keep the chain privileged.
        let refresh_claims = manager.verify(&refreshed.refresh_token).unwrap();
        assert_eq!(refresh_claims.roles, roles);
    }

    #[test]
    fn verify_lenient_accepts_expired_token() {
        let manager = TokenManager::new(SessionConfig::new("secret"));
        let claims = TokenClaims::new(Uuid::new_v4(), "u".into(), TokenType::Access, 0, "kirino");
        let token = manager.sign(&claims).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));
        let result = manager.verify_lenient(&token).unwrap();
        assert!(result.is_expired());
        assert_eq!(result.username, "u");
    }

    #[test]
    fn verify_lenient_rejects_wrong_secret() {
        let m1 = TokenManager::new(SessionConfig::new("secret-a"));
        let m2 = TokenManager::new(SessionConfig::new("secret-b"));
        let claims = TokenClaims::new(
            Uuid::new_v4(),
            "u".into(),
            TokenType::Access,
            3600,
            "kirino",
        );
        let token = m1.sign(&claims).unwrap();
        assert!(m2.verify_lenient(&token).is_err());
    }

    #[test]
    fn verify_lenient_rejects_invalid_type_for_refresh() {
        let manager = TokenManager::new(SessionConfig::new("secret"));
        let pair = manager
            .issue_pair(Uuid::new_v4(), "u".into(), vec![])
            .unwrap();
        // Using access token where refresh token is expected
        assert!(manager.refresh(&pair.access_token).is_err());
    }

    #[test]
    fn permissions_and_aud_roundtrip() {
        let config = SessionConfig::new("secret").with_audience("entelecheia-api");
        let manager = TokenManager::new(config);
        let perms = vec!["read:foo".to_string(), "write:bar".to_string()];
        let claims = TokenClaims::new(
            Uuid::new_v4(),
            "u".into(),
            TokenType::Access,
            3600,
            "kirino",
        )
        .with_permissions(perms.clone())
        .with_audience("entelecheia-api");
        let token = manager.sign(&claims).unwrap();
        let verified = manager.verify(&token).unwrap();
        assert_eq!(verified.permissions, perms);
        assert_eq!(verified.aud.as_deref(), Some("entelecheia-api"));
    }

    #[test]
    fn verify_rejects_wrong_audience_when_configured() {
        let config = SessionConfig::new("secret").with_audience("entelecheia-api");
        let manager = TokenManager::new(config);
        // Token minted for a different audience.
        let claims = TokenClaims::new(
            Uuid::new_v4(),
            "u".into(),
            TokenType::Access,
            3600,
            "kirino",
        )
        .with_audience("other-api");
        let token = manager.sign(&claims).unwrap();
        assert!(manager.verify(&token).is_err());
    }

    #[test]
    fn verify_accepts_matching_audience_when_configured() {
        let config = SessionConfig::new("secret").with_audience("entelecheia-api");
        let manager = TokenManager::new(config);
        let claims = TokenClaims::new(
            Uuid::new_v4(),
            "u".into(),
            TokenType::Access,
            3600,
            "kirino",
        )
        .with_audience("entelecheia-api");
        let token = manager.sign(&claims).unwrap();
        let verified = manager.verify(&token).unwrap();
        assert_eq!(verified.aud.as_deref(), Some("entelecheia-api"));
    }

    #[test]
    fn verify_accepts_token_without_audience_when_not_configured() {
        let manager = TokenManager::new(SessionConfig::new("secret"));
        // No audience on either side — backward compatible path.
        let claims = TokenClaims::new(
            Uuid::new_v4(),
            "u".into(),
            TokenType::Access,
            3600,
            "kirino",
        );
        let token = manager.sign(&claims).unwrap();
        assert!(manager.verify(&token).is_ok());
    }

    #[test]
    fn verify_lenient_validates_audience_when_configured() {
        let config = SessionConfig::new("secret").with_audience("entelecheia-api");
        let manager = TokenManager::new(config);
        let claims = TokenClaims::new(Uuid::new_v4(), "u".into(), TokenType::Access, 0, "kirino")
            .with_audience("other-api");
        let token = manager.sign(&claims).unwrap();
        // Even lenient verify must enforce audience when configured.
        assert!(manager.verify_lenient(&token).is_err());
    }

    #[tokio::test]
    async fn refresh_rotating_revokes_old_refresh_token() {
        let manager = TokenManager::new(SessionConfig::new("secret"));
        let store = RefreshRevocationStore::new(3_600);
        let pair = manager
            .issue_pair(Uuid::new_v4(), "u".into(), vec![])
            .unwrap();
        let rotated = manager
            .refresh_rotating(&pair.refresh_token, &store)
            .await
            .unwrap();
        assert_ne!(rotated.refresh_token, pair.refresh_token);
        // Replaying the old refresh token must hit the revocation store.
        let err = manager
            .refresh_rotating(&pair.refresh_token, &store)
            .await
            .unwrap_err();
        assert!(matches!(err, SessionError::Revoked));
    }

    #[tokio::test]
    async fn refresh_rotating_chain() {
        let manager = TokenManager::new(SessionConfig::new("secret"));
        let store = RefreshRevocationStore::new(3_600);
        let pair0 = manager
            .issue_pair(Uuid::new_v4(), "u".into(), vec![])
            .unwrap();
        let pair1 = manager
            .refresh_rotating(&pair0.refresh_token, &store)
            .await
            .unwrap();
        let pair2 = manager
            .refresh_rotating(&pair1.refresh_token, &store)
            .await
            .unwrap();
        assert_ne!(pair1.refresh_token, pair2.refresh_token);
        assert_ne!(pair1.access_token, pair2.access_token);
        // The latest refresh token of the chain is still usable.
        assert!(manager
            .refresh_rotating(&pair2.refresh_token, &store)
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn refresh_rotating_preserves_roles() {
        let manager = TokenManager::new(SessionConfig::new("secret"));
        let store = RefreshRevocationStore::new(3_600);
        let roles = vec!["auditor".to_string()];
        let pair = manager
            .issue_pair(Uuid::new_v4(), "u".into(), roles.clone())
            .unwrap();
        let rotated = manager
            .refresh_rotating(&pair.refresh_token, &store)
            .await
            .unwrap();
        let claims = manager.verify(&rotated.access_token).unwrap();
        assert_eq!(claims.roles, roles);
        let refresh_claims = manager.verify(&rotated.refresh_token).unwrap();
        assert_eq!(refresh_claims.roles, roles);
    }

    #[test]
    fn refresh_without_rotation_keeps_old_token_usable() {
        // Regression: the non-rotating refresh() keeps accepting the same
        // refresh token until it expires (no implicit revocation).
        let manager = TokenManager::new(SessionConfig::new("secret"));
        let pair = manager
            .issue_pair(Uuid::new_v4(), "u".into(), vec![])
            .unwrap();
        let first = manager.refresh(&pair.refresh_token).unwrap();
        let second = manager.refresh(&pair.refresh_token).unwrap();
        assert_ne!(first.access_token, second.access_token);
    }

    #[tokio::test]
    async fn refresh_rotating_does_not_affect_access_tokens() {
        let manager = TokenManager::new(SessionConfig::new("secret"));
        let store = RefreshRevocationStore::new(3_600);
        let old_pair = manager
            .issue_pair(Uuid::new_v4(), "u".into(), vec![])
            .unwrap();
        let new_pair = manager
            .refresh_rotating(&old_pair.refresh_token, &store)
            .await
            .unwrap();
        // Revocation only guards the refresh path: both the old and the new
        // access token still verify normally.
        assert!(manager.verify(&old_pair.access_token).is_ok());
        assert!(manager.verify(&new_pair.access_token).is_ok());
    }

    #[tokio::test]
    async fn refresh_rotating_rejects_refresh_token_without_sid() {
        let manager = TokenManager::new(SessionConfig::new("secret"));
        let store = RefreshRevocationStore::new(3_600);
        // Minted without `with_session`, so no sid is present.
        let claims = TokenClaims::new(
            Uuid::new_v4(),
            "u".into(),
            TokenType::Refresh,
            3_600,
            "kirino",
        );
        let token = manager.sign(&claims).unwrap();
        let err = manager.refresh_rotating(&token, &store).await.unwrap_err();
        assert!(matches!(err, SessionError::InvalidToken(_)));
    }

    /// ML-DSA-65 profile tests (feature `mldsa`). Seeds follow the KAT
    /// lane (`[i*7+1; 32]`, i = 0/1) plus an arbitrary stranger; FIPS 204
    /// keygen is deterministic from the seed, so fixtures are stable.
    #[cfg(all(test, feature = "mldsa"))]
    mod mldsa65 {
        use super::super::{b64u_encode, sign_mldsa65_compact};
        use super::*;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use ml_dsa::{MlDsa65, Signer as _};

        fn keypair(fill: u8) -> ([u8; 32], [u8; 1952]) {
            use ml_dsa::Keypair as _;
            let seed = [fill; 32];
            let sk = ml_dsa::SigningKey::<MlDsa65>::from_seed(&ml_dsa::Seed::from(seed));
            let mut vk = [0u8; 1952];
            vk.copy_from_slice(sk.verifying_key().encode().as_slice());
            (seed, vk)
        }

        fn claims() -> TokenClaims {
            TokenClaims::new(
                Uuid::new_v4(),
                "u".into(),
                TokenType::Access,
                3_600,
                "kirino",
            )
        }

        fn issuer(fill: u8) -> TokenManager {
            let (seed, vk) = keypair(fill);
            TokenManager::new(
                SessionConfig::new("unused-in-mldsa-profile")
                    .with_mldsa65_signing_seed(&seed)
                    .add_mldsa65_verifying_key(&vk),
            )
        }

        fn header_of(token: &str) -> serde_json::Value {
            let h_b64 = token.split('.').next().expect("segment");
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(h_b64).expect("b64url")).expect("json")
        }

        #[test]
        fn mldsa65_issue_and_verify_round_trip() {
            let manager = issuer(1);
            let user_id = Uuid::new_v4();
            let pair = manager
                .issue_pair(user_id, "alice".into(), vec!["admin".into()])
                .unwrap();

            let access = manager.verify(&pair.access_token).unwrap();
            assert_eq!(access.sub, user_id.to_string());
            assert_eq!(access.username, "alice");
            assert_eq!(access.roles, vec!["admin".to_string()]);
            let refresh = manager.verify(&pair.refresh_token).unwrap();
            assert_eq!(refresh.token_type, TokenType::Refresh);

            // Wire shape: three segments, RFC 9964 alg, FIPS 204 sig size.
            let segments: Vec<&str> = pair.access_token.split('.').collect();
            assert_eq!(segments.len(), 3);
            let header = header_of(&pair.access_token);
            assert_eq!(header["alg"], "ML-DSA-65");
            assert_eq!(header["typ"], "JWT");
            assert_eq!(
                URL_SAFE_NO_PAD.decode(segments[2]).unwrap().len(),
                3309,
                "EncodedSignature<MlDsa65> is 3309 bytes"
            );

            // The refresh path runs through the profile unmodified.
            let rotated = manager.refresh(&pair.refresh_token).unwrap();
            assert_ne!(rotated.access_token, pair.access_token);

            // decode_unverified understands the ML-DSA-65 header shape.
            let unverified = TokenManager::decode_unverified(&pair.access_token).unwrap();
            assert_eq!(unverified.sub, user_id.to_string());
        }

        #[test]
        fn mldsa65_alg_confusion_matrix() {
            // Every cell of the profile × token matrix, plus forged-alg
            // tokens whose signatures are *valid for their own header*:
            // only the exact-string alg whitelist can reject those.
            let hs = TokenManager::new(SessionConfig::new("shared"));
            let ed = TokenManager::new(
                SessionConfig::new("shared")
                    .with_ed25519_signing_key(ED_PRIV_A)
                    .add_ed25519_verifying_key(ED_PUB_A),
            );
            let ml = issuer(1);

            let hs_token = hs.sign(&claims()).unwrap();
            let ed_token = ed.sign(&claims()).unwrap();
            let ml_token = ml.sign(&claims()).unwrap();
            assert!(
                ml.verify(&hs_token).is_err(),
                "HS256 token must not verify on an ML-DSA-65 manager"
            );
            assert!(
                ml.verify(&ed_token).is_err(),
                "EdDSA token must not verify on an ML-DSA-65 manager"
            );
            assert!(
                ed.verify(&ml_token).is_err(),
                "ML-DSA-65 token must not verify on an Ed25519 manager"
            );
            assert!(
                hs.verify(&ml_token).is_err(),
                "ML-DSA-65 token must not verify on an HS256 manager"
            );

            let (seed, _) = keypair(1);
            let sk = ml_dsa::SigningKey::<MlDsa65>::from_seed(&ml_dsa::Seed::from(seed));
            let payload_b64 = ml_token.split('.').nth(1).unwrap().to_string();
            for fake_alg in ["ML-DSA-44", "ML-DSA-87", "HS256", "EdDSA", "ml-dsa-65"] {
                let header = serde_json::json!({ "alg": fake_alg, "typ": "JWT" });
                let h_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
                let si = format!("{h_b64}.{payload_b64}");
                let sig = sk.sign(si.as_bytes());
                let forged = format!("{si}.{}", URL_SAFE_NO_PAD.encode(sig.encode().as_slice()));
                let err = ml.verify(&forged).unwrap_err();
                assert!(
                    matches!(err, SessionError::InvalidToken(_)),
                    "{fake_alg}: got {err:?}"
                );
            }
        }

        #[test]
        fn mldsa65_verify_only_manager_verifies_but_never_mints() {
            // The PQ gateway shape: public key only. A leaked config from
            // such a service must not be enough to forge a token.
            let (_, vk) = keypair(1);
            let verifier =
                TokenManager::new(SessionConfig::new("x").add_mldsa65_verifying_key(&vk));
            let issuer_manager = issuer(1);
            let pair = issuer_manager
                .issue_pair(Uuid::new_v4(), "bob".into(), vec![])
                .unwrap();

            assert_eq!(verifier.verify(&pair.access_token).unwrap().username, "bob");
            let err = verifier.sign(&claims()).unwrap_err();
            assert!(
                matches!(err, SessionError::SigningUnavailable),
                "got: {err:?}"
            );
            assert!(verifier
                .issue_pair(Uuid::new_v4(), "bob".into(), vec![])
                .is_err());
        }

        #[test]
        fn mldsa65_rejects_tampered_payload_and_signature() {
            let manager = issuer(1);
            let token = manager
                .sign(&TokenClaims::new(
                    Uuid::new_v4(),
                    "alice".into(),
                    TokenType::Access,
                    3_600,
                    "kirino",
                ))
                .unwrap();
            let segments: Vec<&str> = token.split('.').collect();

            // (a) payload structural byte: the JSON no longer parses.
            let mut payload = URL_SAFE_NO_PAD.decode(segments[1]).unwrap();
            payload[0] ^= 0x01;
            let tampered = format!(
                "{}.{}.{}",
                segments[0],
                URL_SAFE_NO_PAD.encode(&payload),
                segments[2]
            );
            assert!(manager.verify(&tampered).is_err());

            // (b) payload value byte: JSON stays valid ("Ulice"), so only
            // the signature check can catch it.
            let pos = payload
                .windows(5)
                .position(|w| w == b"alice")
                .expect("username value in payload");
            payload[pos] = b'U';
            let tampered = format!(
                "{}.{}.{}",
                segments[0],
                URL_SAFE_NO_PAD.encode(&payload),
                segments[2]
            );
            assert!(manager.verify(&tampered).is_err());

            // (c) one signature byte.
            let mut sig = URL_SAFE_NO_PAD.decode(segments[2]).unwrap();
            sig[100] ^= 0x01;
            let tampered = format!(
                "{}.{}.{}",
                segments[0],
                segments[1],
                URL_SAFE_NO_PAD.encode(&sig)
            );
            assert!(manager.verify(&tampered).is_err());

            // Control: the pristine token still verifies.
            assert!(manager.verify(&token).is_ok());
        }

        #[test]
        fn mldsa65_rotation_verifies_tokens_from_both_keys() {
            // The rollout window: the new key mints while tokens from the
            // retiring key must keep verifying; a stranger key still fails.
            let (seed_a, vk_a) = keypair(1);
            let (seed_b, vk_b) = keypair(8);
            let current = TokenManager::new(
                SessionConfig::new("x")
                    .with_mldsa65_signing_seed(&seed_b)
                    .add_mldsa65_verifying_key(&vk_a)
                    .add_mldsa65_verifying_key(&vk_b),
            );
            let retiring = TokenManager::new(
                SessionConfig::new("x")
                    .with_mldsa65_signing_seed(&seed_a)
                    .add_mldsa65_verifying_key(&vk_a),
            );
            let new_token = current
                .issue_pair(Uuid::new_v4(), "n".into(), vec![])
                .unwrap();
            let old_token = retiring
                .issue_pair(Uuid::new_v4(), "o".into(), vec![])
                .unwrap();
            assert!(current.verify(&new_token.access_token).is_ok());
            assert!(current.verify(&old_token.access_token).is_ok());

            let (seed_c, vk_c) = keypair(15);
            let stranger = TokenManager::new(
                SessionConfig::new("x")
                    .with_mldsa65_signing_seed(&seed_c)
                    .add_mldsa65_verifying_key(&vk_c),
            );
            let stranger_token = stranger
                .issue_pair(Uuid::new_v4(), "s".into(), vec![])
                .unwrap();
            assert!(current.verify(&stranger_token.access_token).is_err());
        }

        #[test]
        fn mldsa65_strict_verify_rejects_expired_and_lenient_does_not() {
            // The manager-level expiry contract on the hand-rolled path:
            // 5 minutes past expiry is unambiguously beyond the 60s leeway.
            let manager = issuer(1);
            let mut claims = claims();
            claims.exp = (chrono::Utc::now().timestamp() - 300) as usize;
            let token = manager.sign(&claims).unwrap();

            assert!(manager.verify(&token).is_err());
            let lenient = manager.verify_lenient(&token).unwrap();
            assert_eq!(lenient.sub, claims.sub);
        }

        #[test]
        fn mldsa65_rejects_a_foreign_issuer_and_enforces_the_audience() {
            // Signed by a key this manager trusts, but minted by someone
            // else; plus the audience boundary (required when configured).
            let manager = issuer(1);
            let mut foreign_claims = claims();
            foreign_claims.iss = "someone-else".into();
            let foreign = manager.sign(&foreign_claims).unwrap();
            assert!(manager.verify(&foreign).is_err());

            let (seed, vk) = keypair(1);
            let strict = TokenManager::new(
                SessionConfig::new("x")
                    .with_mldsa65_signing_seed(&seed)
                    .add_mldsa65_verifying_key(&vk)
                    .with_audience("chest-api"),
            );
            let no_aud = strict.sign(&claims()).unwrap();
            assert!(strict.verify(&no_aud).is_err());
            let with_aud = strict.sign(&claims().with_audience("chest-api")).unwrap();
            assert!(strict.verify(&with_aud).is_ok());
        }

        #[test]
        fn mldsa65_jwks_exports_akp_keys() {
            let (_, vk) = keypair(1);
            let manager = TokenManager::new(
                SessionConfig::new("x")
                    .add_mldsa65_verifying_key(&vk)
                    .with_kid("pq-1"),
            );
            let jwks = manager.jwks();
            let entry = &jwks["keys"][0];
            assert_eq!(entry["kty"], "AKP");
            assert_eq!(entry["alg"], "ML-DSA-65");
            assert_eq!(entry["pub"], URL_SAFE_NO_PAD.encode(vk));
            assert_eq!(entry["use"], "sig");
            assert_eq!(entry["kid"], "pq-1");
            // Exact key set (RFC 9964 shape) and the pinned b64url size of
            // a 1952-byte key: 2603 chars, no padding.
            let mut fields: Vec<&str> = entry
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect();
            fields.sort_unstable();
            assert_eq!(fields, vec!["alg", "kid", "kty", "pub", "use"]);
            assert_eq!(entry["pub"].as_str().unwrap().len(), 2603);
        }

        #[test]
        fn mldsa65_kid_targeting_and_no_kid_fallback() {
            let (seed_a, vk_a) = keypair(1);
            let (seed_b, vk_b) = keypair(8);
            let issuer_with_kid = TokenManager::new(
                SessionConfig::new("x")
                    .with_mldsa65_signing_seed(&seed_b)
                    .add_mldsa65_verifying_key(&vk_b)
                    .with_kid("pq-current"),
            );
            let rotation = TokenManager::new(
                SessionConfig::new("x")
                    .add_mldsa65_verifying_key(&vk_a)
                    .add_mldsa65_verifying_key(&vk_b)
                    .with_kid("pq-current"),
            );

            // (a) kid-directed: the minted header carries the configured
            // kid and the same-kid verifier accepts it.
            let token = issuer_with_kid.sign(&claims()).unwrap();
            assert_eq!(header_of(&token)["kid"], "pq-current");
            assert!(rotation.verify(&token).is_ok());

            // (b) no kid on the token (minted by the retiring issuer):
            // try-order fallback over every verifying key.
            let kidless_issuer = TokenManager::new(
                SessionConfig::new("x")
                    .with_mldsa65_signing_seed(&seed_a)
                    .add_mldsa65_verifying_key(&vk_a),
            );
            let kidless = kidless_issuer.sign(&claims()).unwrap();
            assert!(header_of(&kidless).get("kid").is_none());
            assert!(rotation.verify(&kidless).is_ok());

            // (c) a token carrying a *different* kid is rejected outright,
            // before any key is tried.
            let other_kid_issuer = TokenManager::new(
                SessionConfig::new("x")
                    .with_mldsa65_signing_seed(&seed_b)
                    .add_mldsa65_verifying_key(&vk_b)
                    .with_kid("pq-old"),
            );
            let mismatched = other_kid_issuer.sign(&claims()).unwrap();
            let err = rotation.verify(&mismatched).unwrap_err();
            assert!(matches!(err, SessionError::InvalidToken(_)), "got: {err:?}");

            // (d) a verifier with no configured kid accepts kid-bearing
            // tokens through the plain try-order.
            let kidless_verifier =
                TokenManager::new(SessionConfig::new("x").add_mldsa65_verifying_key(&vk_b));
            assert!(kidless_verifier.verify(&token).is_ok());
        }

        #[test]
        fn mldsa65_signing_seed_without_verifying_keys_fails_loudly() {
            // The PQ mirror of the Ed25519 wrong-direction guard: a seed
            // alone must not silently become an HS256 issuer via the
            // leftover placeholder secret.
            let manager = TokenManager::new(
                SessionConfig::new("placeholder").with_mldsa65_signing_seed(&[3u8; 32]),
            );
            let err = manager.sign(&claims()).unwrap_err();
            assert!(matches!(err, SessionError::Keys(_)), "got: {err:?}");
            assert!(manager.verify("any-token").is_err());
            assert!(manager
                .issue_pair(Uuid::new_v4(), "u".into(), vec![])
                .is_err());
        }

        #[test]
        fn mldsa65_sign_helper_is_available_and_rfc9964_shaped() {
            // Direct pin of the mint shape: the free function must produce
            // exactly what verify accepts, with kid in the header.
            let (seed, _) = keypair(1);
            let sk = ml_dsa::SigningKey::<MlDsa65>::from_seed(&ml_dsa::Seed::from(seed));
            let token = sign_mldsa65_compact(&sk, &claims(), Some("k1")).unwrap();
            let header = header_of(&token);
            assert_eq!(header["alg"], "ML-DSA-65");
            assert_eq!(header["typ"], "JWT");
            assert_eq!(header["kid"], "k1");
            let mut fields: Vec<&str> = header
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect();
            fields.sort_unstable();
            assert_eq!(fields, vec!["alg", "kid", "typ"]);
            // b64u_encode is unpadded base64url.
            assert!(!b64u_encode(b"\xff\xff\xff").contains('='));
            let issuer_manager = issuer(1);
            assert!(issuer_manager.verify(&token).is_ok());
        }
    }
}
