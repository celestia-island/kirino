use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use uuid::Uuid;

use crate::config::{Ed25519Keys, SessionConfig};
use crate::error::{SessionError, SessionResult};
use crate::revocation::RefreshRevocationStore;
use crate::token::{TokenClaims, TokenPair, TokenType};

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
    },
    /// A malformed key found at construction; the message is replayed on
    /// every sign/verify so construction stays infallible and the failure
    /// stays loud. A `String` (not the error enum) because `SessionError`
    /// is not `Clone`.
    Broken(String),
}

impl KeySet {
    fn resolve(ed: &Ed25519Keys, secret: &str) -> Self {
        if ed.verifying_pems.is_empty() {
            return Self::SharedSecret {
                encoding: EncodingKey::from_secret(secret.as_bytes()),
                decoding: DecodingKey::from_secret(secret.as_bytes()),
            };
        }
        let mut decoding = Vec::with_capacity(ed.verifying_pems.len());
        for (i, pem) in ed.verifying_pems.iter().enumerate() {
            match DecodingKey::from_ed_pem(pem.as_bytes()) {
                Ok(key) => decoding.push(key),
                Err(e) => {
                    return Self::Broken(format!(
                        "Ed25519 verifying key #{} is not a valid PEM key: {e}",
                        i + 1
                    ))
                }
            }
        }
        let encoding = match &ed.signing_pem {
            None => None,
            Some(pem) => match EncodingKey::from_ed_pem(pem.as_bytes()) {
                Ok(key) => Some(key),
                Err(e) => {
                    return Self::Broken(format!(
                        "Ed25519 signing key is not a valid PEM key: {e}"
                    ))
                }
            },
        };
        Self::Ed25519 { encoding, decoding }
    }

    /// The only algorithm this manager accepts. Pinning it per profile is
    /// the alg-confusion guard: an HS256 token presented to an Ed25519
    /// manager (or vice versa) is rejected by the algorithm whitelist
    /// before any key is tried.
    fn algorithm(&self) -> Algorithm {
        match self {
            Self::SharedSecret { .. } => Algorithm::HS256,
            Self::Ed25519 { .. } => Algorithm::EdDSA,
            Self::Broken(_) => Algorithm::EdDSA, // unreachable: sign/verify fail first
        }
    }
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
        let keys = KeySet::resolve(&config.ed25519, &config.secret);
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
        let access = self.sign(
            &stamp(TokenClaims::new(
                user_id,
                username.clone(),
                TokenType::Access,
                self.config.access_ttl_secs,
                &self.config.issuer,
            )
            .with_session(&sid)
            .with_roles(roles.clone())),
        )?;
        let refresh = self.sign(
            &stamp(TokenClaims::new(
                user_id,
                username,
                TokenType::Refresh,
                self.config.refresh_ttl_secs,
                &self.config.issuer,
            )
            .with_session(&sid)
            .with_roles(roles)),
        )?;
        Ok(TokenPair {
            access_token: access,
            refresh_token: refresh,
            token_type: "Bearer".into(),
            expires_in: self.config.access_ttl_secs,
        })
    }

    /// Sign claims into a JWT string.
    pub fn sign(&self, claims: &TokenClaims) -> SessionResult<String> {
        let key = match &self.keys {
            KeySet::SharedSecret { encoding, .. } => encoding,
            KeySet::Ed25519 { encoding: Some(key), .. } => key,
            KeySet::Ed25519 { encoding: None, .. } => {
                return Err(SessionError::SigningUnavailable)
            }
            KeySet::Broken(msg) => return Err(SessionError::Keys(msg.clone())),
        };
        Ok(encode(&Header::new(self.keys.algorithm()), claims, key)?)
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
        let decoding: &[DecodingKey] = match &self.keys {
            KeySet::SharedSecret { decoding, .. } => std::slice::from_ref(decoding),
            KeySet::Ed25519 { decoding, .. } => decoding,
            KeySet::Broken(msg) => return Err(SessionError::Keys(msg.clone())),
        };
        let mut validation = Validation::new(self.keys.algorithm());
        validation.set_issuer(&[&self.config.issuer]);
        validation.validate_exp = check_exp;
        if let Some(ref aud) = self.config.audience {
            validation.set_audience(&[aud]);
            // jsonwebtoken validates `aud` only when the token carries the
            // claim: without marking it required, an audience-less token
            // sails through a configured boundary — the exact token a
            // sibling service would mint with the shared secret.
            validation
                .required_spec_claims
                .insert("aud".to_owned());
        }
        let mut last_err = None;
        for key in decoding {
            match decode::<TokenClaims>(token, key, &validation) {
                Ok(data) => return Ok(data.claims),
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err
            .map(SessionError::Jwt)
            .unwrap_or_else(|| SessionError::Keys("no verifying keys configured".into())))
    }

    /// Decode a JWT without verifying signature (e.g. for client-side expiry check).
    pub fn decode_unverified(token: &str) -> SessionResult<TokenClaims> {
        let data = jsonwebtoken::dangerous::insecure_decode::<TokenClaims>(token)?;
        Ok(data.claims)
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
    fn ed25519_issue_and_verify_round_trip() {
        let manager = TokenManager::new(issuer_config());
        let user_id = Uuid::new_v4();
        let pair = manager.issue_pair(user_id, "alice".into(), vec!["admin".into()]).unwrap();

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
        let verifier = TokenManager::new(SessionConfig::new("x").add_ed25519_verifying_key(ED_PUB_A));
        let issuer = TokenManager::new(issuer_config());
        let pair = issuer.issue_pair(Uuid::new_v4(), "bob".into(), vec![]).unwrap();

        assert_eq!(verifier.verify(&pair.access_token).unwrap().username, "bob");
        let err = verifier
            .sign(&TokenClaims::new(Uuid::new_v4(), "bob".into(), TokenType::Access, 60, "kirino"))
            .unwrap_err();
        assert!(matches!(err, SessionError::SigningUnavailable), "got: {err:?}");
        assert!(verifier.issue_pair(Uuid::new_v4(), "bob".into(), vec![]).is_err());
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
            .sign(&TokenClaims::new(Uuid::new_v4(), "u".into(), TokenType::Access, 60, "kirino"))
            .unwrap();
        let ed_token = ed
            .sign(&TokenClaims::new(Uuid::new_v4(), "u".into(), TokenType::Access, 60, "kirino"))
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
        let new_token = current.issue_pair(Uuid::new_v4(), "n".into(), vec![]).unwrap();
        let old_token = retiring.issue_pair(Uuid::new_v4(), "o".into(), vec![]).unwrap();
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
        let manager = TokenManager::new(
            SessionConfig::new("x").add_ed25519_verifying_key("not a pem"),
        );
        let err = manager
            .sign(&TokenClaims::new(Uuid::new_v4(), "u".into(), TokenType::Access, 60, "kirino"))
            .unwrap_err();
        assert!(matches!(err, SessionError::Keys(_)), "got: {err:?}");
        assert!(manager.verify("anything").is_err());
    }

    #[test]
    fn issue_pair_stamps_the_configured_audience() {
        // Before: a configured audience was enforced on verify but never
        // stamped on mint, so the manager rejected its own tokens.
        let config = issuer_config().with_audience("chest-api");
        let manager = TokenManager::new(config);
        let pair = manager.issue_pair(Uuid::new_v4(), "alice".into(), vec![]).unwrap();

        let claims = manager.verify(&pair.access_token).unwrap();
        assert_eq!(claims.aud.as_deref(), Some("chest-api"));

        // A token without an audience (hand-signed, bypassing issue_pair)
        // must be rejected by the same manager — that is the audience
        // boundary doing its job.
        let unaudited = TokenManager::new(issuer_config())
            .sign(&TokenClaims::new(Uuid::new_v4(), "alice".into(), TokenType::Access, 60, "kirino"))
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
}
