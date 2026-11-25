//! Logout that actually logs out, and the revocation cascade behind it.
//!
//! "Clear the cookie" is not logout. A user who clicks sign-out on one
//! relying party and still holds a live refresh token at the provider — or a
//! live session at every OTHER relying party — has not been logged out; they
//! have been shown a login page. This module is the cascade:
//!
//! ```mermaid
//! flowchart LR
//!   RP[RP: sign-out clicked] -->|1. RP-initiated logout| OP[OP]
//!   OP -->|2. revoke subject's grants| G[(grants)]
//!   OP -->|3. revoke refresh tokens| R[(refresh)]
//!   OP -->|4. end the OP session| S[(session)]
//!   OP -->|5. back-channel logout, signed| RP2[RP 2]
//!   OP -->|5.| RP3[RP 3]
//! ```
//!
//! # Two directions
//!
//! - **RP-initiated** (OIDC RP-Initiated Logout 1.0): the RP sends the
//!   browser to the OP's logout endpoint with `id_token_hint` and optionally
//!   `post_logout_redirect_uri`. [`RpInitiatedLogout::verify`] checks the
//!   hint against the token it was issued from (so one RP cannot log out
//!   another RP's user) and that the redirect URI is registered (so logout
//!   is not an open redirect).
//! - **Back-channel** (OIDC Back-Channel Logout 1.0): the OP tells every RP
//!   that holds a session for the subject. [`BackchannelLogout::build`]
//!   produces a signed `logout_token` per RP; the RP verifies it and drops
//!   its own session.
//!
//! # What "revoke" means, exactly
//!
//! [`Revocation`] is the record of what was revoked and why, and it is the
//! thing the cascade carries. It has one job: every downstream holder that
//! learns of it must be able to tell that THIS subject, at THIS time, lost
//! THIS much — and nothing else. A revocation that revokes more than asked
//! (another user's sessions) or less (the refresh tokens survive) is the
//! two ways this goes wrong.
//!
//! # Properties
//!
//! - **An RP can only log out its own users.** The `id_token_hint`'s `aud`
//!   must be the RP; a hint minted for another client is refused.
//! - **`post_logout_redirect_uri` is registered or absent.** Logout is a
//!   favourite open-redirect: the user expects to be sent somewhere, so an
//!   unregistered target is refused rather than sanitised.
//! - **The logout token is per-RP and names its audience.** A back-channel
//!   message replayed to a second RP fails its `aud` check.
//! - **`sub` is the OP's, never an email**, and a revocation carries it as
//!   the stable key the grants were issued under.
//! - **`events` is `http://schemas.openid.net/event/backchannel-logout`**
//!   and nothing else: an RP MUST reject a token whose `events` it does not
//!   understand, and this crate never produces a token an RP would have to
//!   guess about.
//! - **A `nonce` is forbidden** in a logout token (the spec says so: an ID
//!   token must not be usable as a logout token). It is never minted here,
//!   and [`BackchannelLogout::verify`] refuses one.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The `events` member every back-channel logout token carries.
pub const BACKCHANNEL_LOGOUT_EVENT: &str = "http://schemas.openid.net/event/backchannel-logout";
/// How long a logout token is valid: seconds, not minutes. It is delivered
/// server-to-server immediately; there is no reason for it to live.
pub const LOGOUT_TOKEN_TTL_SECS: i64 = 120;

/// Why an RP-initiated logout was refused.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum LogoutError {
    /// No `id_token_hint`: the RP did not say whose session it wants to end.
    #[error("no id_token_hint was presented")]
    NoHint,
    /// The hint is not an ID token this provider issued, or its signature
    /// does not verify.
    #[error("the id_token_hint is not valid")]
    InvalidHint,
    /// The hint's `aud` is not the RP that presented it.
    #[error("the id_token_hint was issued to another client")]
    WrongAudience,
    /// The `post_logout_redirect_uri` is not one the client registered.
    #[error("the post-logout redirect URI is not registered")]
    UnregisteredRedirect,
    /// The hint is expired. (Still accepted for logout within a grace
    /// window — see [`HINT_GRACE_SECS`] — but refused beyond it.)
    #[error("the id_token_hint is too old")]
    ExpiredHint,
    /// A back-channel logout token was refused: bad signature, wrong
    /// audience, a `nonce` present, an `events` this RP does not know.
    #[error("the logout token is not valid")]
    InvalidLogoutToken,
}

/// How long past its `exp` an `id_token_hint` is still honoured for logout.
///
/// A user who leaves a tab open for an hour and then clicks sign-out should
/// still be signed out. The hint proves which RP and which user; it is not
/// being used to authorise anything, so a grace window is safe — and it is
/// bounded, because an indefinitely-valid hint is an indefinitely-valid
/// way to log a user out of every RP.
pub const HINT_GRACE_SECS: i64 = 24 * 3600;

/// What the RP asks the OP to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpInitiatedLogout<'a> {
    /// The ID token the RP received at login, as a compact JWT.
    pub id_token_hint: &'a str,
    /// Where to send the browser afterwards, if anywhere.
    pub post_logout_redirect_uri: Option<&'a str>,
    /// The RP's own client id, which the hint's `aud` must match.
    pub client_id: &'a str,
}

/// The ID-token claims the logout check needs, as the host's verifier
/// exposes them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HintClaims {
    /// Issuer — must be this OP.
    pub iss: String,
    /// Subject — the OP's stable id, never an email.
    pub sub: String,
    /// Audience — must be the presenting RP.
    pub aud: String,
    /// Expiry.
    pub exp: i64,
}

/// What the OP does after a successful RP-initiated logout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpLogoutVerdict {
    /// The subject to log out.
    pub sub: String,
    /// Where to send the browser, if the RP asked and it is registered.
    pub redirect_to: Option<String>,
}

impl RpInitiatedLogout<'_> {
    /// Verify the request and say what to revoke.
    ///
    /// `verify_hint` is the host's, and its obligations are not optional:
    ///
    /// - it verifies the hint's signature against this OP's keys, with
    ///   `alg` pinned to what this OP signs with and `typ` to `JWT`;
    /// - it does **not** enforce `exp` itself — the grace window here is what
    ///   lets a user with a tab open for an hour still sign out, and a
    ///   verifier that rejects on `exp` makes that window unreachable (the
    ///   crate's own `IdTokenVerifier` sets `validate_exp` by default);
    /// - it answers `None` for every failure. This method refuses when it
    ///   does; a verifier that answers claims for an unverifiable token turns
    ///   any string into a logout request.
    ///
    /// The `client_id` is the CALLER's claim about itself. The `aud` check
    /// proves the hint was minted for that client, which is the spec's
    /// trust model — an RP that holds a user's ID token is asserting it
    /// knows that user — not that the caller proved its own identity.
    ///
    /// # What the host must still do
    ///
    /// The OP's ID tokens carry no `sid`, so this check cannot tell whether
    /// the hint belongs to the **current browser session**. The spec is
    /// explicit (RP-Initiated Logout §2): when it does not, the OP **MUST
    /// ask the End-User** before logging them out. This module cannot see
    /// the browser; a host that skips the prompt turns every leaked ID
    /// token into a remote "log out everywhere" button for its subject,
    /// valid for the grace window. Compare the hint's `sub` against the
    /// session the request arrived on, and prompt on a mismatch.
    ///
    /// The hint's `sub` is also the OP's; under pairwise identifiers each
    /// RP knows the subject under its own `sub`, so `NotifyRp` must be given
    /// the per-RP translation, not this one. `registered_redirects` is the
    /// client's registered post-logout URIs — exact strings, the same way
    /// authorization redirects are registered.
    ///
    /// # Errors
    ///
    /// See [`LogoutError`]. Every refusal is a refusal; there is no
    /// "logout anyway with a warning".
    pub fn verify(
        &self,
        verify_hint: impl Fn(&str) -> Option<HintClaims>,
        registered_redirects: &[String],
        issuer: &str,
        now: DateTime<Utc>,
    ) -> Result<RpLogoutVerdict, LogoutError> {
        let Some(claims) = verify_hint(self.id_token_hint) else {
            return Err(LogoutError::InvalidHint);
        };
        if claims.iss != issuer {
            return Err(LogoutError::InvalidHint);
        }
        // An RP can only log out ITS OWN users: the hint was minted for this
        // audience, and a hint minted for another client is a client trying
        // to log someone out of a different RP.
        if claims.aud != self.client_id {
            return Err(LogoutError::WrongAudience);
        }
        // Grace window past `exp`: see `HINT_GRACE_SECS`.
        if now.timestamp() > claims.exp + HINT_GRACE_SECS {
            return Err(LogoutError::ExpiredHint);
        }
        let redirect_to = match self.post_logout_redirect_uri {
            None => None,
            Some(uri) => {
                // Registered or refused — never sanitised. Logout is a
                // favourite open redirect because the user expects to be
                // sent somewhere.
                if !registered_redirects.iter().any(|r| r == uri) {
                    return Err(LogoutError::UnregisteredRedirect);
                }
                Some(uri.to_owned())
            }
        };
        Ok(RpLogoutVerdict {
            sub: claims.sub,
            redirect_to,
        })
    }
}

/// A back-channel logout token's payload, before it is signed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogoutTokenClaims {
    /// This OP.
    pub iss: String,
    /// The RP this token is FOR — one token per RP.
    pub aud: String,
    /// When it stops being valid.
    pub exp: i64,
    /// When it was made.
    pub iat: i64,
    /// Unique, so a replay is detectable.
    pub jti: String,
    /// The events, as a JSON **object** keyed by event URI (spec §2.4):
    /// `{"http://schemas.openid.net/event/backchannel-logout": {}}`. Always
    /// that one key and an empty object. It is a map rather than an array
    /// because the spec says so, and a conforming RP refuses an array — the
    /// value per key is reserved for event-specific claims this crate never
    /// emits.
    pub events: std::collections::BTreeMap<String, serde_json::Value>,
    /// The subject whose sessions the RP must drop. The OP's stable id.
    pub sub: String,
    /// **Never set.** An ID token must not be usable as a logout token, and
    /// a `nonce` is what would let one be. Absent from the serialized form,
    /// not `null`: the spec says the member MUST NOT be present, and an RP
    /// that reads `"nonce": null` as "a nonce" would refuse every token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

/// The record of a revocation: who, when, and how far it reaches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Revocation {
    /// The OP's stable subject id.
    pub sub: String,
    /// When the user asked.
    pub at: DateTime<Utc>,
    /// Which RP initiated it, if any.
    pub initiated_by: Option<String>,
    /// Why: a user action, an admin action, or a policy change.
    pub reason: RevocationReason,
}

/// Why a subject's grants are being revoked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum RevocationReason {
    /// The user asked.
    UserLogout,
    /// An administrator ended the account's sessions.
    Administrative,
    /// A role or policy change: the privilege epoch moved.
    PrivilegeChange,
}

/// Build and verify back-channel logout tokens.
#[derive(Debug, Clone)]
pub struct BackchannelLogout {
    issuer: String,
    ttl_secs: i64,
}

impl BackchannelLogout {
    /// A builder for `issuer` with the default TTL.
    #[must_use]
    pub fn new(issuer: impl Into<String>) -> Self {
        Self {
            issuer: issuer.into(),
            ttl_secs: LOGOUT_TOKEN_TTL_SECS,
        }
    }

    /// The issuer every token names.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// The TTL stamped into every token, in seconds.
    #[must_use]
    pub fn ttl_secs(&self) -> i64 {
        self.ttl_secs
    }

    /// The claims for one RP's logout token.
    ///
    /// One token per RP: `aud` is the RP, so a token delivered to RP 2 fails
    /// RP 2's audience check even if RP 1 leaked it.
    ///
    /// # Errors
    ///
    /// Never today; the signature is kept so a future validation does not
    /// change every call site.
    pub fn claims_for(
        &self,
        rp_audience: &str,
        sub: &str,
        jti: &str,
        now: DateTime<Utc>,
    ) -> LogoutTokenClaims {
        LogoutTokenClaims {
            iss: self.issuer.clone(),
            aud: rp_audience.to_owned(),
            exp: now.timestamp() + self.ttl_secs,
            iat: now.timestamp(),
            jti: jti.to_owned(),
            events: std::collections::BTreeMap::from([(
                BACKCHANNEL_LOGOUT_EVENT.to_owned(),
                serde_json::Value::Object(Default::default()),
            )]),
            sub: sub.to_owned(),
            nonce: None,
        }
    }

    /// Verify a logout token at the RP, given the host's verified claims.
    ///
    /// The checks an RP MUST make, which this puts in one place: the issuer
    /// is the expected one, the audience is THIS RP, the `events` contains
    /// the back-channel event, there is no `nonce`, and it has not expired.
    ///
    /// # Errors
    ///
    /// [`LogoutError::InvalidLogoutToken`] for every failure — an RP must
    /// reject a token it does not fully understand, not partially honour it.
    pub fn verify(
        claims: &LogoutTokenClaims,
        expected_issuer: &str,
        this_rp: &str,
        now: DateTime<Utc>,
    ) -> Result<String, LogoutError> {
        if claims.iss != expected_issuer {
            return Err(LogoutError::InvalidLogoutToken);
        }
        if claims.aud != this_rp {
            return Err(LogoutError::InvalidLogoutToken);
        }
        // The event MUST be present as a key. An RP MUST also reject a token
        // whose `events` it does not understand — so every key has to be one
        // this RP knows, and this RP knows exactly one.
        if claims.events.is_empty() || !claims.events.contains_key(BACKCHANNEL_LOGOUT_EVENT) {
            return Err(LogoutError::InvalidLogoutToken);
        }
        if claims.events.keys().any(|k| k != BACKCHANNEL_LOGOUT_EVENT) {
            return Err(LogoutError::InvalidLogoutToken);
        }
        if claims.nonce.is_some() {
            // The spec forbids it: an ID token must not be usable here.
            return Err(LogoutError::InvalidLogoutToken);
        }
        if now.timestamp() >= claims.exp {
            return Err(LogoutError::InvalidLogoutToken);
        }
        Ok(claims.sub.clone())
    }
}

/// The cascade: what to revoke, in order, for a revocation.
///
/// This is a list of intents rather than a side-effecting function on
/// purpose — the stores live in the host (K0's `ConsumableStore` for
/// grants, K2's `ServerSessionStore` for sessions), and a cascade that
/// reaches into them directly could not be tested without them.
///
/// **One step the host does NOT have a call for.** `ConsumableStore` is
/// keyed by token fingerprint and has no "every grant for subject X"; a
/// host that wants `RevokeGrants` to mean something must keep its own
/// `sub → tokens` index until the store grows one. The other two map onto
/// `revoke_all_for_subject` and `sign_logout_token` directly.
///
/// `rps_with_sessions` must be COMPLETE: the OP is supposed to track which
/// RPs hold a session for the subject (spec §2.3), and an RP missing from
/// this list is a silently missed notification — exactly the failure this
/// module exists to prevent.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CascadeStep {
    /// Revoke every grant issued to the subject: refresh tokens die here.
    RevokeGrants {
        /// The subject.
        sub: String,
    },
    /// End the subject's sessions at this OP (the cookie is the host's).
    EndOpSession {
        /// The subject.
        sub: String,
    },
    /// Notify one RP with a signed logout token.
    NotifyRp {
        /// The RP's client id — the token's `aud`.
        audience: String,
        /// The subject.
        sub: String,
        /// A fresh jti for this token.
        jti: String,
    },
}

/// The steps for a revocation, in order.
///
/// Grants first: a refresh token that survives the first two steps is a
/// refresh token that mints a new session after the user has "logged out".
#[must_use]
pub fn cascade(
    revocation: &Revocation,
    rps_with_sessions: &[String],
    now: DateTime<Utc>,
) -> Vec<CascadeStep> {
    let _ = now;
    let mut steps = Vec::with_capacity(2 + rps_with_sessions.len());
    steps.push(CascadeStep::RevokeGrants {
        sub: revocation.sub.clone(),
    });
    steps.push(CascadeStep::EndOpSession {
        sub: revocation.sub.clone(),
    });
    for audience in rps_with_sessions {
        steps.push(CascadeStep::NotifyRp {
            audience: audience.clone(),
            sub: revocation.sub.clone(),
            // 256 bits. A logout token is single-use at the RP and the jti
            // is what makes a replay detectable. (The jtis in K5 and K6 are
            // CLIENT-supplied; the access-token jti in `token.rs` is a
            // UUIDv7. This one is random because it is never parsed.)
            jti: {
                use rand::RngExt;
                let raw: [u8; 32] = rand::rng().random();
                crate::utils::base64url::encode(&raw)
            },
        });
    }
    steps
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn hint(now: DateTime<Utc>) -> HintClaims {
        HintClaims {
            iss: "https://auth.example".into(),
            sub: "user-1".into(),
            aud: "erp".into(),
            exp: now.timestamp(),
        }
    }

    fn logout<'a>(hint_str: &'a str, redirect: Option<&'a str>) -> RpInitiatedLogout<'a> {
        RpInitiatedLogout {
            id_token_hint: hint_str,
            post_logout_redirect_uri: redirect,
            client_id: "erp",
        }
    }

    #[test]
    fn a_valid_request_names_the_subject_and_the_registered_redirect() {
        let now = Utc::now();
        let h = hint(now);
        let v = logout("jwt", Some("https://erp.example/bye"))
            .verify(
                move |_| Some(h.clone()),
                &["https://erp.example/bye".into()],
                "https://auth.example",
                now,
            )
            .unwrap();
        assert_eq!(v.sub, "user-1");
        assert_eq!(v.redirect_to.as_deref(), Some("https://erp.example/bye"));
    }

    #[test]
    fn an_rp_can_only_log_out_its_own_users() {
        let now = Utc::now();
        let mut h = hint(now);
        h.aud = "chest".into();
        // MUT:aud-unchecked — without the check, `erp` logs out `chest`'s user.
        assert_eq!(
            logout("jwt", None)
                .verify(move |_| Some(h.clone()), &[], "https://auth.example", now)
                .unwrap_err(),
            LogoutError::WrongAudience
        );
    }

    #[test]
    fn an_unregistered_redirect_is_refused_not_sanitised() {
        let now = Utc::now();
        let h = hint(now);
        // MUT:redirect-unchecked — logout becomes an open redirect.
        assert_eq!(
            logout("jwt", Some("https://evil.example/"))
                .verify(
                    move |_| Some(h.clone()),
                    &["https://erp.example/bye".into()],
                    "https://auth.example",
                    now
                )
                .unwrap_err(),
            LogoutError::UnregisteredRedirect
        );
    }

    #[test]
    fn a_hint_past_the_grace_window_is_refused() {
        let now = Utc::now();
        let mut h = hint(now);
        h.exp = now.timestamp() - HINT_GRACE_SECS - 1;
        assert_eq!(
            logout("jwt", None)
                .verify(move |_| Some(h.clone()), &[], "https://auth.example", now)
                .unwrap_err(),
            LogoutError::ExpiredHint
        );
        // Inside the window (even long expired) it still works: a user who
        // left the tab open for an hour can still sign out.
        let mut h = hint(now);
        h.exp = now.timestamp() - 3600;
        logout("jwt", None)
            .verify(move |_| Some(h.clone()), &[], "https://auth.example", now)
            .expect("inside the grace window");
    }

    #[test]
    fn a_hint_from_another_issuer_is_refused() {
        let now = Utc::now();
        let h = hint(now);
        assert_eq!(
            logout("jwt", None)
                .verify(move |_| Some(h.clone()), &[], "https://other.example", now)
                .unwrap_err(),
            LogoutError::InvalidHint
        );
    }

    // ── back-channel ────────────────────────────────────────────────────

    #[test]
    fn a_logout_token_is_bound_to_one_rp() {
        let b = BackchannelLogout::new("https://auth.example");
        let now = Utc::now();
        let c = b.claims_for("erp", "user-1", "j-1", now);
        assert_eq!(
            BackchannelLogout::verify(&c, "https://auth.example", "erp", now).unwrap(),
            "user-1"
        );
        // MUT:aud-unchecked — a token for `erp` is honoured by `chest`.
        assert_eq!(
            BackchannelLogout::verify(&c, "https://auth.example", "chest", now).unwrap_err(),
            LogoutError::InvalidLogoutToken
        );
    }

    #[test]
    fn a_logout_token_with_a_nonce_is_refused() {
        let b = BackchannelLogout::new("https://auth.example");
        let now = Utc::now();
        let mut c = b.claims_for("erp", "user-1", "j-1", now);
        c.nonce = Some("n".into());
        // MUT:nonce-allowed — an ID token becomes a logout token.
        assert_eq!(
            BackchannelLogout::verify(&c, "https://auth.example", "erp", now).unwrap_err(),
            LogoutError::InvalidLogoutToken
        );
    }

    #[test]
    fn a_logout_token_with_unknown_events_is_refused() {
        let b = BackchannelLogout::new("https://auth.example");
        let now = Utc::now();
        let mut c = b.claims_for("erp", "user-1", "j-1", now);
        c.events = std::collections::BTreeMap::from([(
            "http://example.com/other".into(),
            serde_json::Value::Object(Default::default()),
        )]);
        assert_eq!(
            BackchannelLogout::verify(&c, "https://auth.example", "erp", now).unwrap_err(),
            LogoutError::InvalidLogoutToken
        );
    }

    /// An RP MUST reject a token whose `events` it does not understand —
    /// so a token carrying the logout event AND something else is refused
    /// too, not "honoured for the part I know".
    #[test]
    fn a_logout_token_with_a_mixed_events_map_is_refused() {
        let b = BackchannelLogout::new("https://auth.example");
        let now = Utc::now();
        let mut c = b.claims_for("erp", "user-1", "j-1", now);
        c.events.insert(
            "http://example.com/other".into(),
            serde_json::Value::Object(Default::default()),
        );
        // MUT:events-partial — accepting a token because it CONTAINS the
        // known event honours a token whose other events this RP ignored.
        assert_eq!(
            BackchannelLogout::verify(&c, "https://auth.example", "erp", now).unwrap_err(),
            LogoutError::InvalidLogoutToken
        );
        // And an empty map.
        let mut c = b.claims_for("erp", "user-1", "j-2", now);
        c.events.clear();
        assert_eq!(
            BackchannelLogout::verify(&c, "https://auth.example", "erp", now).unwrap_err(),
            LogoutError::InvalidLogoutToken
        );
    }

    #[test]
    fn an_expired_logout_token_is_refused() {
        let b = BackchannelLogout::new("https://auth.example");
        let now = Utc::now();
        let c = b.claims_for("erp", "user-1", "j-1", now);
        let later = now + Duration::seconds(LOGOUT_TOKEN_TTL_SECS + 1);
        assert_eq!(
            BackchannelLogout::verify(&c, "https://auth.example", "erp", later).unwrap_err(),
            LogoutError::InvalidLogoutToken
        );
    }

    #[test]
    fn a_logout_token_never_carries_a_nonce_when_minted() {
        let b = BackchannelLogout::new("https://auth.example");
        let c = b.claims_for("erp", "user-1", "j-1", Utc::now());
        assert!(c.nonce.is_none());
        assert_eq!(
            c.events.keys().collect::<Vec<_>>(),
            vec![&BACKCHANNEL_LOGOUT_EVENT.to_owned()]
        );
        // And on the wire it is an OBJECT, not an array (spec §2.4). An RP
        // that conforms refuses an array; serde would have emitted one from
        // a Vec. MUT:events-as-array — a `Vec<String>` reddens this.
        let json = serde_json::to_string(&c).unwrap();
        assert!(
            json.contains(&format!("\"{BACKCHANNEL_LOGOUT_EVENT}\":{{}}")),
            "{json}"
        );
        assert!(
            !json.contains(&format!("\"{BACKCHANNEL_LOGOUT_EVENT}\"]")),
            "an array, not an object: {json}"
        );
        // And the WIRE form has no nonce member at all — not `null`. R2's
        // question: `"nonce": null` is what serde would emit by default, and
        // an RP reading it as "a nonce is present" would refuse the token.
        let json = serde_json::to_string(&c).unwrap();
        assert!(!json.contains("nonce"), "{json}");
        // MUT:nonce-serialized — removing `skip_serializing_if` puts
        // `"nonce":null` on the wire and reddens this.
        // And the jti is 43 characters: 256 bits.
        let steps = cascade(
            &Revocation {
                sub: "u".into(),
                at: Utc::now(),
                initiated_by: None,
                reason: RevocationReason::UserLogout,
            },
            &["erp".into()],
            Utc::now(),
        );
        let CascadeStep::NotifyRp { jti, .. } = &steps[2] else {
            panic!()
        };
        assert_eq!(
            jti.len(),
            43,
            "256 bits base64url, like every other jti here"
        );
    }

    /// R2 B1: a verifier that cannot verify answers `None`, and that MUST
    /// refuse — a fallback that mints claims from the request would turn any
    /// string into a logout request for any subject.
    #[test]
    fn an_unverifiable_hint_is_refused_even_if_it_looks_like_a_jwt() {
        let now = Utc::now();
        for junk in ["", "not.a.jwt", "eyJhbGciOiJub25lIn0.."] {
            assert_eq!(
                logout(junk, None)
                    .verify(|_| None, &[], "https://auth.example", now)
                    .unwrap_err(),
                LogoutError::InvalidHint,
                "{junk:?}"
            );
        }
    }

    /// R2 B23: `aud` is an exact match, in BOTH directions. A caller
    /// claiming to be `erp-admin` with a hint minted for `erp` must be
    /// refused (a `client_id.starts_with(aud)` check would accept it), and
    /// the reverse (the original case) is refused by `aud.starts_with`.
    #[test]
    fn the_hints_audience_is_matched_exactly_not_by_prefix() {
        let now = Utc::now();
        // Caller is the LONGER name; the hint was minted for the shorter.
        let mut h = hint(now);
        h.aud = "erp".into();
        // MUT:aud-prefix-caller — `client_id.starts_with(aud)` accepts this.
        assert_eq!(
            RpInitiatedLogout {
                id_token_hint: "jwt",
                post_logout_redirect_uri: None,
                client_id: "erp-admin"
            }
            .verify(move |_| Some(h.clone()), &[], "https://auth.example", now)
            .unwrap_err(),
            LogoutError::WrongAudience
        );
        // And the other direction.
        let mut h = hint(now);
        h.aud = "erp-admin".into();
        // MUT:aud-prefix-claim — `aud.starts_with(client_id)` accepts this.
        assert_eq!(
            logout("jwt", None)
                .verify(move |_| Some(h.clone()), &[], "https://auth.example", now)
                .unwrap_err(),
            LogoutError::WrongAudience
        );
    }

    /// R2 B17: the post-logout redirect is an exact match too.
    #[test]
    fn the_post_logout_redirect_is_matched_exactly_not_by_prefix() {
        let now = Utc::now();
        let h = hint(now);
        // Registered: `https://erp.example/bye`. Requested: a path under it.
        // MUT:redirect-prefix — a prefix match sends the browser to
        // `/bye/evil`, an attacker-controlled page on the RP's own origin.
        assert_eq!(
            logout("jwt", Some("https://erp.example/bye/evil"))
                .verify(
                    move |_| Some(h.clone()),
                    &["https://erp.example/bye".into()],
                    "https://auth.example",
                    now
                )
                .unwrap_err(),
            LogoutError::UnregisteredRedirect
        );
    }

    /// R2 B6: the grace window's far edge is inclusive at exactly
    /// `exp + HINT_GRACE_SECS` and refused one second past it.
    #[test]
    fn the_grace_window_ends_exactly_at_its_bound() {
        let now = Utc::now();
        let at_edge = {
            let mut h = hint(now);
            h.exp = now.timestamp() - HINT_GRACE_SECS;
            h
        };
        logout("jwt", None)
            .verify(
                move |_| Some(at_edge.clone()),
                &[],
                "https://auth.example",
                now,
            )
            .expect("exactly at the bound is still inside");
        let past = {
            let mut h = hint(now);
            h.exp = now.timestamp() - HINT_GRACE_SECS - 1;
            h
        };
        assert_eq!(
            logout("jwt", None)
                .verify(
                    move |_| Some(past.clone()),
                    &[],
                    "https://auth.example",
                    now
                )
                .unwrap_err(),
            LogoutError::ExpiredHint
        );
    }

    /// R2 B5: the back-channel token's `iss` is checked, not only `aud`.
    #[test]
    fn a_logout_token_from_another_issuer_is_refused() {
        let b = BackchannelLogout::new("https://auth.example");
        let now = Utc::now();
        let c = b.claims_for("erp", "user-1", "j-1", now);
        assert_eq!(
            BackchannelLogout::verify(&c, "https://other.example", "erp", now).unwrap_err(),
            LogoutError::InvalidLogoutToken
        );
    }

    /// R2 B9b: every notified RP is told the RIGHT subject. A cascade that
    /// copied the audience into the `sub` slot would log the RP's client out
    /// instead of the user.
    #[test]
    fn every_notified_rp_is_told_the_subject_not_the_audience() {
        let r = Revocation {
            sub: "user-1".into(),
            at: Utc::now(),
            initiated_by: Some("erp".into()),
            reason: RevocationReason::UserLogout,
        };
        let steps = cascade(&r, &["erp".into(), "chest".into()], Utc::now());
        for step in &steps[2..] {
            let CascadeStep::NotifyRp { audience, sub, .. } = step else {
                panic!()
            };
            assert_eq!(sub, "user-1", "the token's sub is the user, not {audience}");
            assert_ne!(audience, sub);
        }
    }

    /// R3: the logout token's `iat` is the clock it was minted at, and its
    /// `exp` is that plus the TTL. (An `iat` off by an hour went unnoticed.)
    #[test]
    fn a_logout_token_is_stamped_with_the_clock_it_was_minted_at() {
        let b = BackchannelLogout::new("https://auth.example");
        let now = Utc::now();
        let c = b.claims_for("erp", "user-1", "j-1", now);
        assert_eq!(
            c.iat,
            now.timestamp(),
            "MUT:iat-skewed — the RP cannot judge freshness"
        );
        assert_eq!(
            c.exp - c.iat,
            LOGOUT_TOKEN_TTL_SECS,
            "MUT:ttl-drift — the spec caps this at two minutes"
        );
        assert_eq!(
            LOGOUT_TOKEN_TTL_SECS, 120,
            "spec §2.6: the token MUST NOT be valid for more than two minutes"
        );
    }

    /// R3: the grace window is a day, no more. (A week went unnoticed; each
    /// extra day is another day a leaked hint is a remote logout button.)
    #[test]
    fn the_grace_window_is_one_day() {
        assert_eq!(
            HINT_GRACE_SECS,
            24 * 3600,
            "MUT:grace-widened — a leaked hint stays a remote logout for longer"
        );
    }

    /// R3: the RP side's own `exp` boundary — accepted one second before,
    /// refused at the second.
    #[test]
    fn a_logout_token_expires_at_its_bound() {
        let b = BackchannelLogout::new("https://auth.example");
        let now = Utc::now();
        let c = b.claims_for("erp", "user-1", "j-1", now);
        let before = now + Duration::seconds(LOGOUT_TOKEN_TTL_SECS - 1);
        BackchannelLogout::verify(&c, "https://auth.example", "erp", before)
            .expect("one second before exp is still valid");
        let at = now + Duration::seconds(LOGOUT_TOKEN_TTL_SECS);
        // MUT:exp-boundary — `>` instead of `>=` accepts it here.
        assert_eq!(
            BackchannelLogout::verify(&c, "https://auth.example", "erp", at).unwrap_err(),
            LogoutError::InvalidLogoutToken
        );
    }

    // ── the cascade ─────────────────────────────────────────────────────

    #[test]
    fn the_cascade_revokes_grants_before_anything_else() {
        let r = Revocation {
            sub: "user-1".into(),
            at: Utc::now(),
            initiated_by: Some("erp".into()),
            reason: RevocationReason::UserLogout,
        };
        let steps = cascade(&r, &["erp".into(), "chest".into()], Utc::now());
        // MUT:grants-not-first — a cascade that ends the session but leaves
        // refresh tokens alive mints a new session after "logout".
        assert!(matches!(steps[0], CascadeStep::RevokeGrants { ref sub } if sub == "user-1"));
        assert!(matches!(steps[1], CascadeStep::EndOpSession { ref sub } if sub == "user-1"));
        let notified: Vec<_> = steps[2..]
            .iter()
            .map(|s| match s {
                CascadeStep::NotifyRp { audience, .. } => audience.clone(),
                _ => unreachable!(),
            })
            .collect();
        assert_eq!(notified, vec!["erp", "chest"]);
        // Every notified RP gets its own jti.
        let jtis: Vec<_> = steps[2..]
            .iter()
            .filter_map(|s| match s {
                CascadeStep::NotifyRp { jti, .. } => Some(jti.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(jtis.len(), 2);
        assert_ne!(jtis[0], jtis[1]);
    }

    #[test]
    fn an_admin_revocation_names_no_initiator() {
        let r = Revocation {
            sub: "user-1".into(),
            at: Utc::now(),
            initiated_by: None,
            reason: RevocationReason::Administrative,
        };
        let steps = cascade(&r, &[], Utc::now());
        assert_eq!(
            steps.len(),
            2,
            "no RPs to notify, still revokes grants and the session"
        );
    }
}
