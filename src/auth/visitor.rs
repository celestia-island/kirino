//! Visitor tickets — the kirino-side primitives of the cyber-tour visitor
//! track (design: `_reports/cyber-tour-20261028` §7.1/§7.7).
//!
//! A visitor ticket is an [`Identity::Temporary`] principal presented as a
//! short-lived HS256 JWT minted through the shared [`LocalJwt`] primitive —
//! no second JWT stack lives here. The lifecycle maps onto the
//! [`TemporaryIdentityProvider`] SPI: [`VisitorTickets::issue`] creates the
//! identity, [`VisitorTickets::verify`] / [`VisitorTickets::renew`] re-check
//! it, [`VisitorTickets::revoke`] retires it. The previously reserved
//! [`AnonymousIdentityProvider`] becomes the formal anonymous consumption
//! entry: on a [`VisitorTickets`] manager, `create_anonymous` IS issuing a
//! visitor ticket (identity view — use `issue` when the token itself is
//! needed).
//!
//! # The unified consumption gate (redline)
//!
//! [`VisitorTickets::verify`] is the only supported way to turn a presented
//! ticket into a usable principal, and it is one fail-closed check:
//! signature + JWT `exp` (strict) + token type + subject parse + store
//! existence + revocation + principal expiry. Gateway middleware calls
//! exactly this once per request; handlers must never verify tickets
//! themselves. [`IdentitySubject`](crate::rbac::identity_subject::IdentitySubject)
//! documents `is_expired` as "a check, not a gate" — it reports expiry while
//! nothing enforces it, and this module is the enforcement home. The
//! negative tests here pin why the gate must be a single choke point: a
//! bare JWT check happily accepts a ticket whose principal is revoked or
//! inactive-expired, so every per-handler JWT-only check is a
//! privilege-escalation surface. Expired / revoked / unknown tickets are
//! rejected — never downgraded to an anonymous pass-through.
//!
//! # Two expiry axes
//!
//! - JWT `exp` (default 24 h): the presentation credential, enforced only
//!   by [`VisitorTickets::verify`].
//! - Principal `expires_at` (default 90 days): the inactivity window of the
//!   [`Identity::Temporary`] row. [`VisitorTickets::renew`] re-mints a fresh
//!   presentation token while the principal is alive; it is the only lenient
//!   path ([`LocalJwt::verify_lenient`] — signature only, expiry forgiven)
//!   and still runs the full gate. Rolling the window forward on renewal is
//!   a follow-up (the SPI has no extend method yet): this crate's reference
//!   store runs the window from issuance, while persistence layers that
//!   track activity (chest's `visitor_tickets` table with `last_seen`) can
//!   derive the expiry from activity instead — the SPI contract absorbs
//!   both.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::errors::ErrorKind;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::auth::identity::anonymous::AnonymousIdentityProvider;
use crate::auth::identity::temporary::TemporaryIdentityProvider;
use crate::local::{ExpClaims, LocalJwt, LocalJwtError};
use crate::models::identity::Identity;

/// `sub` prefix binding a JWT subject to a visitor ticket id (§7.7 wire
/// format: `sub = visitor:<uuid>`).
pub const VISITOR_SUBJECT_PREFIX: &str = "visitor:";

/// The `typ` claim value of a visitor ticket: tickets are the presentation
/// form of an [`Identity::Temporary`], and the gate rejects anything else.
pub const TICKET_TOKEN_TYPE: &str = "temporary";

/// Claims carried by a visitor ticket (§7.7 wire format).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VisitorTicketClaims {
    /// JWT `sub` — [`VISITOR_SUBJECT_PREFIX`] + ticket UUID.
    pub sub: String,
    /// Always [`TICKET_TOKEN_TYPE`]; anything else is rejected at the gate.
    pub typ: String,
    /// Rate-limit tier binding (§7.7: `anon` / `registered` / `expert`).
    pub tier: String,
    /// Issued at (unix seconds).
    pub iat: i64,
    /// Expiration (unix seconds).
    pub exp: i64,
}

impl ExpClaims for VisitorTicketClaims {
    fn exp(&self) -> i64 {
        self.exp
    }
}

impl VisitorTicketClaims {
    /// The ticket UUID — the `visitor:` prefix stripped and parsed.
    ///
    /// Error contract as implemented: a malformed subject is an error, never
    /// a silently substituted principal (the anonymous-downgrade trap the
    /// RBAC `from_subject_id` path warns about).
    pub fn ticket_id(&self) -> Result<Uuid, VisitorTicketError> {
        let raw = self
            .sub
            .strip_prefix(VISITOR_SUBJECT_PREFIX)
            .ok_or_else(|| {
                VisitorTicketError::Invalid(format!(
                    "subject {:?} lacks the {VISITOR_SUBJECT_PREFIX:?} prefix",
                    self.sub
                ))
            })?;
        Uuid::parse_str(raw)
            .map_err(|e| VisitorTicketError::Invalid(format!("subject {raw:?} is not a UUID: {e}")))
    }
}

/// Everything wrong with a presented or minted ticket. The variants that
/// map to a client-visible "why was I rejected" are deliberately distinct:
/// the gateway maps any of them to a rejection, and the reason survives for
/// audit and rate-limiting policy.
#[derive(Debug, thiserror::Error)]
pub enum VisitorTicketError {
    /// The JWT `exp` has passed — the presentation credential is stale.
    /// Renewal (within the principal window) mints a fresh one.
    #[error("visitor ticket token expired")]
    Expired,
    /// The principal lapsed its inactivity window: the ticket chain is
    /// dead. Issue a NEW ticket (new principal — subjects never merge).
    #[error("visitor ticket principal expired (inactivity window elapsed)")]
    PrincipalExpired,
    /// The ticket was revoked; revocation is permanent.
    #[error("visitor ticket revoked")]
    Revoked,
    /// Well-signed ticket for an id the store has never issued. Rejected —
    /// an unknown ticket must never be downgraded to an anonymous
    /// pass-through.
    #[error("unknown visitor ticket")]
    UnknownTicket,
    /// Malformed subject/type or failed signature verification.
    #[error("invalid visitor ticket: {0}")]
    Invalid(String),
    /// Token minting failed (encode-side; internal).
    #[error("visitor ticket mint failed: {0}")]
    Mint(String),
    /// The identity store errored.
    #[error("visitor ticket store failed: {0}")]
    Store(#[from] anyhow::Error),
}

impl From<LocalJwtError> for VisitorTicketError {
    fn from(err: LocalJwtError) -> Self {
        match err {
            LocalJwtError::MissingExp => {
                VisitorTicketError::Invalid("claims without a positive exp".into())
            }
            LocalJwtError::Sign(e) => VisitorTicketError::Mint(format!("sign failed: {e}")),
            LocalJwtError::Verify(e) => {
                if matches!(e.kind(), ErrorKind::ExpiredSignature) {
                    VisitorTicketError::Expired
                } else {
                    VisitorTicketError::Invalid(format!("signature verification failed: {e}"))
                }
            }
        }
    }
}

/// The ticket UUID of a temporary identity, `None` for any other variant —
/// `issue` uses this to refuse stores that hand back a non-temporary
/// identity instead of silently keying the ticket on the wrong variant.
fn temporary_id(identity: &Identity) -> Option<Uuid> {
    match identity {
        Identity::Temporary { id, .. } => Some(*id),
        _ => None,
    }
}

/// Policy and key material for a [`VisitorTickets`] manager.
#[derive(Clone)]
pub struct VisitorTicketConfig {
    /// HS256 secret material, caller-derived and caller-kept (the `LocalJwt`
    /// contract). Never hard-code this in production callers.
    pub secret: Vec<u8>,
    /// Presentation-token lifetime (default 24 h, §7.7).
    pub access_ttl: Duration,
    /// Principal inactivity window (default 90 days, §7.1). Runs from
    /// issuance in the reference store; activity-tracking stores derive it
    /// from their own last-activity timestamp.
    pub inactivity_window: Duration,
    /// Tier stamped into minted tickets (default `anon`). Renewal re-stamps
    /// the CURRENT config tier: tier policy lives in configuration and is
    /// re-applied where a fresh token is minted.
    pub tier: String,
}

impl fmt::Debug for VisitorTicketConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The secret must never surface in logs or panic messages.
        f.debug_struct("VisitorTicketConfig")
            .field("secret", &"[redacted]")
            .field("access_ttl", &self.access_ttl)
            .field("inactivity_window", &self.inactivity_window)
            .field("tier", &self.tier)
            .finish()
    }
}

impl VisitorTicketConfig {
    /// Config with the §7.1/§7.7 defaults: 24 h presentation tokens, a
    /// 90-day inactivity window, the `anon` tier.
    pub fn new(secret: impl Into<Vec<u8>>) -> Self {
        Self {
            secret: secret.into(),
            access_ttl: Duration::hours(24),
            inactivity_window: Duration::days(90),
            tier: "anon".to_string(),
        }
    }

    /// Overrides the presentation-token lifetime.
    pub fn with_access_ttl(mut self, access_ttl: Duration) -> Self {
        self.access_ttl = access_ttl;
        self
    }

    /// Overrides the principal inactivity window.
    pub fn with_inactivity_window(mut self, inactivity_window: Duration) -> Self {
        self.inactivity_window = inactivity_window;
        self
    }

    /// Overrides the tier stamped into minted tokens.
    pub fn with_tier(mut self, tier: impl Into<String>) -> Self {
        self.tier = tier.into();
        self
    }
}

/// A freshly minted ticket: what an issue/renew call hands back to the
/// caller (the token goes to the visitor, the rest is for audit/response).
#[derive(Debug, Clone)]
pub struct IssuedTicket {
    /// The signed JWT to hand to the visitor.
    pub token: String,
    /// The ticket (principal) UUID.
    pub ticket_id: Uuid,
    /// The [`Identity::Temporary`] backing the ticket.
    pub identity: Identity,
    /// When the token — not the principal — stops verifying.
    pub access_expires_at: DateTime<Utc>,
}

/// A ticket that passed the unified gate.
#[derive(Debug, Clone)]
pub struct VerifiedTicket {
    /// The verified claims (`tier` drives downstream rate-limit tiers).
    pub claims: VisitorTicketClaims,
    /// The ticket (principal) UUID.
    pub ticket_id: Uuid,
    /// The [`Identity::Temporary`] backing the ticket.
    pub identity: Identity,
    /// Principal expiry (inactivity window boundary) — surfaced for
    /// "renew soon" hints; enforcement happened inside the gate.
    pub principal_expires_at: DateTime<Utc>,
}

/// The visitor-ticket manager: issue / renew / revoke / verify over any
/// [`TemporaryIdentityProvider`] store. Share it across tasks via `Arc` —
/// gateway middleware holds one manager and routes every request through
/// [`VisitorTickets::verify`].
///
/// The manager also implements [`AnonymousIdentityProvider`], making the
/// previously reserved anonymous SPI the formal consumption entry of the
/// visitor track: `create_anonymous` issues a fresh ticket principal
/// (identity view), `get_anonymous` resolves one by id.
pub struct VisitorTickets<S: TemporaryIdentityProvider> {
    jwt: LocalJwt,
    store: Arc<S>,
    config: VisitorTicketConfig,
}

impl<S: TemporaryIdentityProvider> Clone for VisitorTickets<S> {
    fn clone(&self) -> Self {
        Self {
            jwt: self.jwt.clone(),
            store: Arc::clone(&self.store),
            config: self.config.clone(),
        }
    }
}

impl<S: TemporaryIdentityProvider> VisitorTickets<S> {
    /// Builds a manager over `store` with `config`.
    ///
    /// Panics in debug builds on non-positive durations — a zero window
    /// would mint instantly-dead tickets; release builds fail closed at the
    /// gate instead (every ticket is born expired and every verify
    /// rejects).
    pub fn new(store: Arc<S>, config: VisitorTicketConfig) -> Self {
        debug_assert!(
            config.access_ttl > Duration::zero(),
            "access_ttl must be positive"
        );
        debug_assert!(
            config.inactivity_window > Duration::zero(),
            "inactivity_window must be positive"
        );
        Self {
            jwt: LocalJwt::from_secret(config.secret.clone()),
            store,
            config,
        }
    }

    /// Issues a fresh ticket — the anonymous first-visit entry (§7.7
    /// `visitor.ticket.issue` is free of login for exactly this reason).
    ///
    /// Creates the [`Identity::Temporary`] with `now + inactivity_window`
    /// and mints a presentation token for it.
    pub async fn issue(&self) -> Result<IssuedTicket, VisitorTicketError> {
        let identity = self
            .store
            .create_temporary(Utc::now() + self.config.inactivity_window)
            .await?;
        let Some(ticket_id) = temporary_id(&identity) else {
            return Err(VisitorTicketError::Store(anyhow!(
                "store returned a non-temporary identity from create_temporary: {identity:?}"
            )));
        };
        self.mint(ticket_id, identity)
    }

    /// THE unified consumption path (redline — see the module docs).
    ///
    /// Strict [`LocalJwt::verify`] (signature + `exp`, 60 s leeway) followed
    /// by the full lifecycle gate. Every failure is a hard rejection with a
    /// distinct reason; there is no lenient sibling, because a presentation
    /// path that forgives expiry is an authorization bypass.
    pub async fn verify(&self, token: &str) -> Result<VerifiedTicket, VisitorTicketError> {
        let claims: VisitorTicketClaims = self.jwt.verify(token)?;
        self.admit(claims).await
    }

    /// Rolling renewal (§7.7: 出示有效票换新票).
    ///
    /// Decodes the presented token leniently (signature only — expiry is
    /// forgiven so a chain survives its 24 h presentation windows), then
    /// runs the SAME full lifecycle gate before re-minting: token type,
    /// subject parse, store existence, revocation, principal expiry. A
    /// principal that lapsed its window is dead here — issue a new ticket
    /// (new principal) instead. The fresh token carries the CURRENT config
    /// tier, so tier policy changes apply at renewal without touching the
    /// principal.
    ///
    /// Security note: leniency is confined to this one path. The renewal
    /// still proves possession of a token signed by the issuer for this
    /// exact ticket id, and the gate re-checks everything the short JWT
    /// `exp` would otherwise have covered.
    pub async fn renew(&self, token: &str) -> Result<IssuedTicket, VisitorTicketError> {
        let claims: VisitorTicketClaims = self.jwt.verify_lenient(token)?;
        let verified = self.admit(claims).await?;
        self.mint(verified.ticket_id, verified.identity)
    }

    /// Revokes a ticket by id — idempotent and permanent (SPI contract).
    /// Revoking a never-issued id succeeds and records the flag (the store
    /// layer owns that semantic); existence-sensitive callers check
    /// `get_temporary` first.
    pub async fn revoke(&self, ticket_id: Uuid) -> Result<(), VisitorTicketError> {
        self.store.revoke_temporary(ticket_id).await?;
        Ok(())
    }

    /// The shared lifecycle gate behind `verify` and `renew`: token type,
    /// subject parse, store existence, revocation, principal expiry —
    /// fail-closed, in that order. Both consumption paths MUST go through
    /// here; that is what makes the checks "unified" rather than scattered.
    async fn admit(
        &self,
        claims: VisitorTicketClaims,
    ) -> Result<VerifiedTicket, VisitorTicketError> {
        if claims.typ != TICKET_TOKEN_TYPE {
            return Err(VisitorTicketError::Invalid(format!(
                "unexpected token type {:?}; tickets carry {TICKET_TOKEN_TYPE:?}",
                claims.typ
            )));
        }
        let ticket_id = claims.ticket_id()?;
        let identity = self
            .store
            .get_temporary(ticket_id)
            .await?
            .ok_or(VisitorTicketError::UnknownTicket)?;
        if self.store.is_revoked(ticket_id).await? {
            return Err(VisitorTicketError::Revoked);
        }
        let Identity::Temporary { expires_at, .. } = &identity else {
            return Err(VisitorTicketError::Store(anyhow!(
                "store returned a non-temporary identity for ticket {ticket_id}"
            )));
        };
        // Copy before the move below: `expires_at` borrows `identity`.
        let principal_expires_at = *expires_at;
        // Same exclusive boundary as `IdentitySubject::is_expired`: expired
        // only once `now` has passed `expires_at`.
        if principal_expires_at < Utc::now() {
            return Err(VisitorTicketError::PrincipalExpired);
        }
        Ok(VerifiedTicket {
            claims,
            ticket_id,
            identity,
            principal_expires_at,
        })
    }

    /// Mints a presentation token for an existing principal.
    fn mint(
        &self,
        ticket_id: Uuid,
        identity: Identity,
    ) -> Result<IssuedTicket, VisitorTicketError> {
        let now = Utc::now();
        let access_expires_at = now + self.config.access_ttl;
        let claims = VisitorTicketClaims {
            sub: format!("{VISITOR_SUBJECT_PREFIX}{ticket_id}"),
            typ: TICKET_TOKEN_TYPE.to_string(),
            tier: self.config.tier.clone(),
            iat: now.timestamp(),
            exp: access_expires_at.timestamp(),
        };
        let token = self.jwt.sign(&claims)?;
        Ok(IssuedTicket {
            token,
            ticket_id,
            identity,
            access_expires_at,
        })
    }
}

#[async_trait]
impl<S: TemporaryIdentityProvider> AnonymousIdentityProvider for VisitorTickets<S> {
    /// The reserved anonymous track's formal consumption entry: creating an
    /// anonymous visitor principal IS issuing a ticket. Identity view only —
    /// call [`VisitorTickets::issue`] for the token as well.
    async fn create_anonymous(&self) -> Result<Identity> {
        Ok(self.issue().await?.identity)
    }

    async fn get_anonymous(&self, id: Uuid) -> Result<Option<Identity>> {
        self.store.get_temporary(id).await
    }
}

/// In-memory reference implementation of [`TemporaryIdentityProvider`] for
/// visitor tickets — the shape downstream persistence mirrors: one row per
/// ticket with its absolute expiry plus a permanent revocation flag.
/// Clones share state (each collection sits in its own `Arc`).
#[derive(Clone, Default)]
pub struct InMemoryVisitorTicketStore {
    identities: Arc<RwLock<HashMap<Uuid, Identity>>>,
    revoked: Arc<RwLock<HashSet<Uuid>>>,
}

impl InMemoryVisitorTicketStore {
    /// Creates an empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl TemporaryIdentityProvider for InMemoryVisitorTicketStore {
    async fn create_temporary(&self, expires_at: DateTime<Utc>) -> Result<Identity> {
        let id = Uuid::now_v7();
        let identity = Identity::Temporary { id, expires_at };
        self.identities.write().await.insert(id, identity.clone());
        Ok(identity)
    }

    async fn get_temporary(&self, id: Uuid) -> Result<Option<Identity>> {
        Ok(self.identities.read().await.get(&id).cloned())
    }

    async fn is_expired(&self, id: Uuid) -> Result<bool> {
        Ok(self
            .identities
            .read()
            .await
            .get(&id)
            .is_some_and(|identity| match identity {
                Identity::Temporary { expires_at, .. } => *expires_at < Utc::now(),
                _ => false,
            }))
    }

    async fn revoke_temporary(&self, id: Uuid) -> Result<()> {
        self.revoked.write().await.insert(id);
        Ok(())
    }

    async fn is_revoked(&self, id: Uuid) -> Result<bool> {
        Ok(self.revoked.read().await.contains(&id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> VisitorTicketConfig {
        VisitorTicketConfig::new("visitor-ticket-test-secret")
    }

    /// Manager + its store, so tests can model time passage by editing the
    /// principal rows directly (the SPI has no extend method — see the
    /// module docs).
    fn fixture() -> (
        VisitorTickets<InMemoryVisitorTicketStore>,
        InMemoryVisitorTicketStore,
    ) {
        let store = InMemoryVisitorTicketStore::new();
        let tickets = VisitorTickets::new(Arc::new(store.clone()), test_config());
        (tickets, store)
    }

    fn claims_for(ticket_id: Uuid, exp: DateTime<Utc>) -> VisitorTicketClaims {
        VisitorTicketClaims {
            sub: format!("{VISITOR_SUBJECT_PREFIX}{ticket_id}"),
            typ: TICKET_TOKEN_TYPE.to_string(),
            tier: "anon".to_string(),
            iat: Utc::now().timestamp(),
            exp: exp.timestamp(),
        }
    }

    fn hand_mint(config: &VisitorTicketConfig, claims: &VisitorTicketClaims) -> String {
        LocalJwt::from_secret(config.secret.clone())
            .sign(claims)
            .unwrap()
    }

    /// Models inactivity: overwrites the principal row with a lapsed expiry
    /// (the exclusive-boundary past, per `IdentitySubject::is_expired`).
    async fn lapse_principal(store: &InMemoryVisitorTicketStore, ticket_id: Uuid) {
        let mut identities = store.identities.write().await;
        identities.insert(
            ticket_id,
            Identity::Temporary {
                id: ticket_id,
                expires_at: Utc::now() - Duration::hours(1),
            },
        );
    }

    #[tokio::test]
    async fn issued_ticket_carries_the_spec_wire_format() {
        let (tickets, _) = fixture();
        let issued = tickets.issue().await.unwrap();

        let claims = LocalJwt::from_secret(test_config().secret)
            .verify::<VisitorTicketClaims>(&issued.token)
            .unwrap();
        assert_eq!(claims.sub, format!("visitor:{}", issued.ticket_id));
        assert_eq!(claims.typ, TICKET_TOKEN_TYPE);
        assert_eq!(claims.tier, "anon");
        assert_eq!(claims.exp - claims.iat, Duration::hours(24).num_seconds());
        assert_eq!(issued.access_expires_at.timestamp(), claims.exp);
    }

    #[tokio::test]
    async fn verify_resolves_a_fresh_ticket() {
        let (tickets, _) = fixture();
        let issued = tickets.issue().await.unwrap();

        let verified = tickets.verify(&issued.token).await.unwrap();
        assert_eq!(verified.ticket_id, issued.ticket_id);
        assert_eq!(verified.claims.sub, format!("visitor:{}", issued.ticket_id));
        assert!(matches!(verified.identity, Identity::Temporary { .. }));
        // The principal was born with the full 90-day window.
        assert!(verified.principal_expires_at > Utc::now() + Duration::days(89));
    }

    #[tokio::test]
    async fn expired_jwt_is_rejected_at_the_gate() {
        let (tickets, _) = fixture();
        // Correctly signed, but its 24 h presentation window lapsed five
        // minutes ago (past the 60 s verify leeway): the gate must reject.
        let claims = claims_for(Uuid::now_v7(), Utc::now() - Duration::minutes(5));
        let token = hand_mint(&test_config(), &claims);
        assert!(matches!(
            tickets.verify(&token).await,
            Err(VisitorTicketError::Expired)
        ));
    }

    #[tokio::test]
    async fn principal_expiry_is_enforced_even_while_jwt_is_fresh() {
        // The load-bearing negative: the principal lapsed its inactivity
        // window while the presented token itself is still unexpired. A
        // bare JWT check — the per-handler anti-pattern — would ACCEPT
        // this; the unified gate rejects it.
        let (tickets, store) = fixture();
        let issued = tickets.issue().await.unwrap();
        lapse_principal(&store, issued.ticket_id).await;

        let claims = claims_for(issued.ticket_id, Utc::now() + Duration::hours(1));
        let token = hand_mint(&test_config(), &claims);
        assert!(matches!(
            tickets.verify(&token).await,
            Err(VisitorTicketError::PrincipalExpired)
        ));
    }

    #[tokio::test]
    async fn revoked_ticket_is_rejected_and_renewal_is_refused() {
        let (tickets, _) = fixture();
        let issued = tickets.issue().await.unwrap();

        tickets.revoke(issued.ticket_id).await.unwrap();
        // Revocation is idempotent (SPI contract).
        tickets.revoke(issued.ticket_id).await.unwrap();

        // A freshly signed token for the revoked principal is rejected —
        // proof the gate consults the store, not just the JWT.
        let claims = claims_for(issued.ticket_id, Utc::now() + Duration::hours(1));
        let fresh = hand_mint(&test_config(), &claims);
        assert!(matches!(
            tickets.verify(&fresh).await,
            Err(VisitorTicketError::Revoked)
        ));
        // Renewal runs the same gate.
        assert!(matches!(
            tickets.renew(&issued.token).await,
            Err(VisitorTicketError::Revoked)
        ));
    }

    #[tokio::test]
    async fn unknown_ticket_never_downgrades_to_anonymous() {
        let (tickets, _) = fixture();
        // Correctly signed ticket for an id the store never issued: the
        // gate fails closed instead of fabricating an anonymous principal.
        let claims = claims_for(Uuid::now_v7(), Utc::now() + Duration::hours(1));
        let token = hand_mint(&test_config(), &claims);
        assert!(matches!(
            tickets.verify(&token).await,
            Err(VisitorTicketError::UnknownTicket)
        ));
    }

    #[tokio::test]
    async fn malformed_subjects_and_wrong_types_are_rejected() {
        let (tickets, _) = fixture();
        let now = Utc::now();
        let fresh_exp = now + Duration::hours(1);

        // Subject without the `visitor:` prefix.
        let no_prefix = VisitorTicketClaims {
            sub: Uuid::now_v7().to_string(),
            typ: TICKET_TOKEN_TYPE.to_string(),
            tier: "anon".to_string(),
            iat: now.timestamp(),
            exp: fresh_exp.timestamp(),
        };
        // Subject with a malformed UUID.
        let bad_uuid = VisitorTicketClaims {
            sub: "visitor:not-a-uuid".to_string(),
            typ: TICKET_TOKEN_TYPE.to_string(),
            tier: "anon".to_string(),
            iat: now.timestamp(),
            exp: fresh_exp.timestamp(),
        };
        // Wrong token type.
        let wrong_type = VisitorTicketClaims {
            sub: format!("{VISITOR_SUBJECT_PREFIX}{}", Uuid::now_v7()),
            typ: "access".to_string(),
            tier: "anon".to_string(),
            iat: now.timestamp(),
            exp: fresh_exp.timestamp(),
        };

        for claims in [no_prefix, bad_uuid, wrong_type] {
            let token = hand_mint(&test_config(), &claims);
            assert!(
                matches!(
                    tickets.verify(&token).await,
                    Err(VisitorTicketError::Invalid(_))
                ),
                "expected Invalid for {claims:?}"
            );
        }
    }

    #[tokio::test]
    async fn tampered_and_foreign_key_tokens_are_rejected() {
        let (tickets, _) = fixture();
        let issued = tickets.issue().await.unwrap();

        let mut forged = issued.token.clone();
        forged.replace_range(0..1, "X");
        assert!(matches!(
            tickets.verify(&forged).await,
            Err(VisitorTicketError::Invalid(_))
        ));

        // Same ticket id, but minted under a different secret.
        let foreign_secret = VisitorTicketConfig::new("not-the-issuer-secret");
        let claims = claims_for(issued.ticket_id, Utc::now() + Duration::hours(1));
        let foreign = hand_mint(&foreign_secret, &claims);
        assert!(matches!(
            tickets.verify(&foreign).await,
            Err(VisitorTicketError::Invalid(_))
        ));
    }

    #[tokio::test]
    async fn renewal_rolls_the_chain_within_the_window() {
        let (tickets, _) = fixture();
        let issued = tickets.issue().await.unwrap();

        let renewed = tickets.renew(&issued.token).await.unwrap();
        assert_eq!(renewed.ticket_id, issued.ticket_id);
        // The fresh token passes the strict gate on its own. (A renewal in
        // the same second as the issue can produce a byte-identical token —
        // the §7.7 claim set carries no jti, so identical claims + a
        // deterministic signature are an equivalent credential, not a
        // freshness bug. What matters: the renewed token verifies for the
        // same principal.)
        let verified = tickets.verify(&renewed.token).await.unwrap();
        assert_eq!(verified.ticket_id, issued.ticket_id);
        assert_eq!(
            verified.claims.sub,
            format!("{VISITOR_SUBJECT_PREFIX}{}", renewed.ticket_id)
        );
    }

    #[tokio::test]
    async fn renewal_survives_jwt_expiry_within_the_window() {
        let (tickets, _) = fixture();
        let issued = tickets.issue().await.unwrap();

        // The presented token's JWT window lapsed, but the principal is
        // alive: the strict gate rejects the stale credential…
        let stale = claims_for(issued.ticket_id, Utc::now() - Duration::minutes(5));
        let token = hand_mint(&test_config(), &stale);
        assert!(matches!(
            tickets.verify(&token).await,
            Err(VisitorTicketError::Expired)
        ));
        // …while renewal honours the chain and mints a fresh 24 h ticket.
        let renewed = tickets.renew(&token).await.unwrap();
        assert_eq!(renewed.ticket_id, issued.ticket_id);
        assert!(tickets.verify(&renewed.token).await.is_ok());
    }

    #[tokio::test]
    async fn renewal_refused_after_principal_expiry() {
        let (tickets, store) = fixture();
        let issued = tickets.issue().await.unwrap();
        lapse_principal(&store, issued.ticket_id).await;

        assert!(matches!(
            tickets.renew(&issued.token).await,
            Err(VisitorTicketError::PrincipalExpired)
        ));
    }

    #[tokio::test]
    async fn renewal_restamps_the_current_policy_tier() {
        let store = InMemoryVisitorTicketStore::new();
        let anon = VisitorTickets::new(
            Arc::new(store.clone()),
            VisitorTicketConfig::new("visitor-ticket-test-secret").with_tier("anon"),
        );
        let expert = VisitorTickets::new(
            Arc::new(store.clone()),
            VisitorTicketConfig::new("visitor-ticket-test-secret").with_tier("expert"),
        );

        let issued = anon.issue().await.unwrap();
        let renewed = expert.renew(&issued.token).await.unwrap();
        let claims = LocalJwt::from_secret(test_config().secret)
            .verify::<VisitorTicketClaims>(&renewed.token)
            .unwrap();
        assert_eq!(claims.tier, "expert");
    }

    #[tokio::test]
    async fn anonymous_spi_entry_issues_a_visitor_principal() {
        let (tickets, _) = fixture();
        let anonymous: &dyn AnonymousIdentityProvider = &tickets;

        let identity = anonymous.create_anonymous().await.unwrap();
        let Identity::Temporary { id, .. } = &identity else {
            panic!("the anonymous entry must yield a temporary visitor principal");
        };
        assert_eq!(anonymous.get_anonymous(*id).await.unwrap(), Some(identity));
    }

    #[tokio::test]
    async fn store_expiry_boundary_is_exclusive() {
        // Same boundary as `IdentitySubject::is_expired`: expired only once
        // `now` has passed `expires_at`.
        let store = InMemoryVisitorTicketStore::new();
        let alive = store
            .create_temporary(Utc::now() + Duration::hours(1))
            .await
            .unwrap();
        let Identity::Temporary { id: alive_id, .. } = &alive else {
            panic!("expected a temporary identity");
        };
        assert!(!store.is_expired(*alive_id).await.unwrap());

        let dead = store
            .create_temporary(Utc::now() - Duration::seconds(1))
            .await
            .unwrap();
        let Identity::Temporary { id: dead_id, .. } = &dead else {
            panic!("expected a temporary identity");
        };
        assert!(store.is_expired(*dead_id).await.unwrap());
    }

    #[tokio::test]
    async fn config_debug_never_leaks_the_secret() {
        let rendered = format!("{:?}", test_config());
        assert!(rendered.contains("[redacted]"), "{rendered}");
        assert!(
            !rendered.contains("visitor-ticket-test-secret"),
            "{rendered}"
        );
    }
}
