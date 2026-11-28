//! The device authorization grant (RFC 8628).
//!
//! For clients that cannot show a browser — a TV, a CLI, a kiosk. The flow is
//! two-legged and deliberately awkward to guess at:
//!
//! 1. The device asks for a pairing ([`request`]) and gets a `device_code`
//!    (secret, polled with) and a `user_code` (short, shown to a human), plus
//!    a verification URI and a polling interval.
//! 2. The human opens the URI on any device, types the `user_code`, and
//!    approves ([`decide`]).
//! 3. The device polls ([`poll`]). Until the decision it gets
//!    `authorization_pending`; polling faster than its interval gets
//!    `slow_down` and the interval GROWS; a denial gets `access_denied`; past
//!    the expiry it gets `expired_token`; approval gets the token set.
//!
//! # The parts that are security properties
//!
//! - **The `user_code` is not a credential.** It pairs a human with a pending
//!   request; approving still requires an authenticated browser session. It
//!   is short because it is typed, and it is drawn from an alphabet with no
//!   `0`/`O`, no `1`/`I`/`L`, no `U` — a code that gets mistyped is a support
//!   cost and, worse, a chance to land on someone else's request.
//! - **`slow_down` is mandatory and additive.** A device that polls early is
//!   told to slow down and its interval grows by [`SLOW_DOWN_STEP_SECS`]; a
//!   host that answers `authorization_pending` to an early poll has turned
//!   the interval into decoration.
//! - **A denied or expired pairing never becomes a token**, and every poll
//!   after the decision answers the same thing (the device code is consumed
//!   by the approved poll, so later polls are `expired_token`).
//! - **The device code is claimed, not read.** Exactly one poll may consume
//!   it; a concurrent second poll loses and is told `expired_token` — the
//!   same answer a stale code gets, so a prober learns nothing.
//!
//! # Store shape
//!
//! One store, one record type ([`Parked`]): the `device_code` key holds the
//! [`PendingDevice`], and the `user_code` key holds a [`Pointer`] naming it.
//! `decide` follows the pointer; `poll` claims the device key.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use thiserror::Error;

use super::{
    client::{ClientRecord, GrantType},
    code::{CodeGrant, GrantKind},
    token::{self, TokenContext, TokenResponse},
};
use crate::auth::store::ConsumableStore;

/// The RFC 8628 grant type.
pub const DEVICE_CODE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";

/// How long a pairing lives before the device must ask again.
pub const DEFAULT_DEVICE_TTL_SECS: i64 = 600;
/// The first polling interval, in seconds (RFC 8628 §3.2 recommends five).
pub const DEFAULT_INTERVAL_SECS: i64 = 5;
/// How much the interval grows per `slow_down` (§3.5: "increase by 5").
pub const SLOW_DOWN_STEP_SECS: i64 = 5;

/// The `user_code` alphabet: no `0`/`O`, no `1`/`I`/`L`, no `U`, and no
/// vowels beyond those — nothing that reads as another character and
/// nothing that spells a word.
const USER_CODE_ALPHABET: &[u8] = b"BCDFGHJKMNPQRSTVWXZ";
/// Eight symbols from a 19-symbol alphabet is ~34 bits: with a ten-minute
/// TTL, an authenticated approval and the store's own single-use claim, that
/// is not a guessing surface.
const USER_CODE_LEN: usize = 8;
/// Grouped `BCDF-GHJK` for reading aloud.
const USER_CODE_GROUP: usize = 4;

/// What the device is told to do next.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum DevicePoll {
    /// The human has not decided yet.
    Pending,
    /// The device polled faster than its interval; it must wait longer.
    SlowDown {
        /// The new interval, in seconds.
        interval: i64,
    },
    /// The human refused.
    Denied,
    /// The pairing expired, was never valid, or was already consumed.
    Expired,
    /// Approved: the token set.
    Token(Box<TokenResponse>),
}

/// Why a device-flow step failed.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum DeviceError {
    /// The client's registration does not allow the device grant.
    #[error("client {0} may not use the device grant")]
    UnauthorizedClient(String),
    /// The client asked for a scope outside its allowance.
    #[error("scope {0:?} is not allowed for this client")]
    InvalidScope(String),
    /// The `user_code` does not resolve to a pending pairing.
    #[error("the user code is not valid")]
    UnknownUserCode,
    /// The client asked for `openid` on a grant that carries no `nonce`, so
    /// an ID token could never be minted. Refused at request time rather
    /// than after the human approved.
    #[error("the device grant cannot issue an ID token (no nonce); drop `openid`")]
    OpenIdWithoutNonce,
    /// The pairing already carries a decision.
    #[error("this pairing has already been decided")]
    AlreadyDecided,
    /// The `user_code` is grouped wrong before any store is consulted.
    #[error("a user code is eight symbols, optionally grouped as XXXX-XXXX")]
    Malformed,
    /// The store failed. **Not** a verdict on the pairing.
    #[error("the device store failed: {0}")]
    Store(String),
}

/// What the human did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Decision {
    /// Not yet.
    Pending,
    /// Approved by this subject at this time.
    Approved {
        /// When the human authenticated.
        auth_time: DateTime<Utc>,
    },
    /// Refused.
    Denied,
}

/// The pairing, parked under the `device_code`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingDevice {
    /// The client that asked.
    pub client_id: String,
    /// Its normalised scope.
    pub scope: String,
    /// The human-facing code.
    pub user_code: String,
    /// The human's decision.
    pub decision: Decision,
    /// Who approved; empty while pending.
    pub sub: String,
    /// The interval to honour, grown by each `slow_down`.
    pub interval_secs: i64,
    /// When the device last polled (the interval's reference).
    pub last_poll: Option<DateTime<Utc>>,
    /// When the pairing dies.
    pub expires_at: DateTime<Utc>,
}

/// The pairing store: **mutable** state, unlike the single-use
/// [`ConsumableStore`](crate::auth::store::ConsumableStore).
///
/// This is not a second way of doing the same thing. A credential is handed
/// out once and claimed once, so the store that holds it refuses a second
/// live `put` — that refusal is the property K0 exists for. A pairing is
/// different: it is created, polled (which moves `last_poll` and grows the
/// interval), and decided (which writes the human's answer). Overwriting is
/// the point, so it gets its own trait rather than bending the credential
/// store's contract.
///
/// [`MemoryDeviceStore`](crate::auth::provider::device::MemoryDeviceStore)
/// is the reference; a host with a table implements this over it.
#[async_trait::async_trait]
pub trait DeviceStore: Send + Sync {
    /// Insert or replace. A pairing is mutable by design.
    async fn put(
        &self,
        device_code: &str,
        pairing: PendingDevice,
        expires_at: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> anyhow::Result<()>;
    /// Read without consuming.
    async fn get(
        &self,
        device_code: &str,
        now: DateTime<Utc>,
    ) -> anyhow::Result<Option<PendingDevice>>;
    /// **Claim** the pairing: remove it and return what was removed, or
    /// `None` if there was nothing to remove.
    ///
    /// This is the single-use edge of the device grant. A bare `remove`
    /// returning `()` cannot tell two concurrent polls which of them
    /// actually claimed the pairing — R2 measured both minting a token pair.
    /// One atomic "give me the record and delete it" is the only shape that
    /// cannot be raced.
    async fn take(&self, device_code: &str) -> anyhow::Result<Option<PendingDevice>>;
    /// Record a decision, but only if the pairing is still undecided.
    ///
    /// Returns `false` when it was already decided (or is gone): two
    /// concurrent decides must not both succeed, and the second must not
    /// overwrite the first one's subject. A plain `put` here let a denial be
    /// replaced by an approval (R2 measured it).
    async fn decide_if_pending(
        &self,
        device_code: &str,
        decision: Decision,
        sub: &str,
        now: DateTime<Utc>,
    ) -> anyhow::Result<bool>;
    /// The `user_code` → `device_code` map, which is also mutable (a
    /// re-typed code must still resolve).
    async fn put_pointer(
        &self,
        user_code: &str,
        device_code: &str,
        expires_at: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> anyhow::Result<()>;
    /// Resolve a typed user code.
    async fn pointer(&self, user_code: &str, now: DateTime<Utc>) -> anyhow::Result<Option<String>>;
    /// Drop every pairing and pointer past its expiry. Returns how many
    /// pairings were removed.
    ///
    /// Nothing else deletes an abandoned pairing: `poll` answers
    /// `expired_token` and returns, so a device that gives up leaves its row
    /// behind forever (R2 measured `len() == 1` after an expiry).
    ///
    /// # Errors
    ///
    /// Storage failures.
    async fn sweep(&self, now: DateTime<Utc>) -> anyhow::Result<u64> {
        let _ = now;
        Ok(0)
    }
}

/// The in-memory reference: right for one replica.
#[derive(Default)]
pub struct MemoryDeviceStore {
    pairings:
        tokio::sync::RwLock<std::collections::BTreeMap<String, (PendingDevice, DateTime<Utc>)>>,
    pointers: tokio::sync::RwLock<std::collections::BTreeMap<String, (String, DateTime<Utc>)>>,
}

impl MemoryDeviceStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// How many pairings are live (tests / metrics).
    pub async fn len(&self) -> usize {
        self.pairings.read().await.len()
    }

    /// Whether no pairing is stored.
    pub async fn is_empty(&self) -> bool {
        self.pairings.read().await.is_empty()
    }
}

#[async_trait::async_trait]
impl DeviceStore for MemoryDeviceStore {
    async fn put(
        &self,
        device_code: &str,
        pairing: PendingDevice,
        expires_at: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> anyhow::Result<()> {
        let mut m = self.pairings.write().await;
        m.retain(|_, (_, exp)| *exp > now);
        m.insert(device_code.to_owned(), (pairing, expires_at));
        Ok(())
    }
    async fn get(
        &self,
        device_code: &str,
        now: DateTime<Utc>,
    ) -> anyhow::Result<Option<PendingDevice>> {
        let m = self.pairings.read().await;
        // NOT filtered by expiry: whether a stale pairing is still visible
        // is the CALLER's decision (`poll` answers `expired_token`; `lookup`
        // refuses). A store that silently hides rows makes those checks
        // untestable — the expiry mutation survived exactly that way.
        let _ = now;
        Ok(m.get(device_code).map(|(p, _)| p.clone()))
    }
    async fn take(&self, device_code: &str) -> anyhow::Result<Option<PendingDevice>> {
        let mut m = self.pairings.write().await;
        // Under ONE write lock: read-then-delete as two steps is exactly the
        // shape the credential store exists to prevent.
        Ok(m.remove(device_code).map(|(p, _)| p))
    }
    async fn decide_if_pending(
        &self,
        device_code: &str,
        decision: Decision,
        sub: &str,
        now: DateTime<Utc>,
    ) -> anyhow::Result<bool> {
        let mut m = self.pairings.write().await;
        let Some((pending, expires_at)) = m.get_mut(device_code) else {
            return Ok(false);
        };
        if pending.decision != Decision::Pending {
            return Ok(false);
        }
        let _ = now;
        pending.decision = decision;
        pending.sub = sub.to_owned();
        let _ = expires_at;
        Ok(true)
    }
    async fn put_pointer(
        &self,
        user_code: &str,
        device_code: &str,
        expires_at: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> anyhow::Result<()> {
        let mut m = self.pointers.write().await;
        m.retain(|_, (_, exp)| *exp > now);
        m.insert(
            normalise_user_code(user_code),
            (device_code.to_owned(), expires_at),
        );
        Ok(())
    }
    async fn sweep(&self, now: DateTime<Utc>) -> anyhow::Result<u64> {
        let mut pairings = self.pairings.write().await;
        let before = pairings.len();
        pairings.retain(|_, (_, exp)| *exp > now);
        let removed = (before - pairings.len()) as u64;
        self.pointers.write().await.retain(|_, (_, exp)| *exp > now);
        Ok(removed)
    }
    async fn pointer(&self, user_code: &str, now: DateTime<Utc>) -> anyhow::Result<Option<String>> {
        let m = self.pointers.read().await;
        Ok(m.get(&normalise_user_code(user_code))
            .filter(|(_, exp)| *exp > now)
            .map(|(d, _)| d.clone()))
    }
}

/// What a device gets when it starts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceAuthorization {
    /// The secret the device polls with — never shown to a human.
    pub device_code: String,
    /// The code a human types — shown on the device's screen.
    pub user_code: String,
    /// Where the human goes.
    pub verification_uri: String,
    /// With the code appended, for a link or a QR.
    pub verification_uri_complete: String,
    /// The first interval to honour.
    pub interval_secs: i64,
    /// How long the pairing lives.
    pub expires_in_secs: i64,
}

/// Start a pairing for `client` with `scope` at `now`.
///
/// # Errors
///
/// [`DeviceError::UnauthorizedClient`], [`DeviceError::InvalidScope`],
/// [`DeviceError::Store`].
pub async fn request<S>(
    client: &ClientRecord,
    scope: &str,
    store: &S,
    verification_uri: &str,
    now: DateTime<Utc>,
) -> Result<DeviceAuthorization, DeviceError>
where
    S: DeviceStore + ?Sized,
{
    if !client.allows_grant(GrantType::DeviceCode) {
        return Err(DeviceError::UnauthorizedClient(client.client_id.clone()));
    }
    // The device grant carries no `nonce`: the device is not the browser that
    // authenticates, so there is nothing to bind an ID token to, and
    // `IdTokenClaims::from_grant` refuses an `openid` grant without one.
    // A host that wants an ID token here must carry a nonce through the
    // approval (not modelled yet). So an `openid` request is refused at
    // REQUEST time — accepting it produced a pairing whose mint failed only
    // after the human approved and after the pairing was consumed (R2 S1).
    //
    // This checks what the CALLER ASKED FOR, not the normalised default:
    // `validate_scope("")` yields the provider's default `openid profile`,
    // and RFC 8628 §3.1 makes `scope` OPTIONAL — refusing the default would
    // have made every scope-less device request fail (R3 S1).
    if scope.split_whitespace().any(|s| s == "openid") {
        return Err(DeviceError::OpenIdWithoutNonce);
    }
    let scope =
        super::validate_scope(scope).map_err(|e| DeviceError::InvalidScope(e.to_string()))?;
    if !client.allows_scope(&scope) {
        return Err(DeviceError::InvalidScope(scope));
    }
    // The default still contains `openid`; drop it, since this grant can
    // never honour it, and keep the rest.
    let scope = scope
        .split_whitespace()
        .filter(|s| *s != "openid")
        .collect::<Vec<_>>()
        .join(" ");
    let device_code = device_token();
    let user_code = random_user_code();
    let expires_at = now + Duration::seconds(DEFAULT_DEVICE_TTL_SECS);
    let pending = PendingDevice {
        client_id: client.client_id.clone(),
        scope,
        user_code: user_code.clone(),
        decision: Decision::Pending,
        sub: String::new(),
        interval_secs: DEFAULT_INTERVAL_SECS,
        last_poll: None,
        expires_at,
    };
    store
        .put(&device_code, pending, expires_at, now)
        .await
        .map_err(|e| DeviceError::Store(e.to_string()))?;
    store
        .put_pointer(&user_code, &device_code, expires_at, now)
        .await
        .map_err(|e| DeviceError::Store(e.to_string()))?;
    Ok(DeviceAuthorization {
        verification_uri_complete: {
            // The verification URI belongs to the host and may already carry
            // a query (`?tenant=a`): join with `&` in that case, so the code
            // is a parameter rather than a second `?`.
            let sep = if verification_uri.contains('?') {
                '&'
            } else {
                '?'
            };
            format!("{verification_uri}{sep}user_code={user_code}")
        },
        verification_uri: verification_uri.to_owned(),
        device_code,
        user_code,
        interval_secs: DEFAULT_INTERVAL_SECS,
        expires_in_secs: DEFAULT_DEVICE_TTL_SECS,
    })
}

/// Resolve a typed `user_code` to its pairing.
///
/// The pointer stays put (a human who mistypes one screen may retry), and the
/// pairing is read without being consumed — only [`poll`] consumes.
///
/// # Errors
///
/// [`DeviceError::Malformed`] if the shape is wrong (no store call),
/// [`DeviceError::UnknownUserCode`] if it does not resolve,
/// [`DeviceError::Store`] on a store failure.
pub async fn lookup<S>(
    user_code: &str,
    store: &S,
    now: DateTime<Utc>,
) -> Result<(String, PendingDevice), DeviceError>
where
    S: DeviceStore + ?Sized,
{
    let normal = normalise_user_code(user_code);
    if normal.len() != USER_CODE_LEN {
        return Err(DeviceError::Malformed);
    }
    let device_code = store
        .pointer(&normal, now)
        .await
        .map_err(|e| DeviceError::Store(e.to_string()))?
        .ok_or(DeviceError::UnknownUserCode)?;
    let pending = store
        .get(&device_code, now)
        .await
        .map_err(|e| DeviceError::Store(e.to_string()))?
        .ok_or(DeviceError::UnknownUserCode)?;
    Ok((device_code, pending))
}

/// Record the human's decision for the pairing behind `user_code`.
///
/// # Errors
///
/// [`DeviceError::UnknownUserCode`], [`DeviceError::AlreadyDecided`] if the
/// pairing already carries a decision, [`DeviceError::Store`].
pub async fn decide<S>(
    user_code: &str,
    decision: Decision,
    sub: &str,
    store: &S,
    now: DateTime<Utc>,
) -> Result<(), DeviceError>
where
    S: DeviceStore + ?Sized,
{
    let (device_code, pending) = lookup(user_code, store, now).await?;
    if pending.decision != Decision::Pending {
        return Err(DeviceError::AlreadyDecided);
    }
    // An approved pairing must name who approved: an empty `sub` would mint
    // a token nobody owns.
    if matches!(decision, Decision::Approved { .. }) && sub.trim().is_empty() {
        return Err(DeviceError::UnknownUserCode);
    }
    // Compare-and-set in the store, NOT read-check-write here: two
    // concurrent decides must not both pass the `Pending` check above. R2
    // measured a denial being replaced by an approval (with the attacker's
    // subject) through exactly that window.
    let wrote = store
        .decide_if_pending(&device_code, decision, sub, now)
        .await
        .map_err(|e| DeviceError::Store(e.to_string()))?;
    if !wrote {
        return Err(DeviceError::AlreadyDecided);
    }
    Ok(())
}

/// The device's poll.
///
/// Two stores, because they hold different things: `pending_store` keeps the
/// pairing ([`Parked`]) across polls, and `ctx` carries the code store the
/// minted grant is parked in. They may be the same object (a host with one
/// table) or different ones — the types differ, so the compiler makes the
/// distinction explicit rather than letting one payload type stand in for
/// both.
///
/// # Errors
///
/// [`DeviceError::UnauthorizedClient`] if the client may not use the grant,
/// [`DeviceError::Store`] on a store failure.
pub async fn poll<P, C>(
    device_code: &str,
    client: &ClientRecord,
    pending_store: &P,
    ctx: &TokenContext<'_, C>,
    now: DateTime<Utc>,
) -> Result<DevicePoll, DeviceError>
where
    P: DeviceStore + ?Sized,
    C: ConsumableStore<CodeGrant> + ?Sized,
{
    if !client.allows_grant(GrantType::DeviceCode) {
        return Err(DeviceError::UnauthorizedClient(client.client_id.clone()));
    }
    // CLAIM the pairing: one atomic take, so two concurrent polls cannot
    // both proceed. The loser sees no record and answers `expired_token` —
    // the same answer a stale code gets.
    let Some(claimed) = pending_store
        .take(device_code)
        .await
        .map_err(|e| DeviceError::Store(e.to_string()))?
    else {
        return Ok(DevicePoll::Expired);
    };
    if now > claimed.expires_at {
        return Ok(DevicePoll::Expired);
    }
    // The pairing belongs to the client that requested it (RFC 8628 §3.4).
    // Without this, any registered client could redeem another's device
    // code — and the token would carry the OWNER's `client_id` while the
    // refresh grant followed the POLLER's allowance (R2 measured it).
    if claimed.client_id != client.client_id {
        // Put it back: a mismatch is not the owner's fault, and the owner's
        // device must still be able to finish.
        put_pending(pending_store, device_code, &claimed, now).await?;
        return Err(DeviceError::UnauthorizedClient(client.client_id.clone()));
    }
    // The interval, measured against the last on-time poll. A slow_down
    // rewrites `last_poll` to NOW, so the grown interval starts from the
    // early poll rather than from the old anchor.
    if let Some(last) = claimed.last_poll {
        if now < last + Duration::seconds(claimed.interval_secs) {
            let mut slowed = claimed;
            slowed.interval_secs += SLOW_DOWN_STEP_SECS;
            slowed.last_poll = Some(now);
            put_pending(pending_store, device_code, &slowed, now).await?;
            return Ok(DevicePoll::SlowDown {
                interval: slowed.interval_secs,
            });
        }
    }
    match claimed.decision {
        Decision::Pending => {
            // Still waiting: put the pairing back with the poll recorded.
            let mut touched = claimed;
            touched.last_poll = Some(now);
            put_pending(pending_store, device_code, &touched, now).await?;
            Ok(DevicePoll::Pending)
        }
        // A denial ends the pairing, and `take` already removed it: nothing
        // may revive it.
        Decision::Denied => Ok(DevicePoll::Denied),
        Decision::Approved { auth_time } => {
            let grant = CodeGrant {
                kind: GrantKind::Code,
                client_id: claimed.client_id.clone(),
                // The device grant has no redirect; the token endpoint's
                // redirect check is skipped for it (there is nothing to
                // match), which is why the grant kind exists.
                redirect_uri: String::new(),
                scope: claimed.scope.clone(),
                sub: claimed.sub.clone(),
                auth_time,
                amr: vec!["device".to_owned()],
                acr: None,
                nonce: None,
                code_challenge: None,
                authenticated_at: now,
                expires_at: claimed.expires_at,
            };
            // NOT put back on failure: the approved poll consumes the
            // pairing. A mint failure is reported as a store error, and the
            // device must re-request — the alternative (re-issuing on a 5xx)
            // would hand a fresh token pair to whoever polls next.
            // The pairing was consumed by `take` before the mint: a mint
            // failure must not leave an approved pairing pollable, because
            // the next poll would hand the token pair to whoever holds the
            // device code.
            match token::mint_tokens(&grant, client, ctx).await {
                Ok(response) => Ok(DevicePoll::Token(Box::new(response))),
                Err(e) => Err(DeviceError::Store(e.to_string())),
            }
        }
    }
}

async fn put_pending<S>(
    store: &S,
    device_code: &str,
    pending: &PendingDevice,
    now: DateTime<Utc>,
) -> Result<(), DeviceError>
where
    S: DeviceStore + ?Sized,
{
    store
        .put(device_code, pending.clone(), pending.expires_at, now)
        .await
        .map_err(|e| DeviceError::Store(e.to_string()))
}

// ── codes ───────────────────────────────────────────────────────────────

fn device_token() -> String {
    use rand::RngExt;
    let raw: [u8; 32] = rand::rng().random();
    crate::utils::base64url::encode(&raw)
}

fn random_user_code() -> String {
    use rand::RngExt;
    let mut rng = rand::rng();
    let mut s = String::with_capacity(USER_CODE_LEN + 1);
    for i in 0..USER_CODE_LEN {
        if i == USER_CODE_GROUP {
            s.push('-');
        }
        s.push(char::from(
            USER_CODE_ALPHABET[rng.random_range(0..USER_CODE_ALPHABET.len())],
        ));
    }
    s
}

/// Accept what a human types: case-insensitive, separators ignored.
#[must_use]
pub fn normalise_user_code(typed: &str) -> String {
    typed
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

#[cfg(test)]
mod tests {

    #[test]
    fn the_user_code_alphabet_has_no_look_alikes() {
        let alphabet = std::str::from_utf8(USER_CODE_ALPHABET).unwrap();
        for banned in ['0', 'O', '1', 'I', 'L', 'U'] {
            assert!(!alphabet.contains(banned), "{banned} is confusable");
        }
        // The SIZE is a security number, not incidental: 19 symbols to the
        // 8th is ~34 bits, and the module doc says 34. R2 found the doc
        // claiming 22 symbols when the alphabet had 19.
        assert_eq!(
            alphabet.chars().count(),
            19,
            "19 symbols: ~34 bits at length 8"
        );
        let bits = (USER_CODE_LEN as f64) * 19f64.log2();
        assert!((33.9..34.0).contains(&bits), "{bits} bits");
        // MUT:lookalike-alphabet — putting 'O' or '1' back reddens this.
    }

    #[test]
    fn a_user_code_is_grouped_and_from_the_alphabet() {
        for _ in 0..64 {
            let code = random_user_code();
            assert_eq!(code.len(), USER_CODE_LEN + 1);
            assert_eq!(code.matches('-').count(), 1);
            for c in code.chars().filter(|c| *c != '-') {
                assert!(
                    USER_CODE_ALPHABET.contains(&(c as u8)),
                    "{c} outside the alphabet"
                );
            }
        }
    }

    #[test]
    fn typing_is_forgiving_on_case_and_separators() {
        assert_eq!(normalise_user_code("bcdf-ghjk"), "BCDFGHJK");
        assert_eq!(normalise_user_code("BCDF GHJK"), "BCDFGHJK");
        assert_eq!(normalise_user_code("bcdfghjk"), "BCDFGHJK");
    }

    #[test]
    fn user_codes_do_not_collide_in_a_sample() {
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..5001 {
            assert!(seen.insert(random_user_code()), "collision in 5001 draws");
        }
    }

    use super::*;
    use crate::auth::provider::client::ClientRecord;
    use crate::auth::provider::code::CodeGrant;
    use crate::auth::provider::id_token::IdTokenSigner;
    use crate::auth::provider::token::{AccessTokenSigner, TokenContext};
    use crate::auth::store::MemoryConsumableStore;

    /// Throwaway Ed25519 keypair for tests only (never a deployment key).
    const PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEID3zTmAP9MdPuN/YdS5wbUXgOWWRd4LYu6lNdo/eBgZn
-----END PRIVATE KEY-----";

    type Pending = MemoryDeviceStore;
    type Codes = MemoryConsumableStore<CodeGrant>;

    fn client() -> ClientRecord {
        let mut c = ClientRecord::public("tv-app", vec![]);
        c.allowed_grants = vec![GrantType::DeviceCode, GrantType::RefreshToken];
        c.allowed_scopes = vec!["profile".into(), "openid".into()];
        c
    }

    struct Fixture {
        codes: Codes,
        registry: crate::auth::provider::client::InMemoryClientRegistry,
        signer: IdTokenSigner,
        access: AccessTokenSigner,
    }

    fn fixture() -> Fixture {
        let registry = crate::auth::provider::client::InMemoryClientRegistry::new();
        Fixture {
            codes: MemoryConsumableStore::new(),
            registry,
            signer: IdTokenSigner::from_ed25519_pem(PRIVATE_PEM, "k-1").unwrap(),
            access: AccessTokenSigner::from_ed25519_pem(PRIVATE_PEM, "https://resource.example")
                .unwrap(),
        }
    }

    /// The single `user_code` the store currently points at (tests only).
    async fn lookup_probe_user_code(store: &MemoryDeviceStore) -> String {
        store
            .pointers
            .read()
            .await
            .keys()
            .next()
            .cloned()
            .expect("one pointer was parked")
    }

    fn ctx<'a>(
        f: &'a Fixture,
        _pending: &'a Pending,
        now: DateTime<Utc>,
    ) -> TokenContext<'a, Codes> {
        TokenContext {
            registry: &f.registry,
            codes: &f.codes,
            refresh: &f.codes,
            id_token_signer: Some(&f.signer),
            issuer: "https://auth.example".into(),
            access_signer: &f.access,
            now,
        }
    }

    /// A full pairing: request → human approves → the device polls once and
    /// gets tokens exactly once.
    #[tokio::test]
    async fn a_pairing_needs_a_human_and_the_token_comes_out_once() {
        let f = fixture();
        let store = MemoryDeviceStore::new();
        let now = Utc::now();
        let auth = request(
            &client(),
            "profile",
            &store,
            "https://auth.example/device",
            now,
        )
        .await
        .unwrap();
        assert_eq!(auth.interval_secs, DEFAULT_INTERVAL_SECS);
        // Pending before the human acts.
        let first = poll(
            &auth.device_code,
            &client(),
            &store,
            &ctx(&f, &store, now),
            now,
        )
        .await
        .unwrap();
        assert!(matches!(first, DevicePoll::Pending), "{first:?}");
        // The human approves.
        let t = now + Duration::seconds(DEFAULT_INTERVAL_SECS + 1);
        decide(
            &auth.user_code,
            Decision::Approved { auth_time: now },
            "user-1",
            &store,
            t,
        )
        .await
        .unwrap();
        // Poll again after the interval: tokens.
        let t2 = t + Duration::seconds(DEFAULT_INTERVAL_SECS + 1);
        let out = poll(
            &auth.device_code,
            &client(),
            &store,
            &ctx(&f, &store, t2),
            t2,
        )
        .await
        .unwrap();
        let DevicePoll::Token(resp) = out else {
            panic!("expected tokens, got {out:?}")
        };
        assert!(!resp.access_token.is_empty(), "an access token is minted");
        assert!(resp.refresh_token.is_some());
        // And the device code is spent: the next poll is expired.
        let t3 = t2 + Duration::seconds(DEFAULT_INTERVAL_SECS + 1);
        assert!(matches!(
            poll(
                &auth.device_code,
                &client(),
                &store,
                &ctx(&f, &store, t3),
                t3
            )
            .await
            .unwrap(),
            DevicePoll::Expired
        ));
    }

    /// RFC 8628 §3.5: polling faster than the interval is `slow_down`, and
    /// the interval GROWS. A host that answers `authorization_pending` here
    /// has made the interval decorative.
    #[tokio::test]
    async fn an_early_poll_is_slow_down_and_the_interval_grows() {
        let f = fixture();
        let store = MemoryDeviceStore::new();
        let now = Utc::now();
        let auth = request(
            &client(),
            "profile",
            &store,
            "https://auth.example/device",
            now,
        )
        .await
        .unwrap();
        // First poll: on time, pending.
        assert!(matches!(
            poll(
                &auth.device_code,
                &client(),
                &store,
                &ctx(&f, &store, now),
                now
            )
            .await
            .unwrap(),
            DevicePoll::Pending
        ));
        // Second poll one second later: too fast.
        let early = now + Duration::seconds(1);
        let out = poll(
            &auth.device_code,
            &client(),
            &store,
            &ctx(&f, &store, early),
            early,
        )
        .await
        .unwrap();
        let DevicePoll::SlowDown { interval } = out else {
            panic!("expected slow_down, got {out:?}")
        };
        assert_eq!(interval, DEFAULT_INTERVAL_SECS + SLOW_DOWN_STEP_SECS);
        // MUT:no-slow-down — answering Pending here reddens this.
        // And the grown interval is what is enforced next: a poll that would
        // have been on time at the OLD interval is still too fast.
        let at_old = early + Duration::seconds(DEFAULT_INTERVAL_SECS);
        assert!(matches!(
            poll(
                &auth.device_code,
                &client(),
                &store,
                &ctx(&f, &store, at_old),
                at_old
            )
            .await
            .unwrap(),
            DevicePoll::SlowDown { .. }
        ));
    }

    /// A denial never becomes a token, and it is the same answer forever.
    #[tokio::test]
    async fn a_denied_pairing_never_becomes_a_token() {
        let f = fixture();
        let store = MemoryDeviceStore::new();
        let now = Utc::now();
        let auth = request(
            &client(),
            "profile",
            &store,
            "https://auth.example/device",
            now,
        )
        .await
        .unwrap();
        decide(&auth.user_code, Decision::Denied, "user-1", &store, now)
            .await
            .unwrap();
        let t = now + Duration::seconds(DEFAULT_INTERVAL_SECS + 1);
        assert!(matches!(
            poll(&auth.device_code, &client(), &store, &ctx(&f, &store, t), t)
                .await
                .unwrap(),
            DevicePoll::Denied
        ));
        // MUT:denial-issues — treating Denied as Approved reddens this.
    }

    /// An expired pairing never becomes a token.
    #[tokio::test]
    async fn an_expired_pairing_never_becomes_a_token() {
        let f = fixture();
        let store = MemoryDeviceStore::new();
        let now = Utc::now();
        let auth = request(
            &client(),
            "profile",
            &store,
            "https://auth.example/device",
            now,
        )
        .await
        .unwrap();
        decide(
            &auth.user_code,
            Decision::Approved { auth_time: now },
            "user-1",
            &store,
            now,
        )
        .await
        .unwrap();
        let late = now + Duration::seconds(DEFAULT_DEVICE_TTL_SECS + 1);
        assert!(matches!(
            poll(
                &auth.device_code,
                &client(),
                &store,
                &ctx(&f, &store, late),
                late
            )
            .await
            .unwrap(),
            DevicePoll::Expired
        ));
    }

    /// A decision is write-once: a second `decide` is refused, so a browser
    /// that re-submits cannot flip a denial into an approval.
    #[tokio::test]
    async fn a_pairing_is_decided_exactly_once() {
        let store = MemoryDeviceStore::new();
        let now = Utc::now();
        let auth = request(
            &client(),
            "profile",
            &store,
            "https://auth.example/device",
            now,
        )
        .await
        .unwrap();
        decide(&auth.user_code, Decision::Denied, "user-1", &store, now)
            .await
            .unwrap();
        assert_eq!(
            decide(
                &auth.user_code,
                Decision::Approved { auth_time: now },
                "user-1",
                &store,
                now
            )
            .await
            .unwrap_err(),
            DeviceError::AlreadyDecided
        );
        // MUT:decide-twice — dropping the check flips a denial into an approval.
    }

    /// An approval with no subject would mint a token with an empty `sub`.
    #[tokio::test]
    async fn an_approval_must_name_its_subject() {
        let store = MemoryDeviceStore::new();
        let now = Utc::now();
        let auth = request(
            &client(),
            "profile",
            &store,
            "https://auth.example/device",
            now,
        )
        .await
        .unwrap();
        assert!(matches!(
            decide(
                &auth.user_code,
                Decision::Approved { auth_time: now },
                "  ",
                &store,
                now
            )
            .await,
            Err(DeviceError::UnknownUserCode)
        ));
    }

    /// The user code is not a credential, but it must not be mistakable: it
    /// resolves case-insensitively and with separators dropped.
    #[tokio::test]
    async fn the_user_code_resolves_however_it_is_typed() {
        let store = MemoryDeviceStore::new();
        let now = Utc::now();
        let auth = request(
            &client(),
            "profile",
            &store,
            "https://auth.example/device",
            now,
        )
        .await
        .unwrap();
        let lower = auth.user_code.to_ascii_lowercase().replace('-', " ");
        let (device_code, pending) = lookup(&lower, &store, now).await.unwrap();
        assert_eq!(device_code, auth.device_code);
        assert_eq!(pending.user_code, auth.user_code);
    }

    /// An unknown or malformed user code is one error, and a malformed one
    /// never reaches the store.
    #[tokio::test]
    async fn an_unknown_user_code_is_indistinguishable_from_a_malformed_one() {
        let store = MemoryDeviceStore::new();
        let now = Utc::now();
        assert_eq!(
            lookup("BCDFGHJK", &store, now).await.unwrap_err(),
            DeviceError::UnknownUserCode
        );
        assert_eq!(
            lookup("BCDF", &store, now).await.unwrap_err(),
            DeviceError::Malformed
        );
    }

    /// R2 S1: two concurrent polls of one approved pairing must mint ONE
    /// token set. The first version read, then removed, then minted — both
    /// polls read `Approved` and both minted (measured).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn two_concurrent_polls_mint_exactly_one_token_set() {
        let f = fixture();
        let store = std::sync::Arc::new(MemoryDeviceStore::new());
        let now = Utc::now();
        let auth = request(
            &client(),
            "profile",
            store.as_ref(),
            "https://auth.example/device",
            now,
        )
        .await
        .unwrap();
        decide(
            &auth.user_code,
            Decision::Approved { auth_time: now },
            "user-1",
            store.as_ref(),
            now,
        )
        .await
        .unwrap();
        let later = now + Duration::seconds(DEFAULT_INTERVAL_SECS + 1);
        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));
        let mut handles = Vec::new();
        for _ in 0..2 {
            let store = store.clone();
            let code = auth.device_code.clone();
            let barrier = barrier.clone();
            let c = client();
            handles.push(tokio::spawn(async move {
                let f2 = fixture();
                let ctx = TokenContext {
                    registry: &f2.registry,
                    codes: &f2.codes,
                    refresh: &f2.codes,
                    id_token_signer: Some(&f2.signer),
                    issuer: "https://auth.example".into(),
                    access_signer: &f2.access,
                    now: later,
                };
                barrier.wait().await;
                matches!(
                    poll(&code, &c, store.as_ref(), &ctx, later).await,
                    Ok(DevicePoll::Token(_))
                )
            }));
        }
        let mut tokens = 0;
        for h in handles {
            if h.await.unwrap() {
                tokens += 1;
            }
        }
        assert_eq!(tokens, 1, "exactly one concurrent poll may mint");
        let _ = &f;
    }

    /// R2 S1: two concurrent decides must not both succeed, and a denial
    /// must not be replaced by an approval carrying the other party's
    /// subject.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn two_concurrent_decides_cannot_both_win() {
        let store = std::sync::Arc::new(MemoryDeviceStore::new());
        let now = Utc::now();
        let auth = request(
            &client(),
            "profile",
            store.as_ref(),
            "https://auth.example/device",
            now,
        )
        .await
        .unwrap();
        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));
        let mut handles = Vec::new();
        for (decision, sub) in [
            (Decision::Denied, "owner"),
            (Decision::Approved { auth_time: now }, "attacker"),
        ] {
            let store = store.clone();
            let code = auth.user_code.clone();
            let barrier = barrier.clone();
            handles.push(tokio::spawn(async move {
                barrier.wait().await;
                decide(&code, decision, sub, store.as_ref(), now)
                    .await
                    .is_ok()
            }));
        }
        let mut wins = 0;
        for h in handles {
            if h.await.unwrap() {
                wins += 1;
            }
        }
        assert_eq!(wins, 1, "exactly one decide may win");
        // And the stored pairing carries exactly the winner's decision.
        let (device_code, pending) = lookup(&auth.user_code, store.as_ref(), now).await.unwrap();
        assert_eq!(device_code, auth.device_code);
        match pending.decision {
            Decision::Denied => assert!(pending.sub.is_empty() || pending.sub == "owner"),
            Decision::Approved { .. } => assert_eq!(pending.sub, "attacker"),
            Decision::Pending => panic!("one of the two decides must have landed"),
        }
    }

    /// R2 S1: the pairing belongs to the client that requested it. Without
    /// the check, another registered client redeems the code and the token
    /// carries the OWNER's `client_id`.
    #[tokio::test]
    async fn another_client_cannot_redeem_the_pairing() {
        let f = fixture();
        let store = MemoryDeviceStore::new();
        let now = Utc::now();
        let auth = request(
            &client(),
            "profile",
            &store,
            "https://auth.example/device",
            now,
        )
        .await
        .unwrap();
        decide(
            &auth.user_code,
            Decision::Approved { auth_time: now },
            "user-1",
            &store,
            now,
        )
        .await
        .unwrap();
        let mut other = ClientRecord::public("tv-other", vec![]);
        other.allowed_grants = vec![GrantType::DeviceCode, GrantType::RefreshToken];
        let later = now + Duration::seconds(DEFAULT_INTERVAL_SECS + 1);
        assert_eq!(
            poll(
                &auth.device_code,
                &other,
                &store,
                &ctx(&f, &store, later),
                later
            )
            .await
            .unwrap_err(),
            DeviceError::UnauthorizedClient("tv-other".into())
        );
        // And the owner still finishes: the mismatch put the pairing back.
        let out = poll(
            &auth.device_code,
            &client(),
            &store,
            &ctx(&f, &store, later),
            later,
        )
        .await
        .unwrap();
        assert!(
            matches!(out, DevicePoll::Token(_)),
            "the owner can still claim it: {out:?}"
        );
    }

    /// R2 S1: `openid` on the device grant has no `nonce`, so no ID token
    /// can ever be minted. Refused at REQUEST time — accepting it produced a
    /// pairing whose mint failed only after the human approved and after the
    /// pairing was consumed, leaving the device unable to retry.
    #[tokio::test]
    async fn asking_for_openid_is_refused_up_front() {
        let store = MemoryDeviceStore::new();
        let now = Utc::now();
        assert_eq!(
            request(
                &client(),
                "openid",
                &store,
                "https://auth.example/device",
                now
            )
            .await
            .unwrap_err(),
            DeviceError::OpenIdWithoutNonce
        );
        assert!(store.is_empty().await, "nothing was parked");
    }

    /// R3 S2: the store's compare-and-set is the real guard, so test it
    /// DIRECTLY. Two `decide` calls are serialised by the outer `Pending`
    /// check often enough that a deleted store guard still passes ~96% of
    /// runs (R3 measured 1 red in 25) — the case has to go to the store.
    #[tokio::test]
    async fn the_store_refuses_a_second_decision_on_its_own() {
        let store = MemoryDeviceStore::new();
        let now = Utc::now();
        let auth = request(
            &client(),
            "profile",
            &store,
            "https://auth.example/device",
            now,
        )
        .await
        .unwrap();
        let approved = Decision::Approved { auth_time: now };
        // First decides; second is refused BY THE STORE.
        assert!(store
            .decide_if_pending(&auth.device_code, Decision::Denied, "owner", now)
            .await
            .unwrap());
        assert!(
            !store
                .decide_if_pending(&auth.device_code, approved, "attacker", now)
                .await
                .unwrap(),
            "the store itself must refuse the second decision"
        );
        // And the stored record is the first one, with the first subject.
        let (_, pending) = lookup(&auth.user_code, &store, now).await.unwrap();
        assert_eq!(pending.decision, Decision::Denied);
        assert_eq!(pending.sub, "owner");
        // MUT:store-cas-guard — dropping the `Pending` check inside
        // `decide_if_pending` turns the `!` above into `true` and the
        // subject into "attacker".
    }

    /// R3 S1: RFC 8628 §3.1 makes `scope` OPTIONAL. A scope-less request
    /// must succeed — the first fix refused it, because the provider's
    /// default scope is `openid profile` and the openid check ran on the
    /// normalised value instead of on what the caller asked for.
    #[tokio::test]
    async fn a_scope_less_request_succeeds() {
        let store = MemoryDeviceStore::new();
        let now = Utc::now();
        for scope in ["", "   "] {
            let auth = request(&client(), scope, &store, "https://auth.example/device", now)
                .await
                .unwrap_or_else(|e| panic!("a scope-less device request must work: {e:?}"));
            assert!(!auth.user_code.is_empty());
            // The pairing it parked carries no `openid` — this grant can
            // never honour one.
            let (_, pending) = lookup(&auth.user_code, &store, now).await.unwrap();
            assert!(
                !pending.scope.split_whitespace().any(|s| s == "openid"),
                "{}",
                pending.scope
            );
        }
        // MUT:refuse-normalised-default — checking the normalised scope
        // instead of the request reddens the first leg.
    }

    /// A verification URI that already carries a query gets `&`, not a
    /// second `?`. (R3: the field was built with a bare `?` and had no test.)
    #[tokio::test]
    async fn the_complete_uri_respects_an_existing_query() {
        let store = MemoryDeviceStore::new();
        let now = Utc::now();
        let plain = request(
            &client(),
            "profile",
            &store,
            "https://auth.example/device",
            now,
        )
        .await
        .unwrap();
        assert!(
            plain.verification_uri_complete.contains("?user_code="),
            "{}",
            plain.verification_uri_complete
        );
        let with_query = request(
            &client(),
            "profile",
            &store,
            "https://auth.example/device?tenant=a",
            now,
        )
        .await
        .unwrap();
        let complete = &with_query.verification_uri_complete;
        assert_eq!(
            complete.matches('?').count(),
            1,
            "one query separator: {complete}"
        );
        assert!(complete.contains("&user_code="), "{complete}");
        assert!(complete.ends_with(&with_query.user_code), "{complete}");
    }

    /// R2 S2: an abandoned pairing is swept. `poll` answers `expired_token`
    /// and returns, so nothing else would ever delete the row.
    #[tokio::test]
    async fn an_abandoned_pairing_is_swept() {
        let store = MemoryDeviceStore::new();
        let now = Utc::now();
        let _ = request(
            &client(),
            "profile",
            &store,
            "https://auth.example/device",
            now,
        )
        .await
        .unwrap();
        assert_eq!(store.len().await, 1);
        assert_eq!(
            store.sweep(now).await.unwrap(),
            0,
            "before the TTL it stays"
        );
        let later = now + Duration::seconds(DEFAULT_DEVICE_TTL_SECS + 1);
        // The POINTER is what a human types against; capture it while live so
        // the post-sweep check is about this pairing, not about a code that
        // was never parked (R3: the first version asserted on "BCDFGHJK").
        let live_user_code = lookup_probe_user_code(&store).await;
        assert_eq!(store.sweep(later).await.unwrap(), 1);
        assert_eq!(store.len().await, 0);
        assert!(
            store
                .pointer(&live_user_code, later)
                .await
                .unwrap()
                .is_none(),
            "the pointer is swept too"
        );
        // MUT:no-sweep — a no-op `sweep` leaves the count at 1.
    }

    /// A client without the device grant is refused at both ends.
    #[tokio::test]
    async fn a_client_without_the_device_grant_is_refused() {
        let f = fixture();
        let store = MemoryDeviceStore::new();
        let now = Utc::now();
        let mut c = ClientRecord::public("no-tv", vec![]);
        c.allowed_grants = vec![GrantType::AuthorizationCode];
        assert_eq!(
            request(&c, "profile", &store, "https://auth.example/device", now)
                .await
                .unwrap_err(),
            DeviceError::UnauthorizedClient("no-tv".into())
        );
        // And the poll end, with a real pairing for the good client.
        let auth = request(
            &client(),
            "profile",
            &store,
            "https://auth.example/device",
            now,
        )
        .await
        .unwrap();
        assert_eq!(
            poll(&auth.device_code, &c, &store, &ctx(&f, &store, now), now)
                .await
                .unwrap_err(),
            DeviceError::UnauthorizedClient("no-tv".into())
        );
    }

    /// A scope outside the client's allowance is refused at request time.
    #[tokio::test]
    async fn an_out_of_allowance_scope_is_refused() {
        let store = MemoryDeviceStore::new();
        let now = Utc::now();
        assert!(matches!(
            request(
                &client(),
                "profile admin",
                &store,
                "https://auth.example/device",
                now
            )
            .await,
            Err(DeviceError::InvalidScope(_))
        ));
    }

    /// Two devices get different codes, and the user codes do not collide.
    #[tokio::test]
    async fn two_pairings_do_not_share_a_code() {
        let store = MemoryDeviceStore::new();
        let now = Utc::now();
        let a = request(
            &client(),
            "profile",
            &store,
            "https://auth.example/device",
            now,
        )
        .await
        .unwrap();
        let b = request(
            &client(),
            "profile",
            &store,
            "https://auth.example/device",
            now,
        )
        .await
        .unwrap();
        assert_ne!(a.device_code, b.device_code);
        assert_ne!(a.user_code, b.user_code);
    }
}
