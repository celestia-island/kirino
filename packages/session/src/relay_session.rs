//! Browser-session sign-in over the relay protocol: the BFF orchestration.
//!
//! `kirino::auth::relay` knows how to *configure* relay mode and the RP core
//! (`auth::passport::oauth`) knows how to *run* one authorization round.
//! What a browser-facing host still has to do by hand — and has been doing
//! four different ways across the family — is the glue around it:
//!
//! ```text
//! begin    → start an attempt, bind it to this browser, return the redirect
//! complete → take the callback, finish the round, open a server-side session
//! ```
//!
//! This module is that glue, pure and storage-injected. The session it
//! opens is a [`ServerSession`]: the browser gets an opaque id in a
//! host-only cookie and **never** the provider's tokens. That is the BFF
//! shape. **The tokens are not kept at all**: the RP core's `finish`
//! consumes the token response and returns only the identity and profile,
//! so `ServerSession::tokens` is `None` here. A host that must call the
//! provider on the user's behalf needs the RP core to expose the token
//! response first (not in this crate yet); this module is for hosts that
//! only need to know who is signed in.
//!
//! # The binding cookie
//!
//! The attempt's `state` is bound to a random per-browser value
//! ([`BINDING_COOKIE`]) that the host sets as an `httpOnly` cookie when it
//! redirects and presents on the callback. Without it a callback that
//! arrives at the wrong browser — the login-CSRF shape — would complete
//! an attempt the victim never started.

use chrono::{DateTime, Utc};

use crate::server_session::{CookiePolicy, ServerSession, ServerSessionStore};
use kirino::auth::{
    passport::oauth::{
        self, Callback, CallbackQuery, HttpFetcher, LoginAttemptStore, ProviderMetadata,
    },
    relay::RelayConfig,
};

/// The cookie name carrying the browser binding.
pub const BINDING_COOKIE: &str = "__Host-kirino_login";
/// How long an attempt may sit between redirect and callback.
pub const DEFAULT_ATTEMPT_TTL_SECS: i64 = 600;

/// Everything a host must hand the orchestration. The host owns every
/// store; nothing here is process-global.
pub struct RelaySessionContext<'a> {
    pub config: &'a RelayConfig,
    pub attempts: &'a dyn LoginAttemptStore,
    pub sessions: &'a dyn ServerSessionStore,
    pub http: &'a dyn HttpFetcher,
    pub provider: ProviderMetadata,
    /// The client credential for the token exchange.
    pub client: oauth::ClientAuth,
    pub now: DateTime<Utc>,
}

/// What `begin` answers: where to send the browser, and the binding value
/// to set as a cookie before doing so.
#[derive(Clone, PartialEq, Eq)]
pub struct BeginRedirect {
    /// The provider's authorization URL, with `state`, PKCE and nonce.
    pub url: String,
    /// The value for the [`BINDING_COOKIE`]. Not `Debug`-printed with the
    /// redirect by hosts that log `BeginRedirect` wholesale — it is a
    /// credential for the duration of the attempt.
    pub binding: String,
}

impl std::fmt::Debug for BeginRedirect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BeginRedirect")
            .field("url", &self.url)
            .field("binding", &"<redacted>")
            .finish()
    }
}

/// A completed sign-in: the session (already stored by `complete`) and the
/// `Set-Cookie` value that installs its id in the browser. `Debug`
/// redacts the cookie value and the session — both are the live
/// credential for the session's lifetime.
#[derive(Clone)]
pub struct SignedIn {
    pub session: ServerSession,
    pub set_cookie: String,
    /// Where the browser may land: the request's `return_to` passed
    /// through `safe_return_path` against the relay's allowed origins, so
    /// a foreign or scheme-relative target comes back as `None` (R2: the
    /// first version returned the raw value under this doc — a login-time
    /// open redirect for any host that trusted it).
    pub return_to: Option<String>,
}

impl std::fmt::Debug for SignedIn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignedIn")
            .field("session", &"<redacted: live credential>")
            .field("set_cookie", &"<redacted>")
            .field("return_to", &self.return_to)
            .finish()
    }
}

/// Why a sign-in step refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RelaySessionError {
    /// The attempt store failed in `begin` — the attempt could not be
    /// parked. **Not** a verdict on the browser. (In `complete` a store
    /// failure still arrives folded into the RP core's error; see that
    /// case's docs.)
    #[error("attempt store failed: {0}")]
    AttemptStore(String),
    /// The session store failed.
    #[error("session store failed: {0}")]
    SessionStore(String),
    /// The protocol round refused (state, binding, PKCE, provider, …).
    #[error("sign-in refused: {0}")]
    Refused(String),
    /// The provider metadata is incomplete (no authorize/token endpoint).
    #[error("relay is not fully configured: {0}")]
    NotConfigured(String),
}

/// Start a sign-in for `return_to`, bound to a fresh browser value.
///
/// # Errors
///
/// [`RelaySessionError::AttemptStore`] when the attempt cannot be parked.
/// (`ProviderMetadata::authorize_url` is not an `Option`, so "the metadata
/// lacks the authorize endpoint" is not representable and `NotConfigured`
/// cannot arise from this call; the variant stays for hosts that build
/// their own errors.)
pub async fn begin(
    ctx: &RelaySessionContext<'_>,
    return_to: Option<&str>,
) -> Result<BeginRedirect, RelaySessionError> {
    let binding = random_binding();
    let attempt = oauth::begin_with_binding(
        ctx.attempts,
        ctx.provider.provider.clone(),
        return_to.map(str::to_owned),
        Some(binding.clone()),
        chrono::Duration::seconds(DEFAULT_ATTEMPT_TTL_SECS),
    )
    .await
    .map_err(|e| RelaySessionError::AttemptStore(e.to_string()))?;
    // `return_to` is NOT put on the authorize URL: the RP core's
    // `authorize_url` does not read it, the provider's `AuthorizeRequest`
    // has no such field, and `RelayConfig::return_param` only tells THIS
    // host's UI which parameter name to use after the callback. The attempt
    // carries the value; `complete` filters it before anyone redirects.
    let url = oauth::authorize_url(
        &ctx.provider,
        &ctx.client,
        &ctx.config.redirect_url,
        &attempt,
    );
    Ok(BeginRedirect {
        url: url.to_string(),
        binding,
    })
}

/// Take the provider's callback and open a session.
///
/// `cookie_binding` is the value the browser presents in
/// [`BINDING_COOKIE`]; a callback whose binding does not match the attempt's
/// is refused by the RP core before any exchange.
///
/// The subject is the external identity's **stable key** —
/// `provider + issuer + subject` — never an email. The host resolves that to
/// its own account outside this function if it needs to; the session
/// records the key so a later `generation` bump can target it.
///
/// # Errors
///
/// [`RelaySessionError::Refused`] when the RP core refuses the callback
/// (bad state, a lost binding, a provider error — and, until the RP core
/// splits its error type, a store failure too: see the case named for it);
/// [`RelaySessionError::SessionStore`] when the session cannot be stored.
/// `AttemptStore` and `NotConfigured` are `begin`'s, not this call's.
pub async fn complete(
    ctx: &RelaySessionContext<'_>,
    query: &CallbackQuery,
    cookie_binding: &str,
    redirect_uri: &url::Url,
) -> Result<SignedIn, RelaySessionError> {
    let callback = Callback {
        query,
        browser_binding: Some(cookie_binding),
        id_token_keys: &[],
    };
    let login = oauth::finish(
        ctx.http,
        ctx.attempts,
        &ctx.provider,
        &ctx.client,
        redirect_uri,
        callback,
    )
    .await
    .map_err(|e| {
        // A store failure and a protocol refusal are different things, but
        // the RP core currently folds both into `CallbackProblem`, so this
        // layer cannot tell them apart by type. R2/R3 measured the
        // alternative that looked like a fix — matching on the error
        // message text — and it never fires against a real store (only a
        // test double writes the phrase it matched). The honest form: the
        // RP core grows a `CallbackProblem::Store` variant and this map
        // branches on it. Recorded in the body; until then every failure
        // here is a `Refused`, and a host that needs to tell an outage from
        // a bad callback must check its store's health separately.
        RelaySessionError::Refused(e.to_string())
    })?;
    // The stable key. Length-prefixed rather than `|`-joined (R2: with a
    // separator, `(iss="a|b", sub="c")` and `(iss="a", sub="b|c")` collided
    // and a `bump_generation` on one staled the other's sessions).
    let subject = stable_subject_key(&login.identity);
    // A new session starts at the subject's CURRENT privilege epoch, so a
    // role change that happened before this login applies to it.
    let generation = ctx
        .sessions
        .generation(&subject)
        .await
        .map_err(|e| RelaySessionError::SessionStore(e.to_string()))?;
    let id = random_session_id();
    let session = ServerSession {
        id,
        subject,
        created_at: ctx.now,
        last_seen: ctx.now,
        generation,
        tokens: None,
    };
    ctx.sessions
        .put(&session)
        .await
        .map_err(|e| RelaySessionError::SessionStore(e.to_string()))?;
    let policy = CookiePolicy::strict();
    // The RP core parks and returns `return_to` verbatim; the host-facing
    // promise is that THIS value is safe to redirect to.
    let return_to = login.return_to.as_deref().and_then(|raw| {
        kirino::auth::relay::safe_return_path(raw, &ctx.config.allowed_return_origins)
    });
    Ok(SignedIn {
        set_cookie: policy.set_cookie_value(&session.id, "sid"),
        session,
        return_to,
    })
}

/// The unambiguous stable key for an external identity: each part
/// length-prefixed (`<len>:<part>`), so a `|` or `:` inside a provider id,
/// issuer or subject can never be read as a separator.
#[must_use]
pub fn stable_subject_key(identity: &kirino::auth::identity::external::ExternalIdentity) -> String {
    fn part(s: &str) -> String {
        format!("{}:{s}", s.len())
    }
    // The same normalisation the identity store applies, so a host that
    // calls this with the raw identity gets the key the session was
    // recorded under (R3: without it, an issuer differing only in case or a
    // trailing slash produced a different key and `bump_generation` missed
    // the session).
    let identity = identity.normalised();
    format!(
        "{}|{}|{}",
        part(&identity.provider),
        part(identity.issuer.as_deref().unwrap_or("")),
        part(&identity.subject)
    )
}

/// 32 bytes of OS randomness, base64url. Used for BOTH the browser binding
/// and the session id — same entropy requirement, one implementation (they
/// were byte-identical copies, so a change to one silently missed the other).
fn random_token_256() -> String {
    use rand::RngExt;
    let raw: [u8; 32] = rand::rng().random();
    kirino::utils::base64url::encode(&raw)
}

fn random_binding() -> String {
    random_token_256()
}

fn random_session_id() -> String {
    random_token_256()
}

/// The `Set-Cookie` that clears the binding after the callback (it has
/// served its purpose and must not outlive the attempt).
#[must_use]
pub fn clear_binding_cookie() -> String {
    format!("{BINDING_COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::InMemoryServerSessionStore;
    #[allow(unused_imports)]
    use anyhow as _;
    use kirino::auth::passport::oauth::InMemoryLoginAttemptStore;
    use std::sync::Arc;

    /// A fetcher that answers the token and userinfo exchanges for a fixed
    /// identity, so the round completes without a network.
    struct FixtureFetcher {
        sub: &'static str,
        calls: std::sync::atomic::AtomicUsize,
    }

    #[async_trait::async_trait]
    impl HttpFetcher for FixtureFetcher {
        async fn post_form(
            &self,
            _url: &url::Url,
            _params: &[(&str, &str)],
        ) -> anyhow::Result<serde_json::Value> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(serde_json::json!({ "access_token": "at", "token_type": "Bearer" }))
        }
        async fn post_json(
            &self,
            _url: &url::Url,
            _body: &serde_json::Value,
        ) -> anyhow::Result<serde_json::Value> {
            self.post_form(_url, &[]).await
        }
        async fn get_bearer(
            &self,
            _url: &url::Url,
            _token: &str,
        ) -> anyhow::Result<serde_json::Value> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(serde_json::json!({
                "sub": self.sub,
                "preferred_username": "someone",
                "iss": "https://auth.example",
            }))
        }
    }

    fn config() -> RelayConfig {
        RelayConfig {
            issuer: url::Url::parse("https://auth.example").unwrap(),
            authorize_url: Some(url::Url::parse("https://auth.example/oauth/authorize").unwrap()),
            token_url: Some(url::Url::parse("https://auth.example/api/oauth/token").unwrap()),
            userinfo_url: Some(url::Url::parse("https://auth.example/api/oauth/userinfo").unwrap()),
            client_id: "erp-admin".into(),
            client_secret: None,
            redirect_url: url::Url::parse("https://app.example/api/auth/relay/callback").unwrap(),
            scopes: vec!["openid".into(), "profile".into(), "email".into()],
            return_param: "return_to".into(),
            allowed_return_origins: vec!["https://app.example".into()],
            break_glass: false,
        }
    }

    fn provider() -> ProviderMetadata {
        ProviderMetadata::new(
            "auth.example",
            url::Url::parse("https://auth.example/oauth/authorize").unwrap(),
            url::Url::parse("https://auth.example/api/oauth/token").unwrap(),
        )
        .with_issuer("https://auth.example")
        .with_userinfo_url(url::Url::parse("https://auth.example/api/oauth/userinfo").unwrap())
        .with_scopes(["openid", "profile", "email"])
    }

    struct Fixture {
        config: RelayConfig,
        attempts: Arc<InMemoryLoginAttemptStore>,
        sessions: Arc<InMemoryServerSessionStore>,
        http: Arc<FixtureFetcher>,
    }

    fn fixture() -> Fixture {
        Fixture {
            config: config(),
            attempts: Arc::new(InMemoryLoginAttemptStore::new()),
            sessions: Arc::new(InMemoryServerSessionStore::new()),
            http: Arc::new(FixtureFetcher {
                sub: "user-1",
                calls: std::sync::atomic::AtomicUsize::new(0),
            }),
        }
    }

    fn ctx(f: &Fixture) -> RelaySessionContext<'_> {
        RelaySessionContext {
            config: &f.config,
            attempts: f.attempts.as_ref(),
            sessions: f.sessions.as_ref(),
            http: f.http.as_ref(),
            provider: provider(),
            client: oauth::ClientAuth::Public {
                client_id: "erp-admin".into(),
            },
            now: Utc::now(),
        }
    }

    /// A full round: begin, then the provider's callback with the state
    /// from the redirect, lands a session whose subject is the stable
    /// identity key and whose id the browser receives in a `__Host-` cookie.
    #[tokio::test]
    async fn begin_then_complete_opens_a_bound_session() {
        let f = fixture();
        let c = ctx(&f);
        let begun = begin(&c, Some("/inbox")).await.unwrap();
        assert!(begun
            .url
            .starts_with("https://auth.example/oauth/authorize?"));
        assert!(begun.url.contains("state="));
        assert!(begun.url.contains("code_challenge="));
        // R4: the authorize URL does NOT carry `return_to` — the attempt
        // does, and `complete` filters it. Asserting its absence keeps the
        // unchecked external value out of the Location we hand a third party.
        assert!(!begun.url.contains("return_to="), "{}", begun.url);
        assert_eq!(begun.binding.len(), 43);

        let state = query_param(&begun.url, "state").unwrap();
        let query = CallbackQuery {
            code: Some("the-code".into()),
            state: Some(state),
            error: None,
            error_description: None,
        };
        let redirect = c.config.redirect_url.clone();
        let signed = complete(&c, &query, &begun.binding, &redirect)
            .await
            .unwrap();
        // Subject = provider | issuer | subject — never an email or a name.
        assert_eq!(
            signed.session.subject,
            "12:auth.example|20:https://auth.example|6:user-1"
        );
        assert_eq!(signed.return_to.as_deref(), Some("/inbox"));
        assert!(signed.set_cookie.starts_with("__Host-sid="));
        assert!(signed.set_cookie.contains("HttpOnly"));
        assert!(!signed.set_cookie.contains("Domain="));
        // The cookie carries the session id, not the subject or any
        // provider token (R2: `!contains("=at")` caught neither).
        assert!(signed
            .set_cookie
            .contains(&format!("__Host-sid={}", signed.session.id)));
        assert!(!signed.set_cookie.contains("user-1"));
        assert!(!signed.set_cookie.contains("\"at\""));
        assert!(f.sessions.get(&signed.session.id).await.unwrap().is_some());
        // The attempt is spent: a replay of the same callback is refused.
        let replay = complete(&c, &query, &begun.binding, &redirect).await;
        assert!(matches!(replay, Err(RelaySessionError::Refused(_))));
    }

    /// The binding is load-bearing: a callback presented from a browser
    /// that does not hold the binding cookie is refused before any exchange.
    #[tokio::test]
    async fn a_callback_without_the_binding_is_refused_before_the_exchange() {
        let f = fixture();
        let c = ctx(&f);
        let begun = begin(&c, None).await.unwrap();
        let state = query_param(&begun.url, "state").unwrap();
        let query = CallbackQuery {
            code: Some("the-code".into()),
            state: Some(state),
            error: None,
            error_description: None,
        };
        let redirect = c.config.redirect_url.clone();
        let err = complete(&c, &query, "not-the-binding", &redirect)
            .await
            .unwrap_err();
        assert!(matches!(err, RelaySessionError::Refused(_)), "{err}");
        // No token exchange happened, and no session was opened.
        assert_eq!(f.http.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
        // No session was opened: the store is empty (R2: a lookup for
        // "anything" proved nothing).
        assert_eq!(f.sessions.len().await, 0);
    }

    /// A new session inherits the subject's current privilege epoch, so a
    /// `bump_generation` between two logins makes the first one stale.
    #[tokio::test]
    async fn a_session_inherits_the_current_privilege_epoch() {
        let f = fixture();
        let c = ctx(&f);
        let key = stable_subject_key(&kirino::auth::identity::external::ExternalIdentity {
            provider: "auth.example".into(),
            issuer: Some("https://auth.example".into()),
            subject: "user-1".into(),
        });
        f.sessions.bump_generation(&key).await.unwrap();
        let begun = begin(&c, None).await.unwrap();
        let query = CallbackQuery {
            code: Some("c".into()),
            state: query_param(&begun.url, "state"),
            error: None,
            error_description: None,
        };
        let redirect = c.config.redirect_url.clone();
        let signed = complete(&c, &query, &begun.binding, &redirect)
            .await
            .unwrap();
        assert_eq!(signed.session.generation, 1);
        assert!(matches!(
            signed.session.check(Utc::now(), 60, 60, 2),
            crate::SessionCheck::Refused(crate::SessionRefusal::StaleGeneration)
        ));
    }

    /// R2 S1: `return_to` is filtered through `safe_return_path` against
    /// the relay's allowed origins. A foreign target, a scheme-relative
    /// one and a backslash one all come back as `None`; a same-origin path
    /// passes.
    #[tokio::test]
    async fn return_to_is_filtered_through_safe_return_path() {
        let f = fixture();
        let c = ctx(&f);
        for evil in [
            "https://evil.example/phish",
            "//evil.example/x",
            "/\\evil.example",
            "javascript:alert(1)",
        ] {
            let begun = begin(&c, Some(evil)).await.unwrap();
            let query = CallbackQuery {
                code: Some("c".into()),
                state: query_param(&begun.url, "state"),
                error: None,
                error_description: None,
            };
            let redirect = c.config.redirect_url.clone();
            let signed = complete(&c, &query, &begun.binding, &redirect)
                .await
                .unwrap();
            assert_eq!(
                signed.return_to, None,
                "{evil} must not be a landing target"
            );
        }
        let begun = begin(&c, Some("/inbox")).await.unwrap();
        let query = CallbackQuery {
            code: Some("c".into()),
            state: query_param(&begun.url, "state"),
            error: None,
            error_description: None,
        };
        let redirect = c.config.redirect_url.clone();
        let signed = complete(&c, &query, &begun.binding, &redirect)
            .await
            .unwrap();
        assert_eq!(signed.return_to.as_deref(), Some("/inbox"));
    }

    /// R2 S2: the subject key is unambiguous — a `|` inside the issuer and
    /// inside the subject cannot be made to produce the same key.
    #[test]
    fn the_subject_key_cannot_be_forged_across_fields() {
        use kirino::auth::identity::external::ExternalIdentity;
        let a = ExternalIdentity {
            provider: "p".into(),
            issuer: Some("a|b".into()),
            subject: "c".into(),
        };
        let b = ExternalIdentity {
            provider: "p".into(),
            issuer: Some("a".into()),
            subject: "b|c".into(),
        };
        assert_ne!(stable_subject_key(&a), stable_subject_key(&b));
        // Round-trips: three parts, each length-prefixed.
        let k = stable_subject_key(&a);
        assert!(k.starts_with("1:p|"));
    }

    /// R2 (surviving mutation R27): two sessions get different ids.
    #[tokio::test]
    async fn two_sign_ins_get_different_session_ids() {
        let f = fixture();
        let c = ctx(&f);
        let mut ids = Vec::new();
        for _ in 0..2 {
            let begun = begin(&c, None).await.unwrap();
            let query = CallbackQuery {
                code: Some("c".into()),
                state: query_param(&begun.url, "state"),
                error: None,
                error_description: None,
            };
            let redirect = c.config.redirect_url.clone();
            ids.push(
                complete(&c, &query, &begun.binding, &redirect)
                    .await
                    .unwrap()
                    .session
                    .id,
            );
        }
        assert_ne!(ids[0], ids[1]);
        // The entropy the doc promises, as a number a shortening cannot keep.
        for id in &ids {
            assert_eq!(
                id.len(),
                43,
                "256 bits base64url — the shape the doc promises"
            );
        }
    }

    /// The store-failure seam, pinned at what it is TODAY rather than what
    /// it should be: the RP core folds a store failure into its own error
    /// type, so this layer reports `Refused` and a host that must tell an
    /// outage from a bad callback checks its store separately. R2/R3 showed
    /// the message-text match that used to feed an `AttemptStore` variant
    /// never fires against a real store — only a test double writes the
    /// phrase it matched — so the `contains` arm is gone. When the RP core
    /// grows `CallbackProblem::Store`, this case becomes the "is a store
    /// error" one and the mapping is one line.
    #[tokio::test]
    async fn a_store_failure_is_reported_as_a_refusal_until_the_rp_core_splits_it() {
        struct Down;
        #[async_trait::async_trait]
        impl LoginAttemptStore for Down {
            async fn put(&self, _a: oauth::LoginAttempt) -> anyhow::Result<()> {
                Ok(())
            }
            async fn take(&self, _s: &str) -> anyhow::Result<Option<oauth::LoginAttempt>> {
                // What a real store says — nothing that mentions "attempt
                // store", which is why the removed match arm never fired.
                Err(anyhow::anyhow!(
                    "error returned from database: connection refused"
                ))
            }
        }
        let f = fixture();
        let mut c = ctx(&f);
        let down = Down;
        c.attempts = &down;
        let query = CallbackQuery {
            code: Some("c".into()),
            state: Some("s".into()),
            error: None,
            error_description: None,
        };
        let redirect = c.config.redirect_url.clone();
        let err = complete(&c, &query, "binding", &redirect)
            .await
            .unwrap_err();
        assert!(matches!(err, RelaySessionError::Refused(_)), "{err:?}");
        assert!(
            err.to_string().contains("connection refused"),
            "the store's own text survives: {err}"
        );
    }

    /// R2 S2: `SignedIn`'s `Debug` prints neither the session id nor the
    /// cookie value — both are live credentials for the session's lifetime.
    #[tokio::test]
    async fn signed_in_debug_prints_no_live_credential() {
        let f = fixture();
        let c = ctx(&f);
        let begun = begin(&c, None).await.unwrap();
        let query = CallbackQuery {
            code: Some("c".into()),
            state: query_param(&begun.url, "state"),
            error: None,
            error_description: None,
        };
        let redirect = c.config.redirect_url.clone();
        let signed = complete(&c, &query, &begun.binding, &redirect)
            .await
            .unwrap();
        let rendered = format!("{signed:?}");
        assert!(!rendered.contains(&signed.session.id), "{rendered}");
        assert!(!rendered.contains(&signed.set_cookie), "{rendered}");
        let session_debug = format!("{:?}", signed.session);
        assert!(
            !session_debug.contains(&signed.session.id),
            "{session_debug}"
        );
    }

    /// R3 S2: the binding is the whole of the login-CSRF defence, so two
    /// `begin` calls must not produce the same value. A constant binding
    /// passed every other case.
    #[tokio::test]
    async fn two_begins_get_different_bindings() {
        let f = fixture();
        let c = ctx(&f);
        let a = begin(&c, None).await.unwrap();
        let b = begin(&c, None).await.unwrap();
        assert_ne!(a.binding, b.binding);
        assert_eq!(a.binding.len(), 43, "32 bytes base64url");
        assert_eq!(b.binding.len(), 43);
    }

    /// R3 S2: the session records the caller's clock, not the wall clock —
    /// an injected time is the only way a host can make the timestamps
    /// reproducible, and ignoring it passed every other case.
    #[tokio::test]
    async fn the_session_records_the_callers_clock() {
        let f = fixture();
        let pinned = chrono::Utc::now() - chrono::Duration::days(3);
        let mut c = ctx(&f);
        c.now = pinned;
        let begun = begin(&c, None).await.unwrap();
        let query = CallbackQuery {
            code: Some("c".into()),
            state: query_param(&begun.url, "state"),
            error: None,
            error_description: None,
        };
        let redirect = c.config.redirect_url.clone();
        let signed = complete(&c, &query, &begun.binding, &redirect)
            .await
            .unwrap();
        assert_eq!(signed.session.created_at, pinned);
        assert_eq!(signed.session.last_seen, pinned);
    }

    /// R3 S2: the provider's tokens are NOT stored — this is the regression
    /// the module doc is about, and populating `tokens` passed every other
    /// case because the `Debug` is redacted.
    #[tokio::test]
    async fn the_session_keeps_no_provider_tokens() {
        let f = fixture();
        let c = ctx(&f);
        let begun = begin(&c, None).await.unwrap();
        let query = CallbackQuery {
            code: Some("c".into()),
            state: query_param(&begun.url, "state"),
            error: None,
            error_description: None,
        };
        let redirect = c.config.redirect_url.clone();
        let signed = complete(&c, &query, &begun.binding, &redirect)
            .await
            .unwrap();
        assert!(
            signed.session.tokens.is_none(),
            "the BFF shape keeps no provider tokens"
        );
        // And what the store holds agrees.
        let stored = f
            .sessions
            .get(&signed.session.id)
            .await
            .unwrap()
            .expect("stored");
        assert!(stored.tokens.is_none());
    }

    /// R3 S2: `stable_subject_key` normalises, so a host calling it with the
    /// raw identity gets the key the session was recorded under.
    #[test]
    fn the_subject_key_normalises_like_the_store() {
        use kirino::auth::identity::external::ExternalIdentity;
        let raw = ExternalIdentity {
            provider: "  auth.example  ".into(),
            issuer: Some("HTTPS://Auth.Example/".into()),
            subject: "  user-1 ".into(),
        };
        let normal = ExternalIdentity {
            provider: "auth.example".into(),
            issuer: Some("https://auth.example".into()),
            subject: "user-1".into(),
        };
        assert_eq!(stable_subject_key(&raw), stable_subject_key(&normal));
    }

    #[test]
    fn the_binding_cookie_is_cleared_with_matching_attributes() {
        let clear = clear_binding_cookie();
        assert!(clear.starts_with("__Host-kirino_login=;"));
        assert!(clear.contains("Max-Age=0"));
        for attr in ["Path=/", "Secure", "HttpOnly", "SameSite=Lax"] {
            assert!(clear.contains(attr));
        }
    }

    #[test]
    fn begin_redirect_debug_redacts_the_binding() {
        let b = BeginRedirect {
            url: "https://x".into(),
            binding: "SECRET-BINDING".into(),
        };
        let rendered = format!("{b:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("SECRET-BINDING"));
    }

    fn query_param(url: &str, key: &str) -> Option<String> {
        let raw = url.split('?').nth(1)?;
        raw.split('&').find_map(|kv| {
            let (k, v) = kv.split_once('=')?;
            // Decode percent-encoding only; the value is a bare token, not
            // a `k=v` pair, so `form_urlencoded::parse` would read it as
            // a key with an empty value.
            (k == key).then(|| percent_decode(v))
        })
    }

    fn percent_decode(v: &str) -> String {
        let bytes = v.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' && i + 2 < bytes.len() {
                if let Ok(b) = u8::from_str_radix(&v[i + 1..i + 3], 16) {
                    out.push(b);
                    i += 3;
                    continue;
                }
            }
            out.push(bytes[i]);
            i += 1;
        }
        String::from_utf8(out).unwrap_or_default()
    }
}
