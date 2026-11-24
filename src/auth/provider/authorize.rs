//! The authorization endpoint's decision core: may this browser be sent
//! back with a code, and if so, what exactly is parked under it.
//!
//! The sequence a host drives:
//!
//! 1. [`resolve_redirect`](super::client::resolve_redirect) — establish the
//!    client and that the redirect is registered. Until this passes, **no
//!    error is ever reflected**: the request has no verified destination.
//! 2. [`authorize`] — validate every remaining parameter and produce an
//!    [`AuthorizeDecision`]: either a [`Refused`](AuthorizeDecision::Refused)
//!    that is now safe to send back to the redirect URI, or an
//!    [`Approved`](AuthorizeDecision::Approved) carrying the
//!    [`CodeGrant`] to park.
//! 3. [`mint_code`](super::code::mint_code) — park the grant in the host's
//!    [`ConsumableStore`](crate::auth::store::ConsumableStore); the returned
//!    random code is what rides the redirect.
//!
//! # Why `authorize` does not check the user
//!
//! Authentication is the host's concern (a session cookie, a freshly
//! completed login, a consent screen). This function takes the outcome —
//! the subject and the `auth_time` — as inputs. That keeps it pure and
//! keeps the provider from growing a second opinion about what "signed in"
//! means next to the host's own session model.

use chrono::{DateTime, Utc};

use super::client::{ClientRecord, GrantType, RedirectMatch};
use super::{validate_scope, ProtocolError, ProviderError};

/// A parsed authorization request (the query string of `GET /oauth/authorize`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizeRequest {
    pub response_type: Option<String>,
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub scope: Option<String>,
    pub state: Option<String>,
    /// RFC 7636 §4.3. Required for every client with
    /// [`require_pkce`](ClientRecord::require_pkce).
    pub code_challenge: Option<String>,
    /// Must be `S256`. `plain` is refused unconditionally.
    pub code_challenge_method: Option<String>,
    /// OIDC Core §3.1.2.1. Bound into the ID token; optional only because
    /// `openid` scope itself is optional for a pure-OAuth client.
    pub nonce: Option<String>,
}

/// The identity the host has already authenticated, as far as the
/// authorization is concerned. Deliberately minimal: the provider does not
/// look the user up — the host did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedSubject {
    /// Stable, opaque, never re-used: the `sub` claim.
    pub sub: String,
    /// When the user last authenticated (OIDC `auth_time`). Carried into
    /// the grant so the ID token can say how fresh the login is.
    pub auth_time: DateTime<Utc>,
    /// The authenticating methods, most recent last — the `amr` claim
    /// (`["pwd"]`, `["pwd", "otp"]`, `["fido"]`, …). Free-form on purpose;
    /// the vocabulary is the deployment's.
    pub amr: Vec<String>,
    /// The authenticating context class — the `acr` claim. What the values
    /// mean is deployment policy; the provider only carries it.
    pub acr: Option<String>,
}

/// What the authorization endpoint decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizeDecision {
    /// Refused, and **safe to reflect** to the client's redirect URI: the
    /// client and the redirect in the request were both verified before this
    /// decision was made.
    Refused {
        error: ProtocolError,
        description: String,
    },
    /// Refused because the redirect in the request is **not** the one that
    /// was verified — a different URI, or none. There is no verified place
    /// to send an error, so the host must render it on the provider's own
    /// page. Kept apart from [`Self::Refused`] so a host cannot reflect it
    /// by handling one variant and forgetting the other (R2: the single
    /// `Refused` was the open-redirect channel).
    RefusedUnverifiableRedirect { description: String },
    /// Approved: park `grant`, send back a code for it.
    Approved(Box<super::code::CodeGrant>),
}

/// Validate an authorization request and build the grant to park.
///
/// `client` must already be the record returned by
/// [`resolve_redirect`](super::client::resolve_redirect) — that is what
/// makes every [`Refused`](AuthorizeDecision::Refused) here safe to
/// reflect.
///
/// `now` is a parameter so TTLs and `iat` are testable without a clock.
///
/// # Errors
///
/// Only [`ProviderError::Storage`] cannot arise here (no I/O); this returns
/// a decision rather than a `Result` because every refusal *is* a decision
/// the host can act on.
#[allow(clippy::too_many_arguments)]
pub fn authorize(
    client: &ClientRecord,
    request: &AuthorizeRequest,
    subject: &AuthenticatedSubject,
    consent: ConsentOutcome,
    now: DateTime<Utc>,
) -> AuthorizeDecision {
    let refuse = |error, description: &str| AuthorizeDecision::Refused {
        error,
        description: description.to_owned(),
    };

    // The redirect comes FIRST, before anything that could be reflected:
    // a refusal is only ever sent back to the request's redirect_uri, so
    // until that exact string has been matched against the registration
    // there is no verified destination and every refusal must take the
    // unverifiable shape (R3/R4: two reflectable checks used to precede
    // this, so an evil redirect collected a `Refused` the type called safe).
    match request.redirect_uri.as_deref() {
        Some(uri) if client.matches_redirect(uri) == RedirectMatch::Registered => {}
        _ => {
            return AuthorizeDecision::RefusedUnverifiableRedirect {
                description: "redirect_uri is not registered for this client".into(),
            };
        }
    }
    if request.response_type.as_deref() != Some("code") {
        return refuse(
            ProtocolError::UnsupportedResponseType,
            "response_type must be code",
        );
    }
    if !client.allows_grant(GrantType::AuthorizationCode) {
        return refuse(
            ProtocolError::UnauthorizedClient,
            "client may not use the authorization code grant",
        );
    }
    if let Err(err) = super::client::check_state(request.state.as_deref()) {
        if let Some(error) = err.redirectable() {
            return refuse(error, "state is unusable");
        }
    }
    if request.subject_is_empty(subject) {
        return refuse(ProtocolError::ServerError, "no authenticated subject");
    }

    // Scope: validated against the known set, then against the client's
    // allowance. `openid` scope requires a nonce so the ID token it unlocks
    // is bound to this request (OIDC Core §3.1.2.1: the nonce is optional
    // in the abstract, and mandatory for anyone who actually wants an ID
    // token to be worth verifying).
    let scope = match validate_scope(request.scope.as_deref().unwrap_or("")) {
        Ok(scope) => scope,
        Err(err) => {
            let (error, description) = match err {
                ProviderError::Redirectable { error, description } => (error, description),
                other => (ProtocolError::ServerError, other.to_string()),
            };
            return refuse(error, &description);
        }
    };
    if !client.allows_scope(&scope) {
        return refuse(
            ProtocolError::InvalidScope,
            "scope exceeds the client's allowance",
        );
    }
    let openid = super::scope_granted(&scope, "openid");
    if openid && request.nonce.as_deref().is_none_or(str::is_empty) {
        return refuse(
            ProtocolError::InvalidRequest,
            "openid scope requires a nonce",
        );
    }
    if let Some(nonce) = request.nonce.as_deref() {
        if nonce.len() > 256 || nonce.chars().any(char::is_control) {
            return refuse(ProtocolError::InvalidRequest, "nonce is unusable");
        }
    }

    // PKCE: mandatory unless the client is explicitly exempt, and S256 only.
    match (
        client.require_pkce(),
        request.code_challenge.as_deref(),
        request.code_challenge_method.as_deref(),
    ) {
        (true, None, _) => {
            return refuse(ProtocolError::InvalidRequest, "code_challenge is required");
        }
        (_, _, Some("plain")) => {
            return refuse(
                ProtocolError::InvalidRequest,
                "code_challenge_method must be S256",
            );
        }
        (_, Some(challenge), Some("S256")) => {
            if !(43..=128).contains(&challenge.len())
                || !challenge
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~'))
            {
                return refuse(
                    ProtocolError::InvalidRequest,
                    "code_challenge must be 43-128 unreserved characters",
                );
            }
        }
        (_, Some(_), Some(other)) => {
            return refuse(
                ProtocolError::InvalidRequest,
                &format!("unsupported code_challenge_method {other}"),
            );
        }
        (_, Some(_), None) => {
            return refuse(
                ProtocolError::InvalidRequest,
                "code_challenge_method must be S256",
            );
        }
        (_, None, Some(_)) => {
            return refuse(
                ProtocolError::InvalidRequest,
                "code_challenge_method without a code_challenge",
            );
        }
        (_, None, None) => {}
    }

    if consent == ConsentOutcome::Denied {
        return refuse(ProtocolError::AccessDenied, "the user denied the request");
    }

    AuthorizeDecision::Approved(Box::new(super::code::CodeGrant {
        client_id: client.client_id.clone(),
        redirect_uri: request.redirect_uri.clone().unwrap_or_default(),
        scope,
        sub: subject.sub.clone(),
        auth_time: subject.auth_time,
        amr: subject.amr.clone(),
        acr: subject.acr.clone(),
        nonce: request.nonce.clone(),
        kind: super::code::GrantKind::Code,
        code_challenge: request.code_challenge.clone(),
        authenticated_at: now,
        // A placeholder: `mint_code` stamps the real expiry from its TTL.
        // The grant is not redeemable until it has been minted and parked,
        // so this value is never consulted.
        expires_at: now,
    }))
}

impl AuthorizeRequest {
    fn subject_is_empty(&self, subject: &AuthenticatedSubject) -> bool {
        let _ = self;
        subject.sub.trim().is_empty()
    }
}

/// Whether the user agreed. The host asks (a consent screen, or a remembered
/// consent); the provider only acts on the answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentOutcome {
    Approved,
    Denied,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::provider::client::ClientRecord;

    fn client() -> ClientRecord {
        ClientRecord::confidential(
            "erp-admin",
            vec!["https://admin.example/api/auth/relay/callback".into()],
            "s3cret",
        )
    }

    fn request() -> AuthorizeRequest {
        AuthorizeRequest {
            response_type: Some("code".into()),
            client_id: Some("erp-admin".into()),
            redirect_uri: Some("https://admin.example/api/auth/relay/callback".into()),
            scope: Some("openid profile email".into()),
            state: Some("xyz".into()),
            code_challenge: Some("a".repeat(43)),
            code_challenge_method: Some("S256".into()),
            nonce: Some("n-1".into()),
        }
    }

    fn subject() -> AuthenticatedSubject {
        AuthenticatedSubject {
            sub: "user-1".into(),
            auth_time: Utc::now(),
            amr: vec!["pwd".into(), "otp".into()],
            acr: Some("mfa".into()),
        }
    }

    #[test]
    fn a_valid_request_is_approved_with_the_grant_parked() {
        let d = authorize(
            &client(),
            &request(),
            &subject(),
            ConsentOutcome::Approved,
            Utc::now(),
        );
        let AuthorizeDecision::Approved(grant) = d else {
            panic!("expected approval");
        };
        assert_eq!(grant.sub, "user-1");
        assert_eq!(grant.scope, "email openid profile");
        assert_eq!(grant.amr, vec!["pwd", "otp"]);
        assert_eq!(grant.acr.as_deref(), Some("mfa"));
        assert_eq!(grant.nonce.as_deref(), Some("n-1"));
        assert_eq!(
            grant.code_challenge.as_deref(),
            Some("a".repeat(43).as_str())
        );
    }

    /// Every reflectable refusal shape, as (request, expected error).
    fn refusal_table(base: AuthorizeRequest) -> Vec<(AuthorizeRequest, ProtocolError)> {
        vec![
            (
                AuthorizeRequest {
                    response_type: Some("token".into()),
                    ..base.clone()
                },
                ProtocolError::UnsupportedResponseType,
            ),
            (
                AuthorizeRequest {
                    response_type: None,
                    ..base.clone()
                },
                ProtocolError::UnsupportedResponseType,
            ),
            (
                AuthorizeRequest {
                    scope: Some("openid admin".into()),
                    ..base.clone()
                },
                ProtocolError::InvalidScope,
            ),
            (
                AuthorizeRequest {
                    nonce: None,
                    ..base.clone()
                },
                ProtocolError::InvalidRequest,
            ),
            (
                AuthorizeRequest {
                    nonce: Some(String::new()),
                    ..base.clone()
                },
                ProtocolError::InvalidRequest,
            ),
            // PKCE: missing, plain, malformed, method-only, challenge-only.
            (
                AuthorizeRequest {
                    code_challenge: None,
                    code_challenge_method: None,
                    ..base.clone()
                },
                ProtocolError::InvalidRequest,
            ),
            (
                AuthorizeRequest {
                    code_challenge_method: Some("plain".into()),
                    ..base.clone()
                },
                ProtocolError::InvalidRequest,
            ),
            (
                AuthorizeRequest {
                    code_challenge: Some("short".into()),
                    ..base.clone()
                },
                ProtocolError::InvalidRequest,
            ),
            (
                AuthorizeRequest {
                    code_challenge: Some("a".repeat(43)),
                    code_challenge_method: Some("S512".into()),
                    ..base.clone()
                },
                ProtocolError::InvalidRequest,
            ),
            (
                AuthorizeRequest {
                    code_challenge: None,
                    code_challenge_method: Some("S256".into()),
                    ..base.clone()
                },
                ProtocolError::InvalidRequest,
            ),
            (
                AuthorizeRequest {
                    code_challenge_method: None,
                    ..base.clone()
                },
                ProtocolError::InvalidRequest,
            ),
            (
                AuthorizeRequest {
                    state: Some("x".repeat(2000)),
                    ..base.clone()
                },
                ProtocolError::InvalidRequest,
            ),
        ]
    }

    #[test]
    fn the_refusals_that_may_be_reflected() {
        let base = request();
        let now = Utc::now();
        let cases = refusal_table(base);
        for (req, expected) in cases {
            let d = authorize(&client(), &req, &subject(), ConsentOutcome::Approved, now);
            let AuthorizeDecision::Refused { error, .. } = d else {
                panic!("expected a refusal for {req:?}");
            };
            assert_eq!(error, expected, "for {req:?}");
        }
    }

    /// An unverified redirect is a *different* refusal: it has nowhere safe
    /// to go, so it must never be reflected. This is the open-redirect
    /// defence as a type rather than a doc comment.
    #[test]
    fn an_unverified_redirect_is_never_reflectable() {
        let base = request();
        let evil = AuthorizeRequest {
            redirect_uri: Some("https://evil.example/cb".into()),
            ..base.clone()
        };
        let d = authorize(
            &client(),
            &evil,
            &subject(),
            ConsentOutcome::Approved,
            Utc::now(),
        );
        assert!(
            matches!(d, AuthorizeDecision::RefusedUnverifiableRedirect { .. }),
            "an unregistered redirect must not yield a reflectable refusal"
        );
        // And omitting the redirect when the client has exactly one
        // registered is also unverifiable here (the host may fill it in
        // before calling; this function does not).
        let none = AuthorizeRequest {
            redirect_uri: None,
            ..base
        };
        assert!(matches!(
            authorize(
                &client(),
                &none,
                &subject(),
                ConsentOutcome::Approved,
                Utc::now()
            ),
            AuthorizeDecision::RefusedUnverifiableRedirect { .. }
        ));
    }

    /// The order, pinned across the refusal table plus the three cases that
    /// are not in it (R4 found the first "fix" had duplicated the checks
    /// ahead of the redirect match; R5 found the pin covered only four
    /// refusals; R6 found the scope-allowance and nonce-shape branches were
    /// still outside it). Every `Refused` this mock reaches is replayed
    /// with an unregistered redirect and must take the unverifiable shape.
    ///
    /// Not covered here: the scope-allowance and nonce-length branches.
    /// They are exercised by `grant_and_scope_allowances` / the refusal
    /// table, but their ORDER is not pinned — a reviewer who moves either
    /// above the redirect match will not redden this case. Known, recorded
    /// in the body.
    #[test]
    fn an_unverified_redirect_wins_over_every_other_refusal() {
        let base = request();
        let now = Utc::now();
        let evil = "https://evil.example/cb";
        let with_evil = |r: AuthorizeRequest| AuthorizeRequest {
            redirect_uri: Some(evil.into()),
            ..r
        };
        let mut unchecked = Vec::new();
        for (req, _) in refusal_table(base) {
            let d = authorize(
                &client(),
                &with_evil(req),
                &subject(),
                ConsentOutcome::Approved,
                now,
            );
            assert!(
                matches!(d, AuthorizeDecision::RefusedUnverifiableRedirect { .. }),
                "an unregistered redirect must never yield a reflectable refusal: {d:?}"
            );
            unchecked.push(());
        }
        // Plus the refusals that are not in the table: a client without the
        // code grant, and a denied consent.
        let mut c = client();
        c.allowed_grants = vec![GrantType::RefreshToken];
        let d = authorize(
            &c,
            &with_evil(request()),
            &subject(),
            ConsentOutcome::Approved,
            now,
        );
        assert!(matches!(
            d,
            AuthorizeDecision::RefusedUnverifiableRedirect { .. }
        ));
        let d = authorize(
            &client(),
            &with_evil(request()),
            &subject(),
            ConsentOutcome::Denied,
            now,
        );
        assert!(matches!(
            d,
            AuthorizeDecision::RefusedUnverifiableRedirect { .. }
        ));
        // The two branches outside `refusal_table` that also return a
        // reflectable `Refused`: a scope beyond the client's allowance, and
        // an unusable nonce.
        let mut narrow = client();
        narrow.allowed_scopes = vec!["openid".into()];
        let mut r = with_evil(request());
        r.scope = Some("openid profile".into());
        assert!(matches!(
            authorize(&narrow, &r, &subject(), ConsentOutcome::Approved, now),
            AuthorizeDecision::RefusedUnverifiableRedirect { .. }
        ));
        let mut r = with_evil(request());
        r.nonce = Some("n".repeat(300));
        assert!(matches!(
            authorize(&client(), &r, &subject(), ConsentOutcome::Approved, now),
            AuthorizeDecision::RefusedUnverifiableRedirect { .. }
        ));
        // A nonce with a control character is the other half of that branch.
        let mut r = with_evil(request());
        r.nonce = Some("a\nb".into());
        assert!(matches!(
            authorize(&client(), &r, &subject(), ConsentOutcome::Approved, now),
            AuthorizeDecision::RefusedUnverifiableRedirect { .. }
        ));
        // And an empty subject (ServerError when the redirect is fine).
        let empty = AuthenticatedSubject {
            sub: "  ".into(),
            ..subject()
        };
        let d = authorize(
            &client(),
            &with_evil(request()),
            &empty,
            ConsentOutcome::Approved,
            now,
        );
        assert!(matches!(
            d,
            AuthorizeDecision::RefusedUnverifiableRedirect { .. }
        ));
        assert!(!unchecked.is_empty());
    }

    /// A plain-text challenge is refused even for a PKCE-exempt client: the
    /// exemption is about *having* PKCE, never about leaking the verifier.
    #[test]
    fn plain_is_refused_even_for_an_exempt_client() {
        let mut c = client();
        c.exempt_from_pkce()
            .expect("confidential client may be exempted");
        let req = AuthorizeRequest {
            code_challenge_method: Some("plain".into()),
            ..request()
        };
        let d = authorize(&c, &req, &subject(), ConsentOutcome::Approved, Utc::now());
        assert!(matches!(
            d,
            AuthorizeDecision::Refused {
                error: ProtocolError::InvalidRequest,
                ..
            }
        ));
    }

    #[test]
    fn an_exempt_client_may_omit_pkce_entirely() {
        let mut c = client();
        c.exempt_from_pkce()
            .expect("confidential client may be exempted");
        let req = AuthorizeRequest {
            code_challenge: None,
            code_challenge_method: None,
            ..request()
        };
        assert!(matches!(
            authorize(&c, &req, &subject(), ConsentOutcome::Approved, Utc::now()),
            AuthorizeDecision::Approved(_)
        ));
    }

    #[test]
    fn a_denied_consent_is_access_denied() {
        let d = authorize(
            &client(),
            &request(),
            &subject(),
            ConsentOutcome::Denied,
            Utc::now(),
        );
        assert!(matches!(
            d,
            AuthorizeDecision::Refused {
                error: ProtocolError::AccessDenied,
                ..
            }
        ));
    }

    #[test]
    fn a_client_without_the_code_grant_is_refused() {
        let mut c = client();
        c.allowed_grants = vec![GrantType::RefreshToken];
        let d = authorize(
            &c,
            &request(),
            &subject(),
            ConsentOutcome::Approved,
            Utc::now(),
        );
        assert!(matches!(
            d,
            AuthorizeDecision::Refused {
                error: ProtocolError::UnauthorizedClient,
                ..
            }
        ));
    }

    #[test]
    fn an_empty_subject_is_a_server_error_not_a_redirect() {
        let s = AuthenticatedSubject {
            sub: "  ".into(),
            ..subject()
        };
        let d = authorize(
            &client(),
            &request(),
            &s,
            ConsentOutcome::Approved,
            Utc::now(),
        );
        assert!(matches!(
            d,
            AuthorizeDecision::Refused {
                error: ProtocolError::ServerError,
                ..
            }
        ));
    }
}
