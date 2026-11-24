//! UserInfo: the standard profile claims, trimmed to what was granted.
//!
//! OIDC Core §5.3: the response is a JSON object of the claims the scope
//! unlocks. `profile` unlocks the display fields, `email` unlocks the two
//! email fields, and **nothing else is ever emitted** — a UserInfo endpoint
//! that answers the whole account regardless of scope turns every client
//! into a full-profile reader and makes the scope request decorative.
//!
//! The subject comes from the access token the client presents; the host
//! looks the account up. This module is the shaping and the trimming.

use serde::{Deserialize, Serialize};

use super::scope_granted;

/// The account facts the host supplies for a verified subject. Every field
/// is optional because every field is something a deployment may not have;
/// what gets emitted is decided by the scope, not by what is present.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubjectProfile {
    pub sub: String,
    pub preferred_username: Option<String>,
    pub name: Option<String>,
    pub picture: Option<String>,
    pub locale: Option<String>,
    pub email: Option<String>,
    /// Required by the spec whenever `email` is emitted. The host says
    /// whether it has verified the address; an unverified address is still
    /// emitted (clients may want it) but never claimed as verified.
    pub email_verified: Option<bool>,
}

/// The UserInfo response: only the granted claims, as a JSON object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserInfoClaims(pub serde_json::Map<String, serde_json::Value>);

impl UserInfoClaims {
    /// Shape the response for `profile` under `scope`.
    ///
    /// `sub` is always present (OIDC Core §5.3.2). The rest is opt-in by
    /// scope; an empty profile scope yields exactly `{ "sub": … }`.
    #[must_use]
    pub fn for_scope(profile: &SubjectProfile, scope: &str) -> Self {
        let mut out = serde_json::Map::new();
        out.insert("sub".into(), profile.sub.clone().into());
        if scope_granted(scope, "profile") {
            for (claim, value) in [
                ("preferred_username", &profile.preferred_username),
                ("name", &profile.name),
                ("picture", &profile.picture),
                ("locale", &profile.locale),
            ] {
                if let Some(v) = value {
                    out.insert(claim.into(), v.clone().into());
                }
            }
        }
        if scope_granted(scope, "email") {
            if let Some(v) = &profile.email {
                out.insert("email".into(), v.clone().into());
            }
            if let Some(v) = profile.email_verified {
                out.insert("email_verified".into(), v.into());
            }
        }
        Self(out)
    }

    /// The claims as a JSON object, ready to serialise.
    #[must_use]
    pub fn into_json(self) -> serde_json::Value {
        serde_json::Value::Object(self.0)
    }
}

/// Convenience: shape the response directly.
#[must_use]
pub fn userinfo(profile: &SubjectProfile, scope: &str) -> serde_json::Value {
    UserInfoClaims::for_scope(profile, scope).into_json()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full() -> SubjectProfile {
        SubjectProfile {
            sub: "user-1".into(),
            preferred_username: Some("langyo".into()),
            name: Some("Lang Yo".into()),
            picture: Some("https://avatar.example/u.png".into()),
            locale: Some("zh-Hans".into()),
            email: Some("me@example.com".into()),
            email_verified: Some(true),
        }
    }

    #[test]
    fn sub_is_always_present_and_nothing_else_without_scope() {
        let v = userinfo(&full(), "openid");
        assert_eq!(v, serde_json::json!({ "sub": "user-1" }));
    }

    #[test]
    fn profile_scope_unlocks_only_profile_claims() {
        let v = userinfo(&full(), "openid profile");
        assert_eq!(v["preferred_username"], "langyo");
        assert_eq!(v["name"], "Lang Yo");
        assert_eq!(v["picture"], "https://avatar.example/u.png");
        assert_eq!(v["locale"], "zh-Hans");
        // MUT:userinfo-scope-trim — an untrimmed endpoint would leak these.
        assert!(v.get("email").is_none());
        assert!(v.get("email_verified").is_none());
    }

    #[test]
    fn email_scope_unlocks_both_email_claims_and_nothing_else() {
        let v = userinfo(&full(), "openid email");
        assert_eq!(v["email"], "me@example.com");
        assert_eq!(v["email_verified"], true);
        assert!(v.get("preferred_username").is_none());
        assert!(v.get("name").is_none());
    }

    #[test]
    fn absent_profile_fields_are_omitted_not_null() {
        let p = SubjectProfile {
            sub: "user-1".into(),
            email: Some("me@example.com".into()),
            email_verified: None,
            ..Default::default()
        };
        let v = userinfo(&p, "openid profile email");
        assert_eq!(v.as_object().unwrap().len(), 2, "{v}");
        assert_eq!(v["sub"], "user-1");
        assert_eq!(v["email"], "me@example.com");
        // No `null` placeholders: a client reading `name` must see absence,
        // not a JSON null it has to special-case.
        assert!(v.get("name").is_none());
        assert!(v.get("email_verified").is_none());
    }

    #[test]
    fn an_unverified_email_is_emitted_as_such_never_claimed_verified() {
        let p = SubjectProfile {
            sub: "user-1".into(),
            email: Some("me@example.com".into()),
            email_verified: Some(false),
            ..Default::default()
        };
        let v = userinfo(&p, "email");
        assert_eq!(v["email_verified"], false);
    }

    /// Scope is token-exact: `profiles` does not unlock `profile`.
    #[test]
    fn scope_matching_is_exact() {
        let v = userinfo(&full(), "openid profiles email");
        assert!(v.get("name").is_none());
        assert_eq!(v["email"], "me@example.com");
    }
}
