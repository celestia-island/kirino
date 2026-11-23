//! External identities linked to local accounts.
//!
//! A federated or relay-mode deployment proves *who the visitor is* somewhere
//! else — a third-party provider, the central login site — and then has to
//! answer one question of its own: **which local account does that map to?**
//!
//! The answer is an [`ExternalIdentity`] (provider, optional issuer, subject)
//! joined to a local user id through an [`ExternalIdentityStore`]. Three rules
//! shape the model:
//!
//! * **The subject is the key, never the email.** Email addresses change,
//!   get reassigned and collide across realms; the provider's stable subject
//!   (`sub`, an opaque account id) is the only join key this crate accepts.
//! * **One external identity belongs to exactly one local account.** A second
//!   link to a different account is refused — never merged, never silently
//!   re-pointed. Merging accounts is a product decision the host makes
//!   deliberately, not a side effect of a sign-in.
//! * **No implicit provisioning.** The store only records links; deciding
//!   whether an unknown identity becomes a new account, is refused, or is
//!   offered a bind-existing-account step is the host's policy (see the
//!   login service's `complete_login`, which is the single entry every
//!   externally-authenticated sign-in goes through once the account is known).
//!
//! [`InMemoryExternalIdentityStore`] is the reference implementation and the
//! test double; a host backs the same trait with its own tables.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::error::KirinoError;

/// The stable key of an external identity.
///
/// `subject` is the provider's opaque, stable account id — never an email
/// address. `issuer` disambiguates providers that are addressed by URL (an
/// OIDC issuer); opaque providers leave it `None`, and `None` does not equal
/// `Some(anything)` when comparing two identities.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ExternalIdentity {
    /// The host's provider id as it names it (`"github"`, an internal name, …).
    pub provider: String,
    /// The issuer URL for URL-addressed providers; `None` for opaque ones.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// The provider's stable subject for this account.
    pub subject: String,
}

impl ExternalIdentity {
    /// An identity at an opaque (non-URL-addressed) provider.
    #[must_use]
    pub fn opaque(provider: impl Into<String>, subject: impl Into<String>) -> Self {
        Self {
            provider: provider.into(),
            issuer: None,
            subject: subject.into(),
        }
    }

    /// Refuse a key that cannot join anything: an empty provider or subject.
    ///
    /// # Errors
    ///
    /// [`KirinoError::Validation`] naming the empty field.
    pub fn validate(&self) -> Result<()> {
        if self.provider.trim().is_empty() {
            return Err(
                KirinoError::Validation("external identity provider is empty".into()).into(),
            );
        }
        if self.subject.trim().is_empty() {
            return Err(
                KirinoError::Validation("external identity subject is empty".into()).into(),
            );
        }
        // A present-but-blank issuer, or one with no host, is refused rather
        // than silently taken for an opaque provider: `None` is the spelling.
        if self
            .issuer
            .as_deref()
            .is_some_and(|issuer| canonical_issuer(issuer).is_none())
        {
            return Err(KirinoError::Validation(
                "external identity issuer is blank or has no host (use None for an opaque provider)"
                    .into(),
            )
            .into());
        }
        Ok(())
    }

    /// The canonical form every join key is built from.
    ///
    /// Trims `provider` and `subject`, and canonicalises `issuer` (trimmed,
    /// trailing slashes removed, scheme and host lower-cased). Two identities
    /// that differ only by such spelling are the **same** identity — without
    /// this, `" idp "` and `"idp"` would be two keys and two accounts could
    /// each own "the same" external identity. Every
    /// [`ExternalIdentityStore`] keys on this form.
    #[must_use]
    pub fn normalised(&self) -> Self {
        Self {
            provider: self.provider.trim().to_owned(),
            issuer: self.issuer.as_deref().and_then(canonical_issuer),
            subject: self.subject.trim().to_owned(),
        }
    }
}

/// Canonical spelling of an issuer URL as far as it matters for identity:
/// trimmed, without trailing slashes, with the scheme and host lower-cased.
/// The path keeps its case (paths are case-sensitive).
///
/// `None` when nothing identifies an issuer survives: a blank value, or a
/// scheme with no host. Such a value is refused by
/// [`ExternalIdentity::validate`]; [`ExternalIdentity::normalised`] also
/// collapses it to the opaque (`None`) form, so a store that skipped
/// validation still cannot mint a third key beside `None`.
fn canonical_issuer(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    // A bare scheme ("https:" once the slashes are stripped) names no host.
    if let Some((scheme, "")) = trimmed.split_once(':') {
        let scheme_like = !scheme.is_empty()
            && scheme
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
        if scheme_like {
            return None;
        }
    }
    match trimmed.split_once("://") {
        Some((scheme, rest)) => {
            let (host, path) = match rest.find('/') {
                Some(at) => (&rest[..at], &rest[at..]),
                None => (rest, ""),
            };
            if host.is_empty() {
                return None;
            }
            Some(format!(
                "{}://{}{}",
                scheme.to_ascii_lowercase(),
                host.to_ascii_lowercase(),
                path
            ))
        }
        None => Some(trimmed.to_owned()),
    }
}

/// A stored link between an external identity and a local account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkedAccount {
    pub identity: ExternalIdentity,
    pub user_id: Uuid,
    pub created_at: DateTime<Utc>,
    /// The last sign-in that arrived through this link, if any was recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_login_at: Option<DateTime<Utc>>,
}

/// What [`ExternalIdentityStore::link`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkOutcome {
    /// The link was created.
    Linked,
    /// The identity was already linked to this same account (idempotent).
    AlreadyLinked,
}

/// Persistence for external identities.
///
/// Implementations must make `link` atomic with respect to the identity key:
/// two concurrent links of the same identity to different accounts must yield
/// exactly one [`LinkOutcome::Linked`] and one conflict. The key is always
/// [`ExternalIdentity::normalised`], so spellings that differ only by
/// surrounding whitespace, a trailing slash or the case of the issuer's
/// scheme/host refer to one identity.
#[async_trait]
pub trait ExternalIdentityStore: Send + Sync {
    /// The local account an external identity is linked to, if any.
    async fn find_user(&self, identity: &ExternalIdentity) -> Result<Option<LinkedAccount>>;
    /// Link an identity to an account.
    ///
    /// # Errors
    ///
    /// [`KirinoError::ConstraintViolation`] when the identity is already
    /// linked to a **different** account; linking twice to the same account is
    /// [`LinkOutcome::AlreadyLinked`], not an error.
    async fn link(&self, identity: &ExternalIdentity, user_id: Uuid) -> Result<LinkOutcome>;
    /// Remove a link. `Ok(false)` when it did not exist.
    async fn unlink(&self, identity: &ExternalIdentity, user_id: Uuid) -> Result<bool>;
    /// Every external identity linked to an account.
    async fn list_for_user(&self, user_id: Uuid) -> Result<Vec<LinkedAccount>>;
    /// Record that a sign-in arrived through a link. A no-op for an unknown
    /// identity (the link may have been removed meanwhile).
    async fn record_login(&self, identity: &ExternalIdentity) -> Result<()>;
}

/// In-memory [`ExternalIdentityStore`]: the reference implementation and the
/// test double.
#[derive(Debug, Clone, Default)]
pub struct InMemoryExternalIdentityStore {
    links: Arc<RwLock<HashMap<ExternalIdentity, LinkedAccount>>>,
}

impl InMemoryExternalIdentityStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl ExternalIdentityStore for InMemoryExternalIdentityStore {
    async fn find_user(&self, identity: &ExternalIdentity) -> Result<Option<LinkedAccount>> {
        Ok(self.links.read().await.get(&identity.normalised()).cloned())
    }

    async fn link(&self, identity: &ExternalIdentity, user_id: Uuid) -> Result<LinkOutcome> {
        identity.validate()?;
        let key = identity.normalised();
        // One write lock spans the lookup and the insert: the conflict check and
        // the link are a single step, so two concurrent links of one identity to
        // two accounts cannot both succeed.
        let mut links = self.links.write().await;
        if let Some(existing) = links.get(&key) {
            if existing.user_id == user_id {
                return Ok(LinkOutcome::AlreadyLinked);
            }
            return Err(KirinoError::ConstraintViolation(format!(
                "external identity is already linked to another account ({})",
                existing.user_id
            ))
            .into());
        }
        links.insert(
            key.clone(),
            LinkedAccount {
                identity: key,
                user_id,
                created_at: Utc::now(),
                last_login_at: None,
            },
        );
        Ok(LinkOutcome::Linked)
    }

    async fn unlink(&self, identity: &ExternalIdentity, user_id: Uuid) -> Result<bool> {
        let mut links = self.links.write().await;
        let key = identity.normalised();
        // Only the owner may remove a link: a non-owner's call must leave the
        // link in place, so the owner check precedes the removal.
        if links.get(&key).is_some_and(|link| link.user_id == user_id) {
            links.remove(&key);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn list_for_user(&self, user_id: Uuid) -> Result<Vec<LinkedAccount>> {
        let mut found: Vec<LinkedAccount> = self
            .links
            .read()
            .await
            .values()
            .filter(|link| link.user_id == user_id)
            .cloned()
            .collect();
        // Stable order for callers that show the list: oldest link first, with
        // the key as the tie-breaker so links created within the same
        // timestamp still come out in a reproducible order.
        found.sort_by(|a, b| {
            (a.created_at, &a.identity.provider, &a.identity.subject).cmp(&(
                b.created_at,
                &b.identity.provider,
                &b.identity.subject,
            ))
        });
        Ok(found)
    }

    async fn record_login(&self, identity: &ExternalIdentity) -> Result<()> {
        let mut links = self.links.write().await;
        if let Some(link) = links.get_mut(&identity.normalised()) {
            link.last_login_at = Some(Utc::now());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(provider: &str, subject: &str) -> ExternalIdentity {
        ExternalIdentity::opaque(provider, subject)
    }

    #[tokio::test]
    async fn link_is_idempotent_per_account_and_exclusive_across_accounts() {
        let store = InMemoryExternalIdentityStore::new();
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let who = identity("example-idp", "sub-1");

        assert_eq!(store.find_user(&who).await.expect("lookup"), None);
        assert_eq!(
            store.link(&who, a).await.expect("first link"),
            LinkOutcome::Linked
        );
        assert_eq!(
            store.link(&who, a).await.expect("same account"),
            LinkOutcome::AlreadyLinked
        );
        // MUT:exclusive-link — a second account must never take over an identity.
        let refused = store
            .link(&who, b)
            .await
            .expect_err("another account is refused");
        assert!(
            refused
                .to_string()
                .contains("already linked to another account"),
            "unexpected error: {refused}"
        );
        let stored = store
            .find_user(&who)
            .await
            .expect("lookup")
            .expect("linked");
        assert_eq!(stored.user_id, a, "the first owner keeps the identity");
    }

    #[tokio::test]
    async fn subject_is_the_key_and_a_missing_issuer_is_not_an_issuer() {
        let store = InMemoryExternalIdentityStore::new();
        let user = Uuid::new_v4();
        // Same provider, same subject text, different issuer: two identities.
        let opaque = ExternalIdentity {
            provider: "example-idp".to_owned(),
            issuer: None,
            subject: "s".to_owned(),
        };
        let issued = ExternalIdentity {
            provider: "example-idp".to_owned(),
            issuer: Some("https://idp.example".to_owned()),
            subject: "s".to_owned(),
        };
        // MUT:issuer-discriminates — the issuer is part of the key: `find_user(&issued)`
        // below must return the issued form, and `opaque` must stay a different identity.
        let other_subject = identity("example-idp", "sub-2");
        for who in [&opaque, &issued, &other_subject] {
            store.link(who, user).await.expect("link");
        }
        assert_eq!(store.list_for_user(user).await.expect("list").len(), 3);
        assert_eq!(
            store
                .find_user(&issued)
                .await
                .expect("lookup")
                .expect("linked")
                .identity,
            issued
        );
        assert_ne!(opaque, issued);
    }

    #[tokio::test]
    async fn empty_keys_are_refused_before_they_are_stored() {
        let store = InMemoryExternalIdentityStore::new();
        let user = Uuid::new_v4();
        for bad in [
            identity("", "s"),
            identity(" ", "s"),
            identity("example-idp", ""),
            identity("example-idp", "  "),
        ] {
            assert!(
                store.link(&bad, user).await.is_err(),
                "{bad:?} must be refused"
            );
        }
        assert!(store.list_for_user(user).await.expect("list").is_empty());
    }

    #[tokio::test]
    async fn spellings_that_differ_only_by_padding_or_issuer_case_are_one_identity() {
        // MUT:normalised-key — without normalisation these are three keys and three
        // accounts could each own "the same" identity; they must collapse to one.
        let store = InMemoryExternalIdentityStore::new();
        let (a, b, c) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let padded = ExternalIdentity {
            provider: " example-idp ".to_owned(),
            issuer: Some(" HTTPS://IDP.Example/tenants/A/ ".to_owned()),
            subject: " sub-1\t".to_owned(),
        };
        let slash = ExternalIdentity {
            provider: "example-idp".to_owned(),
            issuer: Some("https://idp.example/tenants/A//".to_owned()),
            subject: "sub-1".to_owned(),
        };
        let lower = ExternalIdentity {
            provider: "example-idp".to_owned(),
            issuer: Some("https://idp.example/tenants/A".to_owned()),
            subject: "sub-1".to_owned(),
        };

        store.link(&padded, a).await.expect("first link");
        assert!(store
            .link(&slash, b)
            .await
            .expect_err("second owner is refused")
            .to_string()
            .contains("already linked"));
        assert!(store
            .link(&lower, c)
            .await
            .expect_err("third owner is refused")
            .to_string()
            .contains("already linked"));
        let stored = store
            .find_user(&lower)
            .await
            .expect("lookup")
            .expect("linked");
        assert_eq!(stored.user_id, a, "the first owner keeps the identity");
        assert_eq!(
            stored.identity, lower,
            "the stored key is the canonical spelling"
        );
        assert_eq!(store.list_for_user(a).await.expect("list").len(), 1);

        // The issuer still discriminates: a different tenant is a different identity.
        let other_tenant = ExternalIdentity {
            issuer: Some("https://idp.example/tenants/B".to_owned()),
            ..lower.clone()
        };
        store
            .link(&other_tenant, b)
            .await
            .expect("another tenant is another identity");
        assert_eq!(store.list_for_user(b).await.expect("list").len(), 1);
    }

    #[test]
    fn a_blank_issuer_is_refused_not_normalised_to_an_empty_key() {
        // MUT:blank-issuer — a present-but-blank issuer (or one with no host) is
        // refused; an opaque provider has to say `None`. And even without that
        // check the key collapses to `None`, so no third key can exist.
        for blank in ["", "   ", "/", "///", "https://", "https:///"] {
            let who = ExternalIdentity {
                provider: "example-idp".to_owned(),
                issuer: Some(blank.to_owned()),
                subject: "sub-1".to_owned(),
            };
            let refused = who.validate().expect_err("blank issuer is refused");
            assert!(
                refused.to_string().contains("issuer is blank"),
                "{blank:?}: {refused}"
            );
            assert_eq!(
                who.normalised().issuer,
                None,
                "{blank:?} collapses to the opaque form"
            );
        }
        ExternalIdentity::opaque("example-idp", "sub-1")
            .validate()
            .expect("None is the spelling for an opaque provider");
    }

    #[tokio::test]
    async fn unlink_only_removes_the_owners_link_and_records_logins() {
        let store = InMemoryExternalIdentityStore::new();
        let (owner, other) = (Uuid::new_v4(), Uuid::new_v4());
        let who = identity("example-idp", "sub-1");
        store.link(&who, owner).await.expect("link");

        store.record_login(&who).await.expect("record");
        let linked = store
            .find_user(&who)
            .await
            .expect("lookup")
            .expect("linked");
        assert!(linked.last_login_at.is_some(), "the sign-in was recorded");

        // MUT:unlink-owner — unlinking with a non-owner id must not remove the link.
        assert!(!store.unlink(&who, other).await.expect("not the owner"));
        assert!(store.find_user(&who).await.expect("lookup").is_some());
        assert!(store.unlink(&who, owner).await.expect("owner"));
        assert_eq!(store.find_user(&who).await.expect("lookup"), None);
        assert!(!store.unlink(&who, owner).await.expect("already gone"));
        // Recording a login for an unknown identity is a no-op, not an error.
        store.record_login(&who).await.expect("unknown identity");
    }

    #[tokio::test]
    async fn list_for_user_is_oldest_first_and_scoped_to_the_user() {
        let store = InMemoryExternalIdentityStore::new();
        let (u1, u2) = (Uuid::new_v4(), Uuid::new_v4());
        store.link(&identity("a", "1"), u1).await.expect("link");
        store.link(&identity("b", "2"), u2).await.expect("link");
        store.link(&identity("c", "3"), u1).await.expect("link");
        let listed = store.list_for_user(u1).await.expect("list");
        assert_eq!(
            listed
                .iter()
                .map(|l| l.identity.provider.as_str())
                .collect::<Vec<_>>(),
            ["a", "c"]
        );
        assert!(listed
            .windows(2)
            .all(|w| w[0].created_at <= w[1].created_at));
    }

    #[tokio::test]
    async fn concurrent_links_of_one_identity_admit_exactly_one_owner() {
        let store = InMemoryExternalIdentityStore::new();
        let who = identity("example-idp", "contested");
        let owners: Vec<Uuid> = (0..16).map(|_| Uuid::new_v4()).collect();
        let mut handles = Vec::new();
        for owner in &owners {
            let store = store.clone();
            let who = who.clone();
            let owner = *owner;
            handles.push(tokio::spawn(async move {
                store.link(&who, owner).await.is_ok()
            }));
        }
        let mut admitted = 0;
        for handle in handles {
            if handle.await.expect("task") {
                admitted += 1;
            }
        }
        // MUT:atomic-link — the conflict check and the insert are one critical section.
        assert_eq!(admitted, 1, "exactly one account may own the identity");
    }
}
