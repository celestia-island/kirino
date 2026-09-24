use anyhow::Result;
use std::collections::HashSet;

use async_trait::async_trait;

/// One permission the RBAC engine can decide on, keyed by
/// [`name`](Permission::name).
///
/// Security semantics: the name is the persistence key, the audit label and
/// the cache key, so two distinct permissions must never share one - a
/// collision would let a grant for one permission satisfy a check for the
/// other. `Eq`/`Hash` define permission identity inside deny sets, grant sets
/// and cache lookups.
///
/// Only `name`, `is_branch` and `ancestry_names` are read by the in-crate
/// decision paths (`rbac::engine`, `rbac::scope`); the remaining methods are
/// extension points for registries, listings and UI. Every method except
/// `name` defaults to the non-widening answer (`None`, empty, exact-name
/// match), so an implementor that forgets an override gains no authority.
pub trait Permission: Eq + std::hash::Hash + Clone + Send + Sync + 'static {
    /// Stable, unique name of this permission. Used as the store key and the
    /// cache key, so it must be unique within a registry and must not be
    /// renamed while persisted grants reference it.
    fn name(&self) -> &str;

    /// Advisory domain label ("deploy", "user", ...) used for grouping and
    /// browsing. An empty string means "no domain declared"; no decision path
    /// gates access on it.
    fn domain(&self) -> &'static str {
        ""
    }

    /// Path components of this permission inside its domain, e.g.
    /// `["deploy", "read"]`. Advisory and unused by the decision paths;
    /// consumers use it for display or to build
    /// [`ancestry_names`](Permission::ancestry_names).
    fn path_segments(&self) -> &[&str] {
        &[]
    }

    /// Names of this permission plus every ancestor it descends from. This is
    /// what makes wildcard/branch grants work: a grant whose
    /// [`is_branch`](Permission::is_branch) is true matches any requested
    /// permission listing the grant name here (`rbac::scope`). The default
    /// lists only the permission itself, so it cannot match an ancestor.
    fn ancestry_names(&self) -> Vec<&str> {
        vec![self.name()]
    }

    /// Whether a pattern selects this permission. The default is exact name
    /// equality only: overrides that add wildcards widen every pattern-based
    /// lookup, so they must be anchored and covered by tests. Not read by the
    /// in-crate decision paths.
    fn matches_pattern(&self, pattern: &str) -> bool {
        pattern == self.name()
    }

    /// Whether this permission has no children. Defaults to `true`, so branch
    /// status must be declared explicitly; the flag is descriptive and grants
    /// nothing by itself.
    fn is_leaf(&self) -> bool {
        true
    }

    /// Whether this permission may act as an ancestor for other permissions,
    /// i.e. whether its name in another permission's
    /// [`ancestry_names`](Permission::ancestry_names) satisfies that
    /// permission's check. Defaults to `false`: nothing is treated as a
    /// wildcard grant unless explicitly declared, so the default cannot widen
    /// an existing grant.
    fn is_branch(&self) -> bool {
        false
    }

    /// Every leaf permission known to this type.
    /// `RbacEngine::resolve_effective_permissions` enumerates this list, so a
    /// truncated (or default, empty) list under-reports what a subject holds:
    /// it hides grants from any listing built on it rather than granting extra
    /// authority.
    fn all() -> Vec<Self>
    where
        Self: Sized,
    {
        Vec::new()
    }

    /// Domain names known to this type, for grouping and browsing. The default
    /// is empty; it gates no decision.
    fn all_domains() -> Vec<&'static str> {
        Vec::new()
    }

    /// Parses a permission from its serialized path. The default returns
    /// `None`, so an implementor that does not override it maps every
    /// untrusted path to "unknown" instead of to some permission. Callers must
    /// treat `None` as a rejection, never as "skip this rule".
    fn from_path(_path: &str) -> Option<Self>
    where
        Self: Sized,
    {
        None
    }

    /// Expands a domain name into the permissions it contains, for bulk
    /// listing or bulk granting. The default expands to nothing; an override
    /// that returns more than intended silently broadens any caller that
    /// grants a whole domain, so keep the mapping explicit and tested.
    fn expand_domain(_domain_str: &str) -> Vec<Self>
    where
        Self: Sized,
    {
        Vec::new()
    }
}

/// A principal that role assignments, denies and permission cache entries are
/// keyed by.
///
/// Security semantics: [`subject_id`](Subject::subject_id) is the identity key
/// for assignment rows, deny sets and cache entries, so equality and hashing
/// must agree with it - two values that compare equal must denote the same
/// principal, otherwise a lookup can return another principal's authority.
/// [`subject_type`](Subject::subject_type) gates delegation
/// ([`Delegatable`](crate::rbac::identity_subject::Delegatable) accepts a
/// delegate only when it reports `"user"`).
pub trait Subject: Eq + std::hash::Hash + Clone + Send + Sync + 'static {
    /// The stable identity string used for assignment rows, deny sets and
    /// cache keys. Must be unique per principal and never reused for a
    /// different principal.
    #[must_use]
    fn subject_id(&self) -> &str;

    /// Discriminator for the kind of principal (`"user"`, `"service"`,
    /// `"anonymous"`, `"temporary"`). The default `"user"` means an implementor
    /// that does not override it is treated as a delegable user by
    /// `Delegatable::can_delegate_to`.
    #[must_use]
    fn subject_type(&self) -> &'static str {
        "user"
    }

    /// Infallible conversion from a stored subject id.
    ///
    /// Error contract as implemented by the shipped subjects: `String` and
    /// `StringSubject` return the id unchanged (every string is accepted, no
    /// validation, no normalization), while `IdentitySubject` parses a UUID and
    /// on failure logs at error level and falls back to an ANONYMOUS identity
    /// with the nil UUID. That fallback is not an authenticated principal and
    /// never carries assignments; callers converting untrusted input must use
    /// [`try_from_subject_id`](Subject::try_from_subject_id) instead.
    #[must_use]
    fn from_subject_id(id: &str) -> Self;

    /// Fallible, error-preserving conversion from a stored subject id: the
    /// path that session persistence uses when rehydrating rows.
    ///
    /// The default delegates to
    /// [`from_subject_id`](Subject::from_subject_id) and therefore always
    /// succeeds, which is correct for infallible id types and wrong for
    /// UUID-backed ones; `IdentitySubject` overrides it to return `Err` on a
    /// malformed UUID. An `Err` here means "identity is unknown", which callers
    /// treat as a failed load (fail-closed), not as an ordinary permission
    /// denial.
    fn try_from_subject_id(id: &str) -> Result<Self> {
        Ok(Self::from_subject_id(id))
    }
}

impl Subject for String {
    /// The whole string is the subject id: no parsing and no validation, so
    /// callers must not hand this type untrusted, unnormalized text.
    fn subject_id(&self) -> &str {
        self
    }

    /// Accepts any string as an id. This cannot fail and performs no
    /// validation; prefer a validated subject type for untrusted input.
    fn from_subject_id(id: &str) -> Self {
        id.to_string()
    }

    /// Always `Ok`: the error-preserving contract is vacuous for this type.
    fn try_from_subject_id(id: &str) -> Result<Self> {
        Ok(id.to_string())
    }
}

/// A named set of permissions that can be assigned to subjects.
///
/// Security semantics: a role is the unit of assignment, and its permission
/// set is exactly the authority the engine grants with
/// [`GrantSource::RoleDefault`]
/// when a subject holds it (grants are additive; nothing here subtracts).
/// Role names are persisted in assignment rows, so renaming a role silently
/// orphans existing assignments unless the rows are migrated too.
pub trait Role<P: Permission>: Clone + Send + Sync + 'static {
    /// The role's unique, persisted name; the key assignment rows refer to.
    #[must_use]
    fn role_name(&self) -> &str;
    /// The full authority of this role. The engine grants every permission in
    /// this set when the role is held - an over-broad set is over-broad
    /// authority, and there is no per-permission deny inside a role.
    #[must_use]
    fn permissions(&self) -> &HashSet<P>;
}

/// Read-only catalogue of the permissions a deployment knows about.
pub trait PermissionRegistry<P: Permission>: Send + Sync {
    /// Snapshot of every known permission, used when enumerating or filtering
    /// a subject's authority. A permission missing from this set is not
    /// recognized by the engine even if it is granted in a store row.
    #[must_use]
    fn all_permissions(&self) -> HashSet<P>;
    /// Looks a permission up by name. `None` means "unknown name": callers
    /// must reject the request rather than skip it, since silently skipping an
    /// unknown permission turns a typo into an unenforced rule.
    #[must_use]
    fn get_permission(&self, name: &str) -> Option<P>;
}

/// Read-only view of role definitions, optionally with a parent hierarchy.
pub trait RoleRegistry<P: Permission>: Send + Sync {
    /// Permissions of one role. `None` means the role is unknown (for example a
    /// stale assignment row naming a deleted role) and contributes no authority:
    /// the engine skips it, so a renamed or deleted role can silently strip
    /// privileges but never add them.
    #[must_use]
    fn get_role_permissions(&self, role_name: &str) -> Option<HashSet<P>>;
    /// Parent roles of one role. The default is "no parents", i.e. no implicit
    /// inheritance at all; an override introduces hierarchy traversal, which
    /// must stay cycle-safe (`rbac::hierarchy::detect_cycle`) because that
    /// traversal is what decides which role defaults apply.
    #[must_use]
    fn role_parents(&self, _role_name: &str) -> Vec<String> {
        Vec::new()
    }
    /// Every role name known here, for listings and admin UI only. It is not an
    /// authorization source: being listed grants nothing.
    #[must_use]
    fn list_role_names(&self) -> Vec<String>;
}

/// Per-subject authority storage: role assignments, extra (added) permissions
/// and denied permissions.
///
/// Security semantics: this is the mutable input to every decision, so writers
/// are as security-relevant as readers. A store `Err` propagates to the caller
/// and the engine treats it as denial (fail-closed): `denied_permissions` and
/// `extra_permissions` errors are preserved as `Err`, and a `roles_of` error
/// makes the engine deny after logging. Missing rows mean "nothing recorded"
/// (an empty set), never "allow": an empty deny set is not a grant either.
///
/// Writes are expected to be idempotent (setting the same value twice leaves
/// the same state) and last-write-wins per subject; the shipped in-memory
/// implementation replaces whole sets rather than merging them, so two
/// concurrent writers can lose one another's update. Callers must therefore
/// invalidate the permission cache after a successful write.
#[async_trait]
pub trait AssignmentStore<S, P>: Send + Sync
where
    S: Subject,
    P: Permission,
{
    /// Adds one role to a subject. Idempotent in the shipped implementations;
    /// whether the role exists in a registry is not checked here, so an
    /// unknown role name can be stored and will later resolve to no
    /// permissions.
    async fn assign_role(&self, subject: &S, role_name: &str) -> Result<()>;
    /// Removes one role from a subject. Idempotent: revoking a role that is not
    /// held succeeds and changes nothing, so callers cannot use the result to
    /// detect that a revocation was unnecessary.
    async fn revoke_role(&self, subject: &S, role_name: &str) -> Result<()>;
    /// Roles currently held by a subject. An unknown subject yields an empty
    /// list rather than an error, so `Ok(vec![])` must be treated as "no
    /// roles" (no authority), not as "lookup failed".
    async fn roles_of(&self, subject: &S) -> Result<Vec<String>>;
    /// Subjects holding a role, for admin listings and audits. Not an
    /// authorization input.
    async fn subjects_with_role(&self, role_name: &str) -> Result<Vec<String>>;
    /// Permissions granted to a subject on top of its roles. An unknown subject
    /// yields an empty set; the engine grants only what is listed here.
    async fn extra_permissions(&self, subject: &S) -> Result<HashSet<P>>;
    /// Replaces the subject's extra-permission set. Whole-set replacement, not
    /// a merge, and idempotent for the same input; an empty set clears the
    /// subject's direct grants.
    async fn set_extra_permissions(&self, subject: &S, perms: HashSet<P>) -> Result<()>;
    /// Permissions explicitly denied to a subject. Denies win over every grant
    /// except an admin bypass, so a store error here must deny rather than
    /// return an empty set.
    async fn denied_permissions(&self, subject: &S) -> Result<HashSet<P>>;
    /// Replaces the subject's deny set. Whole-set replacement, not a merge; an
    /// empty set clears every explicit deny for that subject, which widens its
    /// effective authority back to its grants.
    async fn set_denied_permissions(&self, subject: &S, perms: HashSet<P>) -> Result<()>;
}

/// Persistence for role definitions (the role registry's writable form).
///
/// Security semantics: role definitions are authority templates, so a role
/// whose permissions are mutated silently changes what every holder can do.
/// Errors propagate as `Err` (fail-closed at the caller); the boolean returned
/// by `delete_role` reports whether a row existed, and `false` is not an error.
#[async_trait]
pub trait RoleStore<P: Permission>: Send + Sync {
    /// Creates or replaces a role definition with the given permission set. The
    /// shipped in-memory implementation overwrites an existing role (logging a
    /// warning), so this is an upsert, not a create-only call.
    async fn create_role(&self, role_name: &str, permissions: HashSet<P>) -> Result<()>;
    /// Deletes a role definition. Returns whether a role was removed; `false`
    /// means "not present", not "failed".
    async fn delete_role(&self, role_name: &str) -> Result<bool>;
    /// Permissions of one role. `None` means the role is unknown and grants
    /// nothing; it must not be coerced into a default role.
    async fn get_role_permissions(&self, role_name: &str) -> Result<Option<HashSet<P>>>;
    /// Every role name known to this store, for listings and audits only.
    async fn list_roles(&self) -> Result<Vec<String>>;
}

/// Coarse system-wide role of a subject, carried in
/// [`PermissionContext`] and consulted before scoped grants.
///
/// Security semantics: `Admin` is a bypass (the resolver returns
/// [`GrantSource::AdminBypass`] without consulting grants), while the other
/// variants confer no authority by themselves - they only help label and
/// order decisions. The serde representation is the persisted wire form, so
/// the variant names must stay stable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SystemRole {
    /// Bypasses grant resolution; the highest-privilege value here.
    Admin,
    /// Operational role: no implicit bypass, authority comes from grants.
    Operator,
    /// Default member role: authority comes from grants only.
    Member,
    /// Read-only role: authority comes from grants only.
    Viewer,
}

impl SystemRole {
    /// Parses the persisted name. `None` means the name is unknown: callers
    /// must reject or surface it, never map it to `Admin` or to a permissive
    /// default. Matching is exact and case-sensitive.
    pub fn from_str_lossy(s: &str) -> Option<Self> {
        match s {
            "admin" => Some(Self::Admin),
            "operator" => Some(Self::Operator),
            "member" => Some(Self::Member),
            "viewer" => Some(Self::Viewer),
            _ => None,
        }
    }

    /// The persisted name of this role; used as the storage and audit label.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Operator => "operator",
            Self::Member => "member",
            Self::Viewer => "viewer",
        }
    }
}

/// Coarse per-workspace role of a subject, ordered from least to most
/// privileged.
///
/// Security semantics: the derived `Ord` is the privilege order
/// (`Viewer < Operator < Owner`) that `rbac::workspace_guard` compares
/// against, so reordering the variants would change authorization outcomes.
/// The variants grant nothing on their own: the guard also requires the
/// matching global permission.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceRole {
    /// Least privilege: list/read inside the workspace only.
    Viewer,
    /// Can act on workspace resources but not manage membership.
    Operator,
    /// Highest privileged workspace role; can manage the workspace.
    Owner,
}

impl WorkspaceRole {
    /// Parses the persisted name. `None` means the name is unknown; callers
    /// must treat that as "no workspace role" (deny), not as `Viewer`.
    /// Matching is exact and case-sensitive.
    pub fn from_str_lossy(s: &str) -> Option<Self> {
        match s {
            "viewer" => Some(Self::Viewer),
            "operator" => Some(Self::Operator),
            "owner" => Some(Self::Owner),
            _ => None,
        }
    }

    /// The persisted name of this role; used as the storage and audit label.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Viewer => "viewer",
            Self::Operator => "operator",
            Self::Owner => "owner",
        }
    }
}

/// Everything a scoped decision needs about the acting subject: identity,
/// group memberships, workspace and session freshness.
///
/// Security semantics: the resolver reads this context and never re-derives
/// it, so callers are responsible for filling it from a trusted source - a
/// forged `system_role` or `workspace_id` is an authorization bypass. The
/// version pair drives staleness: a context whose
/// [`is_session_stale`](PermissionContext::is_session_stale) is true must be
/// denied before any grant is consulted.
#[derive(Debug, Clone)]
pub struct PermissionContext {
    /// Subject the decision is about; must be the authenticated principal.
    pub user_id: uuid::Uuid,
    /// System-wide role; `Admin` bypasses grant checks.
    pub system_role: SystemRole,
    /// Groups the subject currently belongs to, used to match group grants.
    pub group_ids: Vec<uuid::Uuid>,
    /// Workspace the request is scoped to, if any.
    pub workspace_id: Option<uuid::Uuid>,
    /// Workspace role inside `workspace_id`, if the subject has one there.
    pub workspace_role: Option<WorkspaceRole>,
    /// Session version stamped when the session was created.
    pub session_version: u64,
    /// Current version of the subject's authority, from the session manager.
    pub current_user_version: u64,
}

impl PermissionContext {
    /// Whether the session predates the subject's current authority version.
    ///
    /// Security semantics: a stale session means the subject's roles or grants
    /// changed after the session was minted; the engine denies such requests
    /// (including for `Admin`) until the session is refreshed or the version
    /// is bumped, which is what bounds how long a revoked privilege can still
    /// be exercised.
    pub fn is_session_stale(&self) -> bool {
        self.session_version < self.current_user_version
    }
}

/// Outcome of a permission decision.
///
/// Security semantics: this type is total - there is no "unknown" outcome, so
/// callers that cannot make a decision must produce `Denied` rather than
/// inventing a third state. `reason` is operator-facing audit text and must
/// not carry secrets or credential material.
#[derive(Debug, Clone)]
pub enum PermissionDecision {
    /// The permission is granted; `source` records which mechanism granted it
    /// so the decision can be audited and re-checked.
    Granted {
        /// Human-readable justification, suitable for audit logs.
        reason: String,
        /// Mechanism that produced the grant.
        source: GrantSource,
    },
    /// The permission is denied. `source` is `None` when no mechanism was
    /// reached at all (for example a stale session), so an absent source is
    /// not evidence that no rule matched.
    Denied {
        /// Human-readable justification, suitable for audit logs.
        reason: String,
        /// Mechanism that denied, when one was reached.
        source: Option<GrantSource>,
    },
}

/// Which mechanism produced a decision, used for audit and for precedence
/// reasoning.
///
/// Security semantics: the variants are ordered by precedence in the
/// resolver, not by privilege - an explicit deny is not represented here (it
/// is `None` or a `Denied` decision), and `AdminBypass` is the only source
/// that ignores grants and denies. Do not derive policy from this label
/// alone; it is a description of why, not an authority.
#[derive(Debug, Clone)]
pub enum GrantSource {
    /// Authority inherited from a role the subject holds.
    RoleDefault,
    /// A grant attached to the subject with global scope.
    GlobalGrant,
    /// A grant that applies because the subject is in the granting group.
    GroupGrant,
    /// A grant attached directly to the subject.
    UserGrant,
    /// Authority from the coarse workspace role map
    /// (`rbac::workspace_guard`), not from scoped grants.
    WorkspaceRole,
    /// A grant that applies inside one workspace only (scoped grants,
    /// `rbac::scope`). Distinct from `WorkspaceRole`, which is the
    /// coarse viewer/operator/owner role map.
    WorkspaceGrant,
    /// The subject is `SystemRole::Admin` and bypassed grant resolution.
    AdminBypass,
}

/// Pluggable decision maker consulted by the engine for scoped checks.
///
/// Security semantics: implementations are the enforcement point, so they
/// must deny (not skip) whenever they cannot evaluate - a store error, an
/// unknown permission or a stale context all mean "no decision", and the
/// engine's caller turns an `Err` into a denial. Returning `Ok(Granted)`
/// without checking the context would bypass every other mechanism.
#[async_trait]
pub trait GrantResolver<P: Permission>: Send + Sync {
    /// Resolves one permission for one context.
    ///
    /// `resource_id` optionally narrows the check to a single resource; when
    /// it is `None` the decision must assume the widest interpretation of the
    /// request rather than the narrowest. `Ok(Denied)` is a completed
    /// decision; `Err` is an evaluation failure that callers must treat as a
    /// denial (fail-closed).
    async fn resolve(
        &self,
        ctx: &PermissionContext,
        permission: &P,
        resource_id: Option<&str>,
    ) -> Result<PermissionDecision>;
}
