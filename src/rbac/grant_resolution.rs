//! Grant-row permission resolution core (T6b, arch review 2026-10-26).
//!
//! The two service-layer RBAC implementations (shittim-chest's 1.6k-line
//! `rbac/mod.rs` and arona's 1.1k-line twin) each carried a private copy
//! of the same three-part algorithm: which grant strings count as
//! permissions, how a grant's permission field expands, and how
//! user/group/global scopes fold into one verdict. Chest's copy folded
//! rows in iteration order; arona's used this tier fold — the version
//! preserved here, because it is deterministic and row-order free: a more
//! specific tier always wins regardless of the order the database
//! returned rows in, and within one tier a deny is sticky.
//!
//! TWO deliberate divergences from chest's historical branches (both in
//! the safe/deterministic direction, both behaviour-visible on migration
//! — consuming services MUST state them in their migration PRs):
//!
//! 1. Same-tier multi-row verdicts: chest was last-wins (DB row order
//!    dependent); here deny is sticky within a tier.
//! 2. Unknown `scope` values: chest's match arm ignored them entirely;
//!    here they take the global tier and DO fold. Because no write-path
//!    whitelist for `scope` could be located on either service, a
//!    hand-edited row with a typo'd scope would change from "inert" to
//!    "effective as global" — consumers that need chest's inertness must
//!    filter unknown-scope rows before feeding them here.
//!
//! Services keep their own tables and queries (the schema belongs to each
//! service's database); this module is the pure function they feed rows
//! into. Versioned here so both consumers drift together.
//!
//! # Time-limited grants (0.9.0)
//!
//! A [`GrantRow`] may carry an absolute deadline ([`GrantRow::expires_at`]).
//! Expiry is evaluated by [`resolve_grant_rows_at`], the only time-sensitive
//! path **in the grant fold**: the evaluation instant is a parameter, never
//! read inside the fold, so callers can pin it in tests and the fold stays
//! pure. (Other kirino subsystems read the wall clock on their own — temporal
//! policy constraints, visitor tickets, session TTLs — this section is about
//! grant rows only.)
//!
//! An expired row is invisible — exactly as if it did not exist, for grants
//! and denies alike. An expired grant lets the permission fall back to the
//! defaults (or to another surviving row); an expired deny stops suppressing
//! it. The boundary is fail-closed: a row is live only while
//! `now < expires_at`, so `now == expires_at` is already expired.
//!
//! This fold is the SECOND line of defence. A service that stores grants in
//! its own database MUST also filter at its own boundary
//! (`WHERE expires_at IS NULL OR expires_at > now()`), because a row the
//! service never feeds into this fold — a TypeScript/HTTP leaf path, a
//! cached permission snapshot, a query that forgot the column — cannot be
//! hidden here. Kirino sees only the rows it is handed and cannot close
//! those paths for the service.
//!
//! Two clocks can meet: a service filters its own rows with the database
//! clock while this fold evaluates the instant it is handed. For deny rows
//! the skew is not symmetric — a deny the service still considers live can
//! already be dropped here, in the permissive direction. Services that need
//! the two to agree pass the same instant they used at their own boundary
//! into [`resolve_grant_rows_at`].

use chrono::{DateTime, Utc};

use crate::rbac::permission::Permission;

/// A dotted, lowercase path that is not a kirino permission and not a
/// kirino domain — treat it as an opaque grantable permission string.
/// Segments may also carry hyphens so runtime ids can ride inside the
/// path (`platform.<uuid>.access` — uuid strings are lowercase hex
/// groups joined by `-`).
pub fn is_opaque_permission_path(s: &str) -> bool {
    !s.is_empty()
        && s.chars().next().is_some_and(|c| c.is_ascii_lowercase())
        && s.split('.').all(|seg| {
            !seg.is_empty()
                && seg
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
        })
}

/// Precedence tier of a grant scope: user (0) beats group (1) beats
/// global (2). Unknown scopes share the global tier — the least specific.
pub fn scope_tier(scope: &str) -> u8 {
    match scope {
        "user" => 0,
        "group" => 1,
        _ => 2,
    }
}

/// Fold one grant verdict into a pending decision. Deterministic and
/// row-order free: a more specific tier always wins regardless of
/// iteration order; within the same tier a deny is sticky (safe default).
pub fn fold_tiered(decision: &mut Option<(u8, bool)>, tier: u8, granted: bool) {
    match *decision {
        Some((t, _)) if t < tier => {}
        Some((t, v)) if t == tier => {
            if v {
                *decision = Some((tier, granted));
            }
        }
        _ => {
            *decision = Some((tier, granted));
        }
    }
}

/// Expand a grant's permission field into concrete permission names: a
/// typed path resolves to itself, a domain ("provider") expands to its
/// leaves, anything opaque-but-well-formed resolves verbatim (services
/// grant string permissions outside kirino's typed catalog, e.g.
/// "usage.read.self").
pub fn expand_grant_permission(raw: &str) -> Vec<String> {
    if Permission::from_path(raw).is_some() {
        return vec![raw.to_string()];
    }
    let expanded: Vec<String> = Permission::expand_domain(raw)
        .iter()
        .map(|p| p.name().to_string())
        .collect();
    if !expanded.is_empty() {
        return expanded;
    }
    if is_opaque_permission_path(raw) {
        return vec![raw.to_string()];
    }
    Vec::new()
}

/// One materialized grant row, scope-resolved by the caller (the service
/// query already filtered to the acting user's rows; this carries what
/// the fold needs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantRow {
    /// `"user"` | `"group"` | `"global"` (unknown scopes fall to the
    /// global tier).
    pub scope: String,
    /// Raw permission field — typed path, domain, or opaque string.
    pub permission: String,
    /// Whether the row grants (true) or denies (false) the permission.
    pub granted: bool,
    /// Resource-pinned rows (`resource_id` set) NEVER widen the flat
    /// permission set — they are only visible through a resource-scoped
    /// check. [`resolve_grant_rows`] skips them; keep the field so the
    /// service can pass its rows through unfiltered.
    pub resource_id: Option<String>,
    /// Absolute deadline for a time-limited grant: the row is live only
    /// while `now < expires_at` ([`resolve_grant_rows_at`] decides what
    /// `now` is). `None` = permanent, the pre-0.9 behaviour every existing
    /// row keeps. The boundary is fail-closed (`now == expires_at` is
    /// already expired) and grants and denies expire identically.
    pub expires_at: Option<DateTime<Utc>>,
}

impl GrantRow {
    /// Convenience constructor for flat (resource-less), permanent rows —
    /// `expires_at` is `None`.
    pub fn flat(scope: &str, permission: &str, granted: bool) -> Self {
        Self {
            scope: scope.to_string(),
            permission: permission.to_string(),
            granted,
            resource_id: None,
            expires_at: None,
        }
    }

    /// Attach an absolute deadline to this row, keeping every other field
    /// as-is (builder form of [`GrantRow::expires_at`]).
    ///
    /// The row is live only while `now < expires_at`: at or after that
    /// instant [`resolve_grant_rows_at`] treats it as nonexistent —
    /// fail-closed, matching the SQL filter services apply on their side.
    /// Calling this again replaces the previous deadline.
    #[must_use]
    pub fn with_expiry(mut self, at: DateTime<Utc>) -> Self {
        self.expires_at = Some(at);
        self
    }
}

/// Whether `row` is live at `now`. Fail-closed: `now == expires_at` is
/// already expired, and `None` never expires.
fn is_visible_at(row: &GrantRow, now: DateTime<Utc>) -> bool {
    match row.expires_at {
        None => true,
        Some(deadline) => now < deadline,
    }
}

/// Fold a full grant set over the builtin defaults into the effective
/// permission-name set, as evaluated at `now`.
///
/// Semantics (the union of both service implementations, verified
/// equivalent against their historical branches):
///
/// - `defaults` seed each permission as granted at the GROUP tier —
///   specific enough that a `global` deny can never revoke a builtin
///   default (chest's `or_insert` behaviour), while `user`/`group` rows
///   still decide it.
/// - A permission absent from `defaults` starts undecided (`None`) and
///   the first grant row that touches it decides it — at any scope.
/// - Resource-pinned rows are skipped entirely.
/// - Expired rows are invisible: a row with `expires_at == Some(t)` only
///   participates while `now < t` (fail-closed at the boundary). This is
///   the only time-sensitive path this fold has; the instant is injected
///   here
///   so the fold stays pure and its tests deterministic. Invisibility is
///   total — an expired grant lets the permission fall back to the
///   defaults or to another row, an expired deny stops suppressing it.
/// - The fold is row-order free: the most specific tier wins; within one
///   tier a deny is sticky.
/// - The result is sorted for deterministic comparisons.
///
/// Services must still filter expired rows at their own storage boundary
/// (see the module docs): rows that never reach this fold are out of its
/// reach.
pub fn resolve_grant_rows_at(
    defaults: &[String],
    grants: &[GrantRow],
    now: DateTime<Utc>,
) -> Vec<String> {
    let mut decisions: std::collections::HashMap<String, Option<(u8, bool)>> = defaults
        .iter()
        .map(|p| (p.clone(), Some((scope_tier("group"), true))))
        .collect();
    for grant in grants {
        if grant.resource_id.is_some() || !is_visible_at(grant, now) {
            continue;
        }
        let tier = scope_tier(&grant.scope);
        for perm in expand_grant_permission(&grant.permission) {
            // Undecided until the first row touches it: `None` outer means
            // "no verdict yet", so ANY scope's first row decides (arona's
            // remove/fold/insert shape, verbatim).
            let mut decision = decisions.remove(&perm).flatten();
            if decision.is_none() {
                decision = Some((tier, grant.granted));
            } else {
                fold_tiered(&mut decision, tier, grant.granted);
            }
            if let Some(d) = decision {
                decisions.insert(perm, Some(d));
            }
        }
    }
    let mut effective: Vec<String> = decisions
        .into_iter()
        .filter(|(_, verdict)| verdict.is_some_and(|(_, granted)| granted))
        .map(|(perm, _)| perm)
        .collect();
    effective.sort();
    effective
}

/// [`resolve_grant_rows_at`] evaluated at the current wall clock.
///
/// Signature-compatible with pre-0.9 consumers; expiry semantics are
/// identical. Callers that need determinism (tests, replays) or a fixed
/// evaluation instant should call [`resolve_grant_rows_at`] directly.
pub fn resolve_grant_rows(defaults: &[String], grants: &[GrantRow]) -> Vec<String> {
    resolve_grant_rows_at(defaults, grants, Utc::now())
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, TimeZone};

    use super::*;

    /// Pinned evaluation clock for the expiry tests: every instant below is
    /// an offset from this fixed point, so nothing depends on wall time.
    fn t0() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 3, 1, 12, 0, 0).unwrap()
    }

    fn at(offset_secs: i64) -> DateTime<Utc> {
        t0() + Duration::seconds(offset_secs)
    }

    fn grant(scope: &str, permission: &str, granted: bool) -> GrantRow {
        GrantRow::flat(scope, permission, granted)
    }

    #[test]
    fn defaults_are_group_tier_so_a_global_deny_cannot_revoke_them() {
        let defaults = vec!["panel.read".to_string()];
        // A global deny must NOT revoke the builtin default (chest's
        // historical `or_insert` behaviour).
        let out = resolve_grant_rows(&defaults, &[grant("global", "panel.read", false)]);
        assert_eq!(out, vec!["panel.read"]);
        // A user-tier deny still decides it.
        let out = resolve_grant_rows(&defaults, &[grant("user", "panel.read", false)]);
        assert!(out.is_empty());
    }

    #[test]
    fn unseen_permissions_are_decided_by_their_first_row_at_any_scope() {
        // No defaults; a global grant introduces the permission.
        let out = resolve_grant_rows(&[], &[grant("global", "usage.read.self", true)]);
        assert_eq!(out, vec!["usage.read.self"]);
        // …and a later more-specific deny retracts it, row order free.
        let out = resolve_grant_rows(
            &[],
            &[
                grant("user", "usage.read.self", false),
                grant("global", "usage.read.self", true),
            ],
        );
        assert!(out.is_empty());
    }

    #[test]
    fn resource_pinned_rows_never_widen_the_flat_set() {
        let mut pinned = grant("user", "panel.read", true);
        pinned.resource_id = Some("platform-42".to_string());
        assert!(resolve_grant_rows(&[], &[pinned]).is_empty());
    }

    #[test]
    fn full_matrix_matches_both_services_branches() {
        // chest's three-branch HashMap fold and arona's tier fold agree;
        // this matrix pins the union: user beats group beats global,
        // deny sticky in-tier, defaults survive global denies.
        let defaults = vec!["base.perm".to_string()];
        let rows = vec![
            grant("global", "base.perm", false), // ignored (group-tier default)
            grant("group", "extra.one", true),   // introduced by group
            grant("user", "extra.one", false),   // retracted by user
            grant("group", "extra.two", true),   // introduced
            grant("global", "extra.two", false), // ignored (row-order free)
            grant("user", "base.perm", true),    // already granted, no-op
        ];
        let out = resolve_grant_rows(&defaults, &rows);
        assert_eq!(out, vec!["base.perm", "extra.two"]);
    }

    #[test]
    fn opaque_paths_accept_runtime_ids_and_reject_uppercase() {
        assert!(is_opaque_permission_path("usage.read.self"));
        assert!(is_opaque_permission_path(
            "platform.550e8400-e29b-41d4-a716.access"
        ));
        assert!(!is_opaque_permission_path("Usage.read"));
        assert!(!is_opaque_permission_path("a..b"));
        assert!(!is_opaque_permission_path(""));
    }

    #[test]
    fn user_tier_beats_group_beats_global_regardless_of_row_order() {
        let mut forward: Option<(u8, bool)> = None;
        fold_tiered(&mut forward, scope_tier("global"), true);
        fold_tiered(&mut forward, scope_tier("group"), false);
        fold_tiered(&mut forward, scope_tier("user"), true);
        assert_eq!(forward, Some((0, true)));

        let mut reverse: Option<(u8, bool)> = None;
        fold_tiered(&mut reverse, scope_tier("user"), true);
        fold_tiered(&mut reverse, scope_tier("group"), false);
        fold_tiered(&mut reverse, scope_tier("global"), false);
        assert_eq!(reverse, Some((0, true)), "row order must not matter");
    }

    #[test]
    fn deny_is_sticky_within_one_tier() {
        let mut d: Option<(u8, bool)> = None;
        fold_tiered(&mut d, scope_tier("group"), true);
        fold_tiered(&mut d, scope_tier("group"), false);
        assert_eq!(d, Some((1, false)));
        // A later grant at the SAME tier cannot resurrect it…
        fold_tiered(&mut d, scope_tier("group"), true);
        assert_eq!(d, Some((1, false)));
        // …but a more specific tier can.
        fold_tiered(&mut d, scope_tier("user"), true);
        assert_eq!(d, Some((0, true)));
    }

    #[test]
    fn expansion_covers_typed_domain_and_opaque_forms() {
        // Typed path resolves to itself.
        assert_eq!(expand_grant_permission("rbac.read"), vec!["rbac.read"]);
        // Domain expands to its leaves (kirino's own catalog).
        let expanded = expand_grant_permission("rbac");
        assert!(!expanded.is_empty());
        assert!(expanded.iter().all(|p| p.starts_with("rbac.")));
        // Opaque-but-well-formed resolves verbatim.
        assert_eq!(
            expand_grant_permission("usage.read.self"),
            vec!["usage.read.self"]
        );
        // Garbage resolves to nothing.
        assert!(expand_grant_permission("NOT A PATH").is_empty());
    }

    #[test]
    fn an_expired_grant_row_is_invisible_and_fail_closed_at_the_boundary() {
        // Live one second before the deadline, invisible AT it (fail-closed)
        // and afterwards.
        let rows = vec![grant("user", "usage.read.self", true).with_expiry(at(60))];
        assert_eq!(
            resolve_grant_rows_at(&[], &rows, at(59)),
            vec!["usage.read.self"]
        );
        assert!(resolve_grant_rows_at(&[], &rows, at(60)).is_empty());
        assert!(resolve_grant_rows_at(&[], &rows, at(61)).is_empty());
    }

    #[test]
    fn an_expired_grant_row_leaves_only_the_defaults() {
        let defaults = vec!["base.perm".to_string()];
        let rows = vec![grant("user", "extra.one", true).with_expiry(at(60))];
        // Before the deadline the row widens the set…
        assert_eq!(
            resolve_grant_rows_at(&defaults, &rows, at(59)),
            vec!["base.perm", "extra.one"]
        );
        // …after it the permission falls back to the defaults.
        assert_eq!(
            resolve_grant_rows_at(&defaults, &rows, at(60)),
            vec!["base.perm"]
        );
    }

    #[test]
    fn an_expired_deny_row_stops_suppressing() {
        // A builtin default survives once the user-tier deny expires.
        let defaults = vec!["panel.read".to_string()];
        let rows = vec![grant("user", "panel.read", false).with_expiry(at(60))];
        assert!(resolve_grant_rows_at(&defaults, &rows, at(59)).is_empty());
        assert_eq!(
            resolve_grant_rows_at(&defaults, &rows, at(60)),
            vec!["panel.read"]
        );
        // A permission outside the defaults falls to the surviving grant.
        let rows = vec![
            grant("user", "usage.read.self", false).with_expiry(at(60)),
            grant("group", "usage.read.self", true),
        ];
        assert!(resolve_grant_rows_at(&[], &rows, at(59)).is_empty());
        assert_eq!(
            resolve_grant_rows_at(&[], &rows, at(60)),
            vec!["usage.read.self"]
        );
    }

    #[test]
    fn a_permanent_grant_survives_an_expired_deny_of_the_same_permission() {
        // Same permission, one permanent grant and one expired deny: the
        // expired deny must behave as if the row did not exist.
        let rows = vec![
            grant("user", "panel.read", false).with_expiry(at(60)),
            grant("user", "panel.read", true),
        ];
        // While both are live the same-tier deny is sticky and wins…
        assert!(resolve_grant_rows_at(&[], &rows, at(59)).is_empty());
        // …and once it expires the permanent grant decides the permission.
        assert_eq!(
            resolve_grant_rows_at(&[], &rows, at(60)),
            vec!["panel.read"]
        );
    }

    #[test]
    fn rows_without_a_deadline_are_permanent_at_any_instant() {
        // `None` = permanent: the pre-0.9 semantics, clock-independent.
        let defaults = vec!["base.perm".to_string()];
        let rows = vec![
            grant("global", "base.perm", false),
            grant("group", "extra.one", true),
            grant("user", "extra.one", false),
            grant("group", "extra.two", true),
        ];
        let expected = vec!["base.perm".to_string(), "extra.two".to_string()];
        let century = 86_400 * 365 * 100;
        for now in [at(-century), at(0), at(century)] {
            assert_eq!(resolve_grant_rows_at(&defaults, &rows, now), expected);
        }
        // The wall-clock wrapper agrees, and `flat` rows really are permanent.
        assert_eq!(resolve_grant_rows(&defaults, &rows), expected);
        assert!(rows.iter().all(|row| row.expires_at.is_none()));
    }

    #[test]
    fn the_wall_clock_wrapper_honours_deadlines() {
        // Far enough from `Utc::now()` that the delegate cannot flake.
        let century = 86_400 * 365 * 100;
        let live = grant("user", "usage.read.self", true).with_expiry(at(century));
        assert_eq!(resolve_grant_rows(&[], &[live]), vec!["usage.read.self"]);
        let dead = grant("user", "usage.read.self", true).with_expiry(at(-century));
        assert!(resolve_grant_rows(&[], &[dead]).is_empty());
    }

    #[test]
    fn with_expiry_sets_the_deadline_and_keeps_the_other_fields() {
        let deadline = at(3600);
        let row = grant("group", "panel.read", true).with_expiry(deadline);
        assert_eq!(row.expires_at, Some(deadline));
        assert_eq!(row.scope, "group");
        assert_eq!(row.permission, "panel.read");
        assert!(row.granted);
        assert!(row.resource_id.is_none());
        // A later deadline replaces the earlier one (mut-self builder).
        let row = row.with_expiry(at(7200));
        assert_eq!(row.expires_at, Some(at(7200)));
        // The resource-pinned skip still outranks a live deadline.
        let mut pinned = grant("user", "panel.read", true).with_expiry(at(7200));
        pinned.resource_id = Some("platform-42".to_string());
        assert!(resolve_grant_rows_at(&[], &[pinned], at(0)).is_empty());
    }

    #[test]
    fn an_expired_grant_falls_back_to_a_surviving_row_at_a_lower_tier() {
        // A dead user grant must not shadow a live group grant of the same
        // permission: "falls back to another surviving row", not only to the
        // defaults.
        let dead = grant("user", "panel.read", true).with_expiry(at(-1));
        let live = grant("group", "panel.read", true);
        assert_eq!(
            resolve_grant_rows_at(&[], &[dead.clone(), live], at(0)),
            vec!["panel.read"]
        );
        // The discriminating direction: a wider-tier DENY only wins if the
        // dead user row really left its tier. Folding it anyway ("invisible"
        // read as "still a grant") would keep the permission and fail here.
        let wider_deny = grant("group", "panel.read", false);
        assert!(resolve_grant_rows_at(&[], &[dead, wider_deny], at(0)).is_empty());
    }

    #[test]
    fn an_unknown_scope_falls_to_the_global_tier() {
        // Documented deviation: unknown scopes resolve at the global tier. A
        // global deny cannot revoke a builtin default (group-tier seed),
        // while a user-tier deny can — this pins the unknown scope to the
        // *least* specific tier through behaviour, not just `scope_tier`.
        let defaults = vec!["base.perm".to_string()];
        let unknown = grant("typo-scope", "base.perm", false);
        assert_eq!(
            resolve_grant_rows_at(&defaults, &[unknown], at(0)),
            vec!["base.perm"]
        );
        let user = grant("user", "base.perm", false);
        assert!(resolve_grant_rows_at(&defaults, &[user], at(0)).is_empty());
        // And an unknown-scope GRANT must fold too: dropping the row as
        // inert would yield no permissions here.
        assert_eq!(
            resolve_grant_rows_at(&[], &[grant("typo-scope", "new.perm", true)], at(0)),
            vec!["new.perm"]
        );
    }

    #[test]
    fn an_expired_domain_row_hides_every_expanded_leaf() {
        // Domain rows expand to all their typed leaves; expiry applies to the
        // whole row, not to the first leaf only.
        let live = grant("user", "plugin", true);
        let expanded = resolve_grant_rows_at(&[], &[live], at(0));
        assert!(expanded.contains(&"plugin.read".to_string()));
        assert!(expanded.contains(&"plugin.manage".to_string()));
        let dead = grant("user", "plugin", true).with_expiry(at(-1));
        assert!(resolve_grant_rows_at(&[], &[dead], at(0)).is_empty());
    }

    #[test]
    fn an_expired_resource_pinned_row_stays_invisible() {
        // Pinned rows are skipped before the deadline is consulted; an
        // expired pinned row must neither grant nor deny anything, and must
        // not disturb a live flat row of the same permission.
        let mut pinned = grant("user", "panel.read", false).with_expiry(at(-1));
        pinned.resource_id = Some("platform-42".to_string());
        let live = grant("user", "panel.read", true);
        assert_eq!(
            resolve_grant_rows_at(&[], &[pinned, live], at(0)),
            vec!["panel.read"]
        );
    }
}
