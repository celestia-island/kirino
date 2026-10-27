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
//! Services keep their own tables and queries (the schema belongs to each
//! service's database); this module is the pure function they feed rows
//! into. Versioned here so both consumers drift together.

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
}

impl GrantRow {
    /// Convenience constructor for flat (resource-less) rows.
    pub fn flat(scope: &str, permission: &str, granted: bool) -> Self {
        Self {
            scope: scope.to_string(),
            permission: permission.to_string(),
            granted,
            resource_id: None,
        }
    }
}

/// Fold a full grant set over the builtin defaults into the effective
/// permission-name set.
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
/// - The fold is row-order free: the most specific tier wins; within one
///   tier a deny is sticky.
/// - The result is sorted for deterministic comparisons.
pub fn resolve_grant_rows(defaults: &[String], grants: &[GrantRow]) -> Vec<String> {
    let mut decisions: std::collections::HashMap<String, Option<(u8, bool)>> = defaults
        .iter()
        .map(|p| (p.clone(), Some((scope_tier("group"), true))))
        .collect();
    for grant in grants {
        if grant.resource_id.is_some() {
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
