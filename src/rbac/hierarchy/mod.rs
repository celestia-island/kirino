//! Role hierarchy: walk a role's parent chain, union the permissions of
//! every reachable ancestor, and detect cycles in that chain.
//!
//! Threat model: parent links are configuration rather than end-user
//! input, but they are still privilege-bearing -- adding a parent adds
//! permissions, and a misconfigured or duplicated link widens privilege
//! silently. A cycle would turn a naive walk into an infinite loop (a
//! hang, not a wrong answer), so both entry points are cycle-safe:
//! [`resolve_role_chain`] keeps a visited set and never expands a role
//! twice, and [`detect_cycle`] tracks the current path and returns as
//! soon as a role repeats.
//!
//! What happens on a cycle, exactly: neither function errors and neither
//! truncates. `resolve_role_chain` returns the union of the permissions
//! it collected before the repeat (for `a <-> b`, both roles'
//! permissions plus every other ancestor reached); `detect_cycle`
//! returns `true` so the caller can refuse the role or report the
//! configuration defect. Nothing is repaired here.
//!
//! Bounds: termination is bounded by the number of distinct role names
//! the registry reports. There is no explicit depth cap, no numeric
//! threshold and no timeout in this module; `resolve_role_chain` is
//! iterative (an explicit stack), while `detect_cycle` is recursive, so
//! its call-stack usage grows with chain depth.
//!
//! Failure mode: neither function returns a `Result`, so there is no
//! error path and nothing to fail open on. An unknown role name -- or a
//! parent name the registry does not know -- contributes no permissions
//! and ends that branch: nothing is invented, but the missing subtree is
//! also not reported, so a typo silently under-grants (the safe
//! direction) instead of failing loudly.
//!
//! Staleness: the registry is read on every call and nothing is cached
//! here, so results reflect registry state at call time.

use std::collections::HashSet;

use crate::rbac::traits::{Permission, Role};

/// A [`Role`] that inherits permissions from named parent roles.
///
/// Security semantics: inheritance is additive only. A parent can add
/// permissions the role does not list, and there is no way to subtract a
/// parent permission from a child -- revocation must remove the role or
/// the grant, never add a negative entry.
///
/// The default implementation returns no parents, so a role that does
/// not override `parent_roles` is a flat role holding exactly its own
/// permissions. Parent names are resolved against the registry at
/// resolution time and are never validated here: an unknown name is
/// silently ignored (see [`resolve_role_chain`]).
pub trait HierarchicalRole<P: Permission>: Role<P> {
    /// Names of the roles this role inherits from.
    ///
    /// The names are looked up in the registry by
    /// [`resolve_role_chain`]; a name the registry does not know
    /// contributes nothing, so a stale entry widens nothing but also
    /// raises no error. The default returns an empty list (no
    /// inheritance). Because the walk visits each name at most once, a
    /// cycle in these names cannot loop it -- use [`detect_cycle`] when
    /// the cycle must be surfaced instead of tolerated.
    fn parent_roles(&self) -> Vec<String> {
        Vec::new()
    }
}

/// A hierarchy node: a role name, the permissions it holds directly, and
/// the names of its parent roles.
///
/// The node is plain data -- it validates nothing. Consequences worth
/// knowing at the call site: an empty permission set is a role that
/// grants nothing on its own (deny by default for the direct set), a
/// parent name no registry knows is a silent no-op at resolution time,
/// and the parent list may contain duplicates or cycles without
/// affecting termination (the walk visits each name once). All fields
/// are private; the only way in is [`HierarchyNode::new`] plus
/// [`HierarchyNode::with_parents`].
#[derive(Debug, Clone)]
pub struct HierarchyNode<P: Permission> {
    name: String,
    permissions: HashSet<P>,
    parents: Vec<String>,
}

impl<P: Permission> HierarchyNode<P> {
    /// Build a node with the given direct permissions and no parents.
    ///
    /// The node grants exactly the permissions passed in, so an empty set
    /// grants nothing. Inherited permissions are not computed or cached
    /// here -- they are resolved per call by [`resolve_role_chain`] -- so
    /// a role's effective set can only widen by adding parents.
    pub fn new(name: impl Into<String>, permissions: HashSet<P>) -> Self {
        Self {
            name: name.into(),
            permissions,
            parents: Vec::new(),
        }
    }

    /// Attach the parent role names (builder style: consumes and returns
    /// `self`, so it composes with `new`).
    ///
    /// The list is stored verbatim. Nothing is checked here: no
    /// deduplication, no lookup of the names in the registry, no
    /// [`detect_cycle`] call and no depth limit. Duplicates and unknown
    /// names are harmless at resolution time because the walk expands
    /// each name once, but they are also invisible -- a wrong parent
    /// name silently drops that whole subtree of inherited permissions.
    #[must_use]
    pub fn with_parents(mut self, parents: Vec<String>) -> Self {
        self.parents = parents;
        self
    }
}

impl<P: Permission> Role<P> for HierarchyNode<P> {
    /// The name this node is registered under. Parent links are stored
    /// and resolved as names, so this string is the key every child looks
    /// up -- renaming a role without updating its children silently
    /// drops their inheritance.
    fn role_name(&self) -> &str {
        &self.name
    }

    /// The permissions held directly by this node (exactly the set given
    /// to [`HierarchyNode::new`]), without any inherited permissions --
    /// for the inherited union use [`resolve_role_chain`].
    fn permissions(&self) -> &HashSet<P> {
        &self.permissions
    }
}

impl<P: Permission> HierarchicalRole<P> for HierarchyNode<P> {
    /// Returns a clone of the parent names configured by
    /// [`HierarchyNode::with_parents`]. No lookup and no validation
    /// happen here, so an unregistered name is passed through unchanged
    /// and is ignored later, during resolution.
    fn parent_roles(&self) -> Vec<String> {
        self.parents.clone()
    }
}

/// Union the permissions of `role_name` and of every ancestor reachable
/// through [`RoleRegistry::role_parents`](crate::rbac::traits::RoleRegistry::role_parents).
///
/// Cycle-safe and terminating: the walk keeps a visited set and skips a
/// role it has already expanded, so a cycle stops the walk instead of
/// looping. A cycle is not an error here and does not truncate the
/// result -- every permission collected before the repeat is returned,
/// so for `a <-> b` the caller gets the union of both roles'
/// permissions. When a cycle must be reported rather than tolerated,
/// check [`detect_cycle`] separately; this function never calls it.
///
/// Bounds: work is bounded by the number of distinct role names, with no
/// explicit depth limit and no numeric threshold. The walk is iterative
/// (an explicit stack), so depth does not consume call stack here.
///
/// Fail-closed details: an unknown `role_name`, or a parent name the
/// registry does not know, contributes no permissions and ends that
/// branch -- the function returns an empty, non-defaulted set for an
/// unresolvable role rather than an error. Nothing is granted that the
/// registry did not report, and role defaults are not applied here.
#[must_use]
pub fn resolve_role_chain<P>(
    role_name: &str,
    registry: &dyn crate::rbac::traits::RoleRegistry<P>,
) -> HashSet<P>
where
    P: Permission,
{
    let mut all_perms = HashSet::new();
    let mut visited = HashSet::new();
    let mut stack = vec![role_name.to_string()];

    while let Some(current) = stack.pop() {
        if visited.contains(&current) {
            continue;
        }
        visited.insert(current.clone());

        if let Some(perms) = registry.get_role_permissions(&current) {
            all_perms.extend(perms);
            for parent in registry.role_parents(&current) {
                if !visited.contains(&parent) {
                    stack.push(parent);
                }
            }
        }
    }

    all_perms
}

/// Depth-first cycle probe behind [`detect_cycle`].
///
/// `path` holds the roles on the current recursion path (the grey set)
/// and `visited` the roles already fully explored (the black set); a
/// name found in `path` is a back edge and returns `true` upwards
/// immediately, which is what makes the probe terminate on cyclic
/// shapes. Parents are followed only for a role the registry knows
/// (`get_role_permissions` returns `Some`), so an unknown name is a leaf
/// here. The sets are working state owned by the caller and must not be
/// reused across queries -- `detect_cycle` allocates fresh ones per
/// call.
fn dfs<P>(
    name: &str,
    registry: &dyn crate::rbac::traits::RoleRegistry<P>,
    visited: &mut HashSet<String>,
    path: &mut HashSet<String>,
) -> bool
where
    P: Permission,
{
    if path.contains(name) {
        return true;
    }
    if visited.contains(name) {
        return false;
    }
    visited.insert(name.to_string());
    path.insert(name.to_string());

    if registry.get_role_permissions(name).is_some() {
        for parent in registry.role_parents(name) {
            if dfs(&parent, registry, visited, path) {
                return true;
            }
        }
    }

    path.remove(name);
    false
}

/// Report whether `role_name` participates in a parent cycle reachable
/// from it (including a role that names itself as its own parent).
///
/// Returns `true` as soon as a role repeats on the current path, and
/// `false` in every other case -- including an unknown role (the
/// registry reports no permissions for it, so no parents are followed)
/// and a diamond where two paths share an ancestor without a cycle.
///
/// This is a diagnosis, not a repair: it does not report where the cycle
/// is, does not enumerate further cycles, and does not change what
/// [`resolve_role_chain`] returns. The caller decides whether a cyclic
/// role is refused, logged or tolerated -- tolerating it still
/// terminates, but the privileges it yields may not be the intended
/// ones.
///
/// Bounds: work is bounded by the number of distinct role names, but the
/// search is recursive, so call-stack usage grows with chain depth.
/// There is no explicit depth limit and no numeric threshold here.
#[must_use]
pub fn detect_cycle<P>(role_name: &str, registry: &dyn crate::rbac::traits::RoleRegistry<P>) -> bool
where
    P: Permission,
{
    let mut visited = HashSet::new();
    let mut path = HashSet::new();

    dfs(role_name, registry, &mut visited, &mut path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rbac::store::registry::StaticRoleRegistry;
    use crate::test_utils::TestPerm;

    fn build_hierarchy() -> StaticRoleRegistry<HierarchyNode<TestPerm>, TestPerm> {
        let mut reg = StaticRoleRegistry::new();
        reg.register_hierarchical(
            HierarchyNode::new("admin", std::iter::once(TestPerm::Admin).collect())
                .with_parents(vec!["operator".to_string(), "auditor".to_string()]),
        );
        reg.register_hierarchical(
            HierarchyNode::new(
                "operator",
                [TestPerm::Write, TestPerm::Delete].into_iter().collect(),
            )
            .with_parents(vec!["viewer".to_string()]),
        );
        reg.register(HierarchyNode::new(
            "auditor",
            std::iter::once(TestPerm::Read).collect(),
        ));
        reg.register(HierarchyNode::new(
            "viewer",
            std::iter::once(TestPerm::Read).collect(),
        ));
        reg
    }

    #[test]
    fn test_resolve_chain_admin() {
        let reg = build_hierarchy();
        let perms = resolve_role_chain("admin", &reg);
        assert!(perms.contains(&TestPerm::Admin));
        assert!(perms.contains(&TestPerm::Write));
        assert!(perms.contains(&TestPerm::Delete));
        assert!(perms.contains(&TestPerm::Read));
    }

    #[test]
    fn test_resolve_chain_operator() {
        let reg = build_hierarchy();
        let perms = resolve_role_chain("operator", &reg);
        assert!(perms.contains(&TestPerm::Write));
        assert!(perms.contains(&TestPerm::Delete));
        assert!(perms.contains(&TestPerm::Read));
        assert!(!perms.contains(&TestPerm::Admin));
    }

    #[test]
    fn test_resolve_chain_viewer() {
        let reg = build_hierarchy();
        let perms = resolve_role_chain("viewer", &reg);
        assert!(perms.contains(&TestPerm::Read));
        assert!(!perms.contains(&TestPerm::Write));
    }

    #[test]
    fn test_resolve_chain_nonexistent() {
        let reg = build_hierarchy();
        let perms = resolve_role_chain("nonexistent", &reg);
        assert!(perms.is_empty());
    }

    #[test]
    fn test_detect_no_cycle() {
        let reg = build_hierarchy();
        assert!(!detect_cycle("admin", &reg));
        assert!(!detect_cycle("viewer", &reg));
    }

    #[test]
    fn test_detect_cycle() {
        let mut reg = StaticRoleRegistry::new();
        reg.register_hierarchical(
            HierarchyNode::new("a", std::iter::once(TestPerm::Read).collect())
                .with_parents(vec!["b".to_string()]),
        );
        reg.register_hierarchical(
            HierarchyNode::new("b", std::iter::once(TestPerm::Write).collect())
                .with_parents(vec!["a".to_string()]),
        );
        assert!(detect_cycle("a", &reg));
        assert!(detect_cycle("b", &reg));
    }

    #[test]
    fn test_detect_self_cycle() {
        let mut reg = StaticRoleRegistry::new();
        reg.register_hierarchical(
            HierarchyNode::new("self_ref", std::iter::once(TestPerm::Read).collect())
                .with_parents(vec!["self_ref".to_string()]),
        );
        assert!(detect_cycle("self_ref", &reg));
    }

    #[test]
    fn test_resolve_chain_with_cycle_terminates() {
        let mut reg = StaticRoleRegistry::new();
        reg.register_hierarchical(
            HierarchyNode::new("a", std::iter::once(TestPerm::Read).collect())
                .with_parents(vec!["b".to_string()]),
        );
        reg.register_hierarchical(
            HierarchyNode::new("b", std::iter::once(TestPerm::Write).collect())
                .with_parents(vec!["a".to_string()]),
        );
        let perms = resolve_role_chain("a", &reg);
        assert!(perms.contains(&TestPerm::Read));
        assert!(perms.contains(&TestPerm::Write));
    }

    #[test]
    fn test_three_way_cycle() {
        let mut reg = StaticRoleRegistry::new();
        reg.register_hierarchical(
            HierarchyNode::new("a", std::iter::once(TestPerm::Read).collect())
                .with_parents(vec!["b".to_string()]),
        );
        reg.register_hierarchical(
            HierarchyNode::new("b", std::iter::once(TestPerm::Write).collect())
                .with_parents(vec!["c".to_string()]),
        );
        reg.register_hierarchical(
            HierarchyNode::new("c", std::iter::once(TestPerm::Delete).collect())
                .with_parents(vec!["a".to_string()]),
        );
        assert!(detect_cycle("a", &reg));
        assert!(detect_cycle("b", &reg));
        assert!(detect_cycle("c", &reg));

        let perms = resolve_role_chain("a", &reg);
        assert_eq!(perms.len(), 3);
    }

    #[test]
    fn test_deep_chain() {
        let mut reg = StaticRoleRegistry::new();
        reg.register_hierarchical(
            HierarchyNode::new("level0", std::iter::once(TestPerm::Admin).collect())
                .with_parents(vec!["level1".to_string()]),
        );
        for i in 1..10 {
            reg.register(HierarchyNode::new(
                format!("level{i}"),
                std::iter::once(TestPerm::Read).collect(),
            ));
        }
        let perms = resolve_role_chain("level0", &reg);
        assert!(perms.contains(&TestPerm::Admin));
        assert!(perms.contains(&TestPerm::Read));
    }

    #[test]
    fn test_diamond_inheritance() {
        let mut reg = StaticRoleRegistry::new();
        reg.register_hierarchical(
            HierarchyNode::new("root", std::iter::once(TestPerm::Admin).collect())
                .with_parents(vec!["left".to_string(), "right".to_string()]),
        );
        reg.register_hierarchical(
            HierarchyNode::new("left", std::iter::once(TestPerm::Read).collect())
                .with_parents(vec!["base".to_string()]),
        );
        reg.register_hierarchical(
            HierarchyNode::new("right", std::iter::once(TestPerm::Write).collect())
                .with_parents(vec!["base".to_string()]),
        );
        reg.register(HierarchyNode::new(
            "base",
            std::iter::once(TestPerm::Delete).collect(),
        ));

        let perms = resolve_role_chain("root", &reg);
        assert!(perms.contains(&TestPerm::Admin));
        assert!(perms.contains(&TestPerm::Read));
        assert!(perms.contains(&TestPerm::Write));
        assert!(perms.contains(&TestPerm::Delete));
        assert_eq!(perms.len(), 4);

        assert!(!detect_cycle("root", &reg));
    }

    #[test]
    fn test_detect_cycle_nonexistent_role() {
        let reg: StaticRoleRegistry<HierarchyNode<TestPerm>, TestPerm> = StaticRoleRegistry::new();
        assert!(!detect_cycle("nonexistent", &reg));
    }
}
