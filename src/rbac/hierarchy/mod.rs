use std::collections::HashSet;

use crate::rbac::traits::{Permission, Role};

pub trait HierarchicalRole<P: Permission>: Role<P> {
    fn parent_roles(&self) -> Vec<String> {
        Vec::new()
    }
}

#[derive(Debug, Clone)]
pub struct HierarchyNode<P: Permission> {
    name: String,
    permissions: HashSet<P>,
    parents: Vec<String>,
}

impl<P: Permission> HierarchyNode<P> {
    pub fn new(name: impl Into<String>, permissions: HashSet<P>) -> Self {
        Self {
            name: name.into(),
            permissions,
            parents: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_parents(mut self, parents: Vec<String>) -> Self {
        self.parents = parents;
        self
    }
}

impl<P: Permission> Role<P> for HierarchyNode<P> {
    fn role_name(&self) -> &str {
        &self.name
    }

    fn permissions(&self) -> &HashSet<P> {
        &self.permissions
    }
}

impl<P: Permission> HierarchicalRole<P> for HierarchyNode<P> {
    fn parent_roles(&self) -> Vec<String> {
        self.parents.clone()
    }
}

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
        reg.register(
            HierarchyNode::new("admin", std::iter::once(TestPerm::Admin).collect())
                .with_parents(vec!["operator".to_string(), "auditor".to_string()]),
        );
        reg.set_parents("admin", vec!["operator".to_string(), "auditor".to_string()]);
        reg.register(
            HierarchyNode::new(
                "operator",
                [TestPerm::Write, TestPerm::Delete].into_iter().collect(),
            )
            .with_parents(vec!["viewer".to_string()]),
        );
        reg.set_parents("operator", vec!["viewer".to_string()]);
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
        reg.register(
            HierarchyNode::new("a", std::iter::once(TestPerm::Read).collect())
                .with_parents(vec!["b".to_string()]),
        );
        reg.set_parents("a", vec!["b".to_string()]);
        reg.register(
            HierarchyNode::new("b", std::iter::once(TestPerm::Write).collect())
                .with_parents(vec!["a".to_string()]),
        );
        reg.set_parents("b", vec!["a".to_string()]);
        assert!(detect_cycle("a", &reg));
        assert!(detect_cycle("b", &reg));
    }

    #[test]
    fn test_detect_self_cycle() {
        let mut reg = StaticRoleRegistry::new();
        reg.register(
            HierarchyNode::new("self_ref", std::iter::once(TestPerm::Read).collect())
                .with_parents(vec!["self_ref".to_string()]),
        );
        reg.set_parents("self_ref", vec!["self_ref".to_string()]);
        assert!(detect_cycle("self_ref", &reg));
    }

    #[test]
    fn test_resolve_chain_with_cycle_terminates() {
        let mut reg = StaticRoleRegistry::new();
        reg.register(
            HierarchyNode::new("a", std::iter::once(TestPerm::Read).collect())
                .with_parents(vec!["b".to_string()]),
        );
        reg.set_parents("a", vec!["b".to_string()]);
        reg.register(
            HierarchyNode::new("b", std::iter::once(TestPerm::Write).collect())
                .with_parents(vec!["a".to_string()]),
        );
        reg.set_parents("b", vec!["a".to_string()]);
        let perms = resolve_role_chain("a", &reg);
        assert!(perms.contains(&TestPerm::Read));
        assert!(perms.contains(&TestPerm::Write));
    }

    #[test]
    fn test_three_way_cycle() {
        let mut reg = StaticRoleRegistry::new();
        reg.register(
            HierarchyNode::new("a", std::iter::once(TestPerm::Read).collect())
                .with_parents(vec!["b".to_string()]),
        );
        reg.set_parents("a", vec!["b".to_string()]);
        reg.register(
            HierarchyNode::new("b", std::iter::once(TestPerm::Write).collect())
                .with_parents(vec!["c".to_string()]),
        );
        reg.set_parents("b", vec!["c".to_string()]);
        reg.register(
            HierarchyNode::new("c", std::iter::once(TestPerm::Delete).collect())
                .with_parents(vec!["a".to_string()]),
        );
        reg.set_parents("c", vec!["a".to_string()]);
        assert!(detect_cycle("a", &reg));
        assert!(detect_cycle("b", &reg));
        assert!(detect_cycle("c", &reg));

        let perms = resolve_role_chain("a", &reg);
        assert_eq!(perms.len(), 3);
    }

    #[test]
    fn test_deep_chain() {
        let mut reg = StaticRoleRegistry::new();
        reg.register(
            HierarchyNode::new("level0", std::iter::once(TestPerm::Admin).collect())
                .with_parents(vec!["level1".to_string()]),
        );
        reg.set_parents("level0", vec!["level1".to_string()]);
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
        reg.register(
            HierarchyNode::new("root", std::iter::once(TestPerm::Admin).collect())
                .with_parents(vec!["left".to_string(), "right".to_string()]),
        );
        reg.set_parents("root", vec!["left".to_string(), "right".to_string()]);
        reg.register(
            HierarchyNode::new("left", std::iter::once(TestPerm::Read).collect())
                .with_parents(vec!["base".to_string()]),
        );
        reg.set_parents("left", vec!["base".to_string()]);
        reg.register(
            HierarchyNode::new("right", std::iter::once(TestPerm::Write).collect())
                .with_parents(vec!["base".to_string()]),
        );
        reg.set_parents("right", vec!["base".to_string()]);
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
