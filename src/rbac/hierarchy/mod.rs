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

pub fn resolve_role_chain<P, R>(
    role_name: &str,
    registry: &dyn crate::rbac::traits::RoleRegistry<R, P>,
) -> HashSet<P>
where
    P: Permission,
    R: HierarchicalRole<P>,
{
    let mut all_perms = HashSet::new();
    let mut visited = HashSet::new();
    let mut stack = vec![role_name.to_string()];

    while let Some(current) = stack.pop() {
        if visited.contains(&current) {
            continue;
        }
        visited.insert(current.clone());

        if let Some(role) = registry.get_role(&current) {
            all_perms.extend(role.permissions().iter().cloned());
            for parent in role.parent_roles() {
                if !visited.contains(&parent) {
                    stack.push(parent);
                }
            }
        }
    }

    all_perms
}

pub fn detect_cycle<P, R>(
    role_name: &str,
    registry: &dyn crate::rbac::traits::RoleRegistry<R, P>,
) -> bool
where
    P: Permission,
    R: HierarchicalRole<P>,
{
    let mut visited = HashSet::new();
    let mut path = HashSet::new();
    fn dfs<P, R>(
        name: &str,
        registry: &dyn crate::rbac::traits::RoleRegistry<R, P>,
        visited: &mut HashSet<String>,
        path: &mut HashSet<String>,
    ) -> bool
    where
        P: Permission,
        R: HierarchicalRole<P>,
    {
        if path.contains(name) {
            return true;
        }
        if visited.contains(name) {
            return false;
        }
        visited.insert(name.to_string());
        path.insert(name.to_string());

        if let Some(role) = registry.get_role(name) {
            for parent in role.parent_roles() {
                if dfs(&parent, registry, visited, path) {
                    return true;
                }
            }
        }

        path.remove(name);
        false
    }

    dfs(role_name, registry, &mut visited, &mut path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rbac::store::registry::StaticRoleRegistry;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    enum TestPerm {
        Read,
        Write,
        Delete,
        Admin,
    }

    impl Permission for TestPerm {
        fn name(&self) -> &str {
            match self {
                TestPerm::Read => "read",
                TestPerm::Write => "write",
                TestPerm::Delete => "delete",
                TestPerm::Admin => "admin",
            }
        }
    }

    fn build_hierarchy() -> StaticRoleRegistry<HierarchyNode<TestPerm>, TestPerm> {
        let mut reg = StaticRoleRegistry::new();
        reg.register(
            HierarchyNode::new("admin", [TestPerm::Admin].into_iter().collect())
                .with_parents(vec!["operator".to_string(), "auditor".to_string()]),
        );
        reg.register(
            HierarchyNode::new(
                "operator",
                [TestPerm::Write, TestPerm::Delete].into_iter().collect(),
            )
            .with_parents(vec!["viewer".to_string()]),
        );
        reg.register(HierarchyNode::new(
            "auditor",
            [TestPerm::Read].into_iter().collect(),
        ));
        reg.register(HierarchyNode::new(
            "viewer",
            [TestPerm::Read].into_iter().collect(),
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
            HierarchyNode::new("a", [TestPerm::Read].into_iter().collect())
                .with_parents(vec!["b".to_string()]),
        );
        reg.register(
            HierarchyNode::new("b", [TestPerm::Write].into_iter().collect())
                .with_parents(vec!["a".to_string()]),
        );
        assert!(detect_cycle("a", &reg));
        assert!(detect_cycle("b", &reg));
    }

    #[test]
    fn test_detect_self_cycle() {
        let mut reg = StaticRoleRegistry::new();
        reg.register(
            HierarchyNode::new("self_ref", [TestPerm::Read].into_iter().collect())
                .with_parents(vec!["self_ref".to_string()]),
        );
        assert!(detect_cycle("self_ref", &reg));
    }
}
