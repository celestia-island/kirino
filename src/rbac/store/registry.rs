use std::{
    collections::{HashMap, HashSet},
    marker::PhantomData,
};

use crate::rbac::traits::{Permission, PermissionRegistry, Role, RoleRegistry};

#[cfg(feature = "rbac-hierarchy")]
use crate::rbac::hierarchy::HierarchicalRole;

#[derive(Debug, Clone)]
pub struct SimpleRole<P: Permission> {
    name: String,
    permissions: HashSet<P>,
}

impl<P: Permission> SimpleRole<P> {
    pub fn new(name: impl Into<String>, permissions: HashSet<P>) -> Self {
        Self {
            name: name.into(),
            permissions,
        }
    }
}

impl<P: Permission> Role<P> for SimpleRole<P> {
    fn role_name(&self) -> &str {
        &self.name
    }

    fn permissions(&self) -> &HashSet<P> {
        &self.permissions
    }
}

pub struct StaticPermissionRegistry<P: Permission> {
    permissions: HashSet<P>,
    by_name: HashMap<String, P>,
}

impl<P: Permission> StaticPermissionRegistry<P> {
    #[must_use]
    pub fn new(permissions: HashSet<P>) -> Self {
        let by_name = permissions
            .iter()
            .map(|p| (p.name().to_string(), p.clone()))
            .collect();
        Self {
            permissions,
            by_name,
        }
    }
}

impl<P: Permission> PermissionRegistry<P> for StaticPermissionRegistry<P> {
    fn all_permissions(&self) -> HashSet<P> {
        self.permissions.clone()
    }

    fn get_permission(&self, name: &str) -> Option<P> {
        self.by_name.get(name).cloned()
    }
}

pub struct StaticRoleRegistry<R, P>
where
    R: Role<P>,
    P: Permission,
{
    roles: HashMap<String, R>,
    parents: HashMap<String, Vec<String>>,
    _phantom: PhantomData<P>,
}

impl<R, P> StaticRoleRegistry<R, P>
where
    R: Role<P>,
    P: Permission,
{
    #[must_use]
    pub fn new() -> Self {
        Self {
            roles: HashMap::new(),
            parents: HashMap::new(),
            _phantom: PhantomData,
        }
    }

    pub fn register(&mut self, role: R) {
        let name = role.role_name().to_string();
        self.parents.remove(&name);
        self.roles.insert(name, role);
    }

    pub fn set_parents(&mut self, role_name: &str, parents: Vec<String>) {
        self.parents.insert(role_name.to_string(), parents);
    }
}

#[cfg(feature = "rbac-hierarchy")]
impl<R, P> StaticRoleRegistry<R, P>
where
    R: HierarchicalRole<P>,
    P: Permission,
{
    pub fn register_hierarchical(&mut self, role: R) {
        let role_name = role.role_name().to_string();
        let parents = role.parent_roles();
        self.parents.insert(role_name.clone(), parents);
        self.roles.insert(role_name, role);
    }
}

impl<R, P> Default for StaticRoleRegistry<R, P>
where
    R: Role<P>,
    P: Permission,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<R, P> RoleRegistry<P> for StaticRoleRegistry<R, P>
where
    R: Role<P>,
    P: Permission,
{
    fn get_role_permissions(&self, role_name: &str) -> Option<HashSet<P>> {
        self.roles.get(role_name).map(|r| r.permissions().clone())
    }

    fn role_parents(&self, role_name: &str) -> Vec<String> {
        self.parents.get(role_name).cloned().unwrap_or_default()
    }

    fn list_role_names(&self) -> Vec<String> {
        self.roles.keys().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TestPerm;

    #[test]
    fn test_simple_role() {
        let role: SimpleRole<TestPerm> =
            SimpleRole::new("editor", [TestPerm::Read, TestPerm::Write].into());
        assert_eq!(role.role_name(), "editor");
        assert!(role.permissions().contains(&TestPerm::Read));
        assert!(role.permissions().contains(&TestPerm::Write));
        assert!(!role.permissions().contains(&TestPerm::Delete));
    }

    #[test]
    fn test_static_permission_registry() {
        let perms: HashSet<TestPerm> = [TestPerm::Read, TestPerm::Write].into();
        let reg = StaticPermissionRegistry::new(perms);

        let all = reg.all_permissions();
        assert_eq!(all.len(), 2);

        assert!(reg.get_permission("read").is_some());
        assert!(reg.get_permission("write").is_some());
        assert!(reg.get_permission("delete").is_none());
    }

    #[test]
    fn test_static_role_registry() {
        let mut reg: StaticRoleRegistry<SimpleRole<TestPerm>, TestPerm> = StaticRoleRegistry::new();
        reg.register(SimpleRole::new("viewer", [TestPerm::Read].into()));
        reg.register(SimpleRole::new(
            "admin",
            [TestPerm::Read, TestPerm::Write, TestPerm::Delete].into(),
        ));

        assert!(reg.get_role_permissions("viewer").is_some());
        assert!(reg.get_role_permissions("admin").is_some());
        assert!(reg.get_role_permissions("unknown").is_none());

        let names = reg.list_role_names();
        assert_eq!(names.len(), 2);

        let admin = reg.get_role_permissions("admin").unwrap();
        assert_eq!(admin.len(), 3);
    }

    #[test]
    fn test_static_role_registry_overwrite() {
        let mut reg: StaticRoleRegistry<SimpleRole<TestPerm>, TestPerm> = StaticRoleRegistry::new();
        reg.register(SimpleRole::new("role", [TestPerm::Read].into()));
        reg.register(SimpleRole::new(
            "role",
            [TestPerm::Read, TestPerm::Write].into(),
        ));

        let perms = reg.get_role_permissions("role").unwrap();
        assert_eq!(perms.len(), 2);
    }
}
