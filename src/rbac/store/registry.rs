use std::collections::{HashMap, HashSet};
use std::marker::PhantomData;

use crate::rbac::traits::{Permission, PermissionRegistry, Role, RoleRegistry};

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
    _phantom: PhantomData<P>,
}

impl<R, P> StaticRoleRegistry<R, P>
where
    R: Role<P>,
    P: Permission,
{
    pub fn new() -> Self {
        Self {
            roles: HashMap::new(),
            _phantom: PhantomData,
        }
    }

    pub fn register(&mut self, role: R) {
        self.roles.insert(role.role_name().to_string(), role);
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

impl<R, P> RoleRegistry<R, P> for StaticRoleRegistry<R, P>
where
    R: Role<P>,
    P: Permission,
{
    fn get_role(&self, role_name: &str) -> Option<R> {
        self.roles.get(role_name).cloned()
    }

    fn list_role_names(&self) -> Vec<String> {
        self.roles.keys().cloned().collect()
    }
}
