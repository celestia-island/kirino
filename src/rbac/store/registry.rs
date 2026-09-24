use std::{
    collections::{HashMap, HashSet},
    marker::PhantomData,
};

use crate::rbac::traits::{Permission, PermissionRegistry, Role, RoleRegistry};

#[cfg(feature = "rbac-hierarchy")]
use crate::rbac::hierarchy::HierarchicalRole;

/// A plain role definition: a name plus its permission set.
///
/// Security semantics: the permission set is the complete authority granted to
/// every holder of this role (grants are additive), so widening the set widens
/// all holders at once. The name is what assignment rows reference, so it must
/// match the persisted role name exactly.
#[derive(Debug, Clone)]
pub struct SimpleRole<P: Permission> {
    name: String,
    permissions: HashSet<P>,
}

impl<P: Permission> SimpleRole<P> {
    /// Builds a role from a name and its permission set. Nothing is validated:
    /// an empty name or an empty set is accepted, and a duplicate name is only
    /// detected when the role is registered.
    pub fn new(name: impl Into<String>, permissions: HashSet<P>) -> Self {
        Self {
            name: name.into(),
            permissions,
        }
    }
}

impl<P: Permission> Role<P> for SimpleRole<P> {
    /// The name this role was constructed with; the key assignment rows use.
    fn role_name(&self) -> &str {
        &self.name
    }

    /// The full permission set handed in at construction.
    fn permissions(&self) -> &HashSet<P> {
        &self.permissions
    }
}

/// Immutable-by-convention permission catalogue built once at startup.
///
/// Security semantics: names are indexed at construction, so two permissions
/// sharing a name collapse to whichever one the `HashSet` iteration yields
/// last - a duplicate name silently shadows a permission instead of failing,
/// so registries must be built from a name-unique source. Adding a permission
/// to the set is how a deployment widens what can be granted at all.
pub struct StaticPermissionRegistry<P: Permission> {
    permissions: HashSet<P>,
    by_name: HashMap<String, P>,
}

impl<P: Permission> StaticPermissionRegistry<P> {
    /// Indexes the given permissions by [`Permission::name`].
    ///
    /// Security semantics: build this once from a trusted, name-unique source.
    /// If two distinct permissions share a name, the map keeps one of them
    /// arbitrarily, so a check for that name may resolve to the other
    /// permission.
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
    /// Clones the whole known set; membership here means "recognized", not
    /// "granted".
    fn all_permissions(&self) -> HashSet<P> {
        self.permissions.clone()
    }

    /// Looks a permission up by exact name. `None` means the name is unknown:
    /// callers must reject the request, since treating an unknown name as "no
    /// rule" would let a typo silently disable a check.
    fn get_permission(&self, name: &str) -> Option<P> {
        self.by_name.get(name).cloned()
    }
}

/// In-memory role registry with an explicit parent map.
///
/// Security semantics: this registry is read on the authorization path, so
/// everything registered here is potentially authority. Registration is
/// mutable and unchecked while the process runs: `register` replaces an
/// existing role with the same name (dropping its parents), and `set_parents`
/// accepts arbitrary strings, so a parent naming a role that was never
/// registered simply contributes nothing. Because the engine holds a shared
/// handle to this registry, mutations after startup affect live decisions.
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
    /// Creates an empty registry: every role lookup returns `None`, so the
    /// engine grants no role default until roles are registered (fail-closed).
    #[must_use]
    pub fn new() -> Self {
        Self {
            roles: HashMap::new(),
            parents: HashMap::new(),
            _phantom: PhantomData,
        }
    }

    /// Inserts or replaces a role by name.
    ///
    /// Security semantics: replacing a role changes the authority of every
    /// subject currently holding that name, with no re-validation of existing
    /// sessions or caches. It also clears any parents previously set for the
    /// name, so re-registering a role silently drops its inherited
    /// permissions.
    pub fn register(&mut self, role: R) {
        let name = role.role_name().to_string();
        self.parents.remove(&name);
        self.roles.insert(name, role);
    }

    /// Sets the parent list for a role name.
    ///
    /// Security semantics: parents widen authority (their permissions are
    /// inherited), and this call does not check that the parents exist or that
    /// the role itself is registered - a dangling parent contributes nothing,
    /// while a cycle is only survivable because the traversal guards against
    /// it (`rbac::hierarchy::detect_cycle`). Setting parents on a role that
    /// resolves to itself would otherwise recurse indefinitely.
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
    /// Registers a role together with the parents it declares.
    ///
    /// Security semantics: unlike [`register`](StaticRoleRegistry::register)
    /// this keeps the hierarchy, so the declared parents' permissions are
    /// inherited; the declarations are persisted in the registry and widen
    /// authority, so they must come from a trusted, cycle-free role catalogue.
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
    /// Same as [`new`](StaticRoleRegistry::new): an empty registry that grants
    /// nothing.
    fn default() -> Self {
        Self::new()
    }
}

impl<R, P> RoleRegistry<P> for StaticRoleRegistry<R, P>
where
    R: Role<P>,
    P: Permission,
{
    /// Permissions of a registered role; `None` for an unknown name, which the
    /// engine skips (contributing no authority) rather than treating as an
    /// error.
    fn get_role_permissions(&self, role_name: &str) -> Option<HashSet<P>> {
        self.roles.get(role_name).map(|r| r.permissions().clone())
    }

    /// Declared parents of a role; empty for a role with no parents and for a
    /// role that was never registered, so "no inheritance" and "unknown role"
    /// are indistinguishable here.
    fn role_parents(&self, role_name: &str) -> Vec<String> {
        self.parents.get(role_name).cloned().unwrap_or_default()
    }

    /// Every registered role name, unordered; used for listings and audits, not
    /// for authorization.
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
