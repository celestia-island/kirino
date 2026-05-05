use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Admin,
    Operator,
    Viewer,
    Agent,
}

impl Role {
    pub fn permissions(&self) -> HashSet<Permission> {
        match self {
            Role::Admin => Permission::all(),
            Role::Operator => [
                Permission::AgentRead,
                Permission::AgentWrite,
                Permission::AgentExecute,
                Permission::ConfigRead,
                Permission::ConfigWrite,
                Permission::KnowledgeRead,
                Permission::KnowledgeWrite,
                Permission::ContainerRead,
                Permission::ContainerWrite,
                Permission::DeployRead,
                Permission::DeployExecute,
                Permission::SystemRead,
            ]
            .iter()
            .copied()
            .collect(),
            Role::Viewer => [
                Permission::AgentRead,
                Permission::ConfigRead,
                Permission::KnowledgeRead,
                Permission::ContainerRead,
                Permission::SystemRead,
                Permission::DeployRead,
            ]
            .iter()
            .copied()
            .collect(),
            Role::Agent => [
                Permission::AgentRead,
                Permission::AgentExecute,
                Permission::KnowledgeRead,
            ]
            .iter()
            .copied()
            .collect(),
        }
    }

    pub fn has_permission(&self, permission: Permission) -> bool {
        self.permissions().contains(&permission)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    AgentRead,
    AgentWrite,
    AgentExecute,
    ConfigRead,
    ConfigWrite,
    KnowledgeRead,
    KnowledgeWrite,
    ContainerRead,
    ContainerWrite,
    SystemRead,
    SystemWrite,
    DeployRead,
    DeployExecute,
}

impl Permission {
    pub fn all() -> HashSet<Permission> {
        use Permission::*;
        [
            AgentRead, AgentWrite, AgentExecute,
            ConfigRead, ConfigWrite,
            KnowledgeRead, KnowledgeWrite,
            ContainerRead, ContainerWrite,
            SystemRead, SystemWrite,
            DeployRead, DeployExecute,
        ]
        .iter()
        .copied()
        .collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRole {
    pub user_id: String,
    pub roles: Vec<Role>,
    pub extra_permissions: HashSet<Permission>,
    pub denied_permissions: HashSet<Permission>,
}

impl UserRole {
    pub fn new(user_id: String, roles: Vec<Role>) -> Self {
        Self {
            user_id,
            roles,
            extra_permissions: HashSet::new(),
            denied_permissions: HashSet::new(),
        }
    }

    pub fn has_permission(&self, permission: Permission) -> bool {
        if self.denied_permissions.contains(&permission) {
            return false;
        }
        self.roles
            .iter()
            .any(|r| r.has_permission(permission))
            || self.extra_permissions.contains(&permission)
    }

    pub fn effective_permissions(&self) -> HashSet<Permission> {
        let mut perms = HashSet::new();
        for role in &self.roles {
            perms.extend(role.permissions());
        }
        perms.extend(&self.extra_permissions);
        perms.retain(|p| !self.denied_permissions.contains(p));
        perms
    }
}

#[derive(Debug, Clone, Default)]
pub struct RbacStore {
    users: HashMap<String, UserRole>,
}

impl RbacStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn assign_role(&mut self, user_id: &str, role: Role) {
        let user = self
            .users
            .entry(user_id.to_string())
            .or_insert_with(|| UserRole::new(user_id.to_string(), vec![]));
        if !user.roles.contains(&role) {
            user.roles.push(role);
        }
    }

    pub fn get_user(&self, user_id: &str) -> Option<&UserRole> {
        self.users.get(user_id)
    }

    pub fn remove_role(&mut self, user_id: &str, role: &Role) {
        if let Some(user) = self.users.get_mut(user_id) {
            user.roles.retain(|r| r != role);
        }
    }

    pub fn all_users(&self) -> impl Iterator<Item = &UserRole> {
        self.users.values()
    }

    pub fn check_permission(&self, user_id: &str, permission: Permission) -> bool {
        self.users
            .get(user_id)
            .map(|u| u.has_permission(permission))
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_role_permissions() {
        assert!(Role::Admin.has_permission(Permission::SystemWrite));
        assert!(Role::Viewer.has_permission(Permission::AgentRead));
        assert!(!Role::Viewer.has_permission(Permission::AgentWrite));
        assert!(Role::Agent.has_permission(Permission::AgentExecute));
        assert!(!Role::Agent.has_permission(Permission::ConfigWrite));
    }

    #[test]
    fn test_rbac_store() {
        let mut store = RbacStore::new();
        store.assign_role("user1", Role::Admin);
        assert!(store.check_permission("user1", Permission::SystemWrite));
        assert!(!store.check_permission("unknown", Permission::AgentRead));
    }

    #[test]
    fn test_denied_permission() {
        let mut store = RbacStore::new();
        store.assign_role("user1", Role::Admin);
        if let Some(user) = store.users.get_mut("user1") {
            user.denied_permissions.insert(Permission::SystemWrite);
        }
        assert!(!store.check_permission("user1", Permission::SystemWrite));
    }
}
