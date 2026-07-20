use kirino_macro::hierarchical_permission;
use serde::{Deserialize, Serialize};
use crate::rbac::traits::Permission as PermissionTrait;

hierarchical_permission!(
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub enum Permission {
        Agent(Read, Write, Execute),
        Config(Read, Write),
        Knowledge(Read, Write),
        Container(Read, Write),
        System(Read, Write),
        Deploy(Read, Execute),
        Provider(List, Create, Update, Delete, Use),
        Mcp(List, Create, Update, Delete, Use),
        Channel(List, Create, Update, Delete, Use),
        Yolo(Use),
        Workspace(List, Create, Manage),
        Device(List, Connect),
        Rbac(Manage),
        Oauth(Read, Write),
    }
);

impl std::fmt::Display for Permission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

impl PermissionTrait for Permission {
    fn name(&self) -> &str {
        Permission::name(self)
    }
    fn domain(&self) -> &'static str {
        Permission::domain(self)
    }
}
