use crate::rbac::traits::Permission as PermissionTrait;
use kirino_macro::hierarchical_permission;
use serde::{Deserialize, Serialize};

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
        Plugin(Read, Install, Publish, Manage),
    }
);

impl Permission {
    /// The plugin-fabric permission points, as path strings — the catalog
    /// and grant model key off these (Celestia Plugin Fabric A2).
    ///
    /// `plugin.read` gates catalog browsing (hosts may additionally default
    /// it to all members), `plugin.install` gates the install RPC — the
    /// self/workspace/instance *scope* lives in the grant record, not in
    /// this point — `plugin.publish` gates submitting plugins to the
    /// distribution channel, and `plugin.manage` covers trust-root
    /// administration (publisher allowlists, key rotation).
    pub const PLUGIN_PATHS: [&'static str; 4] = [
        "plugin.read",
        "plugin.install",
        "plugin.publish",
        "plugin.manage",
    ];
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plugin_permission_points_resolve_as_paths() {
        for path in Permission::PLUGIN_PATHS {
            let parsed =
                Permission::from_path(path).unwrap_or_else(|| panic!("{path} must resolve"));
            assert_eq!(parsed.domain(), "plugin");
            assert_eq!(parsed.name(), path);
        }
    }

    #[test]
    fn plugin_domain_expands_to_exactly_the_four_points() {
        let mut expanded: Vec<&str> = Permission::expand_domain("plugin")
            .iter()
            .map(|p| p.name())
            .collect();
        expanded.sort_unstable();
        let mut expected = Permission::PLUGIN_PATHS;
        expected.sort_unstable();
        assert_eq!(expanded, expected);
        // The other management domains stay untouched by the addition.
        assert!(Permission::expand_domain("rbac").len() == 1);
    }

    #[test]
    fn plugin_points_are_part_of_all() {
        let names: Vec<&str> = Permission::all().iter().map(|p| p.name()).collect();
        for path in Permission::PLUGIN_PATHS {
            assert!(names.contains(&path), "all() must include {path}");
        }
    }

    #[test]
    fn unknown_plugin_sub_actions_are_rejected() {
        // The vocabulary is closed: only the four declared sub-actions
        // exist under the plugin domain.
        for bad in ["plugin.list", "plugin.delete", "plugin.execute"] {
            assert!(
                Permission::from_path(bad).is_none(),
                "{bad} must not resolve"
            );
        }
    }
}
