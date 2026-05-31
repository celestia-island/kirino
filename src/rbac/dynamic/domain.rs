use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use super::metrics::ActionCategory;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskDomain {
    pub domain_name: String,
    pub allowed_action_categories: HashSet<ActionCategory>,
    pub allowed_resource_prefixes: Vec<String>,
    pub trust_floor: f64,
}

impl TaskDomain {
    pub fn new(
        name: impl Into<String>,
        categories: HashSet<ActionCategory>,
        prefixes: Vec<String>,
        trust_floor: f64,
    ) -> Self {
        Self {
            domain_name: name.into(),
            allowed_action_categories: categories,
            allowed_resource_prefixes: prefixes,
            trust_floor: trust_floor.clamp(0.0, 1.0),
        }
    }

    pub fn is_resource_allowed(&self, path: &str) -> bool {
        if self.allowed_resource_prefixes.is_empty() {
            return true;
        }
        self.allowed_resource_prefixes
            .iter()
            .any(|prefix| path.starts_with(prefix))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainScope {
    pub current_task_domain: TaskDomain,
    pub adjacent_domains: Vec<TaskDomain>,
}

impl DomainScope {
    pub fn single(domain: TaskDomain) -> Self {
        Self {
            current_task_domain: domain,
            adjacent_domains: Vec::new(),
        }
    }

    pub fn with_adjacent(domain: TaskDomain, adjacent: Vec<TaskDomain>) -> Self {
        Self {
            current_task_domain: domain,
            adjacent_domains: adjacent,
        }
    }

    pub fn evaluate(&self, category: &ActionCategory, resource_path: Option<&str>) -> DomainMatch {
        let in_domain = self
            .current_task_domain
            .allowed_action_categories
            .contains(category);
        let resource_ok = resource_path
            .map(|p| self.current_task_domain.is_resource_allowed(p))
            .unwrap_or(true);

        if in_domain && resource_ok {
            return DomainMatch::InDomain;
        }

        let in_adjacent = self
            .adjacent_domains
            .iter()
            .any(|d| d.allowed_action_categories.contains(category));

        if in_adjacent {
            return DomainMatch::Adjacent {
                excess_weight: 0.15,
            };
        }

        DomainMatch::OutOfDomain { excess_weight: 0.6 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DomainMatch {
    InDomain,
    Adjacent { excess_weight: f64 },
    OutOfDomain { excess_weight: f64 },
}

impl DomainMatch {
    pub fn excess_weight(&self) -> f64 {
        match self {
            DomainMatch::InDomain => 0.0,
            DomainMatch::Adjacent { excess_weight } => *excess_weight,
            DomainMatch::OutOfDomain { excess_weight } => *excess_weight,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_domain() -> TaskDomain {
        TaskDomain::new(
            "hydrogen-control",
            [ActionCategory::ReadOnly, ActionCategory::StateWrite].into(),
            vec!["/tank/".to_string(), "/valve/".to_string()],
            0.5,
        )
    }

    #[test]
    fn test_domain_resource_allowed() {
        let domain = make_domain();
        assert!(domain.is_resource_allowed("/tank/pressure"));
        assert!(domain.is_resource_allowed("/valve/open"));
        assert!(!domain.is_resource_allowed("/etc/passwd"));
    }

    #[test]
    fn test_domain_empty_prefix_allows_all() {
        let domain = TaskDomain::new("open", [ActionCategory::ReadOnly].into(), vec![], 0.0);
        assert!(domain.is_resource_allowed("/any/path"));
    }

    #[test]
    fn test_domain_scope_in_domain() {
        let scope = DomainScope::single(make_domain());
        let m = scope.evaluate(&ActionCategory::ReadOnly, Some("/tank/pressure"));
        assert!(matches!(m, DomainMatch::InDomain));
    }

    #[test]
    fn test_domain_scope_out_of_domain() {
        let scope = DomainScope::single(make_domain());
        let m = scope.evaluate(&ActionCategory::ProcessExec, Some("/bin/bash"));
        assert!(matches!(m, DomainMatch::OutOfDomain { .. }));
    }

    #[test]
    fn test_domain_scope_adjacent() {
        let adjacent = TaskDomain::new(
            "monitoring",
            [ActionCategory::ReadOnly].into(),
            vec!["/metrics/".to_string()],
            0.3,
        );
        let scope = DomainScope::with_adjacent(
            TaskDomain::new("core", [ActionCategory::StateWrite].into(), vec![], 0.5),
            vec![adjacent],
        );
        let m = scope.evaluate(&ActionCategory::ReadOnly, None);
        assert!(matches!(m, DomainMatch::Adjacent { .. }));
    }

    #[test]
    fn test_excess_weight() {
        let scope = DomainScope::single(make_domain());
        assert_eq!(
            scope
                .evaluate(&ActionCategory::ReadOnly, Some("/tank/x"))
                .excess_weight(),
            0.0
        );
        assert_eq!(
            scope
                .evaluate(&ActionCategory::ProcessExec, None)
                .excess_weight(),
            0.6
        );
    }
}
