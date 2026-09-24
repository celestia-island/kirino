//! Task domains and domain scopes: which action categories and resources a
//! delegator may use in the current task, and the trust floor expected there.
//!
//! Domain data is trusted host configuration. The empty-value conventions are
//! asymmetric and security-relevant: an empty category set grants nothing
//! in-domain, while an empty resource prefix list allows everything, so resource
//! confinement is opt-in per domain.
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use super::metrics::ActionCategory;

const DOMAIN_RESOURCE_MISMATCH_WEIGHT: f64 = 0.3;
const ADJACENT_DOMAIN_WEIGHT: f64 = 0.15;
const OUT_OF_DOMAIN_WEIGHT: f64 = 0.6;

/// The task a delegator is currently allowed to perform: which action
/// categories, which resources, and how much trust it must have.
///
/// Domain data is trusted configuration loaded by the host; it is never derived
/// from the request. The empty-value conventions are asymmetric and
/// security-relevant: an empty category set grants no category in-domain
/// (fail-closed, though adjacent domains may still permit a request), while an
/// empty resource prefix list allows every resource (fail-open), so a domain
/// whose prefixes were left unset imposes no resource confinement at all.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskDomain {
    /// Operator-facing domain name. It takes part in no score; it appears only
    /// in the caller's own logging.
    pub domain_name: String,
    /// Categories considered in-domain. Empty means no category is in-domain, so
    /// every request is classified adjacent or out-of-domain, which is
    /// fail-closed.
    pub allowed_action_categories: HashSet<ActionCategory>,
    /// Resource prefixes allowed in this domain, matched as textual prefixes of
    /// the normalized path. Empty means *all* resources are allowed, so populate
    /// it for every confined domain.
    pub allowed_resource_prefixes: Vec<String>,
    /// Minimum effective trust (`TrustScore::weighted`, i.e. value * confidence,
    /// in `[0, 1]`) expected in this domain. It is not a hard gate:
    /// `AuthorizationArbiter::risk_score` adds `(floor - weighted)` to the trust
    /// penalty, which only raises risk, and a low enough total can still be
    /// allowed. `0.0` disables the extra penalty entirely.
    pub trust_floor: f64,
}

impl TaskDomain {
    /// Builds a domain from explicit allow lists.
    ///
    /// `trust_floor` is clamped into `[0, 1]`, so a misconfigured `5.0` becomes
    /// the maximum floor (fail-closed) and a negative value becomes 0.0 (no
    /// extra penalty). The other arguments are stored verbatim, including an
    /// empty prefix list, which allows every resource.
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

    /// Returns whether `path` falls inside this domain's resource prefixes.
    ///
    /// Fail-open in two places, by design: an empty prefix list allows every
    /// path, and a request without a resource path is treated as allowed by the
    /// caller (`DomainScope::evaluate`). Matching is a plain string `starts_with`
    /// on a textually normalized path, so a prefix should include its trailing
    /// separator (`/tank/`, not `/tank`) or it will also match siblings such as
    /// `/tank2/x`. Normalization only drops empty and `.` components and pops on
    /// `..` (a leading `..` cannot escape above the root); there is no symlink
    /// resolution, percent-decoding, case folding or unicode normalization, so
    /// the caller must pass an already-canonical, unescaped path and must not
    /// treat this as a filesystem sandbox -- it constrains policy, not the
    /// executor.
    #[must_use]
    pub fn is_resource_allowed(&self, path: &str) -> bool {
        if self.allowed_resource_prefixes.is_empty() {
            return true;
        }
        let normalized = Self::normalize_path(path);
        self.allowed_resource_prefixes
            .iter()
            .any(|prefix| normalized.starts_with(prefix))
    }

    fn normalize_path(path: &str) -> String {
        let mut components = Vec::new();
        for part in path.split('/') {
            match part {
                "" | "." => {}
                ".." => {
                    components.pop();
                }
                _ => components.push(part),
            }
        }
        if components.is_empty() {
            return "/".to_string();
        }
        let mut result = String::with_capacity(path.len());
        for comp in &components {
            result.push('/');
            result.push_str(comp);
        }
        result
    }
}

/// The domain a delegator is working in, plus the neighbouring domains it may
/// borrow lower-risk access from.
///
/// Scope data is host-supplied configuration that can be replaced at runtime
/// (`AuthorizationArbiter::set_domain_scope`) and is re-read on every
/// `risk_score` call, so a scope change applies to requests scored after it and
/// never re-scores a request that was already decided.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainScope {
    /// The domain the current task belongs to. Its category set decides
    /// in-domain versus out-of-domain, its prefixes confine resources, and its
    /// `trust_floor` raises the trust penalty.
    pub current_task_domain: TaskDomain,
    /// Domains reachable from the current task. A category allowed here but not
    /// in the current domain scores as adjacent (0.15 excess instead of 0.6), so
    /// listing a domain is an explicit, security-relevant grant; the entries are
    /// not validated against the current domain.
    pub adjacent_domains: Vec<TaskDomain>,
}

impl DomainScope {
    /// Builds a scope with one domain and no adjacent domains, so any category
    /// outside it is out-of-domain.
    #[must_use]
    pub fn single(domain: TaskDomain) -> Self {
        Self {
            current_task_domain: domain,
            adjacent_domains: Vec::new(),
        }
    }

    /// Builds a scope with explicit adjacent domains. Adjacency is an explicit
    /// grant: only the domains listed here can lower a mismatch score, they are
    /// accepted as given (no validation, no de-duplication), and their
    /// `trust_floor` values are never applied -- only the current domain's floor
    /// is.
    #[must_use]
    pub fn with_adjacent(domain: TaskDomain, adjacent: Vec<TaskDomain>) -> Self {
        Self {
            current_task_domain: domain,
            adjacent_domains: adjacent,
        }
    }

    /// Classifies a request against the scope, returning the `DomainMatch` whose
    /// `excess_weight` is charged to the domain-mismatch risk dimension.
    ///
    /// Precedence and pairing, which later changes must preserve: category
    /// membership in the current domain is checked first, then adjacent
    /// categories, then out-of-domain; a resource path is checked only against
    /// the domain that grants the category, so a category allowed by one
    /// adjacent domain cannot borrow another adjacent domain's resource prefix.
    /// A request without a resource path is treated as resource-allowed
    /// everywhere (fail-open on the resource axis).
    ///
    /// The weights are fixed constants: 0.3 for an in-domain category with a
    /// disallowed resource, 0.15 for adjacency, 0.45 for adjacency plus a
    /// disallowed resource, and 0.6 for out-of-domain. Their derivation is not
    /// recorded in the repository (basis to be confirmed with security review).
    /// They are excess weights, not decisions: they scale the policy's domain
    /// dimension weight (0.25 by default, so at most 0.15 of total risk), and an
    /// out-of-domain request is not denied by this classification alone.
    #[must_use]
    pub fn evaluate(&self, category: &ActionCategory, resource_path: Option<&str>) -> DomainMatch {
        let in_domain = self
            .current_task_domain
            .allowed_action_categories
            .contains(category);
        let resource_ok = match resource_path {
            Some(p) => self.current_task_domain.is_resource_allowed(p),
            None => true,
        };

        if in_domain && resource_ok {
            return DomainMatch::InDomain;
        }

        if in_domain && !resource_ok {
            return DomainMatch::DomainResourceMismatch {
                excess_weight: DOMAIN_RESOURCE_MISMATCH_WEIGHT,
            };
        }

        let in_adjacent = self
            .adjacent_domains
            .iter()
            .any(|d| d.allowed_action_categories.contains(category));

        if in_adjacent {
            let adjacent_resource_ok = self.adjacent_domains.iter().any(|d| {
                d.allowed_action_categories.contains(category)
                    && match resource_path {
                        Some(p) => d.is_resource_allowed(p),
                        None => true,
                    }
            });

            if !adjacent_resource_ok {
                return DomainMatch::DomainResourceMismatch {
                    excess_weight: ADJACENT_DOMAIN_WEIGHT + DOMAIN_RESOURCE_MISMATCH_WEIGHT,
                };
            }

            return DomainMatch::Adjacent {
                excess_weight: ADJACENT_DOMAIN_WEIGHT,
            };
        }

        DomainMatch::OutOfDomain {
            excess_weight: OUT_OF_DOMAIN_WEIGHT,
        }
    }
}

/// How one request was classified against a `DomainScope`, carrying the excess
/// weight the domain-mismatch risk dimension should charge.
///
/// The excess weight is data, not a decision: `OutOfDomain` raises risk but does
/// not by itself deny, so a host that needs hard domain confinement must gate on
/// this classification explicitly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DomainMatch {
    /// Category and resource are both inside the current domain: no excess
    /// weight.
    InDomain,
    /// Category is allowed by an adjacent domain (and that domain's resource
    /// check passed): the lowest non-zero excess, so adjacency is a real
    /// widening of authority even though it is not a denial.
    Adjacent { excess_weight: f64 },
    /// Category is in-domain (or adjacent) but the resource is not covered by an
    /// allowed prefix, or the adjacent domain that grants the category does not
    /// cover the resource: charged more than plain adjacency.
    DomainResourceMismatch { excess_weight: f64 },
    /// Category is allowed by neither the current nor any adjacent domain: the
    /// highest excess weight, i.e. the action is outside the delegated task.
    OutOfDomain { excess_weight: f64 },
}

impl DomainMatch {
    /// Excess weight this classification charges, `0.0` for `InDomain`.
    ///
    /// Values produced by `DomainScope::evaluate` come from the four documented
    /// constants, but the variants are public and can be constructed with any
    /// value, so consumers must not assume the result is one of them (and the
    /// arbiter does not clamp it before weighting).
    #[must_use]
    pub fn excess_weight(&self) -> f64 {
        match self {
            Self::InDomain => 0.0,
            Self::Adjacent { excess_weight }
            | Self::DomainResourceMismatch { excess_weight }
            | Self::OutOfDomain { excess_weight } => *excess_weight,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_domain() -> TaskDomain {
        TaskDomain::new(
            "process-control",
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

    #[test]
    fn test_adjacent_domain_resource_mismatch() {
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
        let m = scope.evaluate(&ActionCategory::ReadOnly, Some("/etc/passwd"));
        assert!(
            matches!(m, DomainMatch::DomainResourceMismatch { .. }),
            "adjacent category but disallowed resource should be mismatch"
        );
        assert!(m.excess_weight() > ADJACENT_DOMAIN_WEIGHT);
    }

    #[test]
    fn test_adjacent_domain_resource_allowed() {
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
        let m = scope.evaluate(&ActionCategory::ReadOnly, Some("/metrics/cpu"));
        assert!(matches!(m, DomainMatch::Adjacent { .. }));
    }
}
