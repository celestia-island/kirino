//! Action metrics: the sensitivity taxonomy for actions and the request under
//! evaluation.
//!
//! The category ladder is the only fixed severity mapping in the subsystem, and
//! both the category and the resource path are asserted by the caller, so a
//! mislabelled request is under-scored here rather than rejected.
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

use super::delegator::Delegator;

/// Coarse classification of what an action does, which fixes the *sensitivity*
/// risk dimension.
///
/// The category is asserted per request: nothing in this module maps the
/// free-form `ActionRequest::action` string to a category, so a caller that
/// labels a privileged operation `ReadOnly` also under-scores it. Hosts must
/// therefore derive the category from a trusted action registry, not from user
/// input. The variant set is the whole taxonomy: an action that fits none of
/// them cannot be classified more strictly than the closest one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ActionCategory {
    /// Observation with no state change (base weight 0.1): the lowest charge,
    /// but never zero, so reads still accumulate risk.
    ReadOnly,
    /// Change to application or configuration state (0.3).
    StateWrite,
    /// Write to the filesystem (0.5). Which paths are permitted is decided
    /// separately by the domain scope's resource prefixes, not by this category.
    FileWrite,
    /// Outbound network traffic (0.7): data exfiltration and command-and-control
    /// paths score here.
    NetworkEgress,
    /// Execution of a process or command (0.8), the classic escalation step
    /// from data access to code execution.
    ProcessExec,
    /// Container lifecycle operations (0.9): starting or stopping workloads
    /// changes what else can run.
    ContainerLifecycle,
    /// Privileged/administrative operation (1.0): the top of the ladder, used
    /// for actions that can change the authorization system itself.
    PrivilegedOp,
}

impl ActionCategory {
    /// Sensitivity weight fixed by the category, in `[0.1, 1.0]`; see the
    /// variant list for the ladder.
    ///
    /// This value becomes the `sensitivity` sub-score and is multiplied by the
    /// policy's sensitivity dimension weight (0.25 by default), so even a
    /// `PrivilegedOp` contributes at most 0.25 of total risk and can never deny
    /// on its own. The ladder is fixed and non-configurable: hosts that need a
    /// different severity ordering must change the policy weights, not this
    /// mapping. Values must stay in `[0, 1]` because the total risk is compared
    /// against the policy thresholds without any per-dimension rescaling.
    #[must_use]
    pub fn base_weight(&self) -> f64 {
        match self {
            ActionCategory::ReadOnly => 0.1,
            ActionCategory::StateWrite => 0.3,
            ActionCategory::FileWrite => 0.5,
            ActionCategory::NetworkEgress => 0.7,
            ActionCategory::ProcessExec => 0.8,
            ActionCategory::ContainerLifecycle => 0.9,
            ActionCategory::PrivilegedOp => 1.0,
        }
    }
}

/// An action name paired with the category it belongs to and the sensitivity
/// weight that category implies.
///
/// Annotation/lookup helper only: `AuthorizationArbiter::risk_score` reads the
/// sensitivity from `ActionRequest::category` directly and never consults this
/// struct, so holding or mutating an `ActionSensitivity` value cannot change a
/// verdict. It exists so a host can publish an action catalogue that uses the
/// same weights the arbiter will apply.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionSensitivity {
    /// Free-form action name. Not interpreted by this crate: no matching,
    /// globbing or normalization is applied, so the name never has to agree with
    /// `ActionRequest::action`.
    pub action: String,
    /// Category that determines sensitivity scoring for this action.
    pub category: ActionCategory,
    /// Cached `category.base_weight()`, captured at construction. The field is
    /// public but nothing re-derives it, so a value that disagrees with
    /// `category` is not detected.
    pub base_weight: f64,
}

impl ActionSensitivity {
    /// Builds an entry for `action` and captures `category.base_weight()`.
    ///
    /// The captured weight is a snapshot: if the ladder in
    /// `ActionCategory::base_weight` ever changes, values built earlier keep the
    /// old weight, so deserialized catalogues must be regenerated rather than
    /// reused indefinitely.
    #[must_use]
    pub fn new(action: impl Into<String>, category: ActionCategory) -> Self {
        let bw = category.base_weight();
        Self {
            action: action.into(),
            category,
            base_weight: bw,
        }
    }
}

/// A single action for which authorization is requested.
///
/// This is the claim under evaluation, not a verified fact: the arbiter takes
/// `delegator`, `category` and `resource_path` as given. Do not place
/// credentials or secrets in `parameters`; the arbiter never inspects them, but
/// the derived `Debug` and `Serialize` impls will print them wherever the host
/// logs or transports the request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionRequest {
    /// Claimed acting principal. Its `id` selects the trust record and the
    /// behavioral detector, so the host must populate it from authenticated
    /// context.
    pub delegator: Delegator,
    /// Free-form action name. Recorded in the audit entry as the permission
    /// field and in the per-delegator behavioral record; this layer does not
    /// otherwise interpret it (no matching, globbing or normalization).
    pub action: String,
    /// Caller-asserted sensitivity category; drives the sensitivity dimension.
    /// A mislabelled request is under-scored, so this must come from a trusted
    /// mapping.
    pub category: ActionCategory,
    /// Opaque action payload. Never read, scored or logged by the arbiter, so
    /// parameter-level policy is not enforced here; treat it as
    /// caller-controlled data.
    pub parameters: BTreeMap<String, Value>,
    /// Resource the action targets, used for the domain scope checks. `None`
    /// means no resource confinement is applied (fail-open on that axis), so
    /// callers that care about confinement must always set it.
    pub resource_path: Option<String>,
    /// Caller-supplied time recorded in the behavioral history (an
    /// `ActionRecord`), not the time of the decision. A forged or backdated
    /// value therefore enters the anomaly baseline unchecked, because the
    /// detector never reads the clock for records; the verdict and the audit
    /// entry carry their own server-side timestamps instead.
    pub timestamp: DateTime<Utc>,
}

impl ActionRequest {
    /// Builds a request with no parameters, no resource path and
    /// `timestamp = now`.
    ///
    /// Because the resource path is absent, domain resource confinement does not
    /// apply to the resulting request (see `DomainScope::evaluate`); use
    /// `with_resource` whenever the action targets a path.
    #[must_use]
    pub fn simple(
        delegator: Delegator,
        action: impl Into<String>,
        category: ActionCategory,
    ) -> Self {
        Self {
            delegator,
            action: action.into(),
            category,
            parameters: BTreeMap::new(),
            resource_path: None,
            timestamp: Utc::now(),
        }
    }

    /// Attaches the target resource path and returns the request (builder form).
    ///
    /// The path is normalized textually by `TaskDomain::is_resource_allowed`
    /// (`.` and empty components dropped, `..` popped) with no symlink
    /// resolution, percent-decoding or case folding, so callers must pass an
    /// already-canonical, unescaped path; otherwise a path can match a permitted
    /// prefix here and still denote a different resource to the executor.
    #[must_use]
    pub fn with_resource(mut self, path: impl Into<String>) -> Self {
        self.resource_path = Some(path.into());
        self
    }

    /// Replaces the parameter map and returns the request (builder form).
    ///
    /// A `BTreeMap` gives deterministic iteration order for serialization and
    /// audit output; the arbiter itself never reads the values, and nothing
    /// validates, redacts or size-limits them.
    #[must_use]
    pub fn with_parameters(mut self, params: BTreeMap<String, Value>) -> Self {
        self.parameters = params;
        self
    }
}
