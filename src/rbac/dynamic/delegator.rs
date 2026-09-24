//! Who is acting: the delegator identity and its classification.
//!
//! Both are caller-asserted claims -- the host is trusted to authenticate the
//! principal before asking for a decision -- and the `id` doubles as the trust
//! store key and the anomaly-detector key, so its uniqueness and stability are
//! security-relevant.
use serde::{Deserialize, Serialize};

/// Classification of the principal that requested an action.
///
/// The variant is asserted by the caller rather than derived from the request
/// payload: kirino trusts the host to establish the delegator's identity and
/// type before asking for a decision (trust boundary B1 in
/// `docs/THREAT_MODEL.md`). The value selects the delegator-weight ladder in
/// `AuthorizationArbiter::risk_score` and is recorded in the verdict evidence
/// and the audit entry, so a host must derive it from authenticated context and
/// never from caller-supplied fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DelegatorType {
    /// Interactive human operator: no inherent delegator weight (0.0), because a
    /// human is presumed accountable. The other four risk dimensions still
    /// apply, so a human request is not risk-free.
    Human,
    /// First-party autonomous agent: small inherent weight (0.05); its risk
    /// comes mainly from trust, sensitivity, domain and anomaly.
    Agent,
    /// Agent acting on behalf of another agent (`Delegator::parent_id`): weight
    /// 0.15, so a delegated identity is scored more strictly than the agent
    /// that created it. This layer does not verify the parent chain.
    SubAgent,
    /// Principal outside the trust boundary: highest weight (0.30). Use only for
    /// callers whose identity was established over an authenticated channel; the
    /// arbiter cannot distinguish an external caller from a forged one.
    ExternalSystem,
    /// Internal scheduler or daemon trigger: near-zero inherent weight (0.02)
    /// because the trigger carries no user intent. Action sensitivity, domain
    /// and trust still apply.
    Scheduler,
}

/// The acting principal as seen by the dynamic authorization layer.
///
/// This is the claim made by the caller (normally the host): neither the
/// delegator nor its type is authenticated or verified here. The `id` is the key
/// under which trust is stored and the key under which behavioral state is kept,
/// so it must be a canonical, stable, per-principal identifier: aliasing one
/// principal across several ids fragments its trust, while reusing one id across
/// principals leaks trust from one to the other.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Delegator {
    /// Stable principal identifier; also the trust-store key and the
    /// anomaly-detector key. Unbounded caller-supplied string, so the host must
    /// pass an already-authenticated id (never a raw request parameter); the id
    /// is also copied into verdict evidence and audit entries.
    pub id: String,
    /// Caller-asserted classification that selects the delegator-weight risk
    /// dimension; see `DelegatorType`.
    pub delegator_type: DelegatorType,
    /// Free-form session label kept for operator-facing context only. It takes
    /// part in no risk dimension, domain check or audit entry, so it must never
    /// be used for an authorization decision.
    pub session_badge: String,
    /// Id of the delegating principal for a sub-agent. Informational in this
    /// layer: the arbiter never consults it, so inherited authority is neither
    /// verified nor narrowed by dynamic authorization.
    pub parent_id: Option<String>,
}

impl Delegator {
    /// Builds a `Human` delegator with no parent.
    ///
    /// Both strings are stored verbatim (no validation, no length bound), so the
    /// host is responsible for passing an authenticated, canonical id and a
    /// non-sensitive badge.
    pub fn human(id: impl Into<String>, session_badge: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            delegator_type: DelegatorType::Human,
            session_badge: session_badge.into(),
            parent_id: None,
        }
    }

    /// Builds an `Agent` delegator with no parent: an autonomous first-party
    /// identity that carries its own trust record. Strings are stored verbatim;
    /// see `human` for the host-side obligations.
    pub fn agent(id: impl Into<String>, session_badge: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            delegator_type: DelegatorType::Agent,
            session_badge: session_badge.into(),
            parent_id: None,
        }
    }

    /// Builds a `SubAgent` delegator that records `parent_id` as the delegating
    /// principal. The parent is recorded but not verified, and it contributes
    /// nothing to the risk score, so callers that need accountability for
    /// delegated authority must check the chain outside this layer.
    pub fn sub_agent(
        id: impl Into<String>,
        session_badge: impl Into<String>,
        parent_id: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            delegator_type: DelegatorType::SubAgent,
            session_badge: session_badge.into(),
            parent_id: Some(parent_id.into()),
        }
    }

    /// Sets `parent_id` on any delegator type and returns the delegator (builder
    /// form). The type is not checked, so a `Human` may also be given a parent;
    /// nothing in this layer reads the result.
    #[must_use]
    pub fn with_parent(mut self, parent_id: impl Into<String>) -> Self {
        self.parent_id = Some(parent_id.into());
        self
    }
}
