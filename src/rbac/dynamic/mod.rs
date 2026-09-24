//! Dynamic authorization (`rbac-dynamic`): runtime risk scoring layered on the
//! static RBAC engine.
//!
//! The arbiter scores each action request on five dimensions (delegator type,
//! trust, action sensitivity, domain scope, behavioral anomaly), maps the total
//! risk onto an autonomy level (L0-L4) and derives the allow/deny verdict plus a
//! mitigation strategy. Invariants later refactors must preserve: only L3/L4 can
//! allow, an unmapped risk or a missing strategy falls back to deny, a
//! locked-down delegator is denied before any scoring, and absent or failing
//! evidence may only *raise* risk (a missing trust record, a cold anomaly
//! detector and a store error each add penalty rather than remove it). Whether
//! that penalty crosses the deny threshold is policy data (`DynamicPolicy`), not
//! a hard-coded gate.
pub mod anomaly;
pub mod arbiter;
pub mod delegator;
pub mod domain;
pub mod metrics;
pub mod policy;
pub mod trust;
pub mod verdict;
