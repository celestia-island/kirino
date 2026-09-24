//! Constraint policies for separation of duty, cardinality, prerequisites and
//! time windows, plus the store and validator that enforce them.
//!
//! Constraint checking is a fail-closed gate: `ConstraintValidator` turns a
//! violation or a store error into an `Err`, and a caller on a security path must
//! treat that as a denial. The opposite convention also holds: absence of a stored
//! policy means "no restriction", so seeding the `ConstraintStore` is a
//! security-critical precondition and an empty store permits everything.

/// Constraint policy types: SSD/DSD separation-of-duty, cardinality, prerequisite
/// and temporal windows. Inert data plus pure predicates, with no store access.
pub mod policies;
/// `ConstraintStore` trait and the process-local `InMemoryConstraintStore`.
/// Store reads are the gate's only data source; read errors must not be
/// swallowed into an empty list, which would turn the gate into a no-op.
pub mod store;
/// `ConstraintValidator`, the fail-closed entry point for assignment-time checks.
pub mod validator;

/// Re-exports the separation-of-duty and cardinality/prerequisite/temporal types.
pub use policies::{
    CardinalityConstraint, DsdPolicy, PrerequisiteConstraint, SsdPolicy, TemporalConstraint,
};
/// Re-exports the constraint store trait and its in-memory implementation.
pub use store::{ConstraintStore, InMemoryConstraintStore};
/// Re-exports the validator that applies the stored constraints.
pub use validator::ConstraintValidator;
