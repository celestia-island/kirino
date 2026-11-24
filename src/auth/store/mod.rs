//! Storage SPI family for the login infrastructure.
//!
//! Every credential-shaped thing this crate hands out is **single use**:
//! authorization codes, device codes, `state` values, recovery codes,
//! refresh rotations. One rule makes them safe, and it is the same rule
//! everywhere:
//!
//! > **The claim must be atomic, and the claimer must be *told* whether it
//! > won.**
//!
//! That second half is what separates a correct store from one that merely
//! deletes a row. A `DELETE` that affects zero rows is **not** an error, so
//! an implementation that looks up a credential, decides it is valid, and
//! then deletes it lets two racing callers both proceed — the second
//! delete succeeds trivially. This exact shape shipped once already in a
//! downstream service (authorization-code exchange: `SELECT` the code, then
//! `DELETE` it, checking only that the delete *errored*), which is why
//! [`ConsumableStore`] answers [`Claim::Won`] / [`Claim::Lost`] instead of
//! returning a `bool` from a delete.
//!
//! # Why a trait family rather than per-module traits
//!
//! The in-process stores elsewhere in this crate (WebAuthn challenges,
//! one-time tokens, login attempts, TOTP replay marks) each carry their own
//! narrow trait and a process-local implementation. That is fine for a
//! single replica and wrong for every deployment that runs more than one:
//! a restart or a second replica forgets every pending credential. This
//! module gives the *shared* half — one atomic single-use contract, one
//! in-memory reference implementation, and (behind `store-db`) one
//! multi-replica implementation — so a host picks a backend instead of
//! re-deriving the semantics per feature.
//!
//! Existing module-local traits are **not** replaced here: they keep their
//! public API (a breaking change would ripple through every consumer for no
//! security gain). New capabilities use this family; the existing ones can
//! be backed by it over time.

pub mod consumable;
pub mod memory;

pub use consumable::{fingerprint, Claim, ConsumableStore};
pub use memory::MemoryConsumableStore;

#[cfg(feature = "store-db")]
pub use crate::database::db_consumable::DbConsumableStore;
