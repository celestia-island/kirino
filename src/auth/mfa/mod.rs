//! Multi-factor orchestration, step-up and recovery codes.
//!
//! The primitives already exist — [`TotpVerifier`](crate::auth::passport::dynamic_password::TotpVerifier),
//! the WebAuthn assertion verifier, [`TotpReplayGuard`](crate::auth::passport::totp_replay::TotpReplayGuard)
//! and the single-use [`ConsumableStore`](crate::auth::store::ConsumableStore). What
//! every downstream service has been hand-writing is the **policy around
//! them**: which factors a subject must present, in what order, what may be
//! skipped and when, and how the answer is reported as `amr` / `acr` so a
//! relying party can tell "password" from "password + a second factor".
//!
//! This module is that policy, as pure logic:
//!
//! - a [`Policy`] says which factors are required and which are sufficient;
//! - a [`Journey`] tracks one authentication in flight across steps;
//! - [`Journey::verify`] folds one presented factor into the journey,
//!   refuses a repeat of the same factor within the journey (replay across
//!   journeys is the host's replay guard's job), and answers whether the
//!   subject is done;
//! - [`StepUp::judge`] is the step-up check: given a session's `amr` /
//!   `acr` and a resource's requirement, is this authentication strong
//!   enough, or must the subject prove more?
//! - `recovery` issues and consumes single-use recovery codes through
//!   the single-use store, bound to the subject they were issued for, so a
//!   lost second factor is not a lost account — and not a way in, either.
//!
//! Nothing here stores a secret or opens a socket. The host supplies the
//! verifier, the replay guard, the factor store and the clock.
//!
//! # The step-up contract
//!
//! `amr` is a list of method names, most recent last; `acr` is one value
//! whose meaning is the deployment's. A requirement is a floor expressed
//! in the same vocabulary: a set of methods that must all be present, and an
//! optional `acr` floor. A journey that satisfied "pwd + otp" satisfies a
//! requirement of "pwd" but not one of "pwd + fido"; `acr` is compared as a
//! rank the deployment declares, never as a string comparison.

mod journey;
mod policy;
mod recovery;
mod step_up;

pub use journey::{FactorOutcome, Journey, JourneyError, Presented};
pub use policy::{Factor, Policy, PolicyError};
pub use recovery::{RecoveryCode, RecoveryError, RecoveryIssuer};
pub use step_up::{AcrScale, ScaleError, StepUp, StepUpVerdict};
