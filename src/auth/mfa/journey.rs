//! One authentication in flight, across steps.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use thiserror::Error;

use super::policy::{Factor, Policy};

/// What the subject presented this step.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Presented {
    /// The password verified (the host did the argon2; this is the fact).
    Password,
    /// A TOTP code, verified by the host's [`TotpVerifier`] against the
    /// subject's secret AND accepted by the host's replay guard.
    ///
    /// [`TotpVerifier`]: crate::auth::passport::dynamic_password::TotpVerifier
    Otp,
    /// A WebAuthn assertion verified by the host.
    Fido,
    /// A factor in the deployment's own vocabulary, verified by the host.
    Other(String),
    /// A recovery code — single-use, consumed through the host's store.
    Recovery,
}

impl Presented {
    fn factor(&self) -> Option<&Factor> {
        match self {
            Self::Password => Some(&Factor::Password),
            Self::Otp => Some(&Factor::Otp),
            Self::Fido => Some(&Factor::Fido),
            Self::Other(_) => None,
            Self::Recovery => None,
        }
    }
}

/// Why a step was refused.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum JourneyError {
    /// The same factor was presented twice in one journey.
    #[error("{0} was already presented in this journey")]
    Repeated(&'static str),
    /// A factor outside the policy's vocabulary arrived under an `all`
    /// policy: nothing can be done with it.
    #[error("{0} is not a factor this policy accepts")]
    NotInPolicy(String),
    /// The journey is already complete.
    #[error("the journey is already complete")]
    Complete,
    /// A recovery code arrived where the policy does not allow one.
    #[error("a recovery code may not stand in for this policy's factors")]
    RecoveryNotAllowed,
}

/// The outcome of folding one presented factor into the journey.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FactorOutcome {
    /// More is needed; these are the factors still outstanding.
    NeedMore(Vec<Factor>),
    /// The policy is satisfied. The `amr` is in presentation order; the
    /// `acr` is the highest class the deployment's scale awards it, if any.
    Done {
        amr: Vec<String>,
        acr: Option<String>,
    },
}

/// An authentication in flight: the policy, what has been presented so far,
/// and when it started.
#[derive(Debug, Clone)]
pub struct Journey {
    policy: Policy,
    presented: BTreeSet<Factor>,
    order: Vec<String>,
    recovery_used: bool,
    started_at: DateTime<Utc>,
}

impl Journey {
    /// Start a journey under `policy` at `now`.
    #[must_use]
    pub fn start(policy: Policy, now: DateTime<Utc>) -> Self {
        Self {
            policy,
            presented: BTreeSet::new(),
            order: Vec::new(),
            recovery_used: false,
            started_at: now,
        }
    }

    /// When the journey started — the `auth_time` a completed journey reports.
    #[must_use]
    pub fn started_at(&self) -> DateTime<Utc> {
        self.started_at
    }

    /// The `amr` so far, in presentation order.
    #[must_use]
    pub fn amr(&self) -> &[String] {
        &self.order
    }

    /// Whether the policy is satisfied.
    ///
    /// A recovery code stands in for **one** outstanding non-password factor
    /// (the first in the policy's order), never for the whole remainder: a
    /// three-factor policy is not satisfied by one recovery code. The first
    /// version treated "recovery used" as "done", and the recovery-once
    /// test caught it — one code had cleared two factors.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.outstanding().is_empty()
    }

    /// What is still needed, with the recovery credit applied.
    ///
    /// Under an ANY policy an accepted recovery code IS the one factor the
    /// policy asked for — nothing is outstanding. Under an ALL policy it
    /// covers exactly one outstanding non-password factor. The credit is
    /// applied HERE, in `outstanding`, and never by inserting a factor into
    /// `presented`: `presented` is what the subject proved, and `acr` is
    /// computed from it. (R3: the first fix inserted `Otp` into
    /// `presented` under ANY policies, which both completed policies that
    /// did not list Otp — burning the code — and awarded a recovery session
    /// an otp-class `acr`.)
    fn outstanding(&self) -> Vec<Factor> {
        let mut out: Vec<Factor> = self
            .policy
            .outstanding(&self.presented)
            .into_iter()
            .cloned()
            .collect();
        if self.recovery_used {
            if self.policy.is_any() {
                out.clear();
            } else if let Some(i) = out.iter().position(|f| *f != Factor::Password) {
                out.remove(i);
            }
        }
        out
    }

    /// Fold one presented factor in.
    ///
    /// The host has ALREADY verified the factor — checked the password,
    /// verified the TOTP against the secret and the replay guard, verified
    /// the WebAuthn assertion, consumed the recovery code. This method only
    /// decides what that fact means for the policy.
    ///
    /// # Errors
    ///
    /// - [`JourneyError::Repeated`] if the factor was presented before.
    /// - [`JourneyError::RecoveryNotAllowed`] if a recovery code arrived
    ///   under a policy that does not admit one.
    /// - [`JourneyError::Complete`] if the journey was already done.
    pub fn verify(
        &mut self,
        factor: Presented,
        scale: &super::AcrScale,
    ) -> Result<FactorOutcome, JourneyError> {
        if self.is_complete() {
            return Err(JourneyError::Complete);
        }
        match &factor {
            Presented::Recovery => {
                if !self.policy.allows_recovery() {
                    return Err(JourneyError::RecoveryNotAllowed);
                }
                if self.recovery_used {
                    return Err(JourneyError::Repeated("recovery"));
                }
                // A recovery code stands in for the second factor, never for
                // the password: the password must have been presented.
                if self.policy.required().any(|f| *f == Factor::Password)
                    && !self.presented.contains(&Factor::Password)
                {
                    return Err(JourneyError::NotInPolicy("recovery before password".into()));
                }
                self.recovery_used = true;
                self.order.push("recovery".to_owned());
                // Under an ANY policy, an accepted recovery code IS the one
                // factor the policy asked for. Before this, the code was
                // burned and the journey still said `NeedMore` (R2 S1).
                if self.policy.is_any() {
                    self.presented.insert(Factor::Otp);
                }
            }
            other => {
                let f = other.factor().cloned();
                let Some(f) = f else {
                    // An "other" factor: recorded in amr, never satisfies a
                    // known factor; a policy that names it as Other would
                    // have matched below, which is why Other is a Factor too.
                    if let Presented::Other(name) = other {
                        // A reserved name may not arrive as `Other`: the
                        // journey would refuse to count it as that factor
                        // while writing the canonical name into `amr`, and
                        // `StepUp::judge` would read it back as the real
                        // thing (R2 S1: `Other("otp")` satisfied a 2fa floor
                        // without the subject ever proving otp).
                        if matches!(name.as_str(), "pwd" | "otp" | "fido" | "recovery")
                            || name.trim().is_empty()
                        {
                            return Err(JourneyError::NotInPolicy(name.clone()));
                        }
                        if self.order.iter().any(|a| a == name) {
                            return Err(JourneyError::NotInPolicy(name.clone()));
                        }
                        let as_factor = Factor::Other(name.clone());
                        if self.policy.required().any(|r| *r == as_factor) {
                            self.presented.insert(as_factor);
                        }
                        self.order.push(name.clone());
                    }
                    return Ok(self.outcome(scale));
                };
                if self.presented.contains(&f) {
                    return Err(JourneyError::Repeated(match f {
                        Factor::Password => "pwd",
                        Factor::Otp => "otp",
                        Factor::Fido => "fido",
                        Factor::Other(_) => "other",
                    }));
                }
                self.presented.insert(f.clone());
                self.order.push(f.amr().to_owned());
            }
        }
        Ok(self.outcome(scale))
    }

    fn outcome(&self, scale: &super::AcrScale) -> FactorOutcome {
        if self.is_complete() {
            FactorOutcome::Done {
                amr: self.order.clone(),
                acr: self.policy.acr_for(&self.presented, scale),
            }
        } else {
            FactorOutcome::NeedMore(self.outstanding())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::mfa::{AcrScale, StepUp};

    fn scale() -> AcrScale {
        AcrScale::declared([
            ("urn:celestia:1fa", vec![Factor::Password]),
            ("urn:celestia:2fa", vec![Factor::Password, Factor::Otp]),
        ])
        .unwrap()
    }

    fn at() -> DateTime<Utc> {
        Utc::now()
    }

    #[test]
    fn password_then_otp_completes_with_the_right_amr_and_acr() {
        let mut j = Journey::start(Policy::all([Factor::Password, Factor::Otp]).unwrap(), at());
        let first = j.verify(Presented::Password, &scale()).unwrap();
        assert_eq!(first, FactorOutcome::NeedMore(vec![Factor::Otp]));
        let second = j.verify(Presented::Otp, &scale()).unwrap();
        assert_eq!(
            second,
            FactorOutcome::Done {
                amr: vec!["pwd".into(), "otp".into()],
                acr: Some("urn:celestia:2fa".into())
            }
        );
    }

    #[test]
    fn a_factor_may_not_be_presented_twice() {
        let mut j = Journey::start(Policy::all([Factor::Password, Factor::Otp]).unwrap(), at());
        j.verify(Presented::Password, &scale()).unwrap();
        assert_eq!(
            j.verify(Presented::Password, &scale()).unwrap_err(),
            JourneyError::Repeated("pwd")
        );
    }

    #[test]
    fn a_completed_journey_refuses_more() {
        let mut j = Journey::start(Policy::all([Factor::Password]).unwrap(), at());
        assert!(matches!(
            j.verify(Presented::Password, &scale()).unwrap(),
            FactorOutcome::Done { .. }
        ));
        assert_eq!(
            j.verify(Presented::Otp, &scale()).unwrap_err(),
            JourneyError::Complete
        );
    }

    #[test]
    fn an_any_policy_is_satisfied_by_one_of_its_factors() {
        let mut j = Journey::start(Policy::any([Factor::Otp, Factor::Fido]).unwrap(), at());
        let out = j.verify(Presented::Fido, &scale()).unwrap();
        assert!(matches!(out, FactorOutcome::Done { .. }));
        assert_eq!(j.amr(), &["fido".to_owned()]);
    }

    #[test]
    fn recovery_stands_in_for_the_second_factor_only() {
        let p = Policy::all([Factor::Password, Factor::Otp])
            .unwrap()
            .with_recovery();
        let mut j = Journey::start(p.clone(), at());
        // Recovery before the password: refused.
        assert!(matches!(
            j.verify(Presented::Recovery, &scale()),
            Err(JourneyError::NotInPolicy(_))
        ));
        j.verify(Presented::Password, &scale()).unwrap();
        let out = j.verify(Presented::Recovery, &scale()).unwrap();
        assert!(matches!(out, FactorOutcome::Done { .. }));
        assert_eq!(j.amr(), &["pwd".to_owned(), "recovery".to_owned()]);
        // And once used, not again.
        assert_eq!(
            j.verify(Presented::Recovery, &scale()).unwrap_err(),
            JourneyError::Complete
        );
    }

    /// A recovery code may be used ONCE per journey, and the check must
    /// hold while the journey is still incomplete — otherwise a policy
    /// whose second factor is "any of {otp, fido}" could be satisfied by
    /// presenting recovery twice (R1's mutation removed the `recovery_used`
    /// guard and survived, because every existing case reached `Complete`
    /// on the second presentation, which hid it).
    #[test]
    fn a_second_recovery_code_is_refused_even_while_the_journey_is_incomplete() {
        // A three-factor policy keeps the journey open after one recovery
        // covers one factor — the window where a second recovery would slip.
        let p = Policy::all([Factor::Password, Factor::Otp, Factor::Fido])
            .unwrap()
            .with_recovery();
        let mut j = Journey::start(p, at());
        j.verify(Presented::Password, &scale()).unwrap();
        let out = j.verify(Presented::Recovery, &scale()).unwrap();
        // Still incomplete: otp and fido were both required, recovery covered one.
        assert!(
            matches!(out, FactorOutcome::NeedMore(_)),
            "one recovery covers one factor"
        );
        // MUT:recovery-once — without the `recovery_used` guard the second
        // recovery would be accepted and complete the journey.
        assert_eq!(
            j.verify(Presented::Recovery, &scale()).unwrap_err(),
            JourneyError::Repeated("recovery"),
            "a recovery code is one factor, once"
        );
    }

    #[test]
    fn recovery_is_refused_where_the_policy_does_not_allow_it() {
        let mut j = Journey::start(Policy::all([Factor::Password, Factor::Otp]).unwrap(), at());
        j.verify(Presented::Password, &scale()).unwrap();
        assert_eq!(
            j.verify(Presented::Recovery, &scale()).unwrap_err(),
            JourneyError::RecoveryNotAllowed
        );
    }

    #[test]
    fn a_recovery_login_does_not_reach_the_otp_acr() {
        let p = Policy::all([Factor::Password, Factor::Otp])
            .unwrap()
            .with_recovery();
        let mut j = Journey::start(p, at());
        j.verify(Presented::Password, &scale()).unwrap();
        let FactorOutcome::Done { acr, .. } = j.verify(Presented::Recovery, &scale()).unwrap()
        else {
            panic!("done");
        };
        // The scale awards 2fa only to pwd+otp; recovery is NOT otp, so the
        // journey reports 1fa. A resource demanding 2fa will ask for more.
        assert_eq!(acr.as_deref(), Some("urn:celestia:1fa"));
        // MUT:recovery-is-not-otp — letting recovery count as Otp would
        // report 2fa here and hand a recovered session a 2fa-only resource.
        let v = StepUp::new("urn:celestia:2fa").judge(j.amr(), acr.as_deref(), &scale());
        assert!(matches!(
            v,
            crate::auth::mfa::StepUpVerdict::Required { .. }
        ));
    }

    /// R2 S1: a reserved name may not arrive as `Other`. The journey would
    /// refuse to count it as that factor while writing the canonical name
    /// into `amr` — and `StepUp::judge` reads `amr` back as the real thing,
    /// so `Other("otp")` satisfied a 2fa floor without otp ever being proven.
    #[test]
    fn a_reserved_name_cannot_arrive_as_an_other_factor() {
        let mut j = Journey::start(Policy::all([Factor::Password, Factor::Otp]).unwrap(), at());
        j.verify(Presented::Password, &scale()).unwrap();
        for reserved in ["otp", "fido", "pwd", "recovery", "  "] {
            assert_eq!(
                j.verify(Presented::Other(reserved.into()), &scale())
                    .unwrap_err(),
                JourneyError::NotInPolicy(reserved.to_owned()),
                "{reserved} is a reserved name"
            );
        }
        // MUT:other-reserved — letting `Other("otp")` through writes "otp"
        // into amr and `judge(2fa)` then passes on a journey that never
        // proved otp.
        let v = crate::auth::mfa::StepUp::new("urn:celestia:2fa").judge(j.amr(), None, &scale());
        assert!(matches!(
            v,
            crate::auth::mfa::StepUpVerdict::Required { .. }
        ));
    }

    /// R2 S1: under an ANY policy an accepted recovery code IS the factor.
    /// Before, the code was burned and the journey still said `NeedMore`.
    #[test]
    fn a_recovery_code_completes_an_any_policy() {
        let mut j = Journey::start(
            Policy::any([Factor::Otp, Factor::Fido])
                .unwrap()
                .with_recovery(),
            at(),
        );
        let out = j.verify(Presented::Recovery, &scale()).unwrap();
        assert!(
            matches!(out, FactorOutcome::Done { .. }),
            "accepted recovery satisfies an any-of policy"
        );
        assert!(j.is_complete());
    }

    /// R3 S1: ANY policy that does NOT list Otp — recovery still completes
    /// it. The first fix only worked when `Otp` happened to be in the set.
    #[test]
    fn a_recovery_code_completes_an_any_policy_without_otp() {
        for policy in [
            Policy::any([Factor::Fido]).unwrap(),
            Policy::any([Factor::Fido, Factor::Other("hwk".into())]).unwrap(),
            Policy::any([Factor::Other("sms".into()), Factor::Other("email".into())]).unwrap(),
        ] {
            let mut j = Journey::start(policy.with_recovery(), at());
            let out = j.verify(Presented::Recovery, &scale()).unwrap();
            assert!(
                matches!(out, FactorOutcome::Done { .. }),
                "recovery satisfies any-of"
            );
            assert!(j.is_complete());
        }
    }

    /// R3 S1 (regression): a recovery session is NOT an otp session. Its
    /// `acr` is computed from what the subject proved, and `recovery` is not
    /// in any class's method set — so it reaches `1fa`, never `2fa`.
    #[test]
    fn a_recovery_session_never_earns_an_otp_class_acr() {
        // MUT:recovery-as-otp — inserting Otp into `presented` on recovery
        // makes this `Some("urn:celestia:2fa")`.
        for policy in [
            Policy::any([Factor::Otp, Factor::Fido]).unwrap(),
            Policy::all([Factor::Password, Factor::Otp]).unwrap(),
        ] {
            let mut j = Journey::start(policy.with_recovery(), at());
            if j.verify(Presented::Recovery, &scale()).is_err() {
                // password-first policies need the password
                j.verify(Presented::Password, &scale()).unwrap();
                j.verify(Presented::Recovery, &scale()).unwrap();
            }
            let FactorOutcome::Done { acr, amr } = j.outcome(&scale()) else {
                panic!("done")
            };
            assert!(
                !amr.iter().any(|a| a == "otp"),
                "recovery is not recorded as otp"
            );
            assert_ne!(
                acr.as_deref(),
                Some("urn:celestia:2fa"),
                "a recovery session is not 2fa: {acr:?}"
            );
        }
    }

    /// And an ANY policy that lists the password still needs it first.
    #[test]
    fn an_any_policy_listing_the_password_needs_it_before_recovery() {
        let mut j = Journey::start(
            Policy::any([Factor::Password, Factor::Otp])
                .unwrap()
                .with_recovery(),
            at(),
        );
        assert!(matches!(
            j.verify(Presented::Recovery, &scale()),
            Err(JourneyError::NotInPolicy(_))
        ));
    }

    #[test]
    fn an_other_factor_is_recorded_and_can_satisfy_an_other_requirement() {
        let mut j = Journey::start(
            Policy::all([Factor::Password, Factor::Other("sms".into())]).unwrap(),
            at(),
        );
        j.verify(Presented::Password, &scale()).unwrap();
        let out = j.verify(Presented::Other("sms".into()), &scale()).unwrap();
        assert!(matches!(out, FactorOutcome::Done { .. }));
        assert_eq!(j.amr(), &["pwd".to_owned(), "sms".to_owned()]);
    }

    #[test]
    fn an_unknown_other_factor_is_recorded_but_satisfies_nothing() {
        let mut j = Journey::start(Policy::all([Factor::Password, Factor::Otp]).unwrap(), at());
        j.verify(Presented::Password, &scale()).unwrap();
        let out = j.verify(Presented::Other("sms".into()), &scale()).unwrap();
        assert_eq!(out, FactorOutcome::NeedMore(vec![Factor::Otp]));
        assert!(
            j.amr().contains(&"sms".to_owned()),
            "recorded, since the host verified it"
        );
    }
}
