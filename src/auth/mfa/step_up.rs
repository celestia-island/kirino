//! Is an authentication strong enough for this resource?

use std::collections::BTreeSet;

use thiserror::Error;

use super::policy::Factor;

/// Why an `acr` scale could not be built.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ScaleError {
    /// A class with no method at all: nothing can ever reach it.
    #[error("acr class {0} names no method")]
    EmptyClass(String),
    /// Two classes with the same name.
    #[error("acr class {0} is declared twice")]
    DuplicateClass(String),
    /// A class name that is empty.
    #[error("an acr class name must not be empty")]
    EmptyName,
}

/// The deployment's `acr` vocabulary, ranked.
///
/// OIDC says the meaning of `acr` is the deployment's and that a requester
/// compares values by *some* ordering the deployment defines. This is that
/// ordering, made explicit: each class names the method set that earns it,
/// and classes are ranked by the scale's declaration order.
///
/// A class is **awarded** to a journey when its method set is a subset of
/// what the journey presented. The journey's `acr` is the **highest** such
/// class. A class whose set is `{pwd, otp}` is not awarded to `{pwd,
/// recovery}` — recovery is not otp, and a recovered session is a 1fa
/// session until it proves more.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcrScale {
    ranked: Vec<(String, BTreeSet<Factor>)>,
}

impl AcrScale {
    /// Declare the scale in rank order, lowest first.
    ///
    /// # Errors
    ///
    /// See [`ScaleError`].
    pub fn declared<'a>(
        classes: impl IntoIterator<Item = (&'a str, Vec<Factor>)>,
    ) -> Result<Self, ScaleError> {
        let mut ranked = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        for (name, methods) in classes {
            if name.trim().is_empty() {
                return Err(ScaleError::EmptyName);
            }
            if !seen.insert(name.to_owned()) {
                return Err(ScaleError::DuplicateClass(name.to_owned()));
            }
            if methods.is_empty() {
                return Err(ScaleError::EmptyClass(name.to_owned()));
            }
            ranked.push((name.to_owned(), methods.into_iter().collect()));
        }
        Ok(Self { ranked })
    }

    /// Every class, lowest first.
    pub fn classes(&self) -> impl Iterator<Item = &str> {
        self.ranked.iter().map(|(n, _)| n.as_str())
    }

    /// The highest class whose method set is a subset of `presented`.
    pub(super) fn class_for(&self, presented: &BTreeSet<Factor>) -> Option<String> {
        self.ranked
            .iter()
            .rev()
            .find(|(_, m)| m.is_subset(presented))
            .map(|(n, _)| n.clone())
    }

    /// The rank of a named class, lowest = 0. `None` for a name the scale
    /// does not know — an unknown `acr` is treated as the weakest, never as
    /// the strongest.
    #[must_use]
    pub fn rank_of(&self, acr: &str) -> Option<usize> {
        self.ranked.iter().position(|(n, _)| n == acr)
    }

    /// The method set a class requires.
    #[must_use]
    pub fn methods_of(&self, acr: &str) -> Option<&BTreeSet<Factor>> {
        self.ranked.iter().find(|(n, _)| n == acr).map(|(_, m)| m)
    }
}

/// What a resource demands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepUp {
    /// The `acr` floor, in the deployment's vocabulary.
    acr: String,
    /// The methods that must be present in `amr` regardless of `acr`.
    methods: BTreeSet<Factor>,
}

/// The verdict on a session.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum StepUpVerdict {
    /// The session is strong enough.
    Sufficient,
    /// The session must prove more before it may touch the resource.
    Required {
        /// The `acr` the resource demanded.
        required_acr: String,
        /// The `acr` the session has, if the scale knows it.
        current_acr: Option<String>,
        /// The specific methods still missing from `amr`.
        missing_methods: Vec<Factor>,
    },
}

impl StepUp {
    /// A requirement expressed as an `acr` floor.
    ///
    /// # Errors
    ///
    /// Never today; the signature is kept so a resource can declare a floor
    /// the scale must know without a panic path later.
    pub fn new(acr: impl Into<String>) -> Self {
        Self {
            acr: acr.into(),
            methods: BTreeSet::new(),
        }
    }

    /// Also demand these methods be present in `amr`, whatever the `acr`.
    #[must_use]
    pub fn requiring(mut self, methods: impl IntoIterator<Item = Factor>) -> Self {
        self.methods.extend(methods);
        self
    }

    /// The `acr` floor.
    #[must_use]
    pub fn required_acr(&self) -> &str {
        &self.acr
    }

    /// Judge a session's `amr` / `acr` against this requirement.
    ///
    /// The rule, in order:
    ///
    /// 1. Every method in [`StepUp::requiring`] must be in `amr`.
    /// 2. The session's `acr` must rank at or above the floor on the scale.
    ///    A session with **no** `acr`, or one the scale does not know, is
    ///    below every floor — an absent claim is never a strong one.
    /// 3. The floor's own method set must be a subset of `amr`. This is
    ///    what stops a stale `acr` from a *previous* login from standing in
    ///    for the methods: the methods are what the session proved, and the
    ///    `acr` is what someone called it.
    #[must_use]
    pub fn judge(&self, amr: &[String], acr: Option<&str>, scale: &AcrScale) -> StepUpVerdict {
        let present: BTreeSet<Factor> = amr
            .iter()
            .map(|m| match m.as_str() {
                "pwd" => Factor::Password,
                "otp" => Factor::Otp,
                "fido" => Factor::Fido,
                other => Factor::Other(other.to_owned()),
            })
            .collect();
        let mut missing: Vec<Factor> = self
            .methods
            .iter()
            .filter(|m| !present.contains(*m))
            .cloned()
            .collect();
        let current_rank = acr.and_then(|a| scale.rank_of(a));
        let required_rank = scale.rank_of(&self.acr);
        let enough_rank = match (current_rank, required_rank) {
            (Some(c), Some(r)) => c >= r,
            // A floor the scale does not know cannot be reasoned about: the
            // only safe answer is "not enough".
            _ => false,
        };
        // Rule 3, always: the FLOOR's method set must be in `amr`, whatever
        // the session's `acr` says. A stale `acr` from an earlier login names
        // what someone once called the session; the methods are what THIS
        // session proved. (The first version only checked this when the rank
        // fell short — and its own test caught it: a session claiming 2fa
        // with no `otp` in `amr` passed a 2fa floor.)
        if let Some(methods) = scale.methods_of(&self.acr) {
            for m in methods {
                if !present.contains(m) && !missing.contains(m) {
                    missing.push(m.clone());
                }
            }
        }
        if missing.is_empty() && enough_rank {
            StepUpVerdict::Sufficient
        } else {
            StepUpVerdict::Required {
                required_acr: self.acr.clone(),
                current_acr: acr.map(str::to_owned),
                missing_methods: missing,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scale() -> AcrScale {
        AcrScale::declared([
            ("urn:c:1fa", vec![Factor::Password]),
            ("urn:c:2fa", vec![Factor::Password, Factor::Otp]),
            ("urn:c:max", vec![Factor::Password, Factor::Fido]),
        ])
        .unwrap()
    }

    #[test]
    fn a_class_is_awarded_only_when_its_methods_are_a_subset() {
        let s = scale();
        let pwd = BTreeSet::from([Factor::Password]);
        assert_eq!(s.class_for(&pwd).as_deref(), Some("urn:c:1fa"));
        let pwd_otp = BTreeSet::from([Factor::Password, Factor::Otp]);
        assert_eq!(s.class_for(&pwd_otp).as_deref(), Some("urn:c:2fa"));
        // otp alone is no class at all.
        let otp = BTreeSet::from([Factor::Otp]);
        assert_eq!(s.class_for(&otp), None);
    }

    #[test]
    fn the_scale_refuses_empty_and_duplicate_classes() {
        assert_eq!(
            AcrScale::declared([("a", vec![])]).unwrap_err(),
            ScaleError::EmptyClass("a".into())
        );
        assert_eq!(
            AcrScale::declared([("a", vec![Factor::Password]), ("a", vec![Factor::Otp])])
                .unwrap_err(),
            ScaleError::DuplicateClass("a".into())
        );
        assert_eq!(
            AcrScale::declared([("", vec![Factor::Password])]).unwrap_err(),
            ScaleError::EmptyName
        );
    }

    #[test]
    fn two_methods_beat_one_and_an_unknown_acr_is_the_weakest() {
        let s = scale();
        let v =
            StepUp::new("urn:c:2fa").judge(&["pwd".into(), "otp".into()], Some("urn:c:2fa"), &s);
        assert_eq!(v, StepUpVerdict::Sufficient);
        let v = StepUp::new("urn:c:2fa").judge(&["pwd".into()], Some("urn:c:1fa"), &s);
        assert!(matches!(v, StepUpVerdict::Required { .. }));
        // No acr at all: below every floor, even 1fa.
        let v = StepUp::new("urn:c:1fa").judge(&["pwd".into()], None, &s);
        assert!(
            matches!(v, StepUpVerdict::Required { .. }),
            "an absent acr is never a strong one"
        );
        // An acr the scale does not know: same.
        let v = StepUp::new("urn:c:1fa").judge(&["pwd".into()], Some("urn:elsewhere:x"), &s);
        assert!(matches!(v, StepUpVerdict::Required { .. }));
        // A floor the scale does not know: cannot be reasoned about → not enough.
        let v = StepUp::new("urn:unknown").judge(&["pwd".into()], Some("urn:c:max"), &s);
        assert!(matches!(v, StepUpVerdict::Required { .. }));
    }

    #[test]
    fn a_stale_acr_does_not_stand_in_for_missing_methods() {
        // MUT:stale-acr — if the judge trusted `acr` alone, a session that
        // said "2fa" but whose amr lacked otp would pass a 2fa floor.
        let s = scale();
        let v = StepUp::new("urn:c:2fa").judge(&["pwd".into()], Some("urn:c:2fa"), &s);
        let StepUpVerdict::Required {
            missing_methods, ..
        } = v
        else {
            panic!("a 2fa claim without otp in amr must not pass");
        };
        assert_eq!(missing_methods, vec![Factor::Otp]);
    }

    #[test]
    fn required_methods_are_demanded_whatever_the_acr() {
        let s = scale();
        let v = StepUp::new("urn:c:1fa").requiring([Factor::Fido]).judge(
            &["pwd".into(), "otp".into()],
            Some("urn:c:2fa"),
            &s,
        );
        let StepUpVerdict::Required {
            missing_methods, ..
        } = v
        else {
            panic!("fido was required");
        };
        assert_eq!(missing_methods, vec![Factor::Fido]);
    }

    #[test]
    fn the_verdict_names_what_is_missing_so_the_user_can_be_told() {
        let s = scale();
        let v = StepUp::new("urn:c:max").judge(&["pwd".into()], Some("urn:c:1fa"), &s);
        let StepUpVerdict::Required {
            required_acr,
            current_acr,
            missing_methods,
        } = v
        else {
            panic!("max needs fido");
        };
        assert_eq!(required_acr, "urn:c:max");
        assert_eq!(current_acr.as_deref(), Some("urn:c:1fa"));
        assert_eq!(missing_methods, vec![Factor::Fido]);
    }
}
