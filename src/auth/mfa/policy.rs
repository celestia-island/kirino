//! Which factors exist and which a policy demands.

use std::collections::BTreeSet;

/// One authentication factor, in the `amr` vocabulary.
///
/// The names are the ones this family writes into `amr`; a deployment with
/// its own vocabulary uses [`Factor::Other`] and declares its own `acr`
/// scale (see [`super::AcrScale`]).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Factor {
    /// A password or passphrase: `amr: ["pwd"]`.
    Password,
    /// A TOTP / HOTP one-time code: `amr: ["otp"]`.
    Otp,
    /// A WebAuthn / passkey assertion: `amr: ["fido"]`.
    Fido,
    /// A one-time code sent to a verified address or number: `amr: ["mfa"]`
    /// per RFC 8176's example vocabulary, or a deployment's own name.
    Other(String),
}

impl Factor {
    /// The `amr` claim value for this factor.
    #[must_use]
    pub fn amr(&self) -> &str {
        match self {
            Self::Password => "pwd",
            Self::Otp => "otp",
            Self::Fido => "fido",
            Self::Other(name) => name,
        }
    }

    /// Whether this factor is something the subject *has* (a device, a
    /// key) rather than *knows*. A possession factor is what distinguishes
    /// two-factor from two passwords.
    #[must_use]
    pub fn is_possession(&self) -> bool {
        matches!(self, Self::Otp | Self::Fido)
    }
}

/// What went wrong with a policy.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PolicyError {
    /// A policy that no journey could ever satisfy.
    #[error("the policy requires {0:?} and also demands it be skipped")]
    Contradictory(Factor),
    /// A policy with no factor at all.
    #[error("a policy must require at least one factor")]
    Empty,
    /// The same factor listed twice under different names.
    #[error("factor {0} is listed as both required and optional")]
    ListedTwice(String),
}

/// Which factors a subject must present, and which are enough.
///
/// Two shapes, because deployments use both:
///
/// - **All** of `required` — a password plus every listed second factor.
/// - **Any** of `required` — "one of these second factors", when a user may
///   have enrolled several and any one suffices.
///
/// `allow_recovery` admits a recovery code in place of the second factor
/// (never in place of the password).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    /// The factors that must be presented.
    required: BTreeSet<Factor>,
    /// Whether ALL `required` must be presented, or ANY one.
    any_of: bool,
    /// Whether a recovery code may stand in for a missing second factor.
    allow_recovery: bool,
}

impl Policy {
    /// Every listed factor must be presented.
    ///
    /// # Errors
    ///
    /// [`PolicyError::Empty`] if `required` is empty.
    pub fn all(required: impl IntoIterator<Item = Factor>) -> Result<Self, PolicyError> {
        let set: BTreeSet<Factor> = required.into_iter().collect();
        if set.is_empty() {
            return Err(PolicyError::Empty);
        }
        Ok(Self {
            required: set,
            any_of: false,
            allow_recovery: false,
        })
    }

    /// Any ONE of the listed factors satisfies the policy.
    ///
    /// # Errors
    ///
    /// [`PolicyError::Empty`] if `required` is empty.
    pub fn any(required: impl IntoIterator<Item = Factor>) -> Result<Self, PolicyError> {
        let set: BTreeSet<Factor> = required.into_iter().collect();
        if set.is_empty() {
            return Err(PolicyError::Empty);
        }
        Ok(Self {
            required: set,
            any_of: true,
            allow_recovery: false,
        })
    }

    /// Let a recovery code stand in for a missing second factor.
    #[must_use]
    pub fn with_recovery(mut self) -> Self {
        self.allow_recovery = true;
        self
    }

    /// The factors the policy names.
    pub fn required(&self) -> impl Iterator<Item = &Factor> {
        self.required.iter()
    }

    /// Whether ALL (rather than ANY) of the named factors must be presented.
    #[must_use]
    pub fn is_all(&self) -> bool {
        !self.any_of
    }

    /// Whether a recovery code may stand in for a second factor.
    #[must_use]
    pub fn allows_recovery(&self) -> bool {
        self.allow_recovery
    }

    /// The factors still outstanding after `presented`.
    ///
    /// Under an **any** policy the answer is empty as soon as one required
    /// factor is present; a password, if listed, still has to be presented
    /// on its own — a recovery code never stands in for it.
    pub(super) fn outstanding<'a>(&'a self, presented: &'a BTreeSet<Factor>) -> Vec<&'a Factor> {
        if self.any_of && self.required.iter().any(|f| presented.contains(f)) {
            return Vec::new();
        }
        self.required
            .iter()
            .filter(|f| !presented.contains(*f))
            .collect()
    }

    /// The `acr` a journey that satisfied this policy may report, under the
    /// deployment's scale: the highest class whose method set is a subset of
    /// what was presented.
    pub(super) fn acr_for(
        &self,
        presented: &BTreeSet<Factor>,
        scale: &super::AcrScale,
    ) -> Option<String> {
        scale.class_for(presented)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_amr_vocabulary_is_the_one_the_family_writes() {
        assert_eq!(Factor::Password.amr(), "pwd");
        assert_eq!(Factor::Otp.amr(), "otp");
        assert_eq!(Factor::Fido.amr(), "fido");
        assert_eq!(Factor::Other("sms".into()).amr(), "sms");
    }

    #[test]
    fn only_a_device_or_key_is_a_possession_factor() {
        assert!(!Factor::Password.is_possession());
        assert!(Factor::Otp.is_possession());
        assert!(Factor::Fido.is_possession());
        // An "other" factor is whatever the deployment says; not ours to judge.
        assert!(!Factor::Other("sms".into()).is_possession());
    }

    #[test]
    fn an_empty_policy_is_refused() {
        assert_eq!(Policy::all([]).unwrap_err(), PolicyError::Empty);
        assert_eq!(Policy::any(Vec::new()).unwrap_err(), PolicyError::Empty);
    }

    #[test]
    fn an_all_policy_needs_every_factor_an_any_policy_needs_one() {
        let all = Policy::all([Factor::Password, Factor::Otp]).unwrap();
        let any = Policy::any([Factor::Otp, Factor::Fido]).unwrap();
        let just_pwd = BTreeSet::from([Factor::Password]);
        assert_eq!(all.outstanding(&just_pwd).len(), 1);
        assert!(
            any.outstanding(&just_pwd).len() == 2,
            "neither second factor yet"
        );
        let pwd_otp = BTreeSet::from([Factor::Password, Factor::Otp]);
        assert!(all.outstanding(&pwd_otp).is_empty());
        assert!(
            any.outstanding(&pwd_otp).is_empty(),
            "one of the two is enough"
        );
    }

    #[test]
    fn a_deduplicated_set_is_the_set() {
        let p = Policy::all([Factor::Otp, Factor::Otp, Factor::Password]).unwrap();
        assert_eq!(p.required().count(), 2);
    }
}
