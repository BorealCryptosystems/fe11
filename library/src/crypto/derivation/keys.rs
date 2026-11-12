// SPDX-License-Identifier: Apache-2.0
use super::*;
use crate::{attributes::RequiredAttributes, bounds, ManagedClass, Session};

pub(super) enum BaseSpec<'a> {
    Ec(&'a AgreementKeySpec),
    Montgomery(&'a MontgomeryKeySpec),
    Hkdf(&'a HkdfKeySpec),
}
impl<'a> BaseSpec<'a> {
    pub(super) fn object_admission(&self) -> &'a crate::ObjectAdmission {
        match self {
            Self::Ec(spec) => &spec.private_admission,
            Self::Montgomery(spec) => &spec.private_admission,
            Self::Hkdf(spec) => &spec.admission,
        }
    }

    pub(super) fn mechanism_admission(&self) -> &'a crate::MechanismObservationPlan {
        match self {
            Self::Ec(spec) => &spec.mechanisms,
            Self::Montgomery(spec) => &spec.mechanisms,
            Self::Hkdf(spec) => &spec.mechanisms,
        }
    }

    pub(super) fn id(&self) -> &'a [u8] {
        match self {
            Self::Ec(v) => &v.id,
            Self::Montgomery(v) => &v.id,
            Self::Hkdf(v) => &v.id,
        }
    }
    pub(super) fn label(&self) -> &'a str {
        match self {
            Self::Ec(v) => &v.label,
            Self::Montgomery(v) => &v.label,
            Self::Hkdf(v) => &v.label,
        }
    }
    pub(super) fn persistent(&self) -> bool {
        match self {
            Self::Ec(v) => v.persistent,
            Self::Montgomery(v) => v.persistent,
            Self::Hkdf(v) => v.persistent,
        }
    }
    pub(super) fn class(&self) -> ManagedClass {
        match self {
            Self::Ec(_) | Self::Montgomery(_) => ManagedClass::PrivateKey,
            Self::Hkdf(_) => ManagedClass::SecretKey,
        }
    }
    pub(super) fn kind(&self) -> CK_KEY_TYPE {
        match self {
            Self::Ec(_) => CKK_EC,
            Self::Montgomery(_) => CKK_EC_MONTGOMERY,
            Self::Hkdf(v) => v.kind.raw(),
        }
    }
    pub(super) fn template_as<T: crate::attributes::TemplateSink>(
        &self,
        current: CurrentKeyProtection,
    ) -> Result<T> {
        let mut t = T::empty();
        t.integer(CKA_CLASS, self.class().raw());
        t.integer(CKA_KEY_TYPE, self.kind());
        t.bytes(CKA_ID, self.id());
        t.bytes(CKA_LABEL, self.label().as_bytes());
        let (visibility, usages) = match self {
            Self::Ec(spec) => (spec.private_visibility, spec.private_usages),
            Self::Montgomery(spec) => (spec.private_visibility, spec.private_usages),
            Self::Hkdf(spec) => (spec.visibility, spec.usages),
        };
        for (attribute, value) in [
            (CKA_TOKEN, self.persistent()),
            (CKA_PRIVATE, visibility.is_private()),
            (CKA_SENSITIVE, current.sensitive),
            (CKA_EXTRACTABLE, current.extractable),
        ] {
            t.boolean(attribute, value);
        }
        usages.apply(&mut t);
        // The EC generation mechanism supplies the private domain from the
        // public template (PKCS#11 3.2 section 6.3.7).
        if let Self::Hkdf(spec) = self {
            t.integer(CKA_VALUE_LEN, bounds::ck_length(spec.length)?);
        }
        Ok(t)
    }
    pub(super) fn required_field_iter(&self) -> impl Iterator<Item = CK_ATTRIBUTE_TYPE> {
        [
            CKA_CLASS,
            CKA_KEY_TYPE,
            match self {
                Self::Ec(_) | Self::Montgomery(_) => CKA_EC_PARAMS,
                Self::Hkdf(_) => CKA_VALUE_LEN,
            },
        ]
        .into_iter()
    }
    pub(super) fn validate(&self, v: &RequiredAttributes) -> Result<()> {
        super::observation::Identity::from_base(self).validate(v)
    }
}
impl Session {
    /// Explicitly inspect exact native history and known local contradictions.
    /// Works with private/secret references from find, copy and label changes.
    /// This does not admit a cryptographic use or attest unobserved prior history.
    pub fn key_history(
        &self,
        key: &ManagedObjectRef,
        observation: HistoryObservationPlan,
    ) -> Result<KeyHistory> {
        if !matches!(
            key.class(),
            ManagedClass::PrivateKey | ManagedClass::SecretKey
        ) {
            return Err(Error::Rejected(crate::RejectionReason::KeyDerivation(
                crate::KeyDerivationRejection::KeyHistoryClass,
            )));
        }
        crate::attributes::owned::resident::observe_history_with(
            self,
            key,
            observation,
            |protection| {
                // This final evaluation still holds the original source reader.
                // A resource waiter never carries a completed history snapshot.

                key.identity.access.check(&self.snapshot)?;
                Ok(KeyHistory { protection })
            },
        )
    }

    /// Admit one existing derive-only private key, without asserting a public pair.
    /// The caller supplies the controls applied to actual observed attributes.
    pub fn find_agreement_key(
        &self,
        spec: AgreementKeySpec,
        admission: HistoryObservationPlan,
    ) -> Result<AgreementKey> {
        let mut diagnostics = crate::advanced::PollDiagnostics::default();
        let prepared = crate::crypto::derivation::DerivationBasePlan::new(
            DerivationBaseRequest::Agreement(spec),
            None,
            admission,
        )?;
        match crate::advanced::derivation_base_synchronous(self, prepared, false, &mut diagnostics)
            .and_then(|outcome| outcome.observation)?
        {
            DerivationBaseResult::Agreement(key) => Ok(key),
            _ => Err(Error::Rejected(crate::RejectionReason::KeyDerivation(
                crate::KeyDerivationRejection::FindAgreementKeyResultOwnerMismatch,
            ))),
        }
    }
    /// Select an existing Montgomery private key with an exact native domain.
    /// No public counterpart or private possession test is inferred.
    pub fn find_montgomery_key(
        &self,
        spec: MontgomeryKeySpec,
        admission: HistoryObservationPlan,
    ) -> Result<MontgomeryKey> {
        let mut diagnostics = crate::advanced::PollDiagnostics::default();
        let prepared = crate::crypto::derivation::DerivationBasePlan::new(
            DerivationBaseRequest::Montgomery(spec),
            None,
            admission,
        )?;
        match crate::advanced::derivation_base_synchronous(self, prepared, false, &mut diagnostics)
            .and_then(|outcome| outcome.observation)?
        {
            DerivationBaseResult::Montgomery(key) => Ok(key),
            _ => Err(Error::Rejected(crate::RejectionReason::KeyDerivation(
                crate::KeyDerivationRejection::FindMontgomeryKeyResultOwnerMismatch,
            ))),
        }
    }
    /// Admit an HKDF base with the explicitly selected length and controls.
    pub fn find_hkdf_key(
        &self,
        spec: HkdfKeySpec,
        admission: HistoryObservationPlan,
    ) -> Result<HkdfKey> {
        let mut diagnostics = crate::advanced::PollDiagnostics::default();
        let prepared = crate::crypto::derivation::DerivationBasePlan::new(
            DerivationBaseRequest::Hkdf(spec),
            None,
            admission,
        )?;
        match crate::advanced::derivation_base_synchronous(self, prepared, false, &mut diagnostics)
            .and_then(|outcome| outcome.observation)?
        {
            DerivationBaseResult::Hkdf(key) => Ok(key),
            _ => Err(Error::Rejected(crate::RejectionReason::KeyDerivation(
                crate::KeyDerivationRejection::FindHkdfKeyResultOwnerMismatch,
            ))),
        }
    }
    /// Generate a native HKDF base with the selected length, requests and admission.
    pub fn generate_hkdf_key(
        &self,
        spec: HkdfKeySpec,
        current: CurrentKeyProtection,
        admission: HistoryObservationPlan,
    ) -> Result<crate::CreatedObjects<HkdfKey>> {
        let mut diagnostics = crate::advanced::PollDiagnostics::default();
        let prepared = crate::crypto::derivation::DerivationBasePlan::new(
            DerivationBaseRequest::Hkdf(spec),
            Some(current),
            admission,
        )?;
        Ok(
            crate::advanced::derivation_base_synchronous(self, prepared, true, &mut diagnostics)?
                .try_map(|result| match result {
                    DerivationBaseResult::Hkdf(key) => Ok(key),
                    _ => Err(Error::Rejected(crate::RejectionReason::KeyDerivation(
                        crate::KeyDerivationRejection::GenerateHkdfKeyResultOwnerMismatch,
                    ))),
                }),
        )
    }
    /// Generate a derive-only EC pair; public SPKI comes from the same native call.
    /// No signature, exported secret, or cryptographic probe is needed for admission.
    pub fn generate_agreement_key(
        &self,
        spec: AgreementKeySpec,
        current: CurrentKeyProtection,
        admission: HistoryObservationPlan,
    ) -> Result<crate::CreatedObjects<AgreementKeyPair>> {
        let mut diagnostics = crate::advanced::PollDiagnostics::default();
        let prepared = crate::crypto::derivation::AgreementPairPlan::new(
            AgreementRequest::Weierstrass(spec),
            current,
            admission,
        )?;
        Ok(
            crate::advanced::agreement_pair_synchronous(self, prepared, &mut diagnostics)?.try_map(
                |result| match result {
                    AgreementPairResult::Weierstrass(pair) => Ok(pair),
                    _ => Err(Error::Rejected(crate::RejectionReason::KeyDerivation(
                        crate::KeyDerivationRejection::WeierstrassGenerationResultOwnerMismatch,
                    ))),
                },
            ),
        )
    }
    /// Generate a native Montgomery pair with explicit parameter representation.
    /// The public coordinate remains native bytes; no signature/probe is added.
    pub fn generate_montgomery_key(
        &self,
        spec: MontgomeryKeySpec,
        current: CurrentKeyProtection,
        admission: HistoryObservationPlan,
    ) -> Result<crate::CreatedObjects<MontgomeryKeyPair>> {
        let mut diagnostics = crate::advanced::PollDiagnostics::default();
        let prepared = crate::crypto::derivation::AgreementPairPlan::new(
            AgreementRequest::Montgomery(spec),
            current,
            admission,
        )?;
        Ok(
            crate::advanced::agreement_pair_synchronous(self, prepared, &mut diagnostics)?.try_map(
                |result| match result {
                    AgreementPairResult::Montgomery(pair) => Ok(pair),
                    _ => Err(Error::Rejected(crate::RejectionReason::KeyDerivation(
                        crate::KeyDerivationRejection::MontgomeryGenerationResultOwnerMismatch,
                    ))),
                },
            ),
        )
    }
}
