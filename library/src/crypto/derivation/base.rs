// SPDX-License-Identifier: Apache-2.0
//! Owned admission inputs for native derivation bases; no secret value reads.
use super::*;
use crate::{attributes::RequiredAttributes, symmetric::memory::Credit, ManagedClass};

pub(crate) enum DerivationBaseRequest {
    Agreement(AgreementKeySpec),
    Montgomery(MontgomeryKeySpec),
    Hkdf(HkdfKeySpec),
    IntroducedAgreement(AgreementIntroductionSpec),
}
impl DerivationBaseRequest {
    fn base(&self) -> keys::BaseSpec<'_> {
        match self {
            Self::Agreement(s) => keys::BaseSpec::Ec(s),
            Self::Montgomery(s) => keys::BaseSpec::Montgomery(s),
            Self::Hkdf(s) => keys::BaseSpec::Hkdf(s),
            Self::IntroducedAgreement(s) => keys::BaseSpec::Ec(&s.key),
        }
    }
    fn retained_bytes(&self) -> Result<usize> {
        let (id, label) = match self {
            Self::Agreement(s) => (&s.id, &s.label),
            Self::Montgomery(s) => (&s.id, &s.label),
            Self::Hkdf(s) => (&s.id, &s.label),
            Self::IntroducedAgreement(s) => (&s.key.id, &s.key.label),
        };
        id.capacity()
            .checked_add(label.capacity())
            .ok_or(Error::Rejected(crate::RejectionReason::KeyDerivation(
                crate::KeyDerivationRejection::DerivationBaseRequestSize,
            )))
    }
}
pub(crate) enum DerivationBaseResult {
    Agreement(AgreementKey),
    Montgomery(MontgomeryKey),
    Hkdf(HkdfKey),
    IntroducedAgreement(IntroducedAgreementKey),
}
pub(crate) struct PreparedDerivationBase {
    // Transferred once into the published key; retained across every native step.
    request: Option<DerivationBaseRequest>,
    generation: Option<CurrentKeyProtection>,
    history: HistoryObservationPlan,
    observation: Option<BaseProtection>,
    _credit: Credit,

}
/// Caller-transferred input only. Constructing the plan neither reserves a
/// reference nor acquires byte credit; the enclosing admission supplies both.
pub(crate) struct DerivationBasePlan {
    request: DerivationBaseRequest,
    generation: Option<CurrentKeyProtection>,
    history: HistoryObservationPlan,
}

/// Charges the transferred request without taking it from its initial plan.
pub(crate) struct DerivationBaseOwnerStorage {
    credit: Credit,
}

impl DerivationBasePlan {
    pub(crate) fn introduced_agreement(spec: AgreementIntroductionSpec) -> Result<Self> {
        spec.validate()?;
        let history = spec.history_observation;
        Self::new(
            DerivationBaseRequest::IntroducedAgreement(spec),
            None,
            history,
        )
    }

    pub(crate) fn new(
        request: DerivationBaseRequest,
        generation: Option<CurrentKeyProtection>,
        history: HistoryObservationPlan,
    ) -> Result<Self> {
        let base = request.base();
        crate::bounds::ck_length(base.id().len())?;
        crate::bounds::ck_length(base.label().len())?;
        if let DerivationBaseRequest::Hkdf(spec) = &request {
            crate::bounds::ck_length(spec.length)?;
        }
        if generation.is_some() && !matches!(&request, DerivationBaseRequest::Hkdf(_)) {
            return Err(Error::Rejected(crate::RejectionReason::KeyDerivation(
                crate::KeyDerivationRejection::SingleBaseGenerationRequiresHkdf,
            )));
        }
        history.fields()?;
        Ok(Self {
            request,
            generation,
            history,
        })
    }

    pub(crate) fn requested_bytes(&self) -> Result<usize> {
        std::mem::size_of::<PreparedDerivationBase>()
            .checked_add(self.request.retained_bytes()?)
            .ok_or(Error::Rejected(crate::RejectionReason::KeyDerivation(
                crate::KeyDerivationRejection::DerivationBaseOwnerSize,
            )))
    }

    /// Complete every fallible storage conversion and credit split while the
    /// input plan is only borrowed. A retry can discard this candidate without
    /// consuming caller-transferred requests or observation choices.
    pub(crate) fn prepare_owner(&self, prepaid: &mut Credit) -> Result<DerivationBaseOwnerStorage> {
        Ok(DerivationBaseOwnerStorage {
            credit: prepaid.split(self.requested_bytes()?)?,
        })
    }

    /// Validate before taking either owner. On refusal the caller still holds
    /// all inputs and can release its access guards before discarding them.
    /// The successful transfer neither allocates nor waits for another credit.
    pub(crate) fn finish_owner(
        plan: &mut Option<Self>,
        prepared: &mut Option<DerivationBaseOwnerStorage>,

    ) -> Result<PreparedDerivationBase> {
        if plan.is_none() {
            return Err(Error::Rejected(crate::RejectionReason::KeyDerivation(
                crate::KeyDerivationRejection::FamilyInputPlanAbsent,
            )));
        }
        if prepared.is_none() {
            return Err(Error::Rejected(crate::RejectionReason::KeyDerivation(
                crate::KeyDerivationRejection::FamilyOwnerStorageAbsent,
            )));
        }
        let plan = plan.take().expect("family input checked before transfer");
        let prepared = prepared
            .take()
            .expect("family storage checked before transfer");

        Ok(PreparedDerivationBase {

            request: Some(plan.request),
            generation: plan.generation,
            history: plan.history,
            observation: None,
            _credit: prepared.credit,
        })
    }
}

fn base_generation_template<T: crate::attributes::TemplateSink>(
    request: &DerivationBaseRequest,
    generation: Option<CurrentKeyProtection>,
) -> Result<(CK_MECHANISM_TYPE, T)> {
    let current = generation.ok_or(Error::Rejected(crate::RejectionReason::KeyDerivation(
        crate::KeyDerivationRejection::ExistingDerivationBaseHasNoGenerationRequest,
    )))?;
    match request {
        DerivationBaseRequest::Hkdf(spec) => {
            Ok((spec.kind.generator(), request.base().template_as(current)?))
        }
        _ => Err(Error::Rejected(crate::RejectionReason::KeyDerivation(
            crate::KeyDerivationRejection::SingleBaseGenerationRequiresHkdf,
        ))),
    }
}

impl crate::crypto::KeyGenerationDescription for DerivationBasePlan {
    fn generation_identity(&self) -> Result<crate::crypto::GenerationIdentity<'_>> {
        let base = self.request.base();
        Ok(crate::crypto::GenerationIdentity {
            id: base.id(),
            label: base.label(),
        })
    }
    fn generation_mechanism(&self) -> Result<CK_MECHANISM_TYPE> {
        base_generation_template::<crate::attributes::TemplateSize>(&self.request, self.generation)
            .map(|(kind, _)| kind)
    }
    fn generation_templates_as<T: crate::attributes::TemplateSink>(
        &self,
    ) -> Result<(T, Option<T>)> {
        Ok((
            base_generation_template(&self.request, self.generation)?.1,
            None,
        ))
    }
}

impl crate::crypto::KeyAdmissionDescription for DerivationBasePlan {
    fn is_pair(&self) -> bool {
        false
    }
    fn admission_id(&self) -> &[u8] {
        self.request.base().id()
    }
    fn admission_class(&self) -> crate::ManagedClass {
        self.request.base().class()
    }
    fn object_observation(&self, _private: bool) -> &crate::ObjectAdmission {
        self.request.base().object_admission()
    }
    fn history_observation(&self, _private: bool) -> Option<crate::HistoryObservationPlan> {
        Some(self.history)
    }
    fn mechanism_observation(&self, _private: bool) -> &crate::MechanismObservationPlan {
        self.request.base().mechanism_admission()
    }
    fn visit_required(&self, _private: bool, field: &mut dyn FnMut(CK_ATTRIBUTE_TYPE)) {
        self.request.base().required_field_iter().for_each(field);
    }
    fn visit_material(&self, _private: bool, _field: &mut dyn FnMut(CK_ATTRIBUTE_TYPE)) {}
}

impl PreparedDerivationBase {
    fn request(&self) -> &DerivationBaseRequest {
        self.request
            .as_ref()
            .expect("base request is retained until publication")
    }
    pub(crate) fn id(&self) -> &[u8] {
        self.request().base().id()
    }
    pub(crate) fn label(&self) -> &str {
        self.request().base().label()
    }

    pub(crate) fn class(&self) -> ManagedClass {
        self.request().base().class()
    }
    pub(crate) fn key_type(&self) -> CK_KEY_TYPE {
        self.request().base().kind()
    }
    pub(crate) fn admission(&self) -> &crate::ObjectAdmission {
        self.request().base().object_admission()
    }
    pub(crate) fn mechanisms(&self) -> &crate::MechanismObservationPlan {
        self.request().base().mechanism_admission()
    }
    pub(crate) fn field_iter(&self) -> impl Iterator<Item = CK_ATTRIBUTE_TYPE> {
        self.request().base().required_field_iter()
    }
    pub(crate) fn validate(&self, values: &RequiredAttributes) -> Result<()> {
        self.request().base().validate(values)
    }
    pub(crate) fn history_plan(&self) -> HistoryObservationPlan {
        self.history
    }
    pub(crate) fn observe_history(&mut self, snapshot: BaseProtection) -> Result<()> {
        if self.observation.is_some() {
            return Err(Error::Rejected(crate::RejectionReason::KeyDerivation(
                crate::KeyDerivationRejection::DerivationBaseHistoryAlreadyObserved,
            )));
        }
        // Known local contradictions are reconciled against the selected native
        // reference at publication; do not evaluate them as absent beforehand.
        self.observation = Some(snapshot);
        Ok(())
    }
    pub(crate) fn generation_template_as<T: crate::attributes::TemplateSink>(
        &self,
    ) -> Result<(CK_MECHANISM_TYPE, T)> {
        base_generation_template(self.request(), self.generation)
    }
    pub(crate) fn finish(
        &mut self,
        managed: ManagedObjectRef,
        mechanism_report: crate::MechanismObservationReport,
    ) -> Result<DerivationBaseResult> {
        let protection =
            self.observation
                .ok_or(Error::Rejected(crate::RejectionReason::KeyDerivation(
                    crate::KeyDerivationRejection::DerivationBaseHistoryObservationAbsent,
                )))?;
        enum FinalHistory {
            Ordinary,
            Introduced(crate::IntroductionReport),
        }
        let report = match self.request() {
            DerivationBaseRequest::IntroducedAgreement(_) => {
                let origin = match protection.local {
                    Observation::Observed(true) => crate::IntroductionOrigin::ObservedLocal,
                    Observation::Observed(false) => crate::IntroductionOrigin::ObservedNonLocal,
                    _ => crate::IntroductionOrigin::ObservedUnknown,
                };
                FinalHistory::Introduced(crate::transport::secret_keys::report(protection, origin)?)
            }
            _ => FinalHistory::Ordinary,
        };
        let request =
            self.request
                .take()
                .ok_or(Error::Rejected(crate::RejectionReason::KeyDerivation(
                    crate::KeyDerivationRejection::DerivationBaseAlreadyPublished,
                )))?;
        Ok(match (request, report) {
            (DerivationBaseRequest::Agreement(spec), FinalHistory::Ordinary) => {
                DerivationBaseResult::Agreement(AgreementKey {
                    managed,
                    spec,
                    protection,

                    mechanism_report,
                })
            }
            (DerivationBaseRequest::Montgomery(spec), FinalHistory::Ordinary) => {
                DerivationBaseResult::Montgomery(MontgomeryKey {
                    managed,
                    spec,
                    protection,

                    mechanism_report,
                })
            }
            (DerivationBaseRequest::Hkdf(spec), FinalHistory::Ordinary) => {
                DerivationBaseResult::Hkdf(HkdfKey {
                    managed,
                    spec,
                    protection,

                    mechanism_report,
                })
            }
            (
                DerivationBaseRequest::IntroducedAgreement(spec),
                FinalHistory::Introduced(report),
            ) => DerivationBaseResult::IntroducedAgreement(introduced::finish(
                managed,
                spec,
                report,
                mechanism_report,
            )),
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::KeyDerivation(
                    crate::KeyDerivationRejection::DerivationBasePublicationReportMismatch,
                )))
            }
        })
    }
}
