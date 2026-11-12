// SPDX-License-Identifier: Apache-2.0
//! Caller input and private candidate storage for the common admission start.
//!
//! Input survives every allocation retry. The candidate contains only Fe11
//! storage until final possession. Family-specific builders remain responsible
//! for templates, observations and ownership; this module only dispatches them.
use super::{keys, pair, KeyPolicy, PreparedPair, Publication};
use crate::{
    allocation::Slot,
    crypto::{
        derivation::{
            AgreementPairOwnerStorage, AgreementPairPlan, AgreementPairStorage,
            DerivationBaseOwnerStorage, DerivationBasePlan, PreparedAgreementPair,
            PreparedDerivationBase,
        },
        kem::{KemBoundOwnerStorage, KemOwnerPlan, KemOwnerStorage, PreparedKemPair},
        pqc::{PqcBoundOwnerStorage, PqcOwnerPlan, PqcOwnerStorage, PreparedPqcPair},
        ClassicalPairOwnerStorage, ClassicalPairPlan, ClassicalPairStorage, GenerationIdentity,
        KeyAdmissionDescription, KeyGenerationDescription, PreparedClassicalPair,
        PreparedVerification, VerificationOwnerStorage, VerificationPlan, VerificationStorage,
    },
    symmetric::memory::Credit,
    Error, Result, SymmetricKeySpec,
};
use fe11_sys::{CK_ATTRIBUTE_TYPE, CK_MECHANISM_TYPE};
use std::mem::size_of;

/// Symmetric input has no separately allocated family owner. Its transferred
/// ID/label capacities and inline representation are charged by Admission.
pub(super) struct SymmetricInput {
    pub(super) spec: SymmetricKeySpec,
    pub(super) publication: Publication,
}

/// An Option denotes only the final transfer of this caller-owned plan. All
/// descriptions and allocations precede that transfer; they never inspect a
/// consumed input. Refusal of finish preserves each still-owned input.
pub(super) enum Input<'a> {
    Symmetric(Option<SymmetricInput>),
    Verification(Option<VerificationPlan<'a>>),
    Base(Option<DerivationBasePlan>),
    Classical(Option<ClassicalPairPlan<'a>>),
    Kem(Option<KemOwnerPlan<'a>>),
    Pqc(Option<PqcOwnerPlan<'a>>),
    Agreement(Option<AgreementPairPlan>),
}

/// Uncredited allocations, discarded as a whole if actual capacity grows.
pub(super) enum Storage {
    Symmetric,
    Base(Slot<PreparedDerivationBase>),
    Verification(VerificationStorage),
    Classical(ClassicalPairStorage),
    Kem(KemOwnerStorage),
    Pqc(PqcOwnerStorage),
    Agreement(AgreementPairStorage),
}

/// Bound storage owns only the supplied credit. No quota is acquired here.
pub(super) enum Candidate {
    Symmetric,
    Verification(Option<VerificationOwnerStorage>),
    Base {
        owner: Option<DerivationBaseOwnerStorage>,
        slot: Option<Slot<PreparedDerivationBase>>,
    },
    Pair {
        owner: PairOwner,
        frame: Option<pair::PairFrameStorage>,
    },
}

/// The family survives a refusal to attach its stable envelope. Keeping it in
/// the candidate lets the caller release access before destroying any credit.
pub(super) enum PairOwner {
    Classical(Option<ClassicalPairOwnerStorage>),
    Kem(Option<KemBoundOwnerStorage>),
    Pqc(Option<PqcBoundOwnerStorage>),
    Agreement(Option<AgreementPairOwnerStorage>),
    Ready(Option<PreparedPair>),
}

impl Input<'_> {
    pub(super) fn symmetric(spec: SymmetricKeySpec, publication: Publication) -> Self {
        Self::Symmetric(Some(SymmetricInput { spec, publication }))
    }

    pub(super) fn symmetric_metadata_bytes(&self) -> Result<usize> {
        match self {
            Self::Symmetric(Some(value)) => value
                .spec
                .id
                .capacity()
                .checked_add(value.spec.label.capacity())
                .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
                    crate::KeyAdmissionRejection::SymmetricAdmissionMetadataByteCount,
                ))),
            Self::Symmetric(None) => Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::FamilyInputAbsent,
            ))),
            _ => Ok(0),
        }
    }

    fn description(&self) -> &dyn KeyAdmissionDescription {
        match self {
            Self::Symmetric(value) => value.as_ref().expect("description precedes transfer"),
            Self::Verification(value) => value.as_ref().expect("description precedes transfer"),
            Self::Base(value) => value.as_ref().expect("description precedes transfer"),
            Self::Classical(value) => value.as_ref().expect("description precedes transfer"),
            Self::Kem(value) => value.as_ref().expect("description precedes transfer"),
            Self::Pqc(value) => value.as_ref().expect("description precedes transfer"),
            Self::Agreement(value) => value.as_ref().expect("description precedes transfer"),
        }
    }

    pub(super) fn initial_plan(&self) -> pair::initial::Plan {
        match self {
            Self::Kem(value) => pair::initial::Plan::Kem(
                value
                    .as_ref()
                    .expect("description precedes transfer")
                    .initial_plan(),
            ),
            Self::Pqc(value) => pair::initial::Plan::Pqc(
                value
                    .as_ref()
                    .expect("description precedes transfer")
                    .initial_plan(),
            ),
            _ => pair::initial::Plan::None,
        }
    }

    /// Inline Verification is already charged by its family. Other families
    /// live in heap envelopes, while the symmetric input is charged by Admission.
    pub(super) fn parent_inline_bytes(&self) -> usize {
        match self {
            Self::Verification(_) => size_of::<PreparedVerification>(),
            _ => 0,
        }
    }

    fn pair_inline_bytes(&self) -> Option<usize> {
        match self {
            Self::Classical(_) => Some(size_of::<PreparedClassicalPair>()),
            Self::Kem(_) => Some(size_of::<PreparedKemPair>()),
            Self::Pqc(_) => Some(size_of::<PreparedPqcPair>()),
            Self::Agreement(_) => Some(size_of::<PreparedAgreementPair>()),
            _ => None,
        }
    }

    fn with_envelope(&self, family_bytes: usize) -> Result<usize> {
        let envelope = self
            .pair_inline_bytes()
            .map(pair::PairFrame::requested_bytes)
            .transpose()?
            .unwrap_or(0);
        family_bytes.checked_add(envelope).ok_or(Error::Rejected(
            crate::RejectionReason::KeyAdmission(crate::KeyAdmissionRejection::InitialFamilySize),
        ))
    }

    pub(super) fn requested_bytes(&self) -> Result<usize> {
        let bytes = match self {
            Self::Symmetric(_) => 0,
            Self::Verification(value) => value
                .as_ref()
                .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
                    crate::KeyAdmissionRejection::FamilyInputAbsent,
                )))?
                .requested_bytes()?,
            Self::Base(value) => value
                .as_ref()
                .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
                    crate::KeyAdmissionRejection::FamilyInputAbsent,
                )))?
                .requested_bytes()?,
            Self::Classical(value) => value
                .as_ref()
                .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
                    crate::KeyAdmissionRejection::FamilyInputAbsent,
                )))?
                .requested_bytes()?,
            Self::Kem(value) => value
                .as_ref()
                .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
                    crate::KeyAdmissionRejection::FamilyInputAbsent,
                )))?
                .requested_bytes()?,
            Self::Pqc(value) => value
                .as_ref()
                .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
                    crate::KeyAdmissionRejection::FamilyInputAbsent,
                )))?
                .requested_bytes()?,
            Self::Agreement(value) => value
                .as_ref()
                .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
                    crate::KeyAdmissionRejection::FamilyInputAbsent,
                )))?
                .requested_bytes()?,
        };
        self.with_envelope(bytes)
    }

    pub(super) fn allocate(&self) -> Result<Storage> {
        Ok(match self {
            Self::Symmetric(Some(_)) => Storage::Symmetric,
            Self::Base(Some(_)) => Storage::Base(Slot::new()?),
            Self::Verification(Some(plan)) => Storage::Verification(plan.allocate()?),
            Self::Classical(Some(plan)) => Storage::Classical(plan.allocate()?),
            Self::Kem(Some(plan)) => Storage::Kem(plan.allocate()?),
            Self::Pqc(Some(plan)) => Storage::Pqc(plan.allocate()?),
            Self::Agreement(Some(plan)) => Storage::Agreement(plan.allocate()?),
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                    crate::KeyAdmissionRejection::FamilyInputAbsent,
                )))
            }
        })
    }

    pub(super) fn allocated_bytes(&self, storage: &Storage) -> Result<usize> {
        let bytes = match (self, storage) {
            (Self::Symmetric(Some(_)), Storage::Symmetric) => 0,
            (Self::Base(Some(plan)), Storage::Base(_)) => plan.requested_bytes()?,
            (Self::Verification(Some(_)), Storage::Verification(storage)) => {
                storage.allocated_bytes()?
            }
            (Self::Classical(Some(plan)), Storage::Classical(storage)) => {
                plan.allocated_bytes(storage)?
            }
            (Self::Kem(Some(plan)), Storage::Kem(storage)) => plan.allocated_bytes(storage)?,
            (Self::Pqc(Some(plan)), Storage::Pqc(storage)) => plan.allocated_bytes(storage)?,
            (Self::Agreement(Some(plan)), Storage::Agreement(storage)) => {
                plan.allocated_bytes(storage)?
            }
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                    crate::KeyAdmissionRejection::InitialFamilyPreparationChanged,
                )))
            }
        };
        self.with_envelope(bytes)
    }

    /// All fallible conversions, envelope allocations and credit splits happen
    /// before the access probe. The input is borrowed, never taken on retry.
    pub(super) fn bind(&self, storage: Storage, credit: &mut Credit) -> Result<Candidate> {
        Ok(match (self, storage) {
            (Self::Symmetric(Some(_)), Storage::Symmetric) => Candidate::Symmetric,
            (Self::Verification(Some(plan)), Storage::Verification(storage)) => {
                Candidate::Verification(Some(plan.prepare_owner(storage, credit)?))
            }
            (Self::Base(Some(plan)), Storage::Base(slot)) => Candidate::Base {
                owner: Some(plan.prepare_owner(credit)?),
                slot: Some(slot),
            },
            (Self::Classical(Some(plan)), Storage::Classical(storage)) => Candidate::Pair {
                owner: PairOwner::Classical(Some(plan.prepare_owner(storage, credit)?)),
                frame: Some(pair::PairFrame::prepare_storage(
                    size_of::<PreparedClassicalPair>(),
                    credit,
                )?),
            },
            (Self::Kem(Some(plan)), Storage::Kem(storage)) => Candidate::Pair {
                owner: PairOwner::Kem(Some(plan.prepare_owner(storage, credit)?)),
                frame: Some(pair::PairFrame::prepare_storage(
                    size_of::<PreparedKemPair>(),
                    credit,
                )?),
            },
            (Self::Pqc(Some(plan)), Storage::Pqc(storage)) => Candidate::Pair {
                owner: PairOwner::Pqc(Some(plan.prepare_owner(storage, credit)?)),
                frame: Some(pair::PairFrame::prepare_storage(
                    size_of::<PreparedPqcPair>(),
                    credit,
                )?),
            },
            (Self::Agreement(Some(plan)), Storage::Agreement(storage)) => Candidate::Pair {
                owner: PairOwner::Agreement(Some(plan.prepare_owner(storage, credit)?)),
                frame: Some(pair::PairFrame::prepare_storage(
                    size_of::<PreparedAgreementPair>(),
                    credit,
                )?),
            },
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                    crate::KeyAdmissionRejection::InitialFamilyPreparationChanged,
                )))
            }
        })
    }
}

impl Candidate {
    /// Never consumes the candidate on error. Once a family is transferred,
    /// PairOwner::Ready retains it if attaching the envelope is refused.
    pub(super) fn finish(
        &mut self,
        input: &mut Input<'_>,

    ) -> Result<KeyPolicy> {
        match self {
            Self::Symmetric => {
                let Input::Symmetric(value) = input else {
                    return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                        crate::KeyAdmissionRejection::InitialFamilyPreparationChanged,
                    )));
                };
                let value =
                    value
                        .take()
                        .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
                            crate::KeyAdmissionRejection::FamilyInputAbsent,
                        )))?;
                Ok(KeyPolicy::Symmetric {
                    spec: value.spec,
                    publication: value.publication,
                })
            }
            Self::Verification(owner) => {
                let Input::Verification(plan) = input else {
                    return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                        crate::KeyAdmissionRejection::InitialFamilyPreparationChanged,
                    )));
                };
                Ok(KeyPolicy::VerificationPublic {
                    prepared: VerificationPlan::finish_owner(
                        plan,
                        owner,

                    )?,
                })
            }
            Self::Base { owner, slot } => {
                let Input::Base(plan) = input else {
                    return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                        crate::KeyAdmissionRejection::InitialFamilyPreparationChanged,
                    )));
                };
                if slot.is_none() {
                    return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                        crate::KeyAdmissionRejection::BaseEnvelopeAbsent,
                    )));
                }
                let prepared = DerivationBasePlan::finish_owner(
                    plan,
                    owner,

                )?;
                Ok(KeyPolicy::DerivationBase(
                    slot.take()
                        .expect("base envelope checked before transfer")
                        .write(prepared),
                ))
            }
            Self::Pair { owner, frame } => {
                if !matches!(owner, PairOwner::Ready(_)) {
                    if frame.is_none() {
                        return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                            crate::KeyAdmissionRejection::PairEnvelopeAbsent,
                        )));
                    }
                    let prepared = match (&mut *owner, input) {
                        (PairOwner::Classical(storage), Input::Classical(plan)) => {
                            PreparedPair::Classical(ClassicalPairPlan::finish_owner(
                                plan,
                                storage,

                            )?)
                        }
                        (PairOwner::Kem(storage), Input::Kem(plan)) => {
                            PreparedPair::Kem(KemOwnerPlan::finish_owner(
                                plan,
                                storage,

                            )?)
                        }
                        (PairOwner::Pqc(storage), Input::Pqc(plan)) => {
                            PreparedPair::Pqc(PqcOwnerPlan::finish_owner(
                                plan,
                                storage,

                            )?)
                        }
                        (PairOwner::Agreement(storage), Input::Agreement(plan)) => {
                            PreparedPair::Agreement(AgreementPairPlan::finish_owner(
                                plan,
                                storage,

                            )?)
                        }
                        _ => {
                            return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                                crate::KeyAdmissionRejection::InitialFamilyPreparationChanged,
                            )))
                        }
                    };
                    *owner = PairOwner::Ready(Some(prepared));
                }
                let PairOwner::Ready(prepared) = owner else {
                    unreachable!("family retained before envelope transfer");
                };
                Ok(KeyPolicy::Pair(pair::PairFrameStorage::finish(
                    frame, prepared,
                )?))
            }
        }
    }
}

impl KeyAdmissionDescription for Input<'_> {
    fn is_pair(&self) -> bool {
        self.description().is_pair()
    }
    fn admission_id(&self) -> &[u8] {
        self.description().admission_id()
    }
    fn admission_class(&self) -> crate::ManagedClass {
        self.description().admission_class()
    }
    fn object_observation(&self, private: bool) -> &crate::ObjectAdmission {
        self.description().object_observation(private)
    }
    fn history_observation(&self, private: bool) -> Option<crate::HistoryObservationPlan> {
        self.description().history_observation(private)
    }
    fn mechanism_observation(&self, private: bool) -> &crate::MechanismObservationPlan {
        self.description().mechanism_observation(private)
    }
    fn visit_required(&self, private: bool, field: &mut dyn FnMut(CK_ATTRIBUTE_TYPE)) {
        self.description().visit_required(private, field);
    }
    fn visit_material(&self, private: bool, field: &mut dyn FnMut(CK_ATTRIBUTE_TYPE)) {
        self.description().visit_material(private, field);
    }
}

impl KeyGenerationDescription for Input<'_> {
    fn generation_identity(&self) -> Result<GenerationIdentity<'_>> {
        match self {
            Self::Symmetric(Some(plan)) => plan.generation_identity(),
            Self::Base(Some(plan)) => plan.generation_identity(),
            Self::Classical(Some(plan)) => plan.generation_identity(),
            Self::Kem(Some(plan)) => plan.generation_identity(),
            Self::Pqc(Some(plan)) => plan.generation_identity(),
            Self::Agreement(Some(plan)) => plan.generation_identity(),
            Self::Verification(_) => Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::GenerationPolicy,
            ))),
            _ => Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::FamilyInputAbsent,
            ))),
        }
    }
    fn generation_mechanism(&self) -> Result<CK_MECHANISM_TYPE> {
        match self {
            Self::Symmetric(Some(plan)) => plan.generation_mechanism(),
            Self::Base(Some(plan)) => plan.generation_mechanism(),
            Self::Classical(Some(plan)) => plan.generation_mechanism(),
            Self::Kem(Some(plan)) => plan.generation_mechanism(),
            Self::Pqc(Some(plan)) => plan.generation_mechanism(),
            Self::Agreement(Some(plan)) => plan.generation_mechanism(),
            Self::Verification(_) => Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::GenerationPolicy,
            ))),
            _ => Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::FamilyInputAbsent,
            ))),
        }
    }
    fn generation_templates_as<T: crate::attributes::TemplateSink>(
        &self,
    ) -> Result<(T, Option<T>)> {
        match self {
            Self::Symmetric(Some(plan)) => plan.generation_templates_as(),
            Self::Base(Some(plan)) => plan.generation_templates_as(),
            Self::Classical(Some(plan)) => plan.generation_templates_as(),
            Self::Kem(Some(plan)) => plan.generation_templates_as(),
            Self::Pqc(Some(plan)) => plan.generation_templates_as(),
            Self::Agreement(Some(plan)) => plan.generation_templates_as(),
            Self::Verification(_) => Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::GenerationPolicy,
            ))),
            _ => Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::FamilyInputAbsent,
            ))),
        }
    }
}

impl KeyAdmissionDescription for SymmetricInput {
    fn is_pair(&self) -> bool {
        false
    }
    fn admission_id(&self) -> &[u8] {
        &self.spec.id
    }
    fn admission_class(&self) -> crate::ManagedClass {
        crate::ManagedClass::SecretKey
    }
    fn object_observation(&self, _private: bool) -> &crate::ObjectAdmission {
        &self.spec.admission
    }
    fn history_observation(&self, _private: bool) -> Option<crate::HistoryObservationPlan> {
        Some(self.spec.history)
    }
    fn mechanism_observation(&self, _private: bool) -> &crate::MechanismObservationPlan {
        &self.spec.mechanisms
    }
    fn visit_required(&self, _private: bool, field: &mut dyn FnMut(CK_ATTRIBUTE_TYPE)) {
        [fe11_sys::CKA_CLASS, fe11_sys::CKA_KEY_TYPE]
            .into_iter()
            .for_each(field);
    }
    fn visit_material(&self, _private: bool, _field: &mut dyn FnMut(CK_ATTRIBUTE_TYPE)) {}
}

impl KeyGenerationDescription for SymmetricInput {
    fn generation_identity(&self) -> Result<GenerationIdentity<'_>> {
        Ok(GenerationIdentity {
            id: &self.spec.id,
            label: &self.spec.label,
        })
    }
    fn generation_mechanism(&self) -> Result<CK_MECHANISM_TYPE> {
        self.spec.algorithm.generation(self.spec.hmac_key_type)
    }
    fn generation_templates_as<T: crate::attributes::TemplateSink>(
        &self,
    ) -> Result<(T, Option<T>)> {
        Ok((keys::generation_template_as(&self.spec)?, None))
    }
}
