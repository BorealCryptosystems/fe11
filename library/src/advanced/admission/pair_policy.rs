// SPDX-License-Identifier: Apache-2.0
//! Family-specific policies behind the shared two-object creation lifecycle.
use super::{OperationProgress, RequiredAttributes};
use crate::crypto::derivation::{AgreementPairResult, PreparedAgreementPair};
use crate::crypto::{kem::PreparedKemPair, pqc::PreparedPqcPair, PreparedClassicalPair};
use crate::ManagedObjectRef;
use crate::{Error, Result};
use fe11_sys::{
    CKA_EC_POINT, CKA_VALUE, CKK_ML_KEM, CKM_ML_KEM_KEY_PAIR_GEN, CK_ATTRIBUTE_TYPE, CK_KEY_TYPE,
    CK_MECHANISM_TYPE,
};

pub(super) enum PreparedPair {
    Classical(PreparedClassicalPair),
    Kem(PreparedKemPair),
    Pqc(PreparedPqcPair),
    Agreement(PreparedAgreementPair),
}
pub(super) use crate::crypto::GenerationIdentity;
impl From<PreparedClassicalPair> for PreparedPair {
    fn from(value: PreparedClassicalPair) -> Self {
        Self::Classical(value)
    }
}
impl PreparedPair {
    // Each prepared owner already carries credit for its inline payload.
    // The enclosing enum additionally owns its tag, padding and unused variant space.
    pub(super) fn credited_inline_bytes(&self) -> usize {
        match self {
            Self::Classical(value) => std::mem::size_of_val(value),
            Self::Kem(value) => std::mem::size_of_val(value),
            Self::Pqc(value) => std::mem::size_of_val(value),
            Self::Agreement(value) => std::mem::size_of_val(value),
        }
    }

    pub(super) fn id(&self) -> &[u8] {
        match self {
            Self::Classical(p) => p.id(),
            Self::Kem(p) => p.id(),
            Self::Pqc(p) => p.id(),
            Self::Agreement(p) => p.id(),
        }
    }
    pub(super) fn public_admission(&self) -> &crate::ObjectAdmission {
        match self {
            Self::Classical(p) => p.public_admission(),
            Self::Kem(p) => p.public_admission(),
            Self::Pqc(p) => p.public_admission(),
            Self::Agreement(p) => p.public_admission(),
        }
    }
    pub(super) fn private_admission(&self) -> &crate::ObjectAdmission {
        match self {
            Self::Classical(p) => p.private_admission(),
            Self::Kem(p) => p.private_admission(),
            Self::Pqc(p) => p.private_admission(),
            Self::Agreement(p) => p.private_admission(),
        }
    }
    pub(super) fn public_mechanisms(&self) -> &crate::MechanismObservationPlan {
        match self {
            Self::Classical(p) => &p.public_mechanisms,
            Self::Kem(p) => &p.public_policy.admission,
            Self::Pqc(p) => &p.public_policy.admission,
            Self::Agreement(p) => &p.public_mechanisms,
        }
    }
    pub(super) fn mechanisms(&self) -> &crate::MechanismObservationPlan {
        match self {
            Self::Classical(p) => p.mechanisms(),
            Self::Kem(p) => &p.private_policy.admission,
            Self::Pqc(p) => &p.private_policy.admission,
            Self::Agreement(p) => p.mechanisms(),
        }
    }
    pub(super) fn generation_identity(&self) -> Result<GenerationIdentity<'_>> {
        Ok(match self {
            Self::Classical(p) => {
                let r = p.generation_request()?;
                GenerationIdentity {
                    id: &r.id,
                    label: &r.label,
                }
            }
            Self::Kem(p) => {
                let request = p.generation_request()?;
                GenerationIdentity {
                    id: &request.id,
                    label: &request.label,
                }
            }
            Self::Agreement(p) => {
                let request = p.request();
                GenerationIdentity {
                    id: request.id(),
                    label: request.label(),
                }
            }
            Self::Pqc(p) => {
                let request = p.generation_request()?;
                GenerationIdentity {
                    id: &request.id,
                    label: &request.label,
                }
            }
        })
    }
    pub(super) fn generation_templates_as<T: crate::attributes::TemplateSink>(
        &self,
    ) -> Result<(T, T)> {
        match self {
            Self::Classical(p) => p.generation_templates_as(),
            Self::Kem(p) => p.templates_as(),
            Self::Pqc(p) => p.templates_as(),
            Self::Agreement(p) => p.templates_as(),
        }
    }
    pub(super) fn generation_mechanism(&self) -> Result<CK_MECHANISM_TYPE> {
        match self {
            Self::Classical(p) => p.generation_mechanism(),
            Self::Kem(p) => p.generation_request().map(|_| CKM_ML_KEM_KEY_PAIR_GEN),
            Self::Pqc(p) => p.generation_mechanism(),
            Self::Agreement(p) => Ok(p.generation_mechanism()),
        }
    }
    pub(super) fn key_type(&self) -> CK_KEY_TYPE {
        match self {
            Self::Classical(p) => p.key_type(),
            Self::Kem(_) => CKK_ML_KEM,
            Self::Pqc(p) => p.key_type(),
            Self::Agreement(p) => p.key_type(),
        }
    }
    pub(super) fn public_material_field(&self) -> Option<CK_ATTRIBUTE_TYPE> {
        match self {
            Self::Classical(_) => None,
            Self::Kem(_) | Self::Pqc(_) => Some(CKA_VALUE),
            Self::Agreement(_) => Some(CKA_EC_POINT),
        }
    }
    pub(super) fn prepare_observation(
        &mut self,
        private: bool,
        values: &RequiredAttributes,
    ) -> Result<()> {
        match self {
            Self::Classical(p) => p.prepare_observation(private, values),
            _ => Ok(()),
        }
    }
    pub(super) fn observation_need(&self) -> Option<crate::crypto::integer_key::PublicDerNeed> {
        match self {
            Self::Classical(p) => p.observation_need(),
            _ => None,
        }
    }
    pub(super) fn attach_observation(
        &mut self,
        candidate: crate::crypto::integer_key::PublicDerCandidate,
    ) -> Result<()> {
        match self {
            Self::Classical(p) => p.attach_observation(candidate),
            _ => Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::AdmissionPreparationChanged,
            ))),
        }
    }
    pub(super) fn validate(&mut self, private: bool, values: &RequiredAttributes) -> Result<()> {
        match self {
            Self::Classical(p) => p.validate(private, values),
            Self::Kem(p) => p.validate(private, values),
            Self::Pqc(p) => p.validate(private, values),
            Self::Agreement(p) => p.validate(private, values),
        }
    }
    pub(super) fn observe_public(&mut self, values: &RequiredAttributes) -> Result<()> {
        match self {
            Self::Kem(p) => p.observe_public(values),
            Self::Pqc(p) => p.observe_public(values),
            Self::Agreement(p) => p.observe_public(values),
            Self::Classical(_) => Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::ClassicalMaterialIsPartOfItsStructuralObservation,
            ))),
        }
    }

    pub(super) fn private_history_plan(&self) -> Option<crate::HistoryObservationPlan> {
        match self {
            Self::Classical(p) => p.history_plan(),
            Self::Agreement(p) => Some(p.history_plan()),
            _ => None,
        }
    }
    pub(super) fn observe_history(&mut self, snapshot: crate::BaseProtection) -> Result<()> {
        match self {
            Self::Classical(p) => p.observe_history(snapshot),
            Self::Agreement(p) => p.observe_history(snapshot),
            _ => Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::PairHistoryOwnerAbsent,
            ))),
        }
    }

    pub(super) fn finish(
        &mut self,
        public: ManagedObjectRef,
        private: ManagedObjectRef,
        public_allowed: crate::MechanismObservationReport,
        private_allowed: crate::MechanismObservationReport,
    ) -> Result<OperationProgress> {
        match self {
            Self::Classical(p) if p.is_rsa_transport() => p
                .finish_rsa_transport(public, private, public_allowed, private_allowed)
                .map(OperationProgress::RsaKeyEncryptionPair),
            Self::Classical(p) if p.is_transport() => p
                .finish_transport(public, private, public_allowed, private_allowed)
                .map(OperationProgress::TransportSigningKeyPair),
            Self::Classical(p) => p
                .finish(public, private, public_allowed, private_allowed)
                .map(OperationProgress::ClassicalKeyPair),
            Self::Kem(p) => p
                .finish(public, private, public_allowed, private_allowed)
                .map(OperationProgress::KemKeyPair),
            Self::Pqc(p) => p
                .finish(public, private, public_allowed, private_allowed)
                .map(OperationProgress::PqcKeyPair),
            Self::Agreement(p) => match p.finish(public, private, private_allowed)? {
                AgreementPairResult::Weierstrass(pair) => {
                    Ok(OperationProgress::AgreementKeyPair(pair))
                }
                AgreementPairResult::Montgomery(pair) => {
                    Ok(OperationProgress::MontgomeryKeyPair(pair))
                }
                AgreementPairResult::Transport(pair) => {
                    Ok(OperationProgress::TransportAgreementKeyPair(pair))
                }
            },
        }
    }
}
