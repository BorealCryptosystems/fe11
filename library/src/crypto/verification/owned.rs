// SPDX-License-Identifier: Apache-2.0
//! Public-only classical verification identity and resumable selected observations.

use super::{attributes, ManagedObjectRef, VerificationKey, VerificationProfile};

use crate::symmetric::memory::Credit;
use crate::{Error, Result};
use fe11_sys::*;
use sha2::{Digest, Sha256};

use super::preparation::{PublicMaterial, VerificationInput};
use super::publication::{
    VerificationPublication, VerificationPublicationPlan, VerificationPublicationStorage,
};
#[derive(Clone, Copy, PartialEq, Eq)]
enum ObservationStage {
    AwaitingIdentity,
    ReadPermitted,
    Observed {
        edwards_encoding: Option<crate::EdwardsEncodingReport>,
    },
}

pub(crate) struct PreparedVerification {
    pub(crate) object_admission: crate::ObjectAdmission,
    pub(crate) mechanisms: crate::MechanismObservationPlan,
    pub(crate) id: Vec<u8>,
    publication: Option<VerificationPublication>,
    material: PublicMaterial,
    observation: ObservationStage,
    _credit: Credit,
}
fn copy<T: Clone>(source: &[T]) -> Result<Vec<T>> {
    let mut result = Vec::new();
    result.try_reserve_exact(source.len()).map_err(|_| {
        Error::Rejected(crate::RejectionReason::PublicVerification(
            crate::PublicVerificationRejection::PublicVerificationInputAllocation,
        ))
    })?;
    result.extend_from_slice(source);
    Ok(result)
}
/// Borrowed input and caller-owned observation choices. No quota, byte
/// credit, native handle or copied public material belongs to this plan.
pub(crate) struct VerificationPlan<'a> {
    id: &'a [u8],
    publication: VerificationPublicationPlan<'a>,
    material: PublicMaterial,
    mechanisms: crate::MechanismObservationPlan,
    object_admission: crate::ObjectAdmission,
}

/// All copied input belongs to one unpublished candidate. Allocation is
/// separate from binding so the enclosing admission can replan actual capacity.
pub(crate) struct VerificationStorage {
    id: Vec<u8>,
    publication: VerificationPublicationStorage,
}

/// Private candidate storage only; the borrowed input plan survives its drop.
pub(crate) struct VerificationOwnerStorage {
    id: Vec<u8>,
    publication: VerificationPublication,
    credit: Credit,
}

fn verification_bytes(id: usize, publication: usize) -> Result<usize> {
    [std::mem::size_of::<PreparedVerification>(), id, publication]
        .into_iter()
        .try_fold(0usize, |total, bytes| {
            total.checked_add(bytes).ok_or(Error::Rejected(
                crate::RejectionReason::PublicVerification(
                    crate::PublicVerificationRejection::PublicVerificationOwnerSize,
                ),
            ))
        })
}

impl<'a> VerificationPlan<'a> {
    pub(crate) fn selected(
        id: &'a [u8],
        spki: &'a [u8],
        profiles: &'a [VerificationProfile],
        mechanisms: crate::MechanismObservationPlan,
        object_admission: crate::ObjectAdmission,
        semantics: super::super::EdwardsOptions,
    ) -> Result<Self> {
        crate::bounds::ck_length(id.len())?;
        let input = VerificationInput::parse(spki, semantics)?;
        Ok(Self {
            id,
            publication: VerificationPublicationPlan::new(
                &input,
                profiles,
                Sha256::digest(spki).into(),
            ),
            material: input.material(),
            mechanisms,
            object_admission,
        })
    }
}

impl VerificationPlan<'_> {
    pub(crate) fn requested_bytes(&self) -> Result<usize> {
        verification_bytes(self.id.len(), self.publication.requested_bytes()?)
    }

    pub(crate) fn allocate(&self) -> Result<VerificationStorage> {
        Ok(VerificationStorage {
            id: copy(self.id)?,
            publication: self.publication.allocate()?,
        })
    }

    /// Complete every fallible storage conversion and credit split while the
    /// input plan is only borrowed. A retry can discard this candidate without
    /// consuming caller-transferred requests or observation choices.
    pub(crate) fn prepare_owner(
        &self,
        storage: VerificationStorage,
        prepaid: &mut Credit,
    ) -> Result<VerificationOwnerStorage> {
        let mut credit = prepaid.split(storage.allocated_bytes()?)?;
        // Declare retained buffers after the credit: a failed split/bind drops
        // the remaining candidate before returning its admitted bytes.
        let retained = storage;
        // The result buffers receive their own credit before access is taken.
        // Publication later transfers this owner without allocating or waiting.
        let publication = self.publication.bind(retained.publication, &mut credit)?;
        Ok(VerificationOwnerStorage {
            id: retained.id,
            publication,
            credit,
        })
    }

    /// Validate before taking either owner. On refusal the caller still holds
    /// all inputs and can release its access guards before discarding them.
    /// The successful transfer neither allocates nor waits for another credit.
    pub(crate) fn finish_owner(
        plan: &mut Option<Self>,
        prepared: &mut Option<VerificationOwnerStorage>,
    ) -> Result<PreparedVerification> {
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

        let VerificationOwnerStorage {
            id,
            publication,
            credit,
        } = prepared;
        Ok(PreparedVerification {
            object_admission: plan.object_admission,
            mechanisms: plan.mechanisms,
            id,
            publication: Some(publication),
            material: plan.material,
            observation: ObservationStage::AwaitingIdentity,
            _credit: credit,
        })
    }
}

impl VerificationStorage {
    pub(crate) fn allocated_bytes(&self) -> Result<usize> {
        verification_bytes(self.id.capacity(), self.publication.allocated_bytes()?)
    }
}

impl crate::crypto::KeyAdmissionDescription for VerificationPlan<'_> {
    fn is_pair(&self) -> bool {
        false
    }
    fn admission_id(&self) -> &[u8] {
        self.id
    }
    fn admission_class(&self) -> crate::ManagedClass {
        crate::ManagedClass::PublicKey
    }
    fn object_observation(&self, _private: bool) -> &crate::ObjectAdmission {
        &self.object_admission
    }
    fn history_observation(&self, _private: bool) -> Option<crate::HistoryObservationPlan> {
        None
    }
    fn mechanism_observation(&self, _private: bool) -> &crate::MechanismObservationPlan {
        &self.mechanisms
    }
    fn visit_required(&self, _private: bool, field: &mut dyn FnMut(CK_ATTRIBUTE_TYPE)) {
        [CKA_CLASS, CKA_KEY_TYPE].into_iter().for_each(field);
    }
    fn visit_material(&self, _private: bool, field: &mut dyn FnMut(CK_ATTRIBUTE_TYPE)) {
        if matches!(self.material, PublicMaterial::Edwards(_)) {
            field(CKA_EC_PARAMS);
        }
    }
}

impl PreparedVerification {
    pub(crate) fn key_type(&self) -> CK_KEY_TYPE {
        match &self.material {
            PublicMaterial::Rsa => CKK_RSA,
            PublicMaterial::Dsa => CKK_DSA,
            PublicMaterial::Weierstrass(_) => CKK_EC,
            PublicMaterial::Edwards(_) => CKK_EC_EDWARDS,
        }
    }

    pub(crate) fn needs_material_observation(&self) -> bool {
        matches!(self.material, PublicMaterial::Edwards(_))
    }
    pub(crate) fn material_field_iter(&self) -> impl Iterator<Item = CK_ATTRIBUTE_TYPE> + '_ {
        self.needs_material_observation()
            .then_some(CKA_EC_PARAMS)
            .into_iter()
    }
    pub(crate) fn validate_identity(
        &mut self,
        observed: &attributes::RequiredAttributes,
    ) -> Result<()> {
        if self.observation != ObservationStage::AwaitingIdentity {
            return Err(Error::Rejected(crate::RejectionReason::PublicVerification(
                crate::PublicVerificationRejection::VerificationIdentityAlreadyObserved,
            )));
        }
        observed.integer(CKA_CLASS, CKO_PUBLIC_KEY)?;
        observed.integer(CKA_KEY_TYPE, self.key_type())?;
        self.observation = if self.needs_material_observation() {
            ObservationStage::ReadPermitted
        } else {
            ObservationStage::Observed {
                edwards_encoding: None,
            }
        };
        Ok(())
    }
    pub(crate) fn validate_material(
        &mut self,
        observed: &attributes::RequiredAttributes,
    ) -> Result<()> {
        if self.observation != ObservationStage::ReadPermitted {
            return Err(Error::Rejected(crate::RejectionReason::PublicVerification(
                crate::PublicVerificationRejection::VerificationMaterialRequiresPublicIdentity,
            )));
        }
        let parameters = if let PublicMaterial::Edwards(curve) = &self.material {
            Some(super::super::EdwardsParameterEncoding::read(
                *curve,
                observed.bytes(CKA_EC_PARAMS)?,
            )?)
        } else {
            None
        };
        self.observation = ObservationStage::Observed {
            // This route reads EC_PARAMS only. The caller's point-format choice
            // is not evidence about an unobserved CKA_EC_POINT.
            edwards_encoding: parameters.map(crate::EdwardsEncodingReport::parameters_only),
        };
        Ok(())
    }
    pub(crate) fn finish(
        &mut self,
        managed: ManagedObjectRef,
        mechanism_report: crate::MechanismObservationReport,
    ) -> Result<VerificationKey> {
        let ObservationStage::Observed { edwards_encoding } = self.observation else {
            return Err(Error::Rejected(crate::RejectionReason::PublicVerification(
                crate::PublicVerificationRejection::VerificationPublicObservationIncomplete,
            )));
        };
        let publication = self.publication.take().ok_or(Error::Rejected(
            crate::RejectionReason::PublicVerification(
                crate::PublicVerificationRejection::VerificationPublicationAlreadyTransferred,
            ),
        ))?;
        let mut key = publication.finish(managed, mechanism_report);
        key.edwards_encoding = edwards_encoding;
        Ok(key)
    }
}
