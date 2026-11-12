// SPDX-License-Identifier: Apache-2.0
//! Public observation storage participates in aggregate admission possession.
use super::{PreparedKemPair, PublicState};
use crate::{
    crypto::kem::{KemPublicKey, MlKemParameterSet},
    symmetric::memory::Credit,
    Error, Result,
};

pub(crate) struct KemPairPlan(MlKemParameterSet);
pub(crate) struct KemPairStorage(KemPublicKey);
pub(crate) struct KemPairInitial {
    public: KemPublicKey,
    credit: Credit,
}
impl super::KemOwnerPlan<'_> {
    /// This input has no observation phase yet. Geometry comes directly from
    /// the validated caller request; no prepared family/quota is needed.
    pub(crate) fn initial_plan(&self) -> KemPairPlan {
        let value = match &self.input {
            super::KemOwnerInput::Generation { request, .. } => request.parameter_set,
            super::KemOwnerInput::Existing { parameter_set, .. } => *parameter_set,
        };
        KemPairPlan(value)
    }
}

impl PreparedKemPair {
    pub(crate) fn attach_initial_retained(
        &mut self,
        initial: &mut Option<KemPairInitial>,
    ) -> Result<()> {
        let candidate =
            initial
                .as_mut()
                .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
                    crate::KeyAdmissionRejection::PairInitialCandidateAbsent,
                )))?;
        if !matches!(self.public, PublicState::AwaitingStorage)
            || candidate.public.parameter_set() != self.source.parameter_set()
        {
            return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::MlKemInitialPreparationChanged,
            )));
        }
        self._credit.merge_retained(&mut candidate.credit)?;
        let initial = initial
            .take()
            .expect("pair initial candidate checked before transfer");
        self.public = PublicState::AwaitingIdentity(initial.public);
        Ok(())
    }
}
impl KemPairPlan {
    pub(crate) fn requested_bytes(&self) -> usize {
        self.0.public_key_length()
    }
    pub(crate) fn allocate(&self) -> Result<KemPairStorage> {
        Ok(KemPairStorage(KemPublicKey::observation_storage(self.0)?))
    }
    pub(crate) fn bind(
        &self,
        storage: KemPairStorage,
        credit: &mut Credit,
    ) -> Result<KemPairInitial> {
        Ok(KemPairInitial {
            credit: credit.split(storage.0.retained_bytes())?,
            public: storage.0,
        })
    }
}
impl KemPairStorage {
    pub(crate) fn allocated_bytes(&self) -> usize {
        self.0.retained_bytes()
    }
}


