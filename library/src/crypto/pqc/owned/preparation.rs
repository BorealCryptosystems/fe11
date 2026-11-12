// SPDX-License-Identifier: Apache-2.0
//! Public observation storage prepaid by key admission.
use super::{PreparedPqcPair, PublicState};
use crate::{crypto::pqc::PqcPublicKey, symmetric::memory::Credit, Error, Result};

pub(crate) struct PqcPairPlan {
    algorithm: crate::crypto::pqc::PqcAlgorithm,
}
pub(crate) struct PqcPairStorage {
    public: PqcPublicKey,
}
pub(crate) struct PqcPairInitial {
    public: PqcPublicKey,
    credit: Credit,
}
impl super::PqcOwnerPlan<'_> {
    /// This input has no observation phase yet. Geometry comes directly from
    /// the validated caller request; no prepared family/quota is needed.
    pub(crate) fn initial_plan(&self) -> PqcPairPlan {
        let value = match &self.input {
            super::PqcOwnerInput::Generation { request, .. } => request.algorithm,
            super::PqcOwnerInput::Existing { algorithm, .. } => *algorithm,
        };
        PqcPairPlan { algorithm: value }
    }
}

impl PreparedPqcPair {
    pub(crate) fn attach_initial_retained(
        &mut self,
        initial: &mut Option<PqcPairInitial>,
    ) -> Result<()> {
        let candidate =
            initial
                .as_mut()
                .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
                    crate::KeyAdmissionRejection::PairInitialCandidateAbsent,
                )))?;
        if !matches!(self.public, PublicState::AwaitingStorage) {
            return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::PqcInitialPreparationChanged,
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
impl PqcPairPlan {
    pub(crate) fn requested_bytes(&self) -> Result<usize> {
        Ok(self.algorithm.public_key_length())
    }
    pub(crate) fn allocate(&self) -> Result<PqcPairStorage> {
        Ok(PqcPairStorage {
            public: PqcPublicKey::observation_storage(self.algorithm)?,
        })
    }
    pub(crate) fn bind(
        &self,
        storage: PqcPairStorage,
        credit: &mut Credit,
    ) -> Result<PqcPairInitial> {
        let public_credit = credit.split(storage.public.retained_bytes())?;
        Ok(PqcPairInitial {
            public: storage.public,
            credit: public_credit,
        })
    }
}
impl PqcPairStorage {
    pub(crate) fn allocated_bytes(&self) -> Result<usize> {
        Ok(self.public.retained_bytes())
    }
}
