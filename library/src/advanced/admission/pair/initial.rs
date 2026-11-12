// SPDX-License-Identifier: Apache-2.0
//! Mutually exclusive family storage in the complete initial admission graph.
use super::PreparedPair;
use crate::{
    advanced::admission::KeyPolicy,
    crypto::{
        kem::{KemPairInitial, KemPairPlan, KemPairStorage},
        pqc::{PqcPairInitial, PqcPairPlan, PqcPairStorage},
    },
    symmetric::memory::Credit,
    Error, Result,
};

pub(in crate::advanced::admission) enum Plan {
    None,
    Pqc(PqcPairPlan),
    Kem(KemPairPlan),
}
pub(in crate::advanced::admission) enum Storage {
    None,
    Pqc(PqcPairStorage),
    Kem(KemPairStorage),
}
pub(in crate::advanced::admission) enum Prepared {
    None,
    Pqc(Option<PqcPairInitial>),
    Kem(Option<KemPairInitial>),
}
impl Plan {
    pub(in crate::advanced::admission) fn requested_bytes(&self) -> Result<usize> {
        match self {
            Self::None => Ok(0),
            Self::Pqc(plan) => plan.requested_bytes(),
            Self::Kem(plan) => Ok(plan.requested_bytes()),
        }
    }
    pub(in crate::advanced::admission) fn allocate(&self) -> Result<Storage> {
        Ok(match self {
            Self::None => Storage::None,
            Self::Pqc(plan) => Storage::Pqc(plan.allocate()?),
            Self::Kem(plan) => Storage::Kem(plan.allocate()?),
        })
    }
    pub(in crate::advanced::admission) fn bind(
        &self,
        storage: Storage,
        credit: &mut Credit,
    ) -> Result<Prepared> {
        Ok(match (self, storage) {
            (Self::None, Storage::None) => Prepared::None,
            (Self::Pqc(plan), Storage::Pqc(storage)) => {
                Prepared::Pqc(Some(plan.bind(storage, credit)?))
            }
            (Self::Kem(plan), Storage::Kem(storage)) => {
                Prepared::Kem(Some(plan.bind(storage, credit)?))
            }
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                    crate::KeyAdmissionRejection::PairInitialPreparationChanged,
                )))
            }
        })
    }
}
impl Storage {
    pub(in crate::advanced::admission) fn allocated_bytes(&self) -> Result<usize> {
        match self {
            Self::None => Ok(0),
            Self::Pqc(storage) => storage.allocated_bytes(),
            Self::Kem(storage) => Ok(storage.allocated_bytes()),
        }
    }
}
impl Prepared {
    pub(in crate::advanced::admission) fn attach_retained(
        candidate: &mut Option<Self>,
        policy: &mut KeyPolicy,
    ) -> Result<()> {
        let value =
            candidate
                .as_mut()
                .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
                    crate::KeyAdmissionRejection::PairInitialCandidateAbsent,
                )))?;
        match (value, policy) {
            (Self::None, KeyPolicy::Pair(pair)) => match &pair.prepared {
                PreparedPair::Classical(_) | PreparedPair::Agreement(_) => Ok(()),
                _ => Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                    crate::KeyAdmissionRejection::PairInitialPreparationAbsent,
                ))),
            },
            (Self::None, _) => Ok(()),
            (Self::Pqc(initial), KeyPolicy::Pair(pair)) => match &mut pair.prepared {
                PreparedPair::Pqc(prepared) => prepared.attach_initial_retained(initial),
                _ => Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                    crate::KeyAdmissionRejection::PqcInitialPreparationChanged,
                ))),
            },
            (Self::Kem(initial), KeyPolicy::Pair(pair)) => match &mut pair.prepared {
                PreparedPair::Kem(prepared) => prepared.attach_initial_retained(initial),
                _ => Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                    crate::KeyAdmissionRejection::MlKemInitialPreparationChanged,
                ))),
            },
            _ => Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::PairInitialPreparationChanged,
            ))),
        }
    }
}
