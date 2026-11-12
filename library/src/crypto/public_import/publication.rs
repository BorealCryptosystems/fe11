// SPDX-License-Identifier: Apache-2.0
//! Typed publication payload retained through public creation and observation.
use crate::{
    crypto::{
        integer_key::{PublicDer, PublicDerStorage},
        kem::KemPublicKey,
        VerificationPublication, VerificationPublicationPlan, VerificationPublicationStorage,
    },
    symmetric::memory::Credit,
    Error, Result,
};

pub(crate) enum Plan<'a> {
    Der(&'a [u8]),
    Kem(&'a KemPublicKey),
    Verification(VerificationPublicationPlan<'a>),
}
pub(crate) enum Storage {
    Der(PublicDerStorage),
    Kem(KemPublicKey),
    Verification(VerificationPublicationStorage),
}
pub(crate) enum Prepared {
    Der(PublicDer),
    // Keep the result copy charged until native creation and observation finish.
    Kem {
        /// Copy of the caller-supplied encapsulation key.
        key: KemPublicKey,
        /// Covers this copy until the completed result is transferred.
        credit: Credit,
    },
    Verification(VerificationPublication),
}
impl Plan<'_> {
    pub(crate) fn requested_bytes(&self) -> Result<usize> {
        match self {
            Self::Der(bytes) => Ok(bytes.len()),
            Self::Kem(key) => Ok(key.as_raw().len()),
            Self::Verification(plan) => plan.requested_bytes(),
        }
    }
    pub(crate) fn allocate(&self) -> Result<Storage> {
        Ok(match self {
            Self::Der(bytes) => Storage::Der(PublicDerStorage::allocate(bytes.len())?),
            Self::Kem(key) => {
                Storage::Kem(KemPublicKey::from_raw(key.parameter_set(), key.as_raw())?)
            }
            Self::Verification(plan) => Storage::Verification(plan.allocate()?),
        })
    }
    pub(crate) fn bind(&self, storage: Storage, credit: &mut Credit) -> Result<Prepared> {
        Ok(match (self, storage) {
            (Self::Der(bytes), Storage::Der(storage)) => {
                Prepared::Der(storage.bind(bytes, credit)?)
            }
            (Self::Kem(_), Storage::Kem(key)) => {
                let credit = credit.split(key.retained_bytes())?;
                Prepared::Kem { key, credit }
            }
            (Self::Verification(plan), Storage::Verification(storage)) => {
                Prepared::Verification(plan.bind(storage, credit)?)
            }
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::KeyEncoding(
                    crate::KeyEncodingRejection::PublicPublicationPreparationPairing,
                )))
            }
        })
    }
}
impl Prepared {
    /// Retained payload size after binding, using the same capacities as admission.
    pub(crate) fn allocated_bytes(&self) -> Result<usize> {
        match self {
            Self::Der(value) => Ok(value.allocated_bytes()),
            Self::Kem { key, .. } => Ok(key.retained_bytes()),
            Self::Verification(value) => value.allocated_bytes(),
        }
    }
}
impl Storage {
    pub(crate) fn allocated_bytes(&self) -> Result<usize> {
        match self {
            Self::Der(storage) => Ok(storage.allocated()),
            Self::Kem(key) => Ok(key.retained_bytes()),
            Self::Verification(storage) => storage.allocated_bytes(),
        }
    }
}
