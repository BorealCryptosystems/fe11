// SPDX-License-Identifier: Apache-2.0
//! Pair identity and retained native observations during admission.
use super::{PreparedPair, RequiredAttributes};
use crate::symmetric::memory::Credit;
use crate::{Error, Result};
use fe11_sys::{CK_INVALID_HANDLE, CK_OBJECT_HANDLE};
pub(super) mod initial;

pub(super) struct PairFrame {
    pub(super) prepared: PreparedPair,
    pub(super) private: bool,
    pub(super) public_handle: CK_OBJECT_HANDLE,
    pub(super) public_attributes: Option<RequiredAttributes>,
    pub(super) public_allowed: Option<crate::MechanismObservationReport>,
    pub(super) public_properties: Option<crate::ObjectObservationReport>,
    pub(super) public_search: Option<crate::ObjectSearchReport>,
    _credit: Credit,
}
/// Only the stable envelope and its credit belong to this candidate. The
/// family input remains outside it until successful final possession.
pub(super) struct PairFrameStorage {
    slot: crate::allocation::Slot<PairFrame>,
    family_inline: usize,
    credit: Credit,
}

impl PairFrame {
    /// The family charges its inline payload. Charge the remaining envelope
    /// once, including its enum tag, padding and unused variant space.
    pub(super) fn requested_bytes(family_inline: usize) -> Result<usize> {
        std::mem::size_of::<Self>()
            .checked_sub(family_inline)
            .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::PairOwnerStorageAccounting,
            )))
    }

    pub(super) fn prepare_storage(
        family_inline: usize,
        prepaid: &mut Credit,
    ) -> Result<PairFrameStorage> {
        let credit = prepaid.split(Self::requested_bytes(family_inline)?)?;
        Ok(PairFrameStorage {
            slot: crate::allocation::Slot::new()?,
            family_inline,
            credit,
        })
    }
}

impl PairFrameStorage {
    /// Refusal preserves both owners so the caller can release its access
    /// first. After taking them, initialization cannot allocate or fail.
    pub(super) fn finish(
        storage: &mut Option<Self>,
        prepared: &mut Option<PreparedPair>,
    ) -> Result<Box<PairFrame>> {
        let candidate =
            storage
                .as_ref()
                .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
                    crate::KeyAdmissionRejection::PairEnvelopeAbsent,
                )))?;
        let family =
            prepared
                .as_ref()
                .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
                    crate::KeyAdmissionRejection::PairFamilyAbsent,
                )))?;
        if candidate.family_inline != family.credited_inline_bytes() {
            return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::PairOwnerStorageAccounting,
            )));
        }
        let candidate = storage
            .take()
            .expect("pair envelope checked before transfer");
        let prepared = prepared
            .take()
            .expect("pair family checked before transfer");
        Ok(candidate.slot.write(PairFrame {
            prepared,
            private: false,
            public_handle: CK_INVALID_HANDLE,
            public_attributes: None,
            public_allowed: None,
            public_properties: None,
            public_search: None,
            _credit: candidate.credit,
        }))
    }
}
