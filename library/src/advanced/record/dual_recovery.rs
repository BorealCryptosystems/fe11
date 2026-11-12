// SPDX-License-Identifier: Apache-2.0
//! Fresh dual decryption inputs, never a serialized native continuation.

use super::{Descriptor, KeyBindings, Kind, Limits, Messages, RecoveryOrigin, ValidationRecord};
use crate::advanced::record::Family;
use crate::{Error, Result};
use fe11_sys::CKM_AES_GCM;
pub(in crate::advanced) struct DualRecovery<'a> {
    pub origin: RecoveryOrigin,
    pub descriptor: Descriptor,
    pub keys: KeyBindings<'a>,
    pub messages: Messages<'a>,
    pub validation: Option<ValidationRecord<'a>>,
}

impl<'a> DualRecovery<'a> {
    pub(in crate::advanced) fn read(bytes: &'a [u8], limits: Limits) -> Result<Self> {
        Self::read_with(bytes, limits, None)
    }
    pub(in crate::advanced) fn read_with(
        bytes: &'a [u8],
        limits: Limits,
        observer: super::GraphObserver<'a>,
    ) -> Result<Self> {
        let (kind, mut r) = super::decode_with(bytes, limits, observer)?;
        if kind != Kind::DualRecovery {
            return Err(Error::Rejected(crate::RejectionReason::RecoveryRecord(
                crate::RecoveryRecordRejection::DualRecoveryKind,
            )));
        }
        let origin = RecoveryOrigin::read(&mut r)?;
        let descriptor = Descriptor::read(&mut r)?;
        let keys = KeyBindings::read(&mut r)?;
        let messages = Messages::read(&mut r, limits)?;
        let validation = ValidationRecord::read(&mut r, limits)?;
        r.finish()?;
        let initial = match descriptor.family {
            Family::DecryptDigest => "C_DigestInit",
            Family::DecryptVerify => "C_VerifyInit",
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::RecoveryRecord(
                    crate::RecoveryRecordRejection::DualRecoveryFamily,
                )))
            }
        };
        if descriptor.mechanism != CKM_AES_GCM as u64
            || descriptor.phase.name() != initial
            || descriptor.validation_requested
        {
            return Err(Error::Rejected(crate::RejectionReason::RecoveryRecord(
                crate::RecoveryRecordRejection::DualRecoveryProfile,
            )));
        }
        // Reuse the exact initial-owner invariants without granting any native
        // detachment/restoration authority. There is no ID or opaque state here.
        if descriptor
            .validate_detached(&keys, &messages, None, limits)?
            .is_some()
        {
            return Err(Error::Rejected(crate::RejectionReason::RecoveryRecord(
                crate::RecoveryRecordRejection::DualRecoveryOutput,
            )));
        }
        if let Some(v) = &validation {
            if v.maximum() != 2 {
                return Err(Error::Rejected(crate::RejectionReason::RecoveryRecord(
                    crate::RecoveryRecordRejection::DualRecoveryValidationCapacity,
                )));
            }
            let mut observations = v.iter();
            if let Some(o) = observations.next() {
                let o = o?;
                if o.function != "C_DecryptFinal" || o.message_index.is_some() {
                    return Err(Error::Rejected(crate::RejectionReason::RecoveryRecord(
                        crate::RecoveryRecordRejection::DualRecoveryHistoricalObservation,
                    )));
                }
            }
            if observations.next().is_some() {
                return Err(Error::Rejected(crate::RejectionReason::RecoveryRecord(
                    crate::RecoveryRecordRejection::DualRecoveryHistoricalCompletion,
                )));
            }
        }
        Ok(Self {
            origin,
            descriptor,
            keys,
            messages,
            validation,
        })
    }
}
