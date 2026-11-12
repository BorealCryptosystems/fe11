// SPDX-License-Identifier: Apache-2.0
//! recovery library envelope. Service authority and durable identity remain external.

use super::{Kind, Limits, MessageState, Reader, RecoverySection, ValidationRecord, Writer};
use crate::advanced::MessageRoute;

use crate::{
    module::{Inner, TokenSnapshot},
    Error, Result,
};

#[derive(Clone, Copy)]
pub(in crate::advanced) struct RecoveryOrigin {
    pub module: crate::module::ModuleBinding,
    manufacturer: [u8; 32],
    model: [u8; 16],
    serial: [u8; 16],
}
impl RecoveryOrigin {
    pub(in crate::advanced) fn new(inner: &Inner, snapshot: &TokenSnapshot) -> Self {
        let id = &snapshot.capabilities.identity;
        Self {
            module: inner.module_binding,
            manufacturer: id.manufacturer,
            model: id.model,
            serial: id.serial,
        }
    }
    pub(in crate::advanced) fn check_token(&self, snapshot: &TokenSnapshot) -> Result<()> {
        let id = &snapshot.capabilities.identity;
        if self.manufacturer != id.manufacturer
            || self.model != id.model
            || self.serial != id.serial
        {
            return Err(Error::Rejected(crate::RejectionReason::RecoveryRecord(
                crate::RecoveryRecordRejection::RecoveryTokenIdentity,
            )));
        }
        Ok(())
    }
    pub(in crate::advanced) fn write(&self, w: &mut Writer<'_>) -> Result<()> {
        w.put(&self.module.persistent_digest()?)?;
        w.u8(self.module.table_version.0)?;
        w.u8(self.module.table_version.1)?;
        w.u64(self.module.interface_flags)?;
        w.put(&self.manufacturer)?;
        w.put(&self.model)?;
        w.put(&self.serial)
    }
    pub(in crate::advanced) fn read(r: &mut Reader<'_>) -> Result<Self> {
        fn a<const N: usize>(r: &mut Reader<'_>) -> Result<[u8; N]> {
            r.take(N)?.try_into().map_err(|_| {
                Error::Rejected(crate::RejectionReason::RecoveryRecord(
                    crate::RecoveryRecordRejection::RecoveryIdentityWidth,
                ))
            })
        }
        let module = crate::module::ModuleBinding {
            identity: crate::module::provenance::BindingIdentity::File(a(r)?),
            table_version: (r.u8()?, r.u8()?),
            interface_flags: r.u64()?,
        };
        Ok(Self {
            module,
            manufacturer: a(r)?,
            model: a(r)?,
            serial: a(r)?,
        })
    }
}
pub(in crate::advanced) struct RecoveryManifest<'a> {
    pub origin: RecoveryOrigin,
    pub section: RecoverySection<'a>,
    pub validation: Option<ValidationRecord<'a>>,
}
impl<'a> RecoveryManifest<'a> {
    pub(in crate::advanced) fn read(bytes: &'a [u8], limits: Limits) -> Result<Self> {
        Self::read_with(bytes, limits, None)
    }
    pub(in crate::advanced) fn read_with(
        bytes: &'a [u8],
        limits: Limits,
        observer: super::GraphObserver<'a>,
    ) -> Result<Self> {
        let (kind, mut r) = super::decode_with(bytes, limits, observer)?;
        if kind != Kind::GcmRecoveryManifest {
            return Err(Error::Rejected(crate::RejectionReason::RecoveryRecord(
                crate::RecoveryRecordRejection::RecoveryManifestKind,
            )));
        }
        let origin = RecoveryOrigin::read(&mut r)?;
        let carried = r.u32()? as usize;
        let section = RecoverySection::read_with(r.bytes(limits.bytes)?, limits, observer)?;
        let validation = ValidationRecord::read(&mut r, limits)?;
        r.finish()?;
        let finished = section
            .messages
            .iter()
            .take_while(|m| m.as_ref().is_ok_and(|m| m.state == MessageState::Finished))
            .count();
        if carried > finished {
            return Err(Error::Rejected(crate::RejectionReason::RecoveryRecord(
                crate::RecoveryRecordRejection::RecoveryHistoricalPrefix,
            )));
        }
        if let Some(v) = &validation {
            if v.maximum()
                != section
                    .messages
                    .len()
                    .checked_add(1)
                    .ok_or(Error::Rejected(crate::RejectionReason::Restoration(
                        crate::RestorationRejection::RecoveryValidationCapacity,
                    )))?
            {
                return Err(Error::Rejected(crate::RejectionReason::Restoration(
                    crate::RestorationRejection::RecoveryValidationCapacity,
                )));
            }
            let route = section
                .messages
                .iter()
                .next()
                .ok_or(Error::Rejected(crate::RejectionReason::OperationRecovery(
                    crate::OperationRecoveryRejection::RecoveryEmptyBatch,
                )))??
                .route;
            let name = if route == MessageRoute::Single {
                "C_DecryptMessage"
            } else {
                "C_DecryptMessageNext"
            };
            let mut observations = v.iter();
            for i in carried..finished {
                let o = observations.next().ok_or(Error::Rejected(
                    crate::RejectionReason::RecoveryRecord(
                        crate::RecoveryRecordRejection::RecoveryObservationAbsent,
                    ),
                ))??;
                if o.function != name || o.message_index != Some(i) {
                    return Err(Error::Rejected(crate::RejectionReason::RecoveryRecord(
                        crate::RecoveryRecordRejection::RecoveryObservationAssociation,
                    )));
                }
            }
            if let Some(o) = observations.next() {
                let o = o?;
                if finished != section.messages.len()
                    || o.function != "C_MessageDecryptFinal"
                    || o.message_index.is_some()
                {
                    return Err(Error::Rejected(crate::RejectionReason::RecoveryRecord(
                        crate::RecoveryRecordRejection::RecoveryFinalObservation,
                    )));
                }
            }
            if observations.next().is_some() {
                return Err(Error::Rejected(crate::RejectionReason::RecoveryRecord(
                    crate::RecoveryRecordRejection::RecoveryExcessObservation,
                )));
            }
        }
        Ok(Self {
            origin,
            section,
            validation,
        })
    }
}
