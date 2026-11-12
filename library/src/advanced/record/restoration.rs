// SPDX-License-Identifier: Apache-2.0
//! Private restore-transfer format. Parsing does not restore native state.

use super::{DetachedRecord, Function, Kind, Limits, SavedRecord, Writer};
use crate::advanced::StateKeyEncoding;

use crate::{Error, Result};
use fe11_sys::{CK_SESSION_INFO, CK_SLOT_ID, CK_ULONG};

pub(in crate::advanced) struct RestorationRecord<'a> {
    pub saved: SavedRecord<'a>,

    pub encryption: Option<StateKeyEncoding>,
    pub authentication: Option<StateKeyEncoding>,
    pub function: Function,
    pub id: CK_ULONG,
    pub capacity: Option<usize>,
    pub source_slot: CK_SLOT_ID,
}
fn encoding(code: u8) -> Result<Option<StateKeyEncoding>> {
    match code {
        0 => Ok(None),
        1 => Ok(Some(StateKeyEncoding::Supplied)),
        2 => Ok(Some(StateKeyEncoding::Embedded)),
        _ => Err(Error::Rejected(crate::RejectionReason::RecoveryRecord(
            crate::RecoveryRecordRejection::RestoreKeyEncoding,
        ))),
    }
}
fn code(value: Option<StateKeyEncoding>) -> u8 {
    match value {
        None => 0,
        Some(StateKeyEncoding::Supplied) => 1,
        Some(StateKeyEncoding::Embedded) => 2,
    }
}
fn capacity(function: Function) -> Result<Option<usize>> {
    match function.name() {
        "C_GetSessionInfo" => Ok(Some(std::mem::size_of::<CK_SESSION_INFO>())),
        "C_SetOperationState" => Ok(None),
        _ => Err(Error::Rejected(crate::RejectionReason::RecoveryRecord(
            crate::RecoveryRecordRejection::RestoreTransferFunction,
        ))),
    }
}
impl<'a> RestorationRecord<'a> {
    /// Append only the transfer metadata. The caller writes the nested Saved
    /// record first; the complete parser still checks its key-role agreement.
    pub(in crate::advanced) fn write_tail(
        writer: &mut Writer<'_>,
        encryption: Option<StateKeyEncoding>,
        authentication: Option<StateKeyEncoding>,
        function: Function,
        id: CK_ULONG,
        source_slot: CK_SLOT_ID,
    ) -> Result<()> {
        let capacity = capacity(function)?;
        writer.u8(code(encryption))?;
        writer.u8(code(authentication))?;
        writer.u64(source_slot as u64)?;
        DetachedRecord::write_tail(writer, function, id, capacity)
    }

    pub(in crate::advanced) fn read(bytes: &'a [u8], limits: Limits) -> Result<Self> {
        Self::read_with(bytes, limits, None)
    }
    pub(in crate::advanced) fn read_with(
        bytes: &'a [u8],
        limits: Limits,
        observer: super::GraphObserver<'a>,
    ) -> Result<Self> {
        let (kind, mut r) = super::decode_with(bytes, limits, observer)?;
        if kind != Kind::DetachedRestore {
            return Err(Error::Rejected(crate::RejectionReason::RecoveryRecord(
                crate::RecoveryRecordRejection::RestoreTransferKind,
            )));
        }
        let saved_bytes = r.bytes(limits.bytes)?;
        let saved = SavedRecord::read_with(saved_bytes, limits, observer)?;
        let encryption = encoding(r.u8()?)?;
        let authentication = encoding(r.u8()?)?;
        if encryption.is_some() != saved.keys.cipher.is_some()
            || authentication.is_some() != saved.keys.authentication.is_some()
        {
            return Err(Error::Rejected(crate::RejectionReason::RecoveryRecord(
                crate::RecoveryRecordRejection::RestoreTransferKeyRoles,
            )));
        }
        let source_slot = CK_SLOT_ID::try_from(r.u64()?).map_err(|_| {
            Error::Rejected(crate::RejectionReason::RecoveryRecord(
                crate::RecoveryRecordRejection::RestoreObservationSlotWidth,
            ))
        })?;
        let function = Function::read(&mut r)?;
        let id = r.bytes(8)?;
        let id = u64::from_be_bytes(id.try_into().map_err(|_| {
            Error::Rejected(crate::RejectionReason::RecoveryRecord(
                crate::RecoveryRecordRejection::RestoreIdentifierWidth,
            ))
        })?);
        let id = CK_ULONG::try_from(id).map_err(|_| {
            Error::Rejected(crate::RejectionReason::RecoveryRecord(
                crate::RecoveryRecordRejection::RestoreNativeIdentifierWidth,
            ))
        })?;
        let wire_capacity = usize::try_from(r.u64()?).map_err(|_| {
            Error::Rejected(crate::RejectionReason::RecoveryRecord(
                crate::RecoveryRecordRejection::RestoreCapacityWidth,
            ))
        })?;
        r.finish()?;
        let capacity = capacity(function)?;
        if wire_capacity != capacity.unwrap_or(0) {
            return Err(Error::Rejected(crate::RejectionReason::RecoveryRecord(
                crate::RecoveryRecordRejection::RestoreTransferCapacity,
            )));
        }
        Ok(Self {
            saved,

            encryption,
            authentication,
            function,
            id,
            capacity,
            source_slot,
        })
    }
}
