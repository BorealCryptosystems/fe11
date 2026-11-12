// SPDX-License-Identifier: Apache-2.0
//! Keyless detached description. Parsing grants neither authenticity nor replay rights.
use super::{
    Context, Descriptor, Function, KeyBindings, Kind, Limits, Messages, ValidationRecord, Writer,
};
use crate::{bounds, Error, Result};
use fe11_sys::{CK_FLAGS, CK_ULONG};
pub(in crate::advanced) struct DetachedRecord<'a> {
    pub context: Context,
    pub descriptor: Descriptor,
    pub keys: KeyBindings<'a>,
    pub messages: Messages<'a>,
    pub validation: Option<ValidationRecord<'a>>,
    pub function: Function,
    pub id: CK_ULONG,
    pub capacity: Option<usize>,
    pub capture: bool,
    pub terminal: Option<bool>,
}
impl<'a> DetachedRecord<'a> {
    pub(in crate::advanced) fn read(bytes: &'a [u8], limits: Limits) -> Result<Self> {
        Self::read_with(bytes, limits, None)
    }
    pub(in crate::advanced) fn read_with(
        bytes: &'a [u8],
        limits: Limits,
        observer: super::GraphObserver<'a>,
    ) -> Result<Self> {
        let (kind, mut r) = super::decode_with(bytes, limits, observer)?;
        if !matches!(
            kind,
            Kind::Detached | Kind::DetachedCapture | Kind::DetachedValidation
        ) {
            return Err(Error::Rejected(crate::RejectionReason::Persistence(
                crate::PersistenceRejection::DetachedRecordKind,
            )));
        }
        let capture = kind == Kind::DetachedCapture;
        let context = Context::read(&mut r)?;
        let descriptor = Descriptor::read(&mut r)?;
        let keys = KeyBindings::read(&mut r)?;
        let messages = Messages::read(&mut r, limits)?;
        let validation = ValidationRecord::read(&mut r, limits)?;
        let terminal = if kind == Kind::DetachedValidation {
            Some(r.boolean(crate::RejectionReason::RecoveryRecord(
                crate::RecoveryRecordRejection::TerminalValidityCode,
            ))?)
        } else {
            None
        };
        let function = Function::read(&mut r)?;
        let id = r.bytes(8)?;
        let id = u64::from_be_bytes(id.try_into().map_err(|_| {
            Error::Rejected(crate::RejectionReason::RecoveryRecord(
                crate::RecoveryRecordRejection::DetachedIdentifierWidth,
            ))
        })?);
        let id = CK_ULONG::try_from(id).map_err(|_| {
            Error::Rejected(crate::RejectionReason::RecoveryRecord(
                crate::RecoveryRecordRejection::DetachedNativeIdentifierWidth,
            ))
        })?;
        let wire_capacity = usize::try_from(r.u64()?).map_err(|_| {
            Error::Rejected(crate::RejectionReason::RecoveryRecord(
                crate::RecoveryRecordRejection::DetachedCapacityWidth,
            ))
        })?;
        r.finish()?;
        let capacity = if let Some(valid) = terminal {
            if function.name() != "C_GetSessionValidationFlags" {
                return Err(Error::Rejected(crate::RejectionReason::RecoveryRecord(
                    crate::RecoveryRecordRejection::TerminalObservationFunction,
                )));
            }
            descriptor.validate_terminal(&keys, &messages, validation.as_ref(), limits, valid)?;
            Some(std::mem::size_of::<CK_FLAGS>())
        } else if capture {
            if function.name() != "C_GetOperationState" {
                return Err(Error::Rejected(crate::RejectionReason::RecoveryRecord(
                    crate::RecoveryRecordRejection::DetachedCaptureFunction,
                )));
            }
            descriptor.validate(&keys, &messages, validation.as_ref(), limits)?;
            if wire_capacity > limits.bytes {
                return Err(Error::Rejected(crate::RejectionReason::RecoveryRecord(
                    crate::RecoveryRecordRejection::DetachedCaptureOutputCeiling,
                )));
            }
            bounds::ck_length(wire_capacity)?;
            Some(wire_capacity)
        } else {
            if function.name() != descriptor.phase.name() {
                return Err(Error::Rejected(crate::RejectionReason::RecoveryRecord(
                    crate::RecoveryRecordRejection::DetachedNativeFunctionMismatch,
                )));
            }
            descriptor.validate_detached(&keys, &messages, validation.as_ref(), limits)?
        };
        if wire_capacity != capacity.unwrap_or(0) {
            return Err(Error::Rejected(crate::RejectionReason::RecoveryRecord(
                crate::RecoveryRecordRejection::DetachedOutputCapacityMismatch,
            )));
        }
        Ok(Self {
            context,
            descriptor,
            keys,
            messages,
            validation,
            function,
            id,
            capacity,
            capture,
            terminal,
        })
    }
    pub(in crate::advanced) fn write_tail(
        w: &mut Writer<'_>,
        function: Function,
        id: CK_ULONG,
        capacity: Option<usize>,
    ) -> Result<()> {
        function.write(w)?;
        w.bytes(&(id as u64).to_be_bytes())?;
        w.u64(capacity.unwrap_or(0) as u64)
    }
}
