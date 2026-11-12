// SPDX-License-Identifier: Apache-2.0
//! Exact context and key-role metadata, not proof of a key's secret identity.

use super::{Reader, Writer};

use crate::{
    module::{Inner, TokenSnapshot},
    Error, Result,
};
use fe11_sys::{CK_KEY_TYPE, CK_STATE};
#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::advanced) struct Context {
    module: crate::module::ModuleBinding,
    label: [u8; 32],
    manufacturer: [u8; 32],
    model: [u8; 16],
    serial: [u8; 16],
    session_state: u64,
}
impl Context {
    pub(in crate::advanced) fn from_snapshot(
        inner: &Inner,
        snapshot: &TokenSnapshot,
        session_state: CK_STATE,
    ) -> Result<Self> {
        let c = &snapshot.capabilities;
        let value = Self {
            module: inner.module_binding,
            label: c.label,
            manufacturer: c.identity.manufacturer,
            model: c.identity.model,
            serial: c.identity.serial,
            session_state: session_state as u64,
        };
        value.validate()?;
        Ok(value)
    }
    fn validate(&self) -> Result<()> {
        if !matches!(self.session_state, 0..=4) {
            return Err(Error::Rejected(crate::RejectionReason::OperationRecord(
                crate::OperationRecordRejection::RecordSessionState,
            )));
        }
        Ok(())
    }
    /// Check only identities available without native IO. This deliberately
    /// does not claim to observe the destination session's authentication state.
    pub(in crate::advanced) fn check_destination_binding(
        &self,
        inner: &Inner,
        snapshot: &TokenSnapshot,
    ) -> Result<()> {
        let capabilities = &snapshot.capabilities;
        if self.module != inner.module_binding
            || self.label != capabilities.label
            || self.manufacturer != capabilities.identity.manufacturer
            || self.model != capabilities.identity.model
            || self.serial != capabilities.identity.serial
        {
            return Err(Error::Rejected(crate::RejectionReason::OperationRecord(
                crate::OperationRecordRejection::RecordContextMismatch,
            )));
        }
        Ok(())
    }

    /// Required historical state, not an observation of the destination.
    /// StateIo must compare it with C_GetSessionInfo before C_SetOperationState;
    /// rejoin owners likewise retain their separate native inspection.
    pub(in crate::advanced) fn required_session_state(&self) -> Result<CK_STATE> {
        self.validate()?;
        CK_STATE::try_from(self.session_state).map_err(|_| {
            Error::Rejected(crate::RejectionReason::OperationRecord(
                crate::OperationRecordRejection::RecordSessionWidth,
            ))
        })
    }
    pub(in crate::advanced) fn check(&self, expected: &Self) -> Result<()> {
        if self != expected {
            return Err(Error::Rejected(crate::RejectionReason::OperationRecord(
                crate::OperationRecordRejection::RecordContextMismatch,
            )));
        }
        Ok(())
    }
    pub(in crate::advanced) fn write(&self, w: &mut Writer<'_>) -> Result<()> {
        self.validate()?;
        w.put(&self.module.persistent_digest()?)?;
        w.u8(self.module.table_version.0)?;
        w.u8(self.module.table_version.1)?;
        w.u64(self.module.interface_flags)?;
        w.put(&self.label)?;
        w.put(&self.manufacturer)?;
        w.put(&self.model)?;
        w.put(&self.serial)?;
        w.u64(self.session_state)
    }
    pub(in crate::advanced) fn read(r: &mut Reader<'_>) -> Result<Self> {
        fn array<const N: usize>(r: &mut Reader<'_>) -> Result<[u8; N]> {
            r.take(N)?.try_into().map_err(|_| {
                Error::Rejected(crate::RejectionReason::OperationRecord(
                    crate::OperationRecordRejection::RecordIdentityWidth,
                ))
            })
        }
        let module = crate::module::ModuleBinding {
            identity: crate::module::provenance::BindingIdentity::File(array(r)?),
            table_version: (r.u8()?, r.u8()?),
            interface_flags: r.u64()?,
        };
        let value = Self {
            module,
            label: array(r)?,
            manufacturer: array(r)?,
            model: array(r)?,
            serial: array(r)?,
            session_state: r.u64()?,
        };
        value.validate()?;
        Ok(value)
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::advanced) enum KeyRole {
    Cipher,
    Authentication,
}
#[derive(Clone, Copy)]
pub(in crate::advanced) struct KeyBinding<'a> {
    pub role: KeyRole,
    pub class: Option<u64>,
    pub key_type: Option<u64>,
    pub id: Option<&'a [u8]>,
}
fn write_optional_number(w: &mut Writer<'_>, value: Option<u64>) -> Result<()> {
    match value {
        None => w.u8(0),
        Some(value) => {
            w.u8(1)?;
            w.u64(value)
        }
    }
}
fn read_optional_number(r: &mut Reader<'_>) -> Result<Option<u64>> {
    match r.u8()? {
        0 => Ok(None),
        1 => r.u64().map(Some),
        _ => Err(Error::Rejected(crate::RejectionReason::OperationRecord(
            crate::OperationRecordRejection::RecordOptionalIntegerTag,
        ))),
    }
}
impl<'a> KeyBinding<'a> {
    fn validate(&self) -> Result<()> {
        if let Some(id) = self.id {
            crate::bounds::ck_length(id.len())?;
        }
        if let Some(class) = self.class {
            fe11_sys::CK_OBJECT_CLASS::try_from(class).map_err(|_| {
                Error::Rejected(crate::RejectionReason::OperationRecord(
                    crate::OperationRecordRejection::RecordClassWidth,
                ))
            })?;
        }
        if let Some(key_type) = self.key_type {
            CK_KEY_TYPE::try_from(key_type).map_err(|_| {
                Error::Rejected(crate::RejectionReason::OperationRecord(
                    crate::OperationRecordRejection::RecordKeyTypeWidth,
                ))
            })?;
        }
        // These are optional observations, never an admission condition for a
        // generic native key. Role and parameter representation are independent.

        Ok(())
    }
    fn write(&self, w: &mut Writer<'_>) -> Result<()> {
        self.validate()?;
        w.u8(if self.role == KeyRole::Cipher { 1 } else { 2 })?;
        write_optional_number(w, self.class)?;
        write_optional_number(w, self.key_type)?;
        w.optional_bytes(self.id)
    }
    fn read(r: &mut Reader<'a>) -> Result<Self> {
        let role = match r.u8()? {
            1 => KeyRole::Cipher,
            2 => KeyRole::Authentication,
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::OperationRecord(
                    crate::OperationRecordRejection::RecordKeyRole,
                )))
            }
        };
        let class = read_optional_number(r)?;
        let key_type = read_optional_number(r)?;
        let remaining = r.remaining();
        let id = r.optional_bytes(remaining)?;
        let key = Self {
            role,
            class,
            key_type,
            id,
        };
        key.validate()?;
        Ok(key)
    }
}
pub(in crate::advanced) struct KeyBindings<'a> {
    pub cipher: Option<KeyBinding<'a>>,
    pub authentication: Option<KeyBinding<'a>>,
}
impl<'a> KeyBindings<'a> {
    pub(in crate::advanced) fn write(&self, w: &mut Writer<'_>) -> Result<()> {
        if self.cipher.is_some_and(|k| k.role != KeyRole::Cipher)
            || self
                .authentication
                .is_some_and(|k| k.role != KeyRole::Authentication)
        {
            return Err(Error::Rejected(crate::RejectionReason::OperationRecord(
                crate::OperationRecordRejection::RecordKeyRoleOrder,
            )));
        }
        w.u32(u32::from(self.cipher.is_some()) + u32::from(self.authentication.is_some()))?;
        for key in [self.cipher, self.authentication].into_iter().flatten() {
            key.write(w)?;
        }
        Ok(())
    }
    pub(in crate::advanced) fn read(r: &mut Reader<'a>) -> Result<Self> {
        let count = r.count(2)?;
        let mut value = Self {
            cipher: None,
            authentication: None,
        };
        for _ in 0..count {
            let key = KeyBinding::read(r)?;
            match key.role {
                KeyRole::Cipher if value.cipher.is_none() && value.authentication.is_none() => {
                    value.cipher = Some(key)
                }
                KeyRole::Authentication if value.authentication.is_none() => {
                    value.authentication = Some(key)
                }
                _ => {
                    return Err(Error::Rejected(crate::RejectionReason::OperationRecord(
                        crate::OperationRecordRejection::RecordKeyRoleOrder,
                    )))
                }
            }
        }
        Ok(value)
    }
}
