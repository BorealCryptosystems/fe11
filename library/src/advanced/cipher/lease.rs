// SPDX-License-Identifier: Apache-2.0
//! Explicit key presence; no native handle is inferred or substituted.

use crate::{
    advanced::{keys::KeyLease, record},
    module::SessionEntry,
    Error, Result,
};
use fe11_sys::{CK_INVALID_HANDLE, CK_OBJECT_HANDLE};

/// Key argument for the generic native cipher operation.
/// The module decides whether the selected mechanism accepts the argument.
#[derive(Clone, Copy)]
pub enum CipherKeyReference<'a> {
    /// A native object reference with a managed lifetime. The module checks
    /// whether its class and attributes permit the selected cipher operation.
    Secret(&'a crate::NativeObjectRef),
    /// Pass CK_INVALID_HANDLE explicitly. No object is created or searched for.
    /// This does not promise native support and never reuses a previous key.
    NoKey,
}
impl<'a> From<&'a crate::ManagedObjectRef> for CipherKeyReference<'a> {
    fn from(value: &'a crate::ManagedObjectRef) -> Self {
        Self::Secret(value)
    }
}
impl<'a> From<&'a crate::NativeObjectRef> for CipherKeyReference<'a> {
    fn from(value: &'a crate::NativeObjectRef) -> Self {
        Self::Secret(value)
    }
}
pub(super) enum CipherLease {
    WithKey(KeyLease),
    NoKey,
}
impl CipherLease {
    pub(super) fn writer_roles(&self) -> Option<&crate::advanced::key_roles::Roles> {
        match self {
            Self::WithKey(key) => key.writer_roles(),
            Self::NoKey => None,
        }
    }
    pub(super) fn arm_for_native_call(&mut self) {
        if let Self::WithKey(key) = self {
            key.arm_for_native_call();
        }
    }
    pub(super) fn handle(&self) -> CK_OBJECT_HANDLE {
        match self {
            Self::WithKey(key) => key.handle,
            Self::NoKey => CK_INVALID_HANDLE,
        }
    }
    pub(super) fn check(&self, entry: &SessionEntry) -> Result<()> {
        match self {
            Self::WithKey(key) => key.check(entry),
            Self::NoKey => Ok(()),
        }
    }
    pub(super) fn lease(&self) -> Option<&KeyLease> {
        match self {
            Self::WithKey(key) => Some(key),
            Self::NoKey => None,
        }
    }
    pub(super) fn duplicate(&self) -> Result<Self> {
        Ok(match self {
            Self::WithKey(key) => Self::WithKey(key.duplicate()?),
            Self::NoKey => Self::NoKey,
        })
    }
    pub(super) fn checkpoint_profile(&self) -> Result<u8> {
        match self {
            Self::WithKey(key) => key.checkpoint_profile(),
            Self::NoKey => Ok(0),
        }
    }
    pub(super) fn checkpoint_key(&self) -> Result<Option<record::KeyBinding<'_>>> {
        self.lease()
            .map(|key| key.checkpoint_key(record::KeyRole::Cipher))
            .transpose()
    }

    pub(super) fn check_record(key: Option<&KeyLease>, profile: u8) -> Result<()> {
        match (key, profile) {
            (None, 0) => Ok(()),
            (Some(key), 1..=4) if key.checkpoint_profile()? == profile => Ok(()),
            _ => Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::CipherDestinationKeyPresenceProfile,
            ))),
        }
    }
    /// Ownership transfer after check_record; no key is duplicated or released.
    pub(super) fn from_checked_record(key: Option<KeyLease>) -> Self {
        match key {
            Some(key) => Self::WithKey(key),
            None => Self::NoKey,
        }
    }
}

impl crate::symmetric::memory::RetainedStorage for CipherLease {
    fn retain_credits(
        &self,
        retained: &mut crate::symmetric::memory::RetainedBytes,
    ) -> crate::Result<()> {
        match self {
            Self::WithKey(key) => key.retain_credits(retained),
            Self::NoKey => Ok(()),
        }
    }
}
