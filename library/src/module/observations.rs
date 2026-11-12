// SPDX-License-Identifier: Apache-2.0
//! Explicit native information queries, separate from discovery and selection.
//!
//! Values describe one returned call, not an atomic inventory or a new token
//! identity. Reading them never replaces the module's discovery snapshots.
use super::{check_discovery, list, MechanismInfo, Module, State, TokenSnapshot};
use crate::{native::frame::NativeFrame, native::Native, Error, Result};
use fe11_sys::*;
use std::sync::{atomic::Ordering, Arc};

/// Complete `CK_INFO` from an explicit successful `C_GetInfo` call.
/// Fixed-width text remains space-padded bytes; no encoding is assumed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeLibraryInfo {
    /// Reported Cryptoki version; this does not select the function-table ABI.
    pub cryptoki_version: (u8, u8),
    /// Exact manufacturer bytes.
    pub manufacturer: [u8; 32],
    /// Exact native flags, including bits unknown to Fe11.
    pub flags: u64,
    /// Exact library-description bytes.
    pub description: [u8; 32],
    /// Reported implementation version.
    pub library_version: (u8, u8),
}

/// Complete `CK_SLOT_INFO`, available independently of token presence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeSlotInfo {
    /// Exact space-padded slot-description bytes.
    pub description: [u8; 64],
    /// Exact space-padded manufacturer bytes.
    pub manufacturer: [u8; 32],
    /// Exact native flags; token presence is an observation at this call.
    pub flags: u64,
    /// Reported hardware version.
    pub hardware_version: (u8, u8),
    /// Reported firmware version.
    pub firmware_version: (u8, u8),
}

/// Complete `CK_TOKEN_INFO` from one explicit query.
///
/// Counts and memory sizes retain the native scalar, including
/// `CK_UNAVAILABLE_INFORMATION` and `CK_EFFECTIVELY_INFINITE`. No sentinel is
/// converted to zero or treated as an admission decision. These are native-width
/// values widened to u64, not normalized across different module ABIs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeTokenInfo {
    /// Exact space-padded token label.
    pub label: [u8; 32],
    /// Exact space-padded manufacturer bytes.
    pub manufacturer: [u8; 32],
    /// Exact space-padded model bytes.
    pub model: [u8; 16],
    /// Exact space-padded serial-number bytes.
    pub serial: [u8; 16],
    /// Exact native flags, including unknown bits.
    pub flags: u64,
    /// Announced maximum session count, including native sentinel values.
    pub maximum_sessions: u64,
    /// Observed session count, including native sentinel values.
    pub sessions: u64,
    /// Announced maximum read/write session count.
    pub maximum_read_write_sessions: u64,
    /// Observed read/write session count.
    pub read_write_sessions: u64,
    /// Announced maximum PIN length in bytes.
    pub maximum_pin_length: u64,
    /// Announced minimum PIN length in bytes.
    pub minimum_pin_length: u64,
    /// Announced total public memory in bytes, or its native sentinel.
    pub total_public_memory: u64,
    /// Announced free public memory in bytes, or its native sentinel.
    pub free_public_memory: u64,
    /// Announced total private memory in bytes, or its native sentinel.
    pub total_private_memory: u64,
    /// Announced free private memory in bytes, or its native sentinel.
    pub free_private_memory: u64,
    /// Reported hardware version.
    pub hardware_version: (u8, u8),
    /// Reported firmware version.
    pub firmware_version: (u8, u8),
    /// Exact `utcTime` bytes; no parsing or clock-validity assertion is added.
    pub utc_time: [u8; 16],
}

fn slot_id(slot: u64) -> Result<CK_SLOT_ID> {
    CK_SLOT_ID::try_from(slot).map_err(|_| {
        Error::Rejected(crate::RejectionReason::ModuleLifecycle(
            crate::ModuleLifecycleRejection::SlotIdentifierConversion,
        ))
    })
}

fn observed_token(state: &State, slot: Option<CK_SLOT_ID>) -> Result<Option<Arc<TokenSnapshot>>> {
    let Some(slot) = slot else { return Ok(None) };
    let registry = state.token_registry()?;
    Ok(registry
        .tokens
        .iter()
        .find(|token| {
            token.capabilities.identity.slot == slot as u64 && token.valid.load(Ordering::Acquire)
        })
        .cloned())
}

fn retire_on_error<T>(state: &State, observed: Option<&TokenSnapshot>, result: &Result<T>) {
    if let (Some(token), Err(Error::Native { code, .. })) = (observed, result) {
        // Retire only the pre-call generation. A concurrent explicit refresh
        // may already have published another token at the same numeric slot.
        state.apply_failure_scope(token, crate::native_return::diagnostic_context_scope(*code));
    }
}

fn observe<T>(
    module: &Module,
    slot: Option<CK_SLOT_ID>,
    initial: T,
    name: &'static str,
    call: impl FnOnce(&Native, *mut T) -> Result<CK_RV>,
) -> Result<T> {
    // The output and captured snapshot outlive module admission on all errors.
    // NativeFrame also pins the image if C cannot establish memory return.
    let mut frame = NativeFrame::new(initial)?;
    let observed;
    let state = module.inner.read()?;
    observed = observed_token(&state, slot)?;
    let rv = call(&state.native, &mut *frame)?;
    frame.retain_if_pending(rv, &state.native);
    let result = check_discovery(&state.native, rv, name);
    retire_on_error(&state, observed.as_deref(), &result);
    result?;
    drop(state);
    drop(observed);
    frame.into_inner()
}

/// Convert outside module admission, reserving the widened storage fallibly.
/// CK_ULONG is narrower than u64 on Windows; native-list allocation alone does
/// not cover the result. Each push stays within the capacity reserved here.
fn identifiers_to_u64(values: Vec<CK_ULONG>) -> Result<Vec<u64>> {
    let mut identifiers = Vec::new();
    identifiers.try_reserve_exact(values.len()).map_err(|_| {
        Error::Rejected(crate::RejectionReason::ModuleLifecycle(
            crate::ModuleLifecycleRejection::NativeIdentifierAllocation,
        ))
    })?;
    for value in values {
        identifiers.push(value as u64);
    }
    Ok(identifiers)
}

impl Module {
    /// Query complete current module information through one `C_GetInfo`.
    /// This does not replace `info()` or change the selected function-table ABI.
    pub fn library_info(&self) -> Result<NativeLibraryInfo> {
        let raw = observe(
            self,
            None,
            crate::native::output::info(),
            "C_GetInfo",
            |native, out| {
                let call = native.table.C_GetInfo.ok_or(Error::Rejected(
                    crate::RejectionReason::ModuleLifecycle(
                        crate::ModuleLifecycleRejection::CGetInfoUnavailable,
                    ),
                ))?;
                native.record("C_GetInfo")?;
                // SAFETY: observe retains initialized, aligned CK_INFO storage and
                // module admission through this call and handles uncertain return.
                Ok(unsafe { call(out) })
            },
        )?;
        Ok(NativeLibraryInfo {
            cryptoki_version: (raw.cryptokiVersion.major, raw.cryptokiVersion.minor),
            manufacturer: raw.manufacturerID,
            flags: raw.flags as u64,
            description: raw.libraryDescription,
            library_version: (raw.libraryVersion.major, raw.libraryVersion.minor),
        })
    }

    /// Enumerate native slot identifiers, including empty slots when
    /// `token_present` is false. No token or mechanism query is added.
    /// Uses the caller's `Limits::slots` and `Limits::discovery_attempts`.
    /// A list may change between sizing and filling; only a size-change refusal
    /// permits another bounded attempt. The result is not a selection snapshot.
    pub fn slot_ids(&self, token_present: bool) -> Result<Vec<u64>> {
        let state = self.inner.read()?;
        let call = state.native.table.C_GetSlotList.ok_or(Error::Rejected(
            crate::RejectionReason::ModuleLifecycle(
                crate::ModuleLifecycleRejection::CGetSlotListUnavailable,
            ),
        ))?;
        let present = if token_present { CK_TRUE } else { CK_FALSE };
        let slots = list(
            &state.native,
            "C_GetSlotList",
            self.inner.limits.slots,
            self.inner.limits.discovery_attempts,
            |out, count| {
                // SAFETY: list owns the stable count and initialized slot array,
                // or uses NULL for sizing, under this module's admission.
                unsafe { call(present, out, count) }
            },
        )?;
        drop(state);
        identifiers_to_u64(slots)
    }

    /// Read all slot fields through one `C_GetSlotInfo`, even for an empty slot.
    /// Slot existence and native errors are decided by the module.
    pub fn slot_info(&self, slot: u64) -> Result<NativeSlotInfo> {
        let slot = slot_id(slot)?;
        let raw = observe(
            self,
            Some(slot),
            crate::native::output::slot_info(),
            "C_GetSlotInfo",
            |native, out| {
                let call = native.table.C_GetSlotInfo.ok_or(Error::Rejected(
                    crate::RejectionReason::ModuleLifecycle(
                        crate::ModuleLifecycleRejection::CGetSlotInfoUnavailable,
                    ),
                ))?;
                native.record("C_GetSlotInfo")?;
                // SAFETY: the checked slot and stable CK_SLOT_INFO output belong to
                // this admitted call; observe retains them on uncertain return.
                Ok(unsafe { call(slot, out) })
            },
        )?;
        Ok(NativeSlotInfo {
            description: raw.slotDescription,
            manufacturer: raw.manufacturerID,
            flags: raw.flags as u64,
            hardware_version: (raw.hardwareVersion.major, raw.hardwareVersion.minor),
            firmware_version: (raw.firmwareVersion.major, raw.firmwareVersion.minor),
        })
    }

    /// Read all token fields through one `C_GetTokenInfo`. No discovery,
    /// mechanism query, session opening or cached-authority update is performed.
    pub fn token_info(&self, slot: u64) -> Result<NativeTokenInfo> {
        let slot = slot_id(slot)?;
        let raw = observe(
            self,
            Some(slot),
            crate::native::output::token_info(),
            "C_GetTokenInfo",
            |native, out| {
                let call = native.table.C_GetTokenInfo.ok_or(Error::Rejected(
                    crate::RejectionReason::TokenAdministration(
                        crate::TokenAdministrationRejection::CGetTokenInfoUnavailable,
                    ),
                ))?;
                native.record("C_GetTokenInfo")?;
                // SAFETY: observe owns the complete initialized CK_TOKEN_INFO,
                // holds module admission and retains storage on uncertain return.
                Ok(unsafe { call(slot, out) })
            },
        )?;
        Ok(NativeTokenInfo {
            label: raw.label,
            manufacturer: raw.manufacturerID,
            model: raw.model,
            serial: raw.serialNumber,
            flags: raw.flags as u64,
            maximum_sessions: raw.ulMaxSessionCount as u64,
            sessions: raw.ulSessionCount as u64,
            maximum_read_write_sessions: raw.ulMaxRwSessionCount as u64,
            read_write_sessions: raw.ulRwSessionCount as u64,
            maximum_pin_length: raw.ulMaxPinLen as u64,
            minimum_pin_length: raw.ulMinPinLen as u64,
            total_public_memory: raw.ulTotalPublicMemory as u64,
            free_public_memory: raw.ulFreePublicMemory as u64,
            total_private_memory: raw.ulTotalPrivateMemory as u64,
            free_private_memory: raw.ulFreePrivateMemory as u64,
            hardware_version: (raw.hardwareVersion.major, raw.hardwareVersion.minor),
            firmware_version: (raw.firmwareVersion.major, raw.firmwareVersion.minor),
            utc_time: raw.utcTime,
        })
    }

    /// Enumerate mechanism identifiers without querying their properties or
    /// filtering them through a Fe11 catalog. The caller's mechanism-count and
    /// discovery-attempt limits apply; order and repeated identifiers are kept.
    pub fn mechanism_ids(&self, slot: u64) -> Result<Vec<u64>> {
        let slot = slot_id(slot)?;
        let observed;
        let state = self.inner.read()?;
        observed = observed_token(&state, Some(slot))?;
        let call = state
            .native
            .table
            .C_GetMechanismList
            .ok_or(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                crate::ModuleLifecycleRejection::CGetMechanismListUnavailable,
            )))?;
        let result = list(
            &state.native,
            "C_GetMechanismList",
            self.inner.limits.mechanisms,
            self.inner.limits.discovery_attempts,
            |out, count| {
                // SAFETY: list owns the initialized array and stable length,
                // including its NULL sizing pass; the module remains admitted.
                unsafe { call(slot, out, count) }
            },
        );
        retire_on_error(&state, observed.as_deref(), &result);
        drop(state);
        drop(observed);
        identifiers_to_u64(result?)
    }

    /// Query the exact caller-selected mechanism through `C_GetMechanismInfo`.
    /// No prior discovery or membership check is required. Returned properties
    /// remain observations, not evidence that an operation will succeed.
    pub fn mechanism_info(&self, slot: u64, mechanism: u64) -> Result<MechanismInfo> {
        let slot = slot_id(slot)?;
        let mechanism = CK_MECHANISM_TYPE::try_from(mechanism).map_err(|_| {
            Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                crate::ModuleLifecycleRejection::MechanismIdentifierConversion,
            ))
        })?;
        let raw = observe(
            self,
            Some(slot),
            crate::native::output::mechanism_info(),
            "C_GetMechanismInfo",
            |native, out| {
                let call = native.table.C_GetMechanismInfo.ok_or(Error::Rejected(
                    crate::RejectionReason::ModuleLifecycle(
                        crate::ModuleLifecycleRejection::CGetMechanismInfoUnavailable,
                    ),
                ))?;
                native.record("C_GetMechanismInfo")?;
                // SAFETY: both scalar identifiers fit their ABI types and observe
                // owns the aligned CK_MECHANISM_INFO output for the native call.
                Ok(unsafe { call(slot, mechanism, out) })
            },
        )?;
        Ok(MechanismInfo {
            minimum: raw.ulMinKeySize as u64,
            maximum: raw.ulMaxKeySize as u64,
            flags: raw.flags as u64,
        })
    }
}
