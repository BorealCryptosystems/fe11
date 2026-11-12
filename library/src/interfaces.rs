// SPDX-License-Identifier: Apache-2.0
use crate::{
    native::{frame::NativeFrame, platform::ExportFileCheck},
    Error, Result,
};
use fe11_sys::*;
use libloading::Library;
mod collection;

/// Explicit choice of provider-default or exact standard-interface selection.
/// Native errors never trigger a retry through another interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InterfaceSelection {
    /// Ask for the provider's default interface, as cryptoki does. An absent
    /// C_GetInterface export, a successful null interface, or a table below
    /// version 3 selects C_GetFunctionList. A native error never triggers retry.
    /// Future 3.x tables use only the known 3.2 prefix; major 4+ is unsupported.
    ProviderDefault,
    /// Published 2.20 historical table, accessed through C_GetFunctionList.
    Legacy220,
    /// Archived 2.30 draft table. This is not a published standard edition.
    Legacy230Draft,
    /// Historical C_GetFunctionList, required to return a 2.40 table.
    Legacy240,
    /// Standard named interface, selected before initialization.
    Standard {
        /// Exactly 2.40, 3.0, 3.1 or 3.2; other versions are refused locally.
        version: (u8, u8),
        /// Required standard interface flags. This API does not permit fork use.
        required_flags: u64,
    },
}

/// Caller-selected allocation and retry ceilings for explicit interface discovery.
/// These do not apply to ProviderDefault, which does not enumerate interfaces.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InterfaceDiscoveryLimits {
    /// Maximum number of CK_INTERFACE entries allocated for one fill.
    pub interfaces: usize,
    /// Maximum count/fill pairs, including the first pair.
    pub attempts: usize,
}
impl InterfaceSelection {
    pub(crate) fn validate(self) -> Result<()> {
        if let Self::Standard {
            version,
            required_flags,
        } = self
        {
            if !matches!(version, (2, 40) | (3, 0) | (3, 1) | (3, 2))
                || required_flags & !(CKF_INTERFACE_FORK_SAFE as u64) != 0
            {
                return Err(Error::Rejected(crate::RejectionReason::NativeInterfaces(
                    crate::NativeInterfacesRejection::UnsupportedInterfaceSelection,
                )));
            }
        }
        Ok(())
    }
}

// SAFETY: each named field is read from its exact, prefix-checked OASIS layout.
// No larger table is reinterpreted. Field values enter an aligned Rust view,
// not another ABI allocation; this also avoids borrowing packed Windows fields.
macro_rules! common_table {
    ($t:expr) => {{
        let t = $t;
        CommonFunctions {
            version: $crate::interfaces::common::TableVersion {
                major: t.version.major,
                minor: t.version.minor,
            },
            C_Initialize: t.C_Initialize,
            C_Finalize: t.C_Finalize,
            C_GetInfo: t.C_GetInfo,
            C_GetSlotList: t.C_GetSlotList,
            C_GetSlotInfo: t.C_GetSlotInfo,
            C_GetTokenInfo: t.C_GetTokenInfo,
            C_GetMechanismList: t.C_GetMechanismList,
            C_GetMechanismInfo: t.C_GetMechanismInfo,
            C_InitToken: t.C_InitToken,
            C_InitPIN: t.C_InitPIN,
            C_SetPIN: t.C_SetPIN,
            C_OpenSession: t.C_OpenSession,
            C_CloseSession: t.C_CloseSession,
            C_CloseAllSessions: t.C_CloseAllSessions,
            C_GetSessionInfo: t.C_GetSessionInfo,
            C_GetOperationState: t.C_GetOperationState,
            C_SetOperationState: t.C_SetOperationState,
            C_Login: t.C_Login,
            C_Logout: t.C_Logout,
            C_CreateObject: t.C_CreateObject,
            C_CopyObject: t.C_CopyObject,
            C_DestroyObject: t.C_DestroyObject,
            C_GetObjectSize: t.C_GetObjectSize,
            C_GetAttributeValue: t.C_GetAttributeValue,
            C_SetAttributeValue: t.C_SetAttributeValue,
            C_FindObjectsInit: t.C_FindObjectsInit,
            C_FindObjects: t.C_FindObjects,
            C_FindObjectsFinal: t.C_FindObjectsFinal,
            C_EncryptInit: t.C_EncryptInit,
            C_Encrypt: t.C_Encrypt,
            C_EncryptUpdate: t.C_EncryptUpdate,
            C_EncryptFinal: t.C_EncryptFinal,
            C_DecryptInit: t.C_DecryptInit,
            C_Decrypt: t.C_Decrypt,
            C_DecryptUpdate: t.C_DecryptUpdate,
            C_DecryptFinal: t.C_DecryptFinal,
            C_DigestInit: t.C_DigestInit,
            C_Digest: t.C_Digest,
            C_DigestUpdate: t.C_DigestUpdate,
            C_DigestKey: t.C_DigestKey,
            C_DigestFinal: t.C_DigestFinal,
            C_SignInit: t.C_SignInit,
            C_Sign: t.C_Sign,
            C_SignUpdate: t.C_SignUpdate,
            C_SignFinal: t.C_SignFinal,
            C_SignRecoverInit: t.C_SignRecoverInit,
            C_SignRecover: t.C_SignRecover,
            C_VerifyInit: t.C_VerifyInit,
            C_Verify: t.C_Verify,
            C_VerifyUpdate: t.C_VerifyUpdate,
            C_VerifyFinal: t.C_VerifyFinal,
            C_VerifyRecoverInit: t.C_VerifyRecoverInit,
            C_VerifyRecover: t.C_VerifyRecover,
            C_DigestEncryptUpdate: t.C_DigestEncryptUpdate,
            C_DecryptDigestUpdate: t.C_DecryptDigestUpdate,
            C_SignEncryptUpdate: t.C_SignEncryptUpdate,
            C_DecryptVerifyUpdate: t.C_DecryptVerifyUpdate,
            C_GenerateKey: t.C_GenerateKey,
            C_GenerateKeyPair: t.C_GenerateKeyPair,
            C_WrapKey: t.C_WrapKey,
            C_UnwrapKey: t.C_UnwrapKey,
            C_DeriveKey: t.C_DeriveKey,
            C_SeedRandom: t.C_SeedRandom,
            C_GenerateRandom: t.C_GenerateRandom,
            C_GetFunctionStatus: t.C_GetFunctionStatus,
            C_CancelFunction: t.C_CancelFunction,
            C_WaitForSlotEvent: t.C_WaitForSlotEvent,
        }
    }};
}

// The provider is trusted native code. This check bounds reads of its C string;
// it cannot make an arbitrary malicious native pointer safe.
unsafe fn standard_name(p: *const CK_UTF8CHAR) -> Result<bool> {
    if p.is_null() {
        return Err(Error::Rejected(crate::RejectionReason::NativeInterfaces(
            crate::NativeInterfacesRejection::NullInterfaceName,
        )));
    }
    let expected = b"PKCS 11\0";
    for (i, expected_byte) in expected.iter().enumerate() {
        // SAFETY: the trusted provider owns a null-terminated name. Stop at
        // the first mismatch (including an earlier NUL); never scan an
        // unrelated vendor name, nor read past the selected name's terminator.
        let byte = unsafe { *p.add(i) };
        if byte != *expected_byte {
            return Ok(false);
        }
    }
    Ok(true)
}
unsafe fn prefix(interface: &CK_INTERFACE) -> Result<(u8, u8)> {
    if interface.pFunctionList.is_null() {
        return Err(Error::Rejected(crate::RejectionReason::NativeInterfaces(
            crate::NativeInterfacesRejection::NullInterfaceTable,
        )));
    }
    // SAFETY: every conforming table starts with the two-byte CK_VERSION.
    let v = unsafe { std::ptr::read_unaligned(interface.pFunctionList.cast::<CK_VERSION>()) };
    Ok((v.major, v.minor))
}

#[derive(Clone, Copy)]
pub(crate) struct AuthenticatedKeyTransportFunctions {
    pub wrap: CK_C_WrapKeyAuthenticated,
    pub unwrap: CK_C_UnwrapKeyAuthenticated,
}

#[derive(Clone, Copy)]
pub(crate) struct MessageFunctions {
    pub encrypt_init: CK_C_MessageEncryptInit,
    pub encrypt_message: CK_C_EncryptMessage,
    pub encrypt_begin: CK_C_EncryptMessageBegin,
    pub encrypt_next: CK_C_EncryptMessageNext,
    pub encrypt_finish: CK_C_MessageEncryptFinal,
    pub decrypt_init: CK_C_MessageDecryptInit,
    pub decrypt_message: CK_C_DecryptMessage,
    pub decrypt_begin: CK_C_DecryptMessageBegin,
    pub decrypt_next: CK_C_DecryptMessageNext,
    pub decrypt_finish: CK_C_MessageDecryptFinal,
    pub sign_init: CK_C_MessageSignInit,
    pub sign_message: CK_C_SignMessage,
    pub sign_begin: CK_C_SignMessageBegin,
    pub sign_next: CK_C_SignMessageNext,
    pub sign_finish: CK_C_MessageSignFinal,
    pub verify_init: CK_C_MessageVerifyInit,
    pub verify_message: CK_C_VerifyMessage,
    pub verify_begin: CK_C_VerifyMessageBegin,
    pub verify_next: CK_C_VerifyMessageNext,
    pub verify_finish: CK_C_MessageVerifyFinal,
    pub cancel: CK_C_SessionCancel,
}

#[derive(Clone, Copy)]
pub(crate) struct KemFunctions {
    pub encapsulate: CK_C_EncapsulateKey,
    pub decapsulate: CK_C_DecapsulateKey,
}

#[derive(Clone, Copy)]
pub(crate) struct VerifySignatureFunctions {
    pub init: CK_C_VerifySignatureInit,
    pub single: CK_C_VerifySignature,
    pub update: CK_C_VerifySignatureUpdate,
    pub finish: CK_C_VerifySignatureFinal,
}

#[derive(Clone, Copy)]
pub(crate) struct AsyncFunctions {
    pub complete: CK_C_AsyncComplete,
    pub get_id: CK_C_AsyncGetID,
    pub join: CK_C_AsyncJoin,
    pub validation: CK_C_GetSessionValidationFlags,
}

// Each expansion reads only fields of the exact checked 3.x native table.
macro_rules! message_functions {
    ($t:expr) => {
        MessageFunctions {
            encrypt_init: $t.C_MessageEncryptInit,
            encrypt_message: $t.C_EncryptMessage,
            encrypt_begin: $t.C_EncryptMessageBegin,
            encrypt_next: $t.C_EncryptMessageNext,
            encrypt_finish: $t.C_MessageEncryptFinal,
            decrypt_init: $t.C_MessageDecryptInit,
            decrypt_message: $t.C_DecryptMessage,
            decrypt_begin: $t.C_DecryptMessageBegin,
            decrypt_next: $t.C_DecryptMessageNext,
            decrypt_finish: $t.C_MessageDecryptFinal,
            sign_init: $t.C_MessageSignInit,
            sign_message: $t.C_SignMessage,
            sign_begin: $t.C_SignMessageBegin,
            sign_next: $t.C_SignMessageNext,
            sign_finish: $t.C_MessageSignFinal,
            verify_init: $t.C_MessageVerifyInit,
            verify_message: $t.C_VerifyMessage,
            verify_begin: $t.C_VerifyMessageBegin,
            verify_next: $t.C_VerifyMessageNext,
            verify_finish: $t.C_MessageVerifyFinal,
            cancel: $t.C_SessionCancel,
        }
    };
}

mod catalog;
mod inventory;
pub(crate) use inventory::observe as observe_inventory;
pub use inventory::{InterfaceDescriptor, InterfaceInventory, InterfaceInventoryLimits};
mod common;
pub(crate) use common::CommonFunctions;
mod table;
pub use catalog::{FunctionCatalog, FunctionPresence};
pub(crate) use table::SelectedTable;

#[derive(Default)]
pub(crate) struct SelectionCalls {
    pub list: u64,
    pub interfaces: u64,
    pub interface: u64,
}

pub(crate) fn record_selection(counter: &mut u64) -> Result<()> {
    *counter =
        counter
            .checked_add(1)
            .ok_or(Error::Rejected(crate::RejectionReason::NativeInterfaces(
                crate::NativeInterfacesRejection::CounterExhausted,
            )))?;
    Ok(())
}

struct InterfaceListFrame {
    count: CK_ULONG,
    entries: Vec<CK_INTERFACE>,
}

struct InterfaceRequestFrame {
    name: [u8; 8],
    version: CK_VERSION,
    selected: *mut CK_INTERFACE,
}

pub(crate) fn select(
    library: &Library,
    export_check: ExportFileCheck,
    version: (u8, u8),
    required_flags: u64,
    limits: InterfaceDiscoveryLimits,
    calls: &mut SelectionCalls,
    image_uncertain: &std::cell::Cell<bool>,
) -> Result<(SelectedTable, u64)> {
    InterfaceSelection::Standard {
        version,
        required_flags,
    }
    .validate()?;
    // SAFETY: exact exported OASIS function signatures, library retained by Native.
    let list = unsafe {
        library.get::<unsafe extern "C" fn(*mut CK_INTERFACE, *mut CK_ULONG) -> CK_RV>(
            b"C_GetInterfaceList\0",
        )
    }
    .map_err(|_| {
        Error::Rejected(crate::RejectionReason::NativeInterfaces(
            crate::NativeInterfacesRejection::InterfaceListExport,
        ))
    })?;
    // SAFETY: same ownership and exact OASIS exported signature.
    let get = unsafe {
        library.get::<unsafe extern "C" fn(
            *mut CK_UTF8CHAR,
            *mut CK_VERSION,
            *mut *mut CK_INTERFACE,
            CK_FLAGS,
        ) -> CK_RV>(b"C_GetInterface\0")
    }
    .map_err(|_| {
        Error::Rejected(crate::RejectionReason::NativeInterfaces(
            crate::NativeInterfacesRejection::InterfaceSelectionExport,
        ))
    })?;
    export_check.check(*list as usize)?;
    export_check.check(*get as usize)?;
    let matches = collection::collect(
        *list,
        limits.interfaces,
        limits.attempts,
        image_uncertain,
        || record_selection(&mut calls.interfaces),
        |interfaces| {
            let mut matches = Vec::new();
            matches.try_reserve_exact(interfaces.len()).map_err(|_| {
                Error::Rejected(crate::RejectionReason::NativeInterfaces(
                    crate::NativeInterfacesRejection::InterfaceAllocation,
                ))
            })?;
            for interface in interfaces {
                // SAFETY: the collector owns this returned descriptor span and
                // the live provider retains the referenced name/table storage.
                if !unsafe { standard_name(interface.pInterfaceName)? } {
                    continue;
                }
                // SAFETY: only a named standard table promises the version prefix.
                let actual = unsafe { prefix(interface)? };
                if actual == version && (interface.flags as u64 & required_flags) == required_flags
                {
                    // Retain only the scalar identity used after selection.
                    // CK_INTERFACE is not Copy; the native table remains owned
                    // by the live image, not by this temporary descriptor list.
                    matches.push((interface.pFunctionList, interface.flags));
                }
            }
            if matches.is_empty() {
                return Err(Error::Rejected(crate::RejectionReason::NativeInterfaces(
                    crate::NativeInterfacesRejection::RequestedInterfaceAbsent,
                )));
            }
            Ok(matches)
        },
    )?;
    let mut request = NativeFrame::new(InterfaceRequestFrame {
        name: *b"PKCS 11\0",
        version: CK_VERSION {
            major: version.0,
            minor: version.1,
        },
        selected: std::ptr::null_mut(),
    })?;
    record_selection(&mut calls.interface)?;
    // SAFETY: owned name/version/output pointer remain live; flags already bounded.
    let body = &mut *request;
    let rv = unsafe {
        get(
            body.name.as_mut_ptr(),
            &mut body.version,
            &mut body.selected,
            required_flags as _,
        )
    };
    request.loading_result(rv, "C_GetInterface", image_uncertain, false)?;
    if request.selected.is_null() {
        return Err(Error::Rejected(crate::RejectionReason::NativeInterfaces(
            crate::NativeInterfacesRejection::NullSelectedInterface,
        )));
    }
    // SAFETY: conforming provider returns one complete CK_INTERFACE descriptor.
    let selected = unsafe { std::ptr::read_unaligned(request.selected) };
    if !unsafe { standard_name(selected.pInterfaceName)? }
        || unsafe { prefix(&selected)? } != version
        || (selected.flags as u64 & required_flags) != required_flags
        || !matches
            .iter()
            .any(|(table, flags)| *table == selected.pFunctionList && *flags == selected.flags)
    {
        return Err(Error::Rejected(crate::RejectionReason::NativeInterfaces(
            crate::NativeInterfacesRejection::IncoherentSelectedInterface,
        )));
    }
    // SAFETY: exact version prefix was checked above, then read only that layout.
    let table = unsafe { table_from_interface(&selected)? };
    Ok((table, selected.flags as u64))
}

/// The caller retains the library and trusts its announced table version.
/// This checks a version prefix, not the allocation length of a hostile module.
unsafe fn table_from_interface(selected: &CK_INTERFACE) -> Result<SelectedTable> {
    // SAFETY: the caller guarantees a live native interface descriptor.
    let version = unsafe { prefix(selected)? };
    // SAFETY: under the native-module trust boundary, the announced version
    // guarantees the respective table. For future 3.x only the known prefix
    // is copied; no future suffix is accessed.
    unsafe {
        match version {
            (2, 40) => Ok(SelectedTable::V240(std::ptr::read_unaligned(
                selected.pFunctionList.cast::<CK_FUNCTION_LIST>(),
            ))),
            (3, 0 | 1) => Ok(SelectedTable::V30Or31(std::ptr::read_unaligned(
                selected.pFunctionList.cast::<CK_FUNCTION_LIST_3_0>(),
            ))),
            (3, 2..) => Ok(SelectedTable::V32(std::ptr::read_unaligned(
                selected.pFunctionList.cast::<CK_FUNCTION_LIST_3_2>(),
            ))),
            _ => Err(Error::Unsupported(
                crate::UnsupportedReason::NativeInterfaces(
                    crate::NativeInterfacesUnsupported::FunctionTableVersion,
                ),
            )),
        }
    }
}

pub(crate) fn select_default(
    library: &Library,
    export_check: ExportFileCheck,
    calls: &mut SelectionCalls,
    image_uncertain: &std::cell::Cell<bool>,
) -> Result<Option<(SelectedTable, u64)>> {
    // SAFETY: OASIS export signature; Native retains the library.
    let get = match unsafe {
        library.get::<unsafe extern "C" fn(
            *mut CK_UTF8CHAR,
            *mut CK_VERSION,
            *mut *mut CK_INTERFACE,
            CK_FLAGS,
        ) -> CK_RV>(b"C_GetInterface\0")
    } {
        Ok(get) => get,
        Err(_) => return Ok(None),
    };
    export_check.check(*get as usize)?;
    let mut chosen = NativeFrame::new(std::ptr::null_mut::<CK_INTERFACE>())?;
    record_selection(&mut calls.interface)?;
    // SAFETY: null selectors request the provider default; chosen is a live slot.
    let rv = unsafe { get(std::ptr::null_mut(), std::ptr::null_mut(), &mut *chosen, 0) };
    chosen.loading_result(rv, "C_GetInterface", image_uncertain, false)?;
    if (*chosen).is_null() {
        return Ok(None);
    }
    // SAFETY: the trusted provider returns a live CK_INTERFACE descriptor.
    let selected = unsafe { std::ptr::read_unaligned(*chosen) };
    // Do not inspect or impose a standard name in this explicitly chosen mode.
    if unsafe { prefix(&selected)? }.0 < 3 {
        return Ok(None);
    }
    // SAFETY: selected is owned by the retained native library.
    Ok(Some((
        unsafe { table_from_interface(&selected)? },
        selected.flags as u64,
    )))
}
