// SPDX-License-Identifier: Apache-2.0
//! Independent real-module digest control for the function-entry observer.
//!
//! This control uses the public PKCS#11 C ABI directly. Its result establishes
//! observer readiness, never Fe11 API coverage. The module is a trusted, pinned
//! build input; the control does not attempt to sandbox native code.
use super::native_support::{required, status, verify_image};
use super::{configuration::Configuration, outcome::Failure};
use crate::report::{Observation, Phase, Producer, Report};
use fe11_sys::*;
use std::{
    io::{self, Write},
    ptr,
};

type GetFunctionList = unsafe extern "C" fn(CK_FUNCTION_LIST_PTR_PTR) -> CK_RV;

pub struct Outcome {
    pub body: std::result::Result<(), Failure>,
    pub cleanup: Vec<Failure>,
}

pub fn run<W: Write>(config: &Configuration, report: &mut Report<W>) -> io::Result<Outcome> {
    let mut initialized = false;
    let mut session = None;
    let mut table: Option<&CK_FUNCTION_LIST> = None;
    let mut image = None;
    let body = (|| -> std::result::Result<(), Failure> {
        verify_image(config)?;
        // SAFETY: caller selects a trusted native image whose bytes were checked.
        // Its lease remains alive through all function calls and cleanup below.
        image = Some(
            unsafe { libloading::Library::new(&config.module) }
                .map_err(|_| Failure::Input("direct_image_load"))?,
        );
        let library = image.as_ref().expect("image assigned before symbol lookup");
        // SAFETY: exact PKCS#11 export signature; no function is called by lookup.
        let get: libloading::Symbol<'_, GetFunctionList> =
            unsafe { library.get(b"C_GetFunctionList\0") }
                .map_err(|_| Failure::Input("direct_function_list_export"))?;
        let mut pointer: CK_FUNCTION_LIST_PTR = ptr::null_mut();
        // SAFETY: writable output pointer; trusted provider owns the returned table.
        status("C_GetFunctionList", unsafe { get(&mut pointer) })?;
        if pointer.is_null() {
            return Err(Failure::Input("direct_null_table"));
        }
        // SAFETY: the provider's standard export promises the legacy table layout.
        // This reference does not escape the retained library lease.
        let functions = unsafe { &*pointer };
        if functions.version.major != 2 || functions.version.minor != 40 {
            return Err(Failure::Oracle("direct_legacy_table_version"));
        }
        table = Some(functions);
        // Establish cleanup entry points before acquiring any native runtime state.
        required(functions.C_Finalize)?;
        required(functions.C_CloseSession)?;
        let initialize = required(functions.C_Initialize)?;
        let mut options = CK_C_INITIALIZE_ARGS {
            CreateMutex: None,
            DestroyMutex: None,
            LockMutex: None,
            UnlockMutex: None,
            flags: CKF_OS_LOCKING_OK,
            pReserved: ptr::null_mut(),
        };
        // SAFETY: options and its null callbacks remain valid for this synchronous call.
        status("C_Initialize", unsafe {
            initialize((&mut options as *mut CK_C_INITIALIZE_ARGS).cast())
        })?;
        initialized = true;
        let slots_function = required(functions.C_GetSlotList)?;
        let mut slots = [0 as CK_SLOT_ID; 64];
        let mut count = slots.len() as CK_ULONG;
        // SAFETY: output storage covers the declared capacity and count is writable.
        status("C_GetSlotList", unsafe {
            slots_function(CK_TRUE, slots.as_mut_ptr(), &mut count)
        })?;
        let count = usize::try_from(count).map_err(|_| Failure::Input("direct_slot_count"))?;
        if count > slots.len() {
            return Err(Failure::Oracle("direct_slot_capacity"));
        }
        let token_info = required(functions.C_GetTokenInfo)?;
        let mut selected = None;
        for slot in &slots[..count] {
            let mut info = std::mem::MaybeUninit::<CK_TOKEN_INFO>::uninit();
            // SAFETY: a complete output structure is writable. Read only after CKR_OK.
            status("C_GetTokenInfo", unsafe {
                token_info(*slot, info.as_mut_ptr())
            })?;
            // SAFETY: CKR_OK defines every field in CK_TOKEN_INFO.
            let info = unsafe { info.assume_init() };
            let end = info
                .label
                .iter()
                .rposition(|byte| *byte != b' ')
                .map_or(0, |last| last + 1);
            if &info.label[..end] == config.label.as_bytes() {
                if selected.replace(*slot).is_some() {
                    return Err(Failure::Input("direct_token_ambiguous"));
                }
            }
        }
        let slot = selected.ok_or(Failure::Input("direct_token_absent"))?;
        let open = required(functions.C_OpenSession)?;
        let mut handle = CK_INVALID_HANDLE;
        // SAFETY: no notification callback; writable handle is read only on success.
        status("C_OpenSession", unsafe {
            open(slot, CKF_SERIAL_SESSION, ptr::null_mut(), None, &mut handle)
        })?;
        session = Some(handle);
        let init = required(functions.C_DigestInit)?;
        let update = required(functions.C_DigestUpdate)?;
        let final_call = required(functions.C_DigestFinal)?;
        let single = required(functions.C_Digest)?;
        let mut mechanism = CK_MECHANISM {
            mechanism: CKM_SHA256,
            pParameter: ptr::null_mut(),
            ulParameterLen: 0,
        };
        let mut message = *b"abc";
        // Published SHA-256("abc") answer, also included in RFC 6234 test data.
        let expected = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        let mut output = [0u8; 32];
        let mut length = output.len() as CK_ULONG;
        // SAFETY: all buffers are owned locals, sized as declared, and retained
        // through the synchronous Init/Update/Final sequence. No async flag is set.
        status("C_DigestInit", unsafe { init(handle, &mut mechanism) })?;
        status("C_DigestUpdate", unsafe {
            update(handle, message.as_mut_ptr(), message.len() as CK_ULONG)
        })?;
        status("C_DigestFinal", unsafe {
            final_call(handle, output.as_mut_ptr(), &mut length)
        })?;
        if length != 32 || output != expected {
            return Err(Failure::Oracle("direct_multipart_sha256_abc"));
        }
        output.fill(0);
        length = 32;
        // SAFETY: a new synchronous digest uses the same still-live owned buffers.
        status("C_DigestInit", unsafe { init(handle, &mut mechanism) })?;
        status("C_Digest", unsafe {
            single(
                handle,
                message.as_mut_ptr(),
                message.len() as CK_ULONG,
                output.as_mut_ptr(),
                &mut length,
            )
        })?;
        if length != 32 || output != expected {
            return Err(Failure::Oracle("direct_single_sha256_abc"));
        }
        Ok(())
    })();
    let mut cleanup = Vec::new();
    if let Some(functions) = table {
        if let Some(handle) = session {
            let result = required(functions.C_CloseSession).and_then(|close| {
                // SAFETY: handle belongs to this control; the image lease is alive.
                status("C_CloseSession", unsafe { close(handle) })
            });
            if let Err(error) = result {
                cleanup.push(error);
            }
        }
        if initialized {
            let result = required(functions.C_Finalize).and_then(|finalize| {
                // SAFETY: this process owns the successful initialization, reserved is NULL.
                status("C_Finalize", unsafe { finalize(ptr::null_mut()) })
            });
            if let Err(error) = result {
                cleanup.push(error);
            }
        }
    }
    report.observation(
        Phase::Body,
        "direct_control_is_not_fe11_coverage",
        Producer::Supervisor,
        Observation::Boolean(true),
    )?;
    // The table reference is no longer used when the native image is released.
    if cleanup.is_empty() {
        drop(image);
    } else {
        // This isolated control exits after reporting. Retain the image until
        // process teardown when native finalization was not established.
        std::mem::forget(image);
    }
    Ok(Outcome { body, cleanup })
}
