// SPDX-License-Identifier: Apache-2.0
//! Private owner for direct, synchronous recipe probes on a fresh isolated token.
//! The safe Fe11 test routes do not use this owner or expose its native handles.
use super::{
    configuration::Configuration,
    native_support::{required, status, verify_image},
    outcome::Failure,
};
use fe11_sys::*;
use std::{
    ffi::CStr,
    ptr::{self, NonNull},
};

type GetInterface =
    unsafe extern "C" fn(CK_UTF8CHAR_PTR, CK_VERSION_PTR, CK_INTERFACE_PTR_PTR, CK_FLAGS) -> CK_RV;

pub(super) struct ProbeSession {
    image: Option<libloading::Library>,
    table: Option<NonNull<CK_FUNCTION_LIST_3_2>>,
    initialized: bool,
    initialize_attempted: bool,
    session: Option<CK_SESSION_HANDLE>,
    logged_in: bool,
    objects: Vec<CK_OBJECT_HANDLE>,
}

impl ProbeSession {
    pub fn new() -> Self {
        Self {
            image: None,
            table: None,
            initialized: false,
            initialize_attempted: false,
            session: None,
            logged_in: false,
            objects: Vec::new(),
        }
    }

    pub fn functions(&self) -> Result<&CK_FUNCTION_LIST_3_2, Failure> {
        let table = self.table.ok_or(Failure::Input("probe_table_not_loaded"))?;
        if self.image.is_none() {
            return Err(Failure::Input("probe_image_not_retained"));
        }
        // SAFETY: open() checks the descriptor's exact version before retaining
        // the pointer; its image lease is held for the entire reference lifetime.
        Ok(unsafe { table.as_ref() })
    }

    pub fn handle(&self) -> Result<CK_SESSION_HANDLE, Failure> {
        self.session.ok_or(Failure::Input("probe_session_not_open"))
    }

    pub fn retain(&mut self, handle: CK_OBJECT_HANDLE) -> Result<(), Failure> {
        if handle == CK_INVALID_HANDLE || self.objects.contains(&handle) {
            return Err(Failure::Oracle("probe_object_handle"));
        }
        self.objects.push(handle);
        Ok(())
    }

    pub fn open(&mut self, config: &Configuration, pin: &mut [u8]) -> Result<(), Failure> {
        if self.image.is_some() {
            return Err(Failure::Input("probe_already_loaded"));
        }
        verify_image(config)?;
        // SAFETY: explicitly trusted image whose bytes match the pinned recipe.
        // Drop retains this lease if setup or finalization cannot be proved complete.
        self.image = Some(
            unsafe { libloading::Library::new(&config.module) }
                .map_err(|_| Failure::Input("probe_image_load"))?,
        );
        let image = self
            .image
            .as_ref()
            .ok_or(Failure::Input("probe_image_lease"))?;
        // SAFETY: exact public PKCS#11 export prototype within the image lease.
        let get: libloading::Symbol<'_, GetInterface> =
            unsafe { image.get(b"C_GetInterface\0") }
                .map_err(|_| Failure::Input("probe_interface_export"))?;
        let mut interface = ptr::null_mut();
        let mut version = CK_VERSION { major: 3, minor: 2 };
        let mut name = *b"PKCS 11\0";
        // SAFETY: terminated name, readable version, writable descriptor output.
        status("C_GetInterface", unsafe {
            get(name.as_mut_ptr(), &mut version, &mut interface, 0)
        })?;
        if interface.is_null() {
            return Err(Failure::Oracle("probe_interface_null"));
        }
        // SAFETY: successful export returns a borrowed descriptor owned by image.
        let interface = unsafe { &*interface };
        if interface.pFunctionList.is_null() || interface.pInterfaceName.is_null() {
            return Err(Failure::Oracle("probe_interface_fields"));
        }
        // SAFETY: descriptor name is terminated; every table starts with CK_VERSION.
        let name = unsafe { CStr::from_ptr(interface.pInterfaceName.cast()) };
        let version = unsafe { ptr::read(interface.pFunctionList.cast::<CK_VERSION>()) };
        if name.to_bytes() != b"PKCS 11" || (version.major, version.minor) != (3, 2) {
            return Err(Failure::Oracle("probe_interface_identity"));
        }
        self.table = NonNull::new(interface.pFunctionList.cast());
        let functions = self.functions()?;
        // Acquire every cleanup entry before any native state.
        required(functions.C_DestroyObject)?;
        required(functions.C_Logout)?;
        required(functions.C_CloseSession)?;
        required(functions.C_Finalize)?;
        let initialize = required(functions.C_Initialize)?;
        let mut args = CK_C_INITIALIZE_ARGS {
            CreateMutex: None,
            DestroyMutex: None,
            LockMutex: None,
            UnlockMutex: None,
            flags: CKF_OS_LOCKING_OK,
            pReserved: ptr::null_mut(),
        };
        self.initialize_attempted = true;
        // SAFETY: synchronous initialization with OS locking and no callbacks.
        status("C_Initialize", unsafe {
            initialize((&mut args as *mut CK_C_INITIALIZE_ARGS).cast())
        })?;
        self.initialized = true;
        let get_slots = required(self.functions()?.C_GetSlotList)?;
        let get_token = required(self.functions()?.C_GetTokenInfo)?;
        let mut slots = [0; 64];
        let mut count = slots.len() as CK_ULONG;
        // SAFETY: declared output capacity equals allocated storage.
        status("C_GetSlotList", unsafe {
            get_slots(CK_TRUE, slots.as_mut_ptr(), &mut count)
        })?;
        let count = usize::try_from(count).map_err(|_| Failure::Oracle("probe_slot_count"))?;
        if count > slots.len() {
            return Err(Failure::Oracle("probe_slot_count"));
        }
        let mut selected = None;
        for slot in &slots[..count] {
            let mut info = std::mem::MaybeUninit::<CK_TOKEN_INFO>::uninit();
            // SAFETY: complete writable output, consumed only after CKR_OK.
            status("C_GetTokenInfo", unsafe {
                get_token(*slot, info.as_mut_ptr())
            })?;
            // SAFETY: CKR_OK defines the token metadata.
            let info = unsafe { info.assume_init() };
            let end = info
                .label
                .iter()
                .rposition(|b| *b != b' ')
                .map_or(0, |n| n + 1);
            if &info.label[..end] == config.label.as_bytes() && selected.replace(*slot).is_some() {
                return Err(Failure::Oracle("probe_token_ambiguous"));
            }
        }
        let slot = selected.ok_or(Failure::Input("probe_token_absent"))?;
        let open = required(self.functions()?.C_OpenSession)?;
        let mut handle = CK_INVALID_HANDLE;
        // SAFETY: unique live token, writable output, no callback or application data.
        status("C_OpenSession", unsafe {
            open(
                slot,
                CKF_SERIAL_SESSION | CKF_RW_SESSION,
                ptr::null_mut(),
                None,
                &mut handle,
            )
        })?;
        self.session = Some(handle);
        let login = required(self.functions()?.C_Login)?;
        let length =
            CK_ULONG::try_from(pin.len()).map_err(|_| Failure::Input("probe_pin_length"))?;
        // SAFETY: bounded PIN storage stays alive throughout synchronous login.
        status("C_Login", unsafe {
            login(handle, CKU_USER, pin.as_mut_ptr(), length)
        })?;
        self.logged_in = true;
        Ok(())
    }

    pub fn close(&mut self) -> Vec<Failure> {
        let mut errors = Vec::new();
        if let Some(handle) = self.session {
            while let Some(object) = self.objects.pop() {
                let result = self
                    .functions()
                    .and_then(|f| required(f.C_DestroyObject))
                    .and_then(|destroy| {
                        // SAFETY: this probe owns every recorded session object.
                        status("C_DestroyObject", unsafe { destroy(handle, object) })
                    });
                if let Err(error) = result {
                    errors.push(error);
                }
            }
            if self.logged_in {
                let result = self
                    .functions()
                    .and_then(|f| required(f.C_Logout))
                    .and_then(|logout| {
                        // SAFETY: this probe successfully logged into this live session.
                        status("C_Logout", unsafe { logout(handle) })
                    });
                if let Err(error) = result {
                    errors.push(error);
                }
                self.logged_in = false;
            }
            let result = self
                .functions()
                .and_then(|f| required(f.C_CloseSession))
                .and_then(|close| {
                    // SAFETY: owned session; no other thread or outstanding asynchronous call.
                    status("C_CloseSession", unsafe { close(handle) })
                });
            if let Err(error) = result {
                errors.push(error);
            }
            self.session = None;
        }
        if self.initialized {
            let result = self
                .functions()
                .and_then(|f| required(f.C_Finalize))
                .and_then(|finalize| {
                    // SAFETY: this process owns successful initialization; reserved is NULL.
                    status("C_Finalize", unsafe { finalize(ptr::null_mut()) })
                });
            if let Err(error) = result {
                errors.push(error);
            } else {
                self.initialized = false;
                self.initialize_attempted = false;
            }
        }
        if errors.is_empty() && !self.initialize_attempted {
            self.table = None;
            drop(self.image.take());
        }
        errors
    }
}

impl Drop for ProbeSession {
    fn drop(&mut self) {
        // Reporting and native cleanup belong to close(), including failures.
        // On early unwind, the isolated process owns the remaining lifetime.
        if let Some(image) = self.image.take() {
            std::mem::forget(image);
        }
    }
}
