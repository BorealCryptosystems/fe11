// SPDX-License-Identifier: Apache-2.0
//! Compare complete mechanism metadata with the selected, frozen recipe catalogue.
//! These direct calls qualify test prerequisites and never count as Fe11 cases.
use super::{
    configuration::Configuration,
    native_support::{required, status, verify_image},
    outcome::Failure,
};
use crate::report::{Observation, Phase, Producer, Report};
use fe11_sys::*;
use std::{
    collections::BTreeMap,
    fs,
    io::{self, Write},
    path::Path,
    ptr,
};

type GetLegacy = unsafe extern "C" fn(CK_FUNCTION_LIST_PTR_PTR) -> CK_RV;
type Metadata = BTreeMap<CK_MECHANISM_TYPE, (CK_ULONG, CK_ULONG, CK_FLAGS)>;

fn catalogue(path: &Path) -> Result<Metadata, Failure> {
    if fs::metadata(path)
        .map_err(|_| Failure::Input("catalogue_metadata"))?
        .len()
        > 65536
    {
        return Err(Failure::Input("catalogue_size"));
    }
    let data = fs::read_to_string(path).map_err(|_| Failure::Input("catalogue_read"))?;
    let mut result = BTreeMap::new();
    for line in data.lines().filter(|line| !line.starts_with('#')) {
        let values: Vec<CK_ULONG> = line
            .split('\t')
            .map(str::parse)
            .collect::<Result<_, _>>()
            .map_err(|_| Failure::Input("catalogue_number"))?;
        if values.len() != 4 || values[1] > values[2] || result.len() >= 512 {
            return Err(Failure::Input("catalogue_row"));
        }
        if result
            .insert(values[0], (values[1], values[2], values[3]))
            .is_some()
        {
            return Err(Failure::Input("catalogue_duplicate"));
        }
    }
    if result.is_empty() {
        return Err(Failure::Input("catalogue_empty"));
    }
    Ok(result)
}

pub struct Outcome {
    pub body: Result<(), Failure>,
    pub cleanup: Vec<Failure>,
}

pub fn run<W: Write>(
    config: &Configuration,
    expected: &Path,
    report: &mut Report<W>,
) -> io::Result<Outcome> {
    let mut image = None;
    let mut finalize = None;
    let mut initialize_attempted = false;
    let mut initialized = false;
    let mut observations = Metadata::new();
    let body = (|| -> Result<(), Failure> {
        let expected = catalogue(expected)?;
        verify_image(config)?;
        // SAFETY: the pinned provider is trusted native code; retain its lease
        // across every call and until successful finalization or process exit.
        image = Some(
            unsafe { libloading::Library::new(&config.module) }
                .map_err(|_| Failure::Input("catalogue_image_load"))?,
        );
        let image = image
            .as_ref()
            .ok_or(Failure::Input("catalogue_image_lease"))?;
        // SAFETY: exact PKCS#11 export prototype and retained image.
        let get: libloading::Symbol<'_, GetLegacy> =
            unsafe { image.get(b"C_GetFunctionList\0") }
                .map_err(|_| Failure::Input("catalogue_export"))?;
        let mut pointer: CK_FUNCTION_LIST_PTR = ptr::null_mut();
        // SAFETY: writable output pointer, read only after CKR_OK and null check.
        status("C_GetFunctionList", unsafe { get(&mut pointer) })?;
        if pointer.is_null() {
            return Err(Failure::Oracle("catalogue_null_table"));
        }
        // SAFETY: successful legacy export defines the complete prefix table.
        let table = unsafe { &*pointer };
        finalize = Some(required(table.C_Finalize)?);
        let initialize = required(table.C_Initialize)?;
        let mut args = CK_C_INITIALIZE_ARGS {
            CreateMutex: None,
            DestroyMutex: None,
            LockMutex: None,
            UnlockMutex: None,
            flags: CKF_OS_LOCKING_OK,
            pReserved: ptr::null_mut(),
        };
        initialize_attempted = true;
        // SAFETY: synchronous arguments contain no callbacks or borrowed state.
        status("C_Initialize", unsafe {
            initialize((&mut args as *mut CK_C_INITIALIZE_ARGS).cast())
        })?;
        initialized = true;
        let get_info = required(table.C_GetInfo)?;
        let mut info = std::mem::MaybeUninit::<CK_INFO>::uninit();
        // SAFETY: full writable output structure; no read occurs before CKR_OK.
        status("C_GetInfo", unsafe { get_info(info.as_mut_ptr()) })?;
        // SAFETY: successful C_GetInfo defines all metadata fields.
        let info = unsafe { info.assume_init() };
        if (info.cryptokiVersion.major, info.cryptokiVersion.minor) != (3, 2) {
            return Err(Failure::Oracle("catalogue_info_version"));
        }
        let get_slots = required(table.C_GetSlotList)?;
        let mut slots = [0; 64];
        let mut count = slots.len() as CK_ULONG;
        // SAFETY: storage capacity and writable count correspond exactly.
        status("C_GetSlotList", unsafe {
            get_slots(CK_TRUE, slots.as_mut_ptr(), &mut count)
        })?;
        let count = usize::try_from(count).map_err(|_| Failure::Oracle("catalogue_slot_count"))?;
        if count == 0 || count > slots.len() {
            return Err(Failure::Oracle("catalogue_slot_count"));
        }
        let token = required(table.C_GetTokenInfo)?;
        let mut selected = None;
        for slot in &slots[..count] {
            let mut token_info = std::mem::MaybeUninit::<CK_TOKEN_INFO>::uninit();
            // SAFETY: real slot identifier and writable output; read only on success.
            status("C_GetTokenInfo", unsafe {
                token(*slot, token_info.as_mut_ptr())
            })?;
            // SAFETY: successful call initialized the structure.
            let token_info = unsafe { token_info.assume_init() };
            let end = token_info
                .label
                .iter()
                .rposition(|byte| *byte != b' ')
                .map_or(0, |last| last + 1);
            if &token_info.label[..end] == config.label.as_bytes()
                && selected.replace(*slot).is_some()
            {
                return Err(Failure::Oracle("catalogue_token_ambiguous"));
            }
        }
        let slot = selected.ok_or(Failure::Oracle("catalogue_token_absent"))?;
        let list = required(table.C_GetMechanismList)?;
        let get = required(table.C_GetMechanismInfo)?;
        let mut mechanisms = [0; 512];
        let mut count = mechanisms.len() as CK_ULONG;
        // SAFETY: bounded output storage and writable count have matching capacity.
        status("C_GetMechanismList", unsafe {
            list(slot, mechanisms.as_mut_ptr(), &mut count)
        })?;
        let count =
            usize::try_from(count).map_err(|_| Failure::Oracle("catalogue_mechanism_count"))?;
        if count > mechanisms.len() {
            return Err(Failure::Oracle("catalogue_mechanism_count"));
        }
        for mechanism in &mechanisms[..count] {
            let mut info = std::mem::MaybeUninit::<CK_MECHANISM_INFO>::uninit();
            // SAFETY: advertised mechanism and complete writable output structure.
            status("C_GetMechanismInfo", unsafe {
                get(slot, *mechanism, info.as_mut_ptr())
            })?;
            // SAFETY: CKR_OK defines all three metadata fields.
            let info = unsafe { info.assume_init() };
            if observations
                .insert(
                    *mechanism,
                    (info.ulMinKeySize, info.ulMaxKeySize, info.flags),
                )
                .is_some()
            {
                return Err(Failure::Oracle("catalogue_native_duplicate"));
            }
        }
        if observations != expected {
            return Err(Failure::Oracle("catalogue_exact_metadata"));
        }
        Ok(())
    })();
    let mut cleanup = Vec::new();
    if initialized {
        if let Some(finalize) = finalize {
            // SAFETY: this isolated process owns initialization; reserved is NULL.
            if let Err(error) = status("C_Finalize", unsafe { finalize(ptr::null_mut()) }) {
                cleanup.push(error);
            }
        }
    }
    if cleanup.is_empty() && (!initialize_attempted || initialized) {
        drop(image);
    } else {
        std::mem::forget(image);
    }
    for (mechanism, (minimum, maximum, flags)) in observations {
        for (name, value) in [
            ("mechanism", mechanism),
            ("minimum", minimum),
            ("maximum", maximum),
            ("flags", flags),
        ] {
            report.observation(
                Phase::Setup,
                name,
                Producer::Native,
                Observation::Number(value as u64),
            )?;
        }
    }
    Ok(Outcome { body, cleanup })
}
