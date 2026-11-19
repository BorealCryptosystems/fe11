// SPDX-License-Identifier: Apache-2.0
//! Establish the real module's default/explicit interface equivalence before cases.
//!
//! This direct ABI probe records named slot equality, not addresses or structure
//! padding. It neither initializes the provider nor calls any discovered slot.
use super::{
    configuration::Configuration,
    native_support::{status, verify_image},
    outcome::Failure,
};
use crate::report::{Observation, Phase, Producer, Report};
use fe11_sys::*;
use std::{
    ffi::CStr,
    io::{self, Write},
    ptr,
};

type GetInterface =
    unsafe extern "C" fn(CK_UTF8CHAR_PTR, CK_VERSION_PTR, CK_INTERFACE_PTR_PTR, CK_FLAGS) -> CK_RV;
type GetInterfaces = unsafe extern "C" fn(CK_INTERFACE_PTR, CK_ULONG_PTR) -> CK_RV;
type GetLegacy = unsafe extern "C" fn(CK_FUNCTION_LIST_PTR_PTR) -> CK_RV;

/// The provider guarantees borrowed descriptors remain live with its image.
/// This helper checks version before reading a 3.2 suffix and cannot extend the
/// reference lifetime beyond the descriptor supplied by its caller.
unsafe fn table(interface: &CK_INTERFACE) -> Result<&CK_FUNCTION_LIST_3_2, Failure> {
    if interface.pInterfaceName.is_null() || interface.pFunctionList.is_null() {
        return Err(Failure::Oracle("discovery_null_descriptor_field"));
    }
    // SAFETY: the trusted PKCS#11 descriptor promises a terminated UTF-8 name.
    if unsafe { CStr::from_ptr(interface.pInterfaceName.cast()) }.to_bytes() != b"PKCS 11" {
        return Err(Failure::Oracle("discovery_interface_name"));
    }
    // SAFETY: every standard function table starts with a readable CK_VERSION.
    let version = unsafe { ptr::read(interface.pFunctionList.cast::<CK_VERSION>()) };
    if (version.major, version.minor) != (3, 2) {
        return Err(Failure::Oracle("discovery_interface_version"));
    }
    // SAFETY: the trusted module advertises exactly the 3.2 ABI, whose full table
    // remains borrowed while its owning image is retained by run().
    Ok(unsafe { &*interface.pFunctionList.cast::<CK_FUNCTION_LIST_3_2>() })
}

pub fn run<W: Write>(
    config: &Configuration,
    report: &mut Report<W>,
) -> io::Result<Result<(), Failure>> {
    let result = (|| -> Result<_, Failure> {
        verify_image(config)?;
        // SAFETY: a trusted recipe image with verified bytes; the lease below
        // outlives every borrowed descriptor and function address comparison.
        let image = unsafe { libloading::Library::new(&config.module) }
            .map_err(|_| Failure::Input("discovery_image_load"))?;
        // SAFETY: exact exported PKCS#11 signatures, kept within image lifetime.
        let get: libloading::Symbol<'_, GetInterface> =
            unsafe { image.get(b"C_GetInterface\0") }
                .map_err(|_| Failure::Input("discovery_get_interface_export"))?;
        let list: libloading::Symbol<'_, GetInterfaces> =
            unsafe { image.get(b"C_GetInterfaceList\0") }
                .map_err(|_| Failure::Input("discovery_list_export"))?;
        let legacy: libloading::Symbol<'_, GetLegacy> =
            unsafe { image.get(b"C_GetFunctionList\0") }
                .map_err(|_| Failure::Input("discovery_legacy_export"))?;
        let mut old: CK_FUNCTION_LIST_PTR = ptr::null_mut();
        // SAFETY: writable pointer output, no borrowed input buffers.
        status("C_GetFunctionList", unsafe { legacy(&mut old) })?;
        if old.is_null() {
            return Err(Failure::Oracle("discovery_legacy_null"));
        }
        // SAFETY: the export promises the complete legacy table on success.
        let old_version = unsafe { ((*old).version.major, (*old).version.minor) };
        if old_version != (2, 40) {
            return Err(Failure::Oracle("discovery_legacy_version"));
        }
        // The selected recipe declares one interface. A bounded output prevents
        // unknown module counts from driving allocations in this preparation.
        let mut descriptors = std::array::from_fn::<_, 16, _>(|_| CK_INTERFACE {
            pInterfaceName: ptr::null_mut(),
            pFunctionList: ptr::null_mut(),
            flags: 0,
        });
        let mut count = descriptors.len() as CK_ULONG;
        // SAFETY: array and writable count cover the announced capacity.
        status("C_GetInterfaceList", unsafe {
            list(descriptors.as_mut_ptr(), &mut count)
        })?;
        if count != 1 {
            return Err(Failure::Oracle("discovery_interface_count"));
        }
        // SAFETY: the only descriptor was defined by successful list output.
        let listed = unsafe { table(&descriptors[0]) }?;
        let mut default = ptr::null_mut();
        let mut explicit = ptr::null_mut();
        let mut name = *b"PKCS 11\0";
        let mut version = CK_VERSION { major: 3, minor: 2 };
        // SAFETY: optional default arguments are NULL; writable outputs and
        // explicit terminated name/version are retained through synchronous calls.
        status("C_GetInterface", unsafe {
            get(ptr::null_mut(), ptr::null_mut(), &mut default, 0)
        })?;
        status("C_GetInterface", unsafe {
            get(name.as_mut_ptr(), &mut version, &mut explicit, 0)
        })?;
        if default.is_null() || explicit.is_null() {
            return Err(Failure::Oracle("discovery_null_interface"));
        }
        // SAFETY: successful output descriptors are borrowed under the image lease.
        let default = unsafe { &*default };
        let explicit = unsafe { &*explicit };
        if default.flags != CKF_INTERFACE_FORK_SAFE
            || default.flags != explicit.flags
            || default.flags != descriptors[0].flags
        {
            return Err(Failure::Oracle("discovery_interface_flags"));
        }
        // SAFETY: descriptor checks precede all suffix access; lease still alive.
        let default_table = unsafe { table(default) }?;
        let explicit_table = unsafe { table(explicit) }?;
        let entries = super::interface_slots::compare(default_table, explicit_table, listed);
        Ok((entries, default.flags))
    })();
    match result {
        Err(error) => Ok(Err(error)),
        Ok((entries, flags)) => {
            let mut all_equal = true;
            for (name, equal, present) in entries {
                report.observation(
                    Phase::Setup,
                    name,
                    Producer::Native,
                    Observation::Boolean(equal && present),
                )?;
                all_equal &= equal && present;
            }
            report.observation(
                Phase::Setup,
                "interface_flags",
                Producer::Native,
                Observation::Number(flags as u64),
            )?;
            if all_equal {
                Ok(Ok(()))
            } else {
                Ok(Err(Failure::Oracle("discovery_slot_equivalence")))
            }
        }
    }
}
