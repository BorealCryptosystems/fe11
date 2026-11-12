// SPDX-License-Identifier: Apache-2.0
//! Retain images providing process-visible PKCS#11 selection exports.
use crate::{Error, Result};
use libloading::Library;

pub(super) struct ProcessImage {
    pub library: Library,
    // Library::this() names the process lookup scope. On ELF, symbols may live
    // in a subsequently loaded global DSO, so retain each selected export's
    // actual image too. No pathname is loaded as a replacement image.
    pub providers: Vec<Library>,
    pub exports: Vec<usize>,
}

pub(super) fn open(selection: crate::InterfaceSelection) -> Result<ProcessImage> {
    open_scope(Some(selection))
}

pub(super) fn open_inventory() -> Result<ProcessImage> {
    open_scope(None)
}

// Inventory uses only the list export. Other visible exports need not belong
// to that runtime and neither their availability nor their state is required.
fn open_scope(selection: Option<crate::InterfaceSelection>) -> Result<ProcessImage> {
    #[cfg(windows)]
    let library: Library = libloading::os::windows::Library::this()
        .map_err(|_| {
            Error::Rejected(crate::RejectionReason::NativeLoading(
                crate::NativeLoadingRejection::CurrentProcessImageUnavailable,
            ))
        })?
        .into();
    #[cfg(target_os = "linux")]
    let library: Library = libloading::os::unix::Library::this().into();
    #[cfg(not(any(windows, target_os = "linux")))]
    return Err(Error::Unsupported(crate::UnsupportedReason::NativeLoading(
        crate::NativeLoadingUnsupported::CurrentProcessLoaderPlatform,
    )));

    #[cfg(any(windows, target_os = "linux"))]
    {
        let mut providers = Vec::new();
        let mut exports = Vec::new();
        let names: &[&[u8]] = match selection {
            None => &[b"C_GetInterfaceList\0"],
            Some(crate::InterfaceSelection::Standard { .. }) => {
                &[b"C_GetInterfaceList\0", b"C_GetInterface\0"]
            }
            Some(crate::InterfaceSelection::ProviderDefault) => {
                // Match select_default's symbol-presence choice. A native
                // refusal never selects a second export or another interface.
                if unsafe { library.get::<unsafe extern "C" fn()>(b"C_GetInterface\0") }.is_ok() {
                    &[b"C_GetInterface\0"]
                } else {
                    &[b"C_GetFunctionList\0"]
                }
            }
            _ => &[b"C_GetFunctionList\0"],
        };
        providers.try_reserve_exact(names.len()).map_err(|_| {
            Error::Rejected(crate::RejectionReason::NativeLoading(
                crate::NativeLoadingRejection::ProcessImageOwnerAllocation,
            ))
        })?;
        exports.try_reserve_exact(names.len() + 1).map_err(|_| {
            Error::Rejected(crate::RejectionReason::NativeExecution(
                crate::NativeExecutionRejection::ProcessExportAllocation,
            ))
        })?;
        for &name in names {
            // SAFETY: these known names denote functions. This untyped symbol
            // is only inspected/compared, never invoked through this type.
            let address = match unsafe { library.get::<unsafe extern "C" fn()>(name) } {
                Ok(symbol) => *symbol as usize,
                Err(_) => continue,
            };
            let provider = retain(address)?;
            // The process lookup and retention are separate loader operations.
            // Re-resolve from the retained image before using any earlier
            // pointer: an intervening unload/reload must not grant authority.
            let retained =
                unsafe { provider.get::<unsafe extern "C" fn()>(name) }.map_err(|_| {
                    Error::Rejected(crate::RejectionReason::NativeLoading(
                        crate::NativeLoadingRejection::RetainedProcessExportUnavailable,
                    ))
                })?;
            if *retained as usize != address {
                return Err(Error::Rejected(crate::RejectionReason::NativeLoading(
                    crate::NativeLoadingRejection::ProcessExportMappingChanged,
                )));
            }
            providers.push(provider);
            exports.push(address);
        }
        Ok(ProcessImage {
            library,
            providers,
            exports,
        })
    }
}

#[cfg(windows)]
pub(super) fn retain(address: usize) -> Result<Library> {
    use std::ffi::c_void;
    #[link(name = "kernel32")]
    extern "system" {
        fn GetModuleHandleExW(flags: u32, address: *const u16, module: *mut *mut c_void) -> i32;
    }
    let mut handle = std::ptr::null_mut();
    // SAFETY: FROM_ADDRESS treats the argument as an address. Without
    // UNCHANGED_REFCOUNT the successful call transfers one owned reference.
    let found = unsafe { GetModuleHandleExW(0x4, address as *const u16, &mut handle) };
    if found == 0 || handle.is_null() {
        return Err(Error::Rejected(crate::RejectionReason::NativeLoading(
            crate::NativeLoadingRejection::ProcessExportImageUnavailable,
        )));
    }
    // SAFETY: exactly the reference acquired above; Library releases it once.
    Ok(unsafe { libloading::os::windows::Library::from_raw(handle as isize) }.into())
}

#[cfg(target_os = "linux")]
pub(super) fn retain(address: usize) -> Result<Library> {
    use std::ffi::{c_char, c_int, c_void, CStr, OsStr};
    use std::os::unix::ffi::OsStrExt;

    // Linux <elf.h>/<link.h> native-width prefixes. The callback's size checks
    // the stable dl_phdr_info prefix; added libc fields are never inspected.
    #[repr(C)]
    struct ProgramHeader {
        kind: u32,
        #[cfg(target_pointer_width = "64")]
        flags: u32,
        offset: usize,
        virtual_address: usize,
        physical_address: usize,
        file_size: usize,
        memory_size: usize,
        #[cfg(target_pointer_width = "32")]
        flags: u32,
        alignment: usize,
    }
    #[repr(C)]
    struct Info {
        base: usize,
        name: *const c_char,
        headers: *const ProgramHeader,
        count: u16,
    }
    struct Query {
        address: usize,
        first: bool,
        found: Option<Result<Option<Vec<u8>>>>,
    }
    unsafe extern "C" fn visit(info: *mut Info, size: usize, data: *mut c_void) -> c_int {
        // SAFETY: the loader supplies the stable prefix and program-header
        // array while invoking this callback; data points to our live query.
        let query = unsafe { &mut *data.cast::<Query>() };
        let main = query.first;
        query.first = false;
        if size < std::mem::size_of::<Info>() || info.is_null() {
            query.found = Some(Err(Error::Rejected(crate::RejectionReason::NativeLoading(
                crate::NativeLoadingRejection::ProcessLoaderMetadataWidth,
            ))));
            return 1;
        }
        let info = unsafe { &*info };
        if info.headers.is_null() || info.name.is_null() {
            return 0;
        }
        let headers = unsafe { std::slice::from_raw_parts(info.headers, usize::from(info.count)) };
        let contains = headers.iter().any(|header| {
            header.kind == 1
                && info
                    .base
                    .checked_add(header.virtual_address)
                    .and_then(|start| {
                        start
                            .checked_add(header.memory_size)
                            .map(|end| (start, end))
                    })
                    .is_some_and(|(start, end)| query.address >= start && query.address < end)
        });
        if !contains {
            return 0;
        }
        if main {
            // The main executable cannot be dlclosed; the process handle owns
            // its lookup scope even for a non-PIE image with load bias zero.
            query.found = Some(Ok(None));
        } else {
            let bytes = unsafe { CStr::from_ptr(info.name) }.to_bytes();
            let mut name = Vec::new();
            if name.try_reserve_exact(bytes.len()).is_err() {
                query.found = Some(Err(Error::Rejected(crate::RejectionReason::NativeLoading(
                    crate::NativeLoadingRejection::ProcessImageNameAllocation,
                ))));
            } else {
                name.extend_from_slice(bytes);
                query.found = Some(Ok(Some(name)));
            }
        }
        1
    }
    #[link(name = "dl")]
    extern "C" {
        fn dl_iterate_phdr(
            callback: unsafe extern "C" fn(*mut Info, usize, *mut c_void) -> c_int,
            data: *mut c_void,
        ) -> c_int;
    }
    let mut query = Query {
        address,
        first: true,
        found: None,
    };
    // SAFETY: visit does not unwind or retain libc's pointers; query outlives
    // the synchronous enumeration. No PKCS#11 code is invoked here.
    unsafe { dl_iterate_phdr(visit, (&mut query as *mut Query).cast()) };
    let name = query
        .found
        .ok_or(Error::Rejected(crate::RejectionReason::NativeLoading(
            crate::NativeLoadingRejection::ProcessExportMappingUnavailable,
        )))??;
    match name {
        None => Ok(libloading::os::unix::Library::this().into()),
        Some(name) => {
            // RTLD_NOLOAD is Linux's existing-image-only request. Do not fall
            // back to an ordinary path load if the mapping has disappeared.
            const RTLD_NOLOAD: c_int = 0x4;
            let image = unsafe {
                libloading::os::unix::Library::open(
                    Some(OsStr::from_bytes(&name)),
                    libloading::os::unix::RTLD_NOW | RTLD_NOLOAD,
                )
            }
            .map_err(|_| {
                Error::Rejected(crate::RejectionReason::NativeLoading(
                    crate::NativeLoadingRejection::ProcessImageNoLongerLoaded,
                ))
            })?;
            Ok(image.into())
        }
    }
}
