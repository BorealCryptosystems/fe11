// SPDX-License-Identifier: Apache-2.0
//! OS image lifetime and address membership, distinct from file trust controls.
use crate::{
    Error, Result, WindowsDependencySearch, WindowsLoaderObservations, WindowsLoaderReport,
};
use std::path::Path;

/// Loading executes trusted native initializers under the application boundary.
pub(super) unsafe fn load(
    path: &Path,
    search: WindowsDependencySearch,
    observations: WindowsLoaderObservations,
) -> Result<(libloading::Library, WindowsLoaderReport)> {
    #[cfg(target_os = "linux")]
    {
        crate::native::platform::dependency_search_flags(search)?;
        crate::native::platform::validate_observations(observations)?;
        // SAFETY: exact retained source descriptor path and trusted component.
        // NODELETE is an image-lifetime guarantee, not symbol isolation; the
        // component's private local binding must be verified on its final ELF.
        let library = unsafe {
            libloading::os::unix::Library::open(
                Some(path),
                libc::RTLD_NOW | libc::RTLD_LOCAL | libc::RTLD_NODELETE,
            )
        }
        .map_err(|_| {
            Error::Rejected(crate::RejectionReason::VerificationEngine(
                crate::VerificationEngineRejection::VerificationEngineLoad,
            ))
        })?;
        Ok((library.into(), WindowsLoaderReport::not_requested()))
    }
    #[cfg(windows)]
    {
        // SAFETY: inherited trusted-native-code contract; existing local Windows
        // flags and observation controls retain their documented behavior.
        let (library, report) =
            unsafe { crate::native::platform::load_library(path, search, observations) }?;
        // Initializers have already run. Establish image lifetime before any
        // subsequent path/export/ABI check can refuse this selection.
        Ok((pin_loaded_image(library)?, report))
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = (path, search, observations);
        Err(Error::Rejected(crate::RejectionReason::VerificationEngine(
            crate::VerificationEngineRejection::VerificationEngineLoadingPlatformUnavailable,
        )))
    }
}

#[cfg(windows)]
#[link(name = "kernel32")]
extern "system" {
    fn GetModuleHandleExW(
        flags: u32,
        address: *const u16,
        module: *mut *mut std::ffi::c_void,
    ) -> i32;
}

/// Preserve the original loading reference if OS pinning fails. Initializers
/// may already have registered callbacks, so unloading that image on refusal is
/// unsafe even though Fe11 has not called its interface or initialized OpenSSL.
#[cfg(windows)]
fn pin_loaded_image(library: libloading::Library) -> Result<libloading::Library> {
    let native: libloading::os::windows::Library = library.into();
    let handle = native.into_raw();
    // SAFETY: reconstruct exactly the owned reference just extracted. No
    // fallible action or native call intervenes between these ownership moves.
    let library: libloading::Library =
        unsafe { libloading::os::windows::Library::from_raw(handle) }.into();
    const PIN: u32 = 0x1;
    const FROM_ADDRESS: u32 = 0x4;
    let mut pinned = std::ptr::null_mut();
    // SAFETY: HMODULE is the base address of this still-owned loaded image.
    // FROM_ADDRESS takes an image address, not a string; PIN retains it until
    // process termination. We do not depend on finding a usable export first.
    if unsafe { GetModuleHandleExW(PIN | FROM_ADDRESS, handle as *const u16, &mut pinned) } == 0
        || pinned as usize != handle as usize
    {
        // Deliberate quarantine: preserve this owned loader reference for the
        // process lifetime, without allocation or a fallible registry insertion.
        // No component ABI function is invoked and there is no retry/fallback.
        std::mem::forget(library);
        return Err(Error::Rejected(crate::RejectionReason::VerificationEngine(
            crate::VerificationEngineRejection::VerificationEngineImagePinFailedLoadedImageRetained,
        )));
    }
    Ok(library)
}

/// The library owner is kept live by the caller while querying this address.
pub(super) fn image_for_address(address: usize) -> Result<usize> {
    if address == 0 {
        return Err(Error::Rejected(crate::RejectionReason::VerificationEngine(
            crate::VerificationEngineRejection::VerificationEngineNullFunction,
        )));
    }
    #[cfg(target_os = "linux")]
    {
        let mut information: libc::Dl_info = unsafe { std::mem::zeroed() };
        // SAFETY: dladdr inspects a value, not pointed-to application memory;
        // information is an initialized aligned output and the image stays live.
        if unsafe { libc::dladdr(address as *const _, &mut information) } == 0
            || information.dli_fbase.is_null()
        {
            return Err(Error::Rejected(crate::RejectionReason::VerificationEngine(
                crate::VerificationEngineRejection::VerificationEngineFunctionMapping,
            )));
        }
        Ok(information.dli_fbase as usize)
    }
    #[cfg(windows)]
    {
        const FROM_ADDRESS: u32 = 0x4;
        const UNCHANGED_REFCOUNT: u32 = 0x2;
        let mut module = std::ptr::null_mut();
        // SAFETY: FROM_ADDRESS interprets the argument as an address, not text.
        // The owning Library keeps this image live; this borrowed handle is never
        // passed to FreeLibrary or reconstructed as an owned Library.
        if unsafe {
            GetModuleHandleExW(
                FROM_ADDRESS | UNCHANGED_REFCOUNT,
                address as *const u16,
                &mut module,
            )
        } == 0
            || module.is_null()
        {
            return Err(Error::Rejected(crate::RejectionReason::VerificationEngine(
                crate::VerificationEngineRejection::VerificationEngineFunctionMapping,
            )));
        }
        Ok(module as usize)
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        Err(Error::Rejected(crate::RejectionReason::VerificationEngine(
            crate::VerificationEngineRejection::VerificationEngineLoadingPlatformUnavailable,
        )))
    }
}

/// Identify the getter inside the already process-pinned image. Windows
/// forwarded getters are refused instead of accepting another component's ABI.
pub(super) fn identify(
    library: libloading::Library,
    getter: usize,
) -> Result<(libloading::Library, usize)> {
    let identity = image_for_address(getter)?;
    #[cfg(windows)]
    {
        let native: libloading::os::windows::Library = library.into();
        let handle = native.into_raw();
        // SAFETY: restore the exact owned handle before any fallible work.
        let library: libloading::Library =
            unsafe { libloading::os::windows::Library::from_raw(handle) }.into();
        if identity != handle as usize {
            return Err(Error::Rejected(crate::RejectionReason::VerificationEngine(
                crate::VerificationEngineRejection::VerificationEngineGetterBelongsToAnotherImage,
            )));
        }
        Ok((library, identity))
    }
    #[cfg(not(windows))]
    {
        // Linux supplied NODELETE at load time; unsupported platforms are
        // refused by load() and image_for_address().
        Ok((library, identity))
    }
}

pub(super) fn require_same_image(address: usize, identity: usize) -> Result<()> {
    if image_for_address(address)? != identity {
        return Err(Error::Rejected(
            crate::RejectionReason::VerificationEngine(crate::VerificationEngineRejection::VerificationEngineTableFunctionBelongsToAnotherImage),
        ));
    }
    Ok(())
}
