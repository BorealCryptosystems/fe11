// SPDX-License-Identifier: Apache-2.0
//! File identity and export observations for the selected loading platform.
use crate::{Error, Observation, Result};

use std::{
    fs::File,
    path::{Path, PathBuf},
};

// Windows file IDs have 128 bits. Unix inode values occupy the same lossless
// representation; no path spelling or truncated hash becomes an identity.
pub(crate) type FileIdentity = (u64, u128);

/// Process-local identity of the image owning a resolved native function.
/// The caller already retains that function's library. Never serialize this
/// address: it is valid only while those loader references prevent unloading.
pub(crate) fn local_image_identity(address: usize) -> Result<usize> {
    #[cfg(windows)]
    {
        use std::ffi::c_void;
        #[link(name = "kernel32")]
        extern "system" {
            fn GetModuleHandleExW(flags: u32, address: *const u16, module: *mut *mut c_void)
                -> i32;
        }
        let mut base = std::ptr::null_mut();
        // SAFETY: FROM_ADDRESS plus UNCHANGED_REFCOUNT borrows the mapping
        // already retained by the caller; no FreeLibrary obligation is created.
        if unsafe { GetModuleHandleExW(0x4 | 0x2, address as *const u16, &mut base) } == 0
            || base.is_null()
        {
            return Err(Error::Rejected(crate::RejectionReason::NativeLoading(
                crate::NativeLoadingRejection::NativeImageIdentityUnavailable,
            )));
        }
        Ok(base as usize)
    }
    #[cfg(target_os = "linux")]
    {
        use std::ffi::{c_char, c_int, c_void};
        #[repr(C)]
        struct Info {
            name: *const c_char,
            base: *mut c_void,
            symbol: *const c_char,
            address: *mut c_void,
        }
        #[link(name = "dl")]
        extern "C" {
            fn dladdr(address: *const c_void, info: *mut Info) -> c_int;
        }
        let mut info = Info {
            name: std::ptr::null(),
            base: std::ptr::null_mut(),
            symbol: std::ptr::null(),
            address: std::ptr::null_mut(),
        };
        // SAFETY: initialized ABI output; the caller's image lease keeps this
        // mapping present. No pointed-to code or string is dereferenced here.
        if unsafe { dladdr(address as *const c_void, &mut info) } == 0 || info.base.is_null() {
            return Err(Error::Rejected(crate::RejectionReason::NativeLoading(
                crate::NativeLoadingRejection::NativeImageIdentityUnavailable,
            )));
        }
        Ok(info.base as usize)
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = address;
        Err(Error::Unsupported(crate::UnsupportedReason::NativeLoading(
            crate::NativeLoadingUnsupported::NativeImageIdentityPlatform,
        )))
    }
}

#[cfg(windows)]
mod windows;

/// File and optional ancestor pins outlive every native image lease. Field
/// order closes the file before releasing the ancestor handles after unload.
pub(crate) struct SourceFiles {
    pub(crate) file: File,
    _ancestors: Vec<File>,
}

/// Validate before file lookup, so a selected platform option is never ignored.
pub(crate) fn dependency_search_flags(selection: crate::WindowsDependencySearch) -> Result<u32> {
    let crate::WindowsDependencySearch::Directories {
        module_directory,
        application_directory,
        application_added_directories,
        system32,
    } = selection
    else {
        return Ok(0);
    };
    if !cfg!(windows) {
        return Err(Error::Rejected(crate::RejectionReason::NativeLoading(
            crate::NativeLoadingRejection::WindowsDependencySearchUnavailable,
        )));
    }
    const DLL_LOAD_DIR: u32 = 0x100;
    const APPLICATION_DIR: u32 = 0x200;
    const USER_DIRS: u32 = 0x400;
    const SYSTEM32: u32 = 0x800;
    let flags = if module_directory { DLL_LOAD_DIR } else { 0 }
        | if application_directory {
            APPLICATION_DIR
        } else {
            0
        }
        | if application_added_directories {
            USER_DIRS
        } else {
            0
        }
        | if system32 { SYSTEM32 } else { 0 };
    if flags == 0 {
        return Err(Error::Rejected(crate::RejectionReason::NativeLoading(
            crate::NativeLoadingRejection::EmptyWindowsDependencySearchSelection,
        )));
    }
    Ok(flags)
}

/// The caller must trust the selected native module and all code executed by
/// its loader/initializers/finalizers. This operation provides no sandbox.
pub(crate) unsafe fn load_library(
    path: &Path,
    selection: crate::WindowsDependencySearch,
    observations: crate::WindowsLoaderObservations,
) -> Result<(libloading::Library, crate::WindowsLoaderReport)> {
    let flags = dependency_search_flags(selection)?;
    validate_observations(observations)?;
    #[cfg(windows)]
    {
        if !path.is_absolute() {
            return Err(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                crate::ModuleLifecycleRejection::AbsoluteModulePathRequired,
            )));
        }
        let report = windows::collect_observations(path, selection, observations)?;
        // SAFETY: caller supplies the trusted native image. Only documented
        // local search flags are passed; loading is attempted exactly once.
        let native = unsafe { libloading::os::windows::Library::load_with_flags(path, flags) }
            .map_err(|_| {
                Error::Rejected(crate::RejectionReason::NativeLoading(
                    crate::NativeLoadingRejection::ModuleLoad,
                ))
            })?;
        Ok((native.into(), report))
    }
    #[cfg(not(windows))]
    {
        let _ = flags;
        // SAFETY: same trusted-code contract; Windows-specific selection has
        // already been refused. Linux keeps its retained descriptor path.
        let library = unsafe { libloading::Library::new(path) }.map_err(|_| {
            Error::Rejected(crate::RejectionReason::NativeLoading(
                crate::NativeLoadingRejection::ModuleLoad,
            ))
        })?;
        Ok((library, crate::WindowsLoaderReport::not_requested()))
    }
}

pub(crate) fn validate_observations(options: crate::WindowsLoaderObservations) -> Result<()> {
    use crate::{WindowsLoaderChannel as C, WindowsLoaderRequest as R};
    let crate::WindowsLoaderObservations::Selected { requests, .. } = options else {
        return Ok(());
    };
    if requests == crate::WindowsLoaderRequests::all(R::NotRequested) {
        return Ok(());
    }
    if !cfg!(windows) {
        return Err(Error::Rejected(crate::RejectionReason::NativeLoading(
            crate::NativeLoadingRejection::WindowsLoaderObservationsUnavailable,
        )));
    }
    // These documented limits do not require touching the file, registry or
    // native loader to discover. Refuse impossible requirements at preparation.
    for (request, channel) in [
        (requests.dev_override_effective, C::DevOverrideEffective),
        (requests.api_sets, C::ApiSets),
        (requests.package_dependency_graph, C::PackageDependencyGraph),
        (requests.global_search_state, C::GlobalSearchState),
    ] {
        if request == R::RequireKnown {
            return Err(Error::LoaderObservationUnavailable {
                channel,
                cause: crate::WindowsLoaderUnavailable::NoDocumentedProbe,
            });
        }
    }
    Ok(())
}

pub(crate) fn open_source(
    path: &Path,
    pinning: crate::WindowsFilePinning,
) -> Result<(PathBuf, SourceFiles, Observation<bool>)> {
    match pinning {
        crate::WindowsFilePinning::NotRequested => {
            let path = path.canonicalize().map_err(|_| {
                Error::Rejected(crate::RejectionReason::NativeLoading(
                    crate::NativeLoadingRejection::ModulePath,
                ))
            })?;
            let file = File::open(&path).map_err(|_| {
                Error::Rejected(crate::RejectionReason::NativeLoading(
                    crate::NativeLoadingRejection::ModuleFile,
                ))
            })?;
            Ok((
                path,
                SourceFiles {
                    file,
                    _ancestors: Vec::new(),
                },
                Observation::NotRequested,
            ))
        }
        #[cfg(windows)]
        crate::WindowsFilePinning::Pin {
            reparse,
            maximum_path_code_units,
            maximum_ancestors,
        } => windows::open_pinned(path, reparse, maximum_path_code_units, maximum_ancestors),
        #[cfg(not(windows))]
        crate::WindowsFilePinning::Pin { .. } => {
            Err(Error::Rejected(crate::RejectionReason::NativeLoading(
                crate::NativeLoadingRejection::WindowsFilePinningUnavailable,
            )))
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum ExportFileCheck {
    #[cfg(target_os = "linux")]
    LinuxPinned(FileIdentity),
    #[cfg(windows)]
    WindowsRequested {
        identity: FileIdentity,
        maximum: std::num::NonZeroUsize,
    },
    #[cfg(windows)]
    WindowsChecked {
        identity: FileIdentity,
        maximum: std::num::NonZeroUsize,
        image_base: usize,
    },
    NotRequested,
}
impl ExportFileCheck {
    pub(crate) fn check(self, address: usize) -> Result<()> {
        match self {
            #[cfg(target_os = "linux")]
            Self::LinuxPinned(identity) => {
                if !super::mapped_image_matches(address, identity)? {
                    return Err(Error::Rejected(crate::RejectionReason::NativeLoading(
                        crate::NativeLoadingRejection::LoadedModuleIdentityMismatch,
                    )));
                }
                Ok(())
            }
            #[cfg(windows)]
            Self::WindowsRequested { .. } => {
                Err(Error::Rejected(crate::RejectionReason::NativeLoading(
                    crate::NativeLoadingRejection::LoadedImageCheckIncomplete,
                )))
            }
            #[cfg(windows)]
            Self::WindowsChecked {
                identity,
                maximum,
                image_base,
            } => windows::check_export(address, image_base, identity, maximum),
            Self::NotRequested => {
                let _ = address;
                Ok(())
            }
        }
    }

    // Only publish after Native::open has successfully checked every export it
    // used to select the table. This says nothing about dependencies or DllMain.
    pub(crate) fn completed_observation(self) -> Result<Observation<bool>> {
        Ok(match self {
            #[cfg(target_os = "linux")]
            Self::LinuxPinned(_) => Observation::Observed(true),
            #[cfg(windows)]
            Self::WindowsRequested { .. } => {
                return Err(Error::Rejected(crate::RejectionReason::NativeLoading(
                    crate::NativeLoadingRejection::LoadedImageCheckIncomplete,
                )))
            }
            #[cfg(windows)]
            Self::WindowsChecked { .. } => Observation::Observed(true),
            Self::NotRequested => Observation::NotRequested,
        })
    }
}

pub(crate) fn validate_image_selection(
    pinning: crate::WindowsFilePinning,
    selection: crate::WindowsImageConsistency,
) -> Result<()> {
    if let crate::WindowsImageConsistency::CompareToPinnedFile {
        maximum_mapped_path_code_units,
    } = selection
    {
        if !cfg!(windows) {
            return Err(Error::Rejected(crate::RejectionReason::NativeLoading(
                crate::NativeLoadingRejection::WindowsImageComparisonUnavailable,
            )));
        }
        if !matches!(pinning, crate::WindowsFilePinning::Pin { .. }) {
            return Err(Error::Rejected(crate::RejectionReason::NativeLoading(
                crate::NativeLoadingRejection::WindowsImageComparisonRequiresFilePinning,
            )));
        }
        u32::try_from(maximum_mapped_path_code_units.get()).map_err(|_| {
            Error::Rejected(crate::RejectionReason::NativeLoading(
                crate::NativeLoadingRejection::MappedImagePathSize,
            ))
        })?;
    }
    Ok(())
}

pub(crate) fn check_loaded_image(
    library: libloading::Library,
    check: ExportFileCheck,
) -> Result<(libloading::Library, ExportFileCheck)> {
    #[cfg(windows)]
    if let ExportFileCheck::WindowsRequested { identity, maximum } = check {
        let (library, base) = windows::image_base(library);
        windows::check_mapping(base, identity, maximum)?;
        return Ok((
            library,
            ExportFileCheck::WindowsChecked {
                identity,
                maximum,
                image_base: base,
            },
        ));
    }
    Ok((library, check))
}

#[cfg(target_os = "linux")]
pub(crate) fn prepare(
    file: &File,
    _path: &Path,
    _selection: crate::WindowsImageConsistency,
) -> Result<(PathBuf, FileIdentity, ExportFileCheck)> {
    use std::os::{fd::AsRawFd, unix::fs::MetadataExt};
    let metadata = file.metadata().map_err(|_| {
        Error::Rejected(crate::RejectionReason::ModuleLifecycle(
            crate::ModuleLifecycleRejection::ModuleMetadata,
        ))
    })?;
    let identity = (metadata.dev(), u128::from(metadata.ino()));
    Ok((
        PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd())),
        identity,
        ExportFileCheck::LinuxPinned(identity),
    ))
}

#[cfg(windows)]
pub(crate) fn prepare(
    file: &File,
    path: &Path,
    selection: crate::WindowsImageConsistency,
) -> Result<(PathBuf, FileIdentity, ExportFileCheck)> {
    let identity = windows::file_identity(file)?;
    let check = match selection {
        crate::WindowsImageConsistency::NotRequested => ExportFileCheck::NotRequested,
        crate::WindowsImageConsistency::CompareToPinnedFile {
            maximum_mapped_path_code_units,
        } => ExportFileCheck::WindowsRequested {
            identity,
            maximum: maximum_mapped_path_code_units,
        },
    };
    Ok((path.to_path_buf(), identity, check))
}

#[cfg(not(any(target_os = "linux", windows)))]
pub(crate) fn prepare(
    _file: &File,
    _path: &Path,
    _selection: crate::WindowsImageConsistency,
) -> Result<(PathBuf, FileIdentity, ExportFileCheck)> {
    Err(Error::Rejected(crate::RejectionReason::NativeLoading(
        crate::NativeLoadingRejection::ModuleLoadingPlatformUnavailable,
    )))
}
