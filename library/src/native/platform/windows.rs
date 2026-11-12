// SPDX-License-Identifier: Apache-2.0
//! Windows file pins. No process-global search settings are changed.
mod observations;
use super::{FileIdentity, SourceFiles};
use crate::{Error, Observation, Result, WindowsReparseHandling};
pub(super) use observations::collect as collect_observations;
use std::{
    ffi::{c_void, OsString},
    fs::{File, OpenOptions},
    num::NonZeroUsize,
    os::windows::{
        ffi::OsStringExt,
        fs::{MetadataExt, OpenOptionsExt},
        io::AsRawHandle,
    },
    path::{Path, PathBuf},
};

const FILE_SHARE_READ: u32 = 1;
const FILE_SHARE_WRITE: u32 = 2;
const FILE_READ_ATTRIBUTES: u32 = 0x80;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
const FILE_ID_INFO_CLASS: i32 = 0x12;

#[repr(C)]
struct FileIdInfo {
    volume_serial_number: u64,
    file_id: [u8; 16],
}

#[link(name = "kernel32")]
extern "system" {
    fn GetFileInformationByHandleEx(
        handle: *mut c_void,
        class: i32,
        info: *mut c_void,
        size: u32,
    ) -> i32;
    fn GetFinalPathNameByHandleW(
        handle: *mut c_void,
        path: *mut u16,
        units: u32,
        flags: u32,
    ) -> u32;
    fn GetCurrentProcess() -> *mut c_void;
    fn K32GetMappedFileNameW(
        process: *mut c_void,
        address: *mut c_void,
        path: *mut u16,
        units: u32,
    ) -> u32;
    fn GetModuleHandleExW(flags: u32, address: *const u16, module: *mut *mut c_void) -> i32;
}

pub(super) fn image_base(library: libloading::Library) -> (libloading::Library, usize) {
    let native: libloading::os::windows::Library = library.into();
    let handle = native.into_raw();
    // SAFETY: restore exactly the owned handle just extracted, before any
    // fallible work or callback. No extra reference or FreeLibrary is performed.
    let native = unsafe { libloading::os::windows::Library::from_raw(handle) };
    (native.into(), handle as usize)
}

pub(super) fn check_mapping(
    address: usize,
    expected: FileIdentity,
    maximum: NonZeroUsize,
) -> Result<()> {
    if address == 0 {
        return Err(Error::Rejected(crate::RejectionReason::NativeLoading(
            crate::NativeLoadingRejection::NullLoadedImageAddress,
        )));
    }
    let capacity = u32::try_from(maximum.get()).map_err(|_| {
        Error::Rejected(crate::RejectionReason::NativeLoading(
            crate::NativeLoadingRejection::MappedImagePathSize,
        ))
    })?;
    let mut units = Vec::new();
    units.try_reserve_exact(maximum.get()).map_err(|_| {
        Error::Rejected(crate::RejectionReason::NativeLoading(
            crate::NativeLoadingRejection::MappedImagePathAllocation,
        ))
    })?;
    units.resize(maximum.get(), 0u16);
    // SAFETY: Library is retained by the calling load operation. This kernel
    // observation receives an initialized buffer and never dereferences the
    // address in Rust. The current-process handle is a borrowed pseudo-handle.
    let length = unsafe {
        K32GetMappedFileNameW(
            GetCurrentProcess(),
            address as *mut c_void,
            units.as_mut_ptr(),
            capacity,
        )
    };
    let length = usize::try_from(length).map_err(|_| {
        Error::Rejected(crate::RejectionReason::NativeLoading(
            crate::NativeLoadingRejection::MappedImagePathSize,
        ))
    })?;
    if length == 0 || length >= units.len() || units[length] != 0 || units[..length].contains(&0) {
        return Err(Error::Rejected(crate::RejectionReason::NativeLoading(
            crate::NativeLoadingRejection::MappedImagePathUnavailableOrTruncated,
        )));
    }
    // The kernel returns an NT device path. GLOBALROOT exposes that exact
    // namespace without a drive-letter substitution or basename lookup.
    const DEVICE: &[u16] = &[92, 68, 101, 118, 105, 99, 101, 92];
    const GLOBAL_ROOT: &[u16] = &[92, 92, 63, 92, 71, 76, 79, 66, 65, 76, 82, 79, 79, 84];
    if !units[..length].starts_with(DEVICE) {
        return Err(Error::Rejected(crate::RejectionReason::NativeLoading(
            crate::NativeLoadingRejection::MappedImagePathNamespaceUnavailable,
        )));
    }
    let total = GLOBAL_ROOT
        .len()
        .checked_add(length)
        .ok_or(Error::Rejected(crate::RejectionReason::NativeLoading(
            crate::NativeLoadingRejection::MappedImagePathSize,
        )))?;
    let mut absolute = Vec::new();
    absolute.try_reserve_exact(total).map_err(|_| {
        Error::Rejected(crate::RejectionReason::NativeLoading(
            crate::NativeLoadingRejection::MappedImagePathAllocation,
        ))
    })?;
    absolute.extend_from_slice(GLOBAL_ROOT);
    absolute.extend_from_slice(&units[..length]);
    let path = PathBuf::from(OsString::from_wide(&absolute));
    let file = OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|_| {
            Error::Rejected(crate::RejectionReason::NativeLoading(
                crate::NativeLoadingRejection::MappedImageFileUnavailable,
            ))
        })?;
    if file_identity(&file)? != expected {
        return Err(Error::Rejected(crate::RejectionReason::NativeLoading(
            crate::NativeLoadingRejection::LoadedImageFileIdentityMismatch,
        )));
    }
    Ok(())
}

pub(super) fn check_export(
    address: usize,
    image_base: usize,
    expected: FileIdentity,
    maximum: NonZeroUsize,
) -> Result<()> {
    const FROM_ADDRESS: u32 = 0x4;
    const UNCHANGED_REFCOUNT: u32 = 0x2;
    let mut owner = std::ptr::null_mut::<c_void>();
    // SAFETY: FROM_ADDRESS interprets this value as an address, not a UTF-16
    // string. The original Library is retained throughout the comparison.
    // UNCHANGED_REFCOUNT means this result must never be passed to FreeLibrary.
    let found = unsafe {
        GetModuleHandleExW(
            FROM_ADDRESS | UNCHANGED_REFCOUNT,
            address as *const u16,
            &mut owner,
        )
    };
    if found == 0 || owner.is_null() || owner as usize != image_base {
        return Err(Error::Rejected(crate::RejectionReason::NativeLoading(
            crate::NativeLoadingRejection::TableSelectionExportBelongsToAnotherImage,
        )));
    }
    check_mapping(address, expected, maximum)
}

pub(super) fn file_identity(file: &File) -> Result<FileIdentity> {
    let mut info = FileIdInfo {
        volume_serial_number: 0,
        file_id: [0; 16],
    };
    let size = u32::try_from(std::mem::size_of::<FileIdInfo>()).map_err(|_| {
        Error::Rejected(crate::RejectionReason::NativeLoading(
            crate::NativeLoadingRejection::ModuleFileIdentitySize,
        ))
    })?;
    // SAFETY: live retained handle; exact repr(C) output and checked DWORD size.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FILE_ID_INFO_CLASS,
            (&mut info as *mut FileIdInfo).cast(),
            size,
        )
    };
    if ok == 0 {
        return Err(Error::Rejected(crate::RejectionReason::NativeLoading(
            crate::NativeLoadingRejection::ModuleFileIdentityUnavailable,
        )));
    }
    Ok((info.volume_serial_number, u128::from_le_bytes(info.file_id)))
}

fn final_path(file: &File, maximum: NonZeroUsize) -> Result<PathBuf> {
    // FILE_NAME_NORMALIZED | VOLUME_NAME_DOS are both zero. The size query
    // includes the terminator; a successful fill returns a length excluding it.
    // SAFETY: live handle; NULL/0 requests only the documented buffer size.
    let required =
        unsafe { GetFinalPathNameByHandleW(file.as_raw_handle(), std::ptr::null_mut(), 0, 0) };
    let required_usize = usize::try_from(required).map_err(|_| {
        Error::Rejected(crate::RejectionReason::NativeLoading(
            crate::NativeLoadingRejection::ModuleFinalPathSize,
        ))
    })?;
    if required == 0 || required_usize > maximum.get() {
        return Err(Error::Rejected(crate::RejectionReason::NativeLoading(
            crate::NativeLoadingRejection::ModuleFinalPathUnavailableOrOverLimit,
        )));
    }
    let mut units = Vec::new();
    units.try_reserve_exact(required_usize).map_err(|_| {
        Error::Rejected(crate::RejectionReason::NativeLoading(
            crate::NativeLoadingRejection::ModuleFinalPathAllocation,
        ))
    })?;
    units.resize(required_usize, 0u16);
    // SAFETY: complete initialized u16 allocation; capacity is the exact count
    // supplied to the synchronous Win32 call, not an inferred byte count.
    let length =
        unsafe { GetFinalPathNameByHandleW(file.as_raw_handle(), units.as_mut_ptr(), required, 0) };
    let length = usize::try_from(length).map_err(|_| {
        Error::Rejected(crate::RejectionReason::NativeLoading(
            crate::NativeLoadingRejection::ModuleFinalPathSize,
        ))
    })?;
    if length == 0 || length >= units.len() || units[length] != 0 || units[..length].contains(&0) {
        return Err(Error::Rejected(crate::RejectionReason::NativeLoading(
            crate::NativeLoadingRejection::ModuleFinalPathChangedOrInvalid,
        )));
    }
    let path = PathBuf::from(OsString::from_wide(&units[..length]));
    if !path.is_absolute() {
        return Err(Error::Rejected(crate::RejectionReason::NativeLoading(
            crate::NativeLoadingRejection::ModuleFinalPathIsNotAbsolute,
        )));
    }
    Ok(path)
}

fn pin_ancestors(path: &Path, maximum: Option<usize>) -> Result<Vec<File>> {
    let count = path
        .ancestors()
        .skip(1)
        .try_fold(0usize, |n, _| n.checked_add(1))
        .ok_or(Error::Rejected(crate::RejectionReason::NativeLoading(
            crate::NativeLoadingRejection::ModuleAncestorCount,
        )))?;
    if maximum.is_some_and(|maximum| count > maximum) {
        return Err(Error::Rejected(crate::RejectionReason::NativeLoading(
            crate::NativeLoadingRejection::ModuleAncestorLimit,
        )));
    }
    let mut paths = Vec::new();
    paths.try_reserve_exact(count).map_err(|_| {
        Error::Rejected(crate::RejectionReason::NativeLoading(
            crate::NativeLoadingRejection::ModuleAncestorAllocation,
        ))
    })?;
    paths.extend(path.ancestors().skip(1));
    let mut held = Vec::new();
    held.try_reserve_exact(count).map_err(|_| {
        Error::Rejected(crate::RejectionReason::NativeLoading(
            crate::NativeLoadingRejection::ModuleAncestorAllocation,
        ))
    })?;
    // Establish root-to-leaf guards before using the final file spelling.
    for path in paths.into_iter().rev() {
        let file = OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .map_err(|_| {
                Error::Rejected(crate::RejectionReason::NativeLoading(
                    crate::NativeLoadingRejection::ModuleAncestorPinUnavailable,
                ))
            })?;
        let metadata = file.metadata().map_err(|_| {
            Error::Rejected(crate::RejectionReason::NativeLoading(
                crate::NativeLoadingRejection::ModuleAncestorMetadata,
            ))
        })?;
        if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(Error::Rejected(crate::RejectionReason::NativeLoading(
                crate::NativeLoadingRejection::ModuleAncestorIsNotAPlainDirectory,
            )));
        }
        held.push(file);
    }
    Ok(held)
}

fn pinned_file(path: &Path, reject_reparse: bool) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(if reject_reparse {
            FILE_FLAG_OPEN_REPARSE_POINT
        } else {
            0
        })
        .open(path)
        .map_err(|_| {
            Error::Rejected(crate::RejectionReason::NativeLoading(
                crate::NativeLoadingRejection::ModuleFilePinUnavailable,
            ))
        })?;
    let metadata = file.metadata().map_err(|_| {
        Error::Rejected(crate::RejectionReason::NativeLoading(
            crate::NativeLoadingRejection::ModuleFilePinMetadata,
        ))
    })?;
    if !metadata.is_file()
        || (reject_reparse && metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0)
    {
        return Err(Error::Rejected(crate::RejectionReason::NativeLoading(
            crate::NativeLoadingRejection::ModulePinnedTargetIsNotAPlainFile,
        )));
    }
    Ok(file)
}

pub(super) fn open_pinned(
    path: &Path,
    reparse: WindowsReparseHandling,
    maximum_path: NonZeroUsize,
    maximum_ancestors: Option<usize>,
) -> Result<(PathBuf, SourceFiles, Observation<bool>)> {
    let (file, ancestors, expected_resolved) = match reparse {
        WindowsReparseHandling::Reject => {
            let ancestors = pin_ancestors(path, maximum_ancestors)?;
            (pinned_file(path, true)?, ancestors, None)
        }
        WindowsReparseHandling::ResolveAndPin => {
            let file = pinned_file(path, false)?;
            let resolved = final_path(&file, maximum_path)?;
            let ancestors = pin_ancestors(&resolved, maximum_ancestors)?;
            (file, ancestors, Some(resolved))
        }
    };
    let resolved = final_path(&file, maximum_path)?;
    if expected_resolved
        .as_ref()
        .is_some_and(|expected| expected != &resolved)
    {
        return Err(Error::Rejected(crate::RejectionReason::NativeLoading(
            crate::NativeLoadingRejection::ModuleResolvedAncestorChainChanged,
        )));
    }
    // Reopen only for identity comparison, not as a loading retry. The target
    // must remain the original pinned file after ancestor acquisition.
    let checked = pinned_file(&resolved, true)?;
    if file_identity(&file)? != file_identity(&checked)? {
        return Err(Error::Rejected(crate::RejectionReason::NativeLoading(
            crate::NativeLoadingRejection::ModulePinnedFileIdentityChanged,
        )));
    }
    drop(checked);
    Ok((
        resolved,
        SourceFiles {
            file,
            _ancestors: ancestors,
        },
        Observation::Observed(true),
    ))
}
