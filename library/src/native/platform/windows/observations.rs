// SPDX-License-Identifier: Apache-2.0
//! Bounded observations. Never alter loader, registry or activation state.
use crate::*;
use std::{
    ffi::{c_void, OsString},
    mem::size_of,
    os::windows::ffi::{OsStrExt, OsStringExt},
    path::{Path, PathBuf},
    time::SystemTime,
};

mod activation;
mod registry;
type Probe<T> = std::result::Result<T, WindowsLoaderUnavailable>;
type Limits = WindowsLoaderObservationLimits;
use WindowsLoaderUnavailable as Unavailable;

#[link(name = "kernel32")]
extern "system" {
    fn GetLastError() -> u32;
    fn GetModuleFileNameW(module: *mut c_void, buffer: *mut u16, capacity: u32) -> u32;
    fn GetSystemDirectoryW(buffer: *mut u16, capacity: u32) -> u32;
    fn GetModuleHandleW(name: *const u16) -> *mut c_void;
    fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
    fn K32EnumProcessModules(
        process: *mut c_void,
        modules: *mut *mut c_void,
        bytes: u32,
        needed: *mut u32,
    ) -> i32;
}

fn os_error(function: &'static str) -> Unavailable {
    // SAFETY: reads this thread's last OS error immediately after the failed call.
    Unavailable::Os {
        function,
        code: unsafe { GetLastError() },
    }
}
fn dword(n: usize) -> Probe<u32> {
    u32::try_from(n).map_err(|_| Unavailable::ResourceLimit)
}
fn buffer<T: Clone>(n: usize, fill: T) -> Probe<Vec<T>> {
    let mut result = Vec::new();
    result
        .try_reserve_exact(n)
        .map_err(|_| Unavailable::Allocation)?;
    result.resize(n, fill);
    Ok(result)
}
fn push<T>(out: &mut Vec<T>, value: T) -> Probe<()> {
    out.try_reserve(1).map_err(|_| Unavailable::Allocation)?;
    out.push(value);
    Ok(())
}
fn path_from_terminated(units: &[u16], length: usize) -> Probe<PathBuf> {
    if length == 0 || length >= units.len() || units[length] != 0 || units[..length].contains(&0) {
        return Err(Unavailable::InvalidOutput);
    }
    Ok(PathBuf::from(OsString::from_wide(&units[..length])))
}
fn bound_path(path: PathBuf, limits: Limits) -> Probe<PathBuf> {
    if path.as_os_str().encode_wide().count() >= limits.maximum_path_code_units.get() {
        return Err(Unavailable::ResourceLimit);
    }
    Ok(path)
}
fn executable(limits: Limits) -> Probe<PathBuf> {
    let mut path = buffer(limits.maximum_path_code_units.get(), 0u16)?;
    // SAFETY: NULL selects the current executable; initialized bounded output.
    let n =
        unsafe { GetModuleFileNameW(std::ptr::null_mut(), path.as_mut_ptr(), dword(path.len())?) };
    if n == 0 {
        return Err(os_error("GetModuleFileNameW"));
    }
    if n as usize >= path.len() {
        return Err(Unavailable::ResourceLimit);
    }
    path_from_terminated(&path, n as usize)
}
fn presence(path: PathBuf) -> Probe<WindowsLoaderPath> {
    let kind = match std::fs::symlink_metadata(&path) {
        Ok(meta) if meta.is_dir() => WindowsLoaderPathKind::Directory,
        Ok(meta) if meta.is_file() => WindowsLoaderPathKind::File,
        Ok(_) => WindowsLoaderPathKind::Other,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => WindowsLoaderPathKind::Missing,
        Err(e) => {
            return Err(Unavailable::Os {
                function: "symlink_metadata",
                code: e.raw_os_error().map(|v| v as u32).ok_or(
                    Unavailable::OsErrorWithoutCode {
                        function: "symlink_metadata",
                    },
                )?,
            })
        }
    };
    Ok(WindowsLoaderPath { path, kind })
}
fn dot_local(limits: Limits) -> Probe<WindowsLoaderPath> {
    let mut name = executable(limits)?.into_os_string();
    name.push(".local");
    presence(bound_path(PathBuf::from(name), limits)?)
}
fn packaged_dot_local(limits: Limits) -> Probe<WindowsLoaderPath> {
    // Resolve this optional Windows 8+ observer without imposing its import on
    // applications that do not select package inspection. Kernel32 is already a
    // dependency of the executing code; no library is loaded or pinned here.
    const KERNEL32: &[u16] = &[107, 101, 114, 110, 101, 108, 51, 50, 46, 100, 108, 108, 0];
    // SAFETY: terminated constant module name; borrowed handle, never freed.
    let kernel32 = unsafe { GetModuleHandleW(KERNEL32.as_ptr()) };
    if kernel32.is_null() {
        return Err(os_error("GetModuleHandleW"));
    }
    // SAFETY: exact exported name in the existing system module.
    let entry = unsafe { GetProcAddress(kernel32, b"GetCurrentPackagePath\0".as_ptr()) };
    if entry.is_null() {
        return Err(os_error("GetProcAddress"));
    }
    // SAFETY: documented Win32 signature of this exact system export. Windows
    // function and address pointers share the native pointer representation.
    let get_package_path: unsafe extern "system" fn(*mut u32, *mut u16) -> u32 =
        unsafe { std::mem::transmute(entry) };
    let mut path = buffer(limits.maximum_path_code_units.get(), 0u16)?;
    let mut length = dword(path.len())?;
    // SAFETY: length describes the complete initialized UTF-16 allocation.
    let status = unsafe { get_package_path(&mut length, path.as_mut_ptr()) };
    if status != 0 {
        return Err(Unavailable::Os {
            function: "GetCurrentPackagePath",
            code: status,
        });
    }
    let n = (length as usize)
        .checked_sub(1)
        .ok_or(Unavailable::InvalidOutput)?;
    let root = path_from_terminated(&path, n)?;
    if !root.is_absolute() {
        return Err(Unavailable::ProvenanceUnavailable);
    }
    // A missing/inaccessible package root cannot be interpreted as an absent
    // application.local file. Establish a readable directory first; this is
    // still a dated observation, not a pin against concurrent removal.
    let metadata =
        std::fs::metadata(&root).map_err(|error| io_error("package root metadata", error))?;
    if !metadata.is_dir() {
        return Err(Unavailable::ProvenanceUnavailable);
    }
    let directory =
        std::fs::read_dir(&root).map_err(|error| io_error("package root read_dir", error))?;
    drop(directory);
    presence(bound_path(
        root.join("microsoft.system.package.metadata")
            .join("application.local"),
        limits,
    )?)
}

fn io_error(function: &'static str, error: std::io::Error) -> Unavailable {
    match error.raw_os_error() {
        Some(code) => Unavailable::Os {
            function,
            code: code as u32,
        },
        None => Unavailable::OsErrorWithoutCode { function },
    }
}
fn search_directories(
    path: &Path,
    selection: WindowsDependencySearch,
    limits: Limits,
) -> Probe<WindowsLoaderSearchDirectories> {
    let exe = executable(limits)?;
    let application_directory = exe
        .parent()
        .ok_or(Unavailable::ProvenanceUnavailable)?
        .to_path_buf();
    let mut system = buffer(limits.maximum_path_code_units.get(), 0u16)?;
    // SAFETY: initialized UTF-16 allocation with its checked capacity.
    let n = unsafe { GetSystemDirectoryW(system.as_mut_ptr(), dword(system.len())?) };
    if n == 0 {
        return Err(os_error("GetSystemDirectoryW"));
    }
    if n as usize >= system.len() {
        return Err(Unavailable::ResourceLimit);
    }
    Ok(WindowsLoaderSearchDirectories {
        requested_module: bound_path(path.to_path_buf(), limits)?,
        application_directory,
        system_directory: path_from_terminated(&system, n as usize)?,
        selection,
    })
}
fn loaded_modules(limits: Limits) -> Probe<Vec<PathBuf>> {
    let width = size_of::<*mut c_void>();
    let bytes = limits
        .maximum_modules
        .checked_mul(width)
        .ok_or(Unavailable::ResourceLimit)?;
    let capacity = dword(bytes)?;
    let mut handles = buffer(limits.maximum_modules, std::ptr::null_mut::<c_void>())?;
    let mut needed = 0u32;
    // SAFETY: borrowed pseudo-handle; module addresses are only passed back to
    // OS observers, never dereferenced or treated as owned library references.
    let ok = unsafe {
        K32EnumProcessModules(
            super::GetCurrentProcess(),
            handles.as_mut_ptr(),
            capacity,
            &mut needed,
        )
    };
    if ok == 0 {
        return Err(os_error("K32EnumProcessModules"));
    }
    if needed > capacity {
        return Err(Unavailable::ResourceLimit);
    }
    if needed as usize % width != 0 {
        return Err(Unavailable::InvalidOutput);
    }
    handles.truncate(needed as usize / width);
    let mut paths = Vec::new();
    for handle in handles {
        if handle.is_null() {
            return Err(Unavailable::InvalidOutput);
        }
        let mut units = buffer(limits.maximum_path_code_units.get(), 0u16)?;
        // SAFETY: OS mapping query and owned output. Concurrent unload can make
        // this observation unavailable; no pin or atomic snapshot is claimed.
        let n = unsafe {
            super::K32GetMappedFileNameW(
                super::GetCurrentProcess(),
                handle,
                units.as_mut_ptr(),
                dword(units.len())?,
            )
        };
        if n == 0 {
            return Err(os_error("K32GetMappedFileNameW"));
        }
        if n as usize >= units.len() {
            return Err(Unavailable::ResourceLimit);
        }
        push(&mut paths, path_from_terminated(&units, n as usize)?)?;
    }
    Ok(paths)
}

fn observe<T>(
    request: WindowsLoaderRequest,
    channel: WindowsLoaderChannel,
    probe: impl FnOnce() -> Probe<T>,
) -> Result<WindowsLoaderObservation<T>> {
    if request == WindowsLoaderRequest::NotRequested {
        return Ok(WindowsLoaderObservation::NotRequested);
    }
    let observed_at = SystemTime::now();
    match probe() {
        Ok(value) => Ok(WindowsLoaderObservation::Known { observed_at, value }),
        Err(cause) if request == WindowsLoaderRequest::RequireKnown => {
            Err(Error::LoaderObservationUnavailable { channel, cause })
        }
        Err(cause) => Ok(WindowsLoaderObservation::Unavailable { observed_at, cause }),
    }
}

pub(crate) fn collect(
    path: &Path,
    search: WindowsDependencySearch,
    options: WindowsLoaderObservations,
) -> Result<WindowsLoaderReport> {
    let WindowsLoaderObservations::Selected {
        requests: r,
        limits: l,
    } = options
    else {
        return Ok(WindowsLoaderReport::not_requested());
    };
    use WindowsLoaderChannel as C;
    let mut report = WindowsLoaderReport::not_requested();
    report.dot_local = observe(r.dot_local, C::DotLocal, || dot_local(l))?;
    report.packaged_dot_local = observe(r.packaged_dot_local, C::PackagedDotLocal, || {
        packaged_dot_local(l)
    })?;
    report.dev_override_registry =
        observe(r.dev_override_registry, C::DevOverrideRegistry, || {
            registry::dev_override(l)
        })?;
    report.dev_override_effective =
        observe(r.dev_override_effective, C::DevOverrideEffective, || {
            Err(Unavailable::NoDocumentedProbe)
        })?;
    report.api_sets = observe(r.api_sets, C::ApiSets, || {
        Err(Unavailable::NoDocumentedProbe)
    })?;
    report.loaded_modules = observe(r.loaded_modules, C::LoadedModules, || loaded_modules(l))?;
    report.known_dlls = observe(r.known_dlls, C::KnownDlls, || registry::known_dlls(l))?;
    report.package_dependency_graph = observe(
        r.package_dependency_graph,
        C::PackageDependencyGraph,
        || Err(Unavailable::NoDocumentedProbe),
    )?;
    report.search_directories = observe(r.search_directories, C::SearchDirectories, || {
        search_directories(path, search, l)
    })?;
    report.global_search_state = observe(r.global_search_state, C::GlobalSearchState, || {
        Err(Unavailable::NoDocumentedProbe)
    })?;
    // This must remain last: the caller loads on this same thread immediately
    // afterward, with no application callback or activation-context mutation.
    report.activation_context = observe(r.activation_context, C::ActivationContext, || {
        activation::snapshot(l)
    })?;
    Ok(report)
}
