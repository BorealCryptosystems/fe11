// SPDX-License-Identifier: Apache-2.0
//! Owned QueryActCtx outputs. Returned pointers never escape their allocation.
use super::*;

#[repr(C)]
#[derive(Clone, Copy)]
struct ContextInfo {
    flags: u32,
    format_version: u32,
    assembly_count: u32,
    root_type: u32,
    root_chars: u32,
    configuration_type: u32,
    configuration_chars: u32,
    app_type: u32,
    app_chars: u32,
    root: *const u16,
    configuration: *const u16,
    app: *const u16,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct AssemblyInfo {
    flags: u32,
    identity_bytes: u32,
    manifest_type: u32,
    manifest_bytes: u32,
    manifest_time: i64,
    policy_type: u32,
    policy_bytes: u32,
    policy_time: i64,
    metadata_index: u32,
    manifest_major: u32,
    manifest_minor: u32,
    policy_major: u32,
    policy_minor: u32,
    directory_bytes: u32,
    identity: *const u16,
    manifest: *const u16,
    policy: *const u16,
    directory: *const u16,
    file_count: u32,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct FileInfo {
    flags: u32,
    name_bytes: u32,
    path_bytes: u32,
    name: *const u16,
    path: *const u16,
}
#[repr(C)]
struct QueryIndex {
    assembly: u32,
    file: u32,
}
#[link(name = "kernel32")]
extern "system" {
    fn QueryActCtxW(
        flags: u32,
        context: *mut c_void,
        sub: *const c_void,
        class: u32,
        output: *mut c_void,
        bytes: usize,
        required: *mut usize,
    ) -> i32;
}
struct OwnedQuery {
    words: Vec<u64>,
    valid_bytes: usize,
}
impl OwnedQuery {
    /// T must be the matching repr(C) output header and admit every bit pattern.
    unsafe fn header<T: Copy>(&self) -> Probe<T> {
        if size_of::<T>() > self.valid_bytes {
            return Err(Unavailable::InvalidOutput);
        }
        // SAFETY: caller selects the exact native header; full bytes are owned
        // and initialized. Unaligned read does not impose an extra ABI alignment.
        Ok(unsafe { std::ptr::read_unaligned(self.words.as_ptr().cast::<T>()) })
    }
    fn chars(&self, pointer: *const u16, count: usize, limits: Limits) -> Probe<OsString> {
        if pointer.is_null() {
            return if count == 0 {
                Ok(OsString::new())
            } else {
                Err(Unavailable::InvalidOutput)
            };
        }
        let units = count.checked_add(1).ok_or(Unavailable::ResourceLimit)?;
        if units > limits.maximum_path_code_units.get() {
            return Err(Unavailable::ResourceLimit);
        }
        let bytes = units.checked_mul(2).ok_or(Unavailable::ResourceLimit)?;
        let offset = (pointer as usize)
            .checked_sub(self.words.as_ptr() as usize)
            .ok_or(Unavailable::InvalidOutput)?;
        let end = offset
            .checked_add(bytes)
            .ok_or(Unavailable::InvalidOutput)?;
        if offset % 2 != 0 || end > self.valid_bytes {
            return Err(Unavailable::InvalidOutput);
        }
        // SAFETY: derive the pointer from our allocation after checking its full
        // extent and u16 alignment; do not dereference the returned native pointer.
        let text = unsafe {
            std::slice::from_raw_parts(
                self.words.as_ptr().cast::<u8>().add(offset).cast::<u16>(),
                units,
            )
        };
        if text[count] != 0 || text[..count].contains(&0) {
            return Err(Unavailable::InvalidOutput);
        }
        Ok(OsString::from_wide(&text[..count]))
    }
    fn bytes(&self, pointer: *const u16, count: u32, limits: Limits) -> Probe<OsString> {
        if count % 2 != 0 {
            return Err(Unavailable::InvalidOutput);
        }
        self.chars(pointer, count as usize / 2, limits)
    }
}
fn query(class: u32, index: Option<&QueryIndex>, limits: Limits) -> Probe<OwnedQuery> {
    const USE_ACTIVE_ACTCTX: u32 = 4;
    let sub = index.map_or(std::ptr::null(), |index| {
        (index as *const QueryIndex).cast()
    });
    let mut required = 0usize;
    // SAFETY: documented size-only query; optional index is an aligned live
    // pair (assembly class reads its first DWORD). No output buffer is supplied.
    let first = unsafe {
        QueryActCtxW(
            USE_ACTIVE_ACTCTX,
            std::ptr::null_mut(),
            sub,
            class,
            std::ptr::null_mut(),
            0,
            &mut required,
        )
    };
    if first == 0 {
        let cause = os_error("QueryActCtxW");
        if !matches!(cause, Unavailable::Os { code: 122, .. }) {
            return Err(cause);
        }
    }
    if required == 0 {
        return Err(Unavailable::InvalidOutput);
    }
    if required > limits.maximum_activation_query_bytes.get() {
        return Err(Unavailable::ResourceLimit);
    }
    let count = required.checked_add(7).ok_or(Unavailable::ResourceLimit)? / 8;
    let mut words = buffer(count, 0u64)?;
    let capacity = required;
    // SAFETY: aligned initialized storage holds at least capacity bytes. The
    // single fill may fail if the active context changed; it is never retried.
    let ok = unsafe {
        QueryActCtxW(
            USE_ACTIVE_ACTCTX,
            std::ptr::null_mut(),
            sub,
            class,
            words.as_mut_ptr().cast(),
            capacity,
            &mut required,
        )
    };
    if ok == 0 {
        return Err(os_error("QueryActCtxW"));
    }
    if required == 0 || required > capacity {
        return Err(Unavailable::ChangedDuringObservation);
    }
    Ok(OwnedQuery {
        words,
        valid_bytes: required,
    })
}
pub(super) fn snapshot(limits: Limits) -> Probe<WindowsActivationContext> {
    let root = query(2, None, limits)?;
    // SAFETY: information class 2 returns this all-bit-pattern-valid header.
    let info: ContextInfo = unsafe { root.header()? };
    if info.assembly_count as usize > limits.maximum_activation_assemblies {
        return Err(Unavailable::ResourceLimit);
    }
    let mut result = WindowsActivationContext {
        root_manifest: root.chars(info.root, info.root_chars as usize, limits)?,
        root_configuration: root.chars(
            info.configuration,
            info.configuration_chars as usize,
            limits,
        )?,
        application_directory: root.chars(info.app, info.app_chars as usize, limits)?,
        assemblies: Vec::new(),
    };
    let mut total_files = 0usize;
    for assembly in 1..=info.assembly_count {
        let mut index = QueryIndex { assembly, file: 0 };
        let raw = query(3, Some(&index), limits)?;
        // SAFETY: information class 3 returns this exact native header.
        let info: AssemblyInfo = unsafe { raw.header()? };
        total_files = total_files
            .checked_add(info.file_count as usize)
            .ok_or(Unavailable::ResourceLimit)?;
        if total_files > limits.maximum_activation_files {
            return Err(Unavailable::ResourceLimit);
        }
        let mut entry = WindowsActivationAssembly {
            identity: raw.bytes(info.identity, info.identity_bytes, limits)?,
            manifest: raw.bytes(info.manifest, info.manifest_bytes, limits)?,
            policy: raw.bytes(info.policy, info.policy_bytes, limits)?,
            directory: raw.bytes(info.directory, info.directory_bytes, limits)?,
            files: Vec::new(),
        };
        for file in 0..info.file_count {
            index.file = file;
            let raw = query(4, Some(&index), limits)?;
            // SAFETY: information class 4 returns this exact native header.
            let info: FileInfo = unsafe { raw.header()? };
            push(
                &mut entry.files,
                WindowsActivationFile {
                    name: raw.bytes(info.name, info.name_bytes, limits)?,
                    path: raw.bytes(info.path, info.path_bytes, limits)?,
                },
            )?;
        }
        push(&mut result.assemblies, entry)?;
    }
    Ok(result)
}
