// SPDX-License-Identifier: Apache-2.0
use super::*;

#[repr(C)]
struct SystemInfo {
    architecture: u16,
    reserved: u16,
    page_size: u32,
    minimum_address: *mut c_void,
    maximum_address: *mut c_void,
    active_processor_mask: usize,
    processor_count: u32,
    processor_type: u32,
    allocation_granularity: u32,
    processor_level: u16,
    processor_revision: u16,
}
#[link(name = "kernel32")]
extern "system" {
    fn GetNativeSystemInfo(info: *mut SystemInfo);
}
#[link(name = "advapi32")]
extern "system" {
    fn RegOpenKeyExW(
        key: *mut c_void,
        name: *const u16,
        options: u32,
        access: u32,
        result: *mut *mut c_void,
    ) -> u32;
    fn RegCloseKey(key: *mut c_void) -> u32;
    fn RegQueryValueExW(
        key: *mut c_void,
        name: *const u16,
        reserved: *const u32,
        kind: *mut u32,
        data: *mut u8,
        bytes: *mut u32,
    ) -> u32;
    fn RegEnumValueW(
        key: *mut c_void,
        index: u32,
        name: *mut u16,
        name_units: *mut u32,
        reserved: *const u32,
        kind: *mut u32,
        data: *mut u8,
        bytes: *mut u32,
    ) -> u32;
}
struct Key(*mut c_void);
impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: only a successfully opened registry handle is owned here.
        unsafe {
            RegCloseKey(self.0);
        }
    }
}
fn native_x64_view() -> Probe<u32> {
    // SAFETY: every field admits zero; the exact repr(C) Win32 output is writable.
    let mut info: SystemInfo = unsafe { std::mem::zeroed() };
    // SAFETY: the exclusive stack output has the SYSTEM_INFO layout and remains
    // alive for this synchronous Win32 call, which retains no pointer.
    unsafe {
        GetNativeSystemInfo(&mut info);
    }
    if !cfg!(target_arch = "x86_64") || info.architecture != 9 {
        return Err(Unavailable::ProvenanceUnavailable);
    }
    Ok(0x100) // KEY_WOW64_64KEY; no inference about emulated architectures.
}
fn wide_literal(text: &str) -> Probe<Vec<u16>> {
    let mut out = buffer(
        text.len()
            .checked_add(1)
            .ok_or(Unavailable::ResourceLimit)?,
        0u16,
    )?;
    // All callers use ASCII registry literals, not external names.
    if !text.is_ascii() || text.as_bytes().contains(&0) {
        return Err(Unavailable::InvalidOutput);
    }
    for (slot, byte) in out.iter_mut().zip(text.bytes()) {
        *slot = u16::from(byte);
    }
    Ok(out)
}
fn open(name: &str) -> Probe<Key> {
    let view = native_x64_view()?;
    let name = wide_literal(name)?;
    let mut key = std::ptr::null_mut();
    // SAFETY: predefined HKLM pseudo-handle, terminated constant path, output
    // handle; query-only access. No create, set, delete or change-notification rights.
    let status = unsafe {
        RegOpenKeyExW(
            -2147483646isize as *mut c_void,
            name.as_ptr(),
            0,
            1 | view,
            &mut key,
        )
    };
    if status != 0 {
        return Err(Unavailable::Os {
            function: "RegOpenKeyExW",
            code: status,
        });
    }
    if key.is_null() {
        return Err(Unavailable::InvalidOutput);
    }
    Ok(Key(key))
}
pub(super) fn dev_override(limits: Limits) -> Probe<Option<u32>> {
    let key =
        match open(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options") {
            Ok(key) => key,
            Err(Unavailable::Os { code: 2, .. }) => return Ok(None),
            Err(cause) => return Err(cause),
        };
    if limits.maximum_registry_value_bytes.get() < 4 {
        return Err(Unavailable::ResourceLimit);
    }
    let name = wide_literal("DevOverrideEnable")?;
    let mut value = [0u8; 4];
    let mut bytes = 4u32;
    let mut kind = 0;
    // SAFETY: exact initialized four-byte output, live query-only key and name.
    let status = unsafe {
        RegQueryValueExW(
            key.0,
            name.as_ptr(),
            std::ptr::null(),
            &mut kind,
            value.as_mut_ptr(),
            &mut bytes,
        )
    };
    if status == 2 {
        return Ok(None);
    }
    if status != 0 {
        return Err(Unavailable::Os {
            function: "RegQueryValueExW",
            code: status,
        });
    }
    if kind != 4 || bytes != 4 {
        return Err(Unavailable::InvalidOutput);
    }
    Ok(Some(u32::from_le_bytes(value)))
}
pub(super) fn known_dlls(limits: Limits) -> Probe<Vec<WindowsLoaderRegistryValue>> {
    let key = open(r"SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs")?;
    let mut values = Vec::new();
    // One additional bounded query determines whether the selected count is
    // sufficient. An over-limit inventory is never published as complete.
    for index in 0..=limits.maximum_registry_entries {
        let mut name = buffer(limits.maximum_path_code_units.get(), 0u16)?;
        let mut data = buffer(limits.maximum_registry_value_bytes.get(), 0u8)?;
        let mut name_units = dword(name.len())?;
        let mut bytes = dword(data.len())?;
        let mut kind = 0;
        // SAFETY: live key, initialized independent outputs with checked sizes;
        // the OS returns lengths, never Rust vector ownership.
        let status = unsafe {
            RegEnumValueW(
                key.0,
                dword(index)?,
                name.as_mut_ptr(),
                &mut name_units,
                std::ptr::null(),
                &mut kind,
                data.as_mut_ptr(),
                &mut bytes,
            )
        };
        if status == 259 {
            return Ok(values);
        } // ERROR_NO_MORE_ITEMS
        if status != 0 {
            return Err(Unavailable::Os {
                function: "RegEnumValueW",
                code: status,
            });
        }
        if index == limits.maximum_registry_entries {
            return Err(Unavailable::ResourceLimit);
        }
        let n = name_units as usize;
        if n >= name.len() || name[n] != 0 || name[..n].contains(&0) || bytes as usize > data.len()
        {
            return Err(Unavailable::InvalidOutput);
        }
        data.truncate(bytes as usize);
        push(
            &mut values,
            WindowsLoaderRegistryValue {
                name: OsString::from_wide(&name[..n]),
                value_type: kind,
                data,
            },
        )?;
    }
    Err(Unavailable::ResourceLimit)
}
