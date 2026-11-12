// SPDX-License-Identifier: Apache-2.0
//! Inspect the executable mapping without allocating the process's maps file.
use super::{mapping_matches, FileIdentity};
use crate::{Error, Result};
use std::io::Read;

/// Scan the kernel's five leading fields and discard filenames while reading.
/// The scratch size follows integer widths, not a ceiling on mapping count or
/// pathname length. The retained library/file owners prevent normal unloading
/// and inode reuse throughout this observation and subsequent dispatch.
pub(crate) fn mapped_image_matches(address: usize, identity: FileIdentity) -> Result<bool> {
    // address-address, permissions, u64 offset, u32:u32 device, u64 decimal
    // inode, and exactly four normalized separators. No filename is stored.
    const PREFIX_BYTES: usize = (usize::BITS as usize / 4) * 2 + 1 + 4 + 16 + 17 + 20 + 4;
    let mut prefix = [0u8; PREFIX_BYTES];
    let mut length = 0;
    let mut fields = 0;
    let mut in_field = false;
    let mut discard = false;
    let mut chunk = [0u8; 4096];
    let mut input = std::fs::File::open("/proc/self/maps").map_err(|_| {
        Error::Rejected(crate::RejectionReason::NativeLoading(
            crate::NativeLoadingRejection::ModuleMappingUnavailable,
        ))
    })?;
    loop {
        let count = match input.read(&mut chunk) {
            Ok(count) => count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => {
                return Err(Error::Rejected(crate::RejectionReason::NativeLoading(
                    crate::NativeLoadingRejection::ModuleMappingUnavailable,
                )))
            }
        };
        if count == 0 {
            // Also handle an EOF directly after the fifth field.
            return Ok(!discard
                && fields == 4
                && in_field
                && mapping_matches(&prefix[..length], address, identity));
        }
        for &byte in &chunk[..count] {
            if byte == b'\n' {
                if !discard
                    && fields == 4
                    && in_field
                    && mapping_matches(&prefix[..length], address, identity)
                {
                    return Ok(true);
                }
                length = 0;
                fields = 0;
                in_field = false;
                discard = false;
                continue;
            }
            if discard {
                continue;
            }
            if byte.is_ascii_whitespace() {
                if in_field {
                    fields += 1;
                    in_field = false;
                    if fields == 5 {
                        if mapping_matches(&prefix[..length], address, identity) {
                            return Ok(true);
                        }
                        discard = true;
                    }
                }
                continue;
            }
            if !in_field && fields != 0 {
                if length == prefix.len() {
                    discard = true;
                    continue;
                }
                prefix[length] = b' ';
                length += 1;
            }
            if length == prefix.len() {
                // This cannot be a representable kernel mapping prefix. Skip
                // the entire remaining line, never interpret a truncated value.
                discard = true;
                continue;
            }
            prefix[length] = byte;
            length += 1;
            in_field = true;
        }
    }
}
