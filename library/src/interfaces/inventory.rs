// SPDX-License-Identifier: Apache-2.0
//! Owned interface metadata; enumeration does not select or initialize a table.
use super::prefix;
use crate::{Error, NativeInterfacesRejection as Reason, RejectionReason, Result};
use fe11_sys::*;

/// Caller-selected bounds for one interface inventory observation.
#[derive(Clone, Copy, Debug)]
pub struct InterfaceInventoryLimits {
    /// Maximum number of interface descriptors.
    pub interfaces: usize,
    /// Maximum count/fill attempts, including the first. Zero makes no native call.
    pub attempts: usize,
    /// Maximum readable bytes per name, including its terminating NUL.
    pub name_bytes: usize,
    /// Maximum total copied name bytes, excluding NUL terminators.
    pub total_name_bytes: usize,
}

/// One owned descriptor, with no native pointer or callable table.
#[derive(Debug, PartialEq, Eq)]
pub struct InterfaceDescriptor {
    /// Exact name bytes without the terminating NUL. No UTF-8 conversion is imposed.
    pub name: Vec<u8>,
    /// Version prefix for the exact standard name `PKCS 11`; other tables are opaque.
    /// An unknown standard version remains observable but need not be selectable.
    pub standard_version: Option<(u8, u8)>,
    /// All native flags, including bits unknown to this library.
    pub flags: u64,
}

/// Snapshot of the provider's interface list, in native order with duplicates.
/// It grants no initialization, session, or future image authority.
#[derive(Debug)]
pub struct InterfaceInventory {
    /// Fully copied descriptors. The native image need not remain loaded.
    pub interfaces: Vec<InterfaceDescriptor>,
    /// Observations requested through the builder's Windows loader options.
    pub loader_report: crate::WindowsLoaderReport,
}

fn rejected(reason: Reason) -> Error {
    Error::Rejected(RejectionReason::NativeInterfaces(reason))
}

/// Copy names while the caller retains the trusted provider and excludes Finalize.
/// Unknown interfaces never have their table contents interpreted.
unsafe fn copy_descriptors(
    entries: &[CK_INTERFACE],
    limits: InterfaceInventoryLimits,
) -> Result<Vec<InterfaceDescriptor>> {
    let mut output = Vec::new();
    output
        .try_reserve_exact(entries.len())
        .map_err(|_| rejected(Reason::InterfaceAllocation))?;
    let mut total = 0usize;
    for (index, entry) in entries.iter().enumerate() {
        if entry.pInterfaceName.is_null() {
            return Err(rejected(Reason::NullInterfaceName));
        }
        if entry.pFunctionList.is_null() {
            return Err(rejected(Reason::NullInterfaceTable));
        }
        let mut length = None;
        for offset in 0..limits.name_bytes {
            // SAFETY: trusted provider supplies a live NUL-terminated name;
            // stop at its terminator and at the caller's explicit read bound.
            if unsafe { *entry.pInterfaceName.add(offset) } == 0 {
                length = Some(offset);
                break;
            }
        }
        let length = length.ok_or_else(|| {
            rejected(Reason::InterfaceNameLimit {
                index,
                limit: limits.name_bytes,
            })
        })?;
        total = total
            .checked_add(length)
            .filter(|n| *n <= limits.total_name_bytes)
            .ok_or_else(|| {
                rejected(Reason::InterfaceNamesTotalLimit {
                    index,
                    limit: limits.total_name_bytes,
                })
            })?;
        let mut name = Vec::new();
        name.try_reserve_exact(length)
            .map_err(|_| rejected(Reason::InterfaceAllocation))?;
        // SAFETY: the preceding bounded scan established this initialized span;
        // the provider keeps its names immutable while its image is retained.
        name.extend_from_slice(unsafe { std::slice::from_raw_parts(entry.pInterfaceName, length) });
        let standard_version = if name == b"PKCS 11" {
            // SAFETY: only standard tables promise the CK_VERSION prefix.
            Some(unsafe { prefix(entry)? })
        } else {
            None
        };
        output.push(InterfaceDescriptor {
            name,
            standard_version,
            flags: entry.flags as u64,
        });
    }
    Ok(output)
}

pub(crate) fn observe(
    list: unsafe extern "C" fn(*mut CK_INTERFACE, *mut CK_ULONG) -> CK_RV,
    limits: InterfaceInventoryLimits,
    uncertain: &std::cell::Cell<bool>,
) -> Result<Vec<InterfaceDescriptor>> {
    super::collection::collect(
        list,
        limits.interfaces,
        limits.attempts,
        uncertain,
        || Ok(()),
        |entries| {
            // SAFETY: the collector established the initialized returned span;
            // the loading owner retains the provider and its immutable names.
            unsafe { copy_descriptors(entries, limits) }
        },
    )
}
