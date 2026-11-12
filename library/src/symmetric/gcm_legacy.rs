// SPDX-License-Identifier: Apache-2.0
//! Explicit historical GCM representation omitting ulIvBits.
//! This is an application-selected ABI, never inferred from a module version.
use fe11_sys::{CK_BYTE_PTR, CK_ULONG};

// The Windows PKCS#11 headers use one-byte packing; Unix uses native C layout.
// We never borrow a potentially unaligned packed field. The owning frame keeps
// all pointer targets alive, just as for CK_GCM_PARAMS in fe11-sys.
#[repr(C)]
#[cfg_attr(target_os = "windows", repr(packed))]
#[allow(non_snake_case)]
pub(crate) struct GcmWithoutIvBits {
    pub pIv: CK_BYTE_PTR,
    pub ulIvLen: CK_ULONG,
    pub pAAD: CK_BYTE_PTR,
    pub ulAADLen: CK_ULONG,
    pub ulTagBits: CK_ULONG,
}
