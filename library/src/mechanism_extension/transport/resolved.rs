// SPDX-License-Identifier: Apache-2.0
//! Non-null creation functions selected before publishing creation effects.
use fe11_sys::*;

pub(super) type UnwrapKey = unsafe extern "C" fn(
    CK_SESSION_HANDLE,
    CK_MECHANISM_PTR,
    CK_OBJECT_HANDLE,
    CK_BYTE_PTR,
    CK_ULONG,
    CK_ATTRIBUTE_PTR,
    CK_ULONG,
    CK_OBJECT_HANDLE_PTR,
) -> CK_RV;

pub(super) type EncapsulateKey = unsafe extern "C" fn(
    CK_SESSION_HANDLE,
    CK_MECHANISM_PTR,
    CK_OBJECT_HANDLE,
    CK_ATTRIBUTE_PTR,
    CK_ULONG,
    CK_BYTE_PTR,
    CK_ULONG_PTR,
    CK_OBJECT_HANDLE_PTR,
) -> CK_RV;

pub(super) type DecapsulateKey = unsafe extern "C" fn(
    CK_SESSION_HANDLE,
    CK_MECHANISM_PTR,
    CK_OBJECT_HANDLE,
    CK_ATTRIBUTE_PTR,
    CK_ULONG,
    CK_BYTE_PTR,
    CK_ULONG,
    CK_OBJECT_HANDLE_PTR,
) -> CK_RV;
