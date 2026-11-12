// SPDX-License-Identifier: Apache-2.0
//! Non-null signatures for the selected message function.
use fe11_sys::*;

pub(crate) type Init =
    unsafe extern "C" fn(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE) -> CK_RV;

pub(crate) type Begin =
    unsafe extern "C" fn(CK_SESSION_HANDLE, CK_VOID_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG) -> CK_RV;

pub(crate) type Single = unsafe extern "C" fn(
    CK_SESSION_HANDLE,
    CK_VOID_PTR,
    CK_ULONG,
    CK_BYTE_PTR,
    CK_ULONG,
    CK_BYTE_PTR,
    CK_ULONG,
    CK_BYTE_PTR,
    CK_ULONG_PTR,
) -> CK_RV;

pub(crate) type Next = unsafe extern "C" fn(
    CK_SESSION_HANDLE,
    CK_VOID_PTR,
    CK_ULONG,
    CK_BYTE_PTR,
    CK_ULONG,
    CK_BYTE_PTR,
    CK_ULONG_PTR,
    CK_FLAGS,
) -> CK_RV;

pub(crate) type Final = unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV;
