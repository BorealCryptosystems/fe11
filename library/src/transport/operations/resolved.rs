// SPDX-License-Identifier: Apache-2.0

//! Non-null transport entries bound to the prepared AAD selection.

use fe11_sys::*;

use crate::{native::Native, Error, Result};

pub(super) type WrapKey = unsafe extern "C" fn(
    CK_SESSION_HANDLE,
    CK_MECHANISM_PTR,
    CK_OBJECT_HANDLE,
    CK_OBJECT_HANDLE,
    CK_BYTE_PTR,
    CK_ULONG_PTR,
) -> CK_RV;

pub(super) type WrapKeyAuthenticated = unsafe extern "C" fn(
    CK_SESSION_HANDLE,
    CK_MECHANISM_PTR,
    CK_OBJECT_HANDLE,
    CK_OBJECT_HANDLE,
    CK_BYTE_PTR,
    CK_ULONG,
    CK_BYTE_PTR,
    CK_ULONG_PTR,
) -> CK_RV;

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

pub(super) type UnwrapKeyAuthenticated = unsafe extern "C" fn(
    CK_SESSION_HANDLE,
    CK_MECHANISM_PTR,
    CK_OBJECT_HANDLE,
    CK_BYTE_PTR,
    CK_ULONG,
    CK_ATTRIBUTE_PTR,
    CK_ULONG,
    CK_BYTE_PTR,
    CK_ULONG,
    CK_OBJECT_HANDLE_PTR,
) -> CK_RV;

#[derive(Clone, Copy)]
pub(super) enum Wrap {
    Standard(WrapKey),
    Authenticated {
        native: WrapKeyAuthenticated,
        aad: CK_BYTE_PTR,
        aad_len: CK_ULONG,
    },
}
impl Wrap {
    pub(super) fn resolve(native: &Native, aad: Option<(CK_BYTE_PTR, CK_ULONG)>) -> Result<Self> {
        Ok(match aad {
            Some((aad, aad_len)) => Self::Authenticated {
                native: native.authenticated_transport.and_then(|f| f.wrap).ok_or(Error::Rejected(
                    crate::RejectionReason::KeyTransport(crate::KeyTransportRejection::CWrapKeyAuthenticatedUnavailableInSelectedInterface)))?,
                aad, aad_len,
            },
            None => Self::Standard(native.table.C_WrapKey.ok_or(Error::Rejected(
                crate::RejectionReason::KeyTransport(crate::KeyTransportRejection::CWrapKeyUnavailable)))?),
        })
    }
}

#[derive(Clone, Copy)]
pub(super) enum Unwrap {
    Standard(UnwrapKey),
    Authenticated {
        native: UnwrapKeyAuthenticated,
        aad: CK_BYTE_PTR,
        aad_len: CK_ULONG,
    },
}
impl Unwrap {
    pub(super) fn resolve(native: &Native, aad: Option<(CK_BYTE_PTR, CK_ULONG)>) -> Result<Self> {
        Ok(match aad {
            Some((aad, aad_len)) => Self::Authenticated {
                native: native.authenticated_transport.and_then(|f| f.unwrap).ok_or(Error::Rejected(
                    crate::RejectionReason::KeyTransport(crate::KeyTransportRejection::CUnwrapKeyAuthenticatedUnavailableInSelectedInterface)))?,
                aad, aad_len,
            },
            None => Self::Standard(native.table.C_UnwrapKey.ok_or(Error::Rejected(
                crate::RejectionReason::KeyTransport(crate::KeyTransportRejection::CUnwrapKeyUnavailable)))?),
        })
    }
}
