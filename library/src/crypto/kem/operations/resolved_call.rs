// SPDX-License-Identifier: Apache-2.0

//! Resolve the selected KEM entry before creation dispatch.

use fe11_sys::*;

use crate::{Error, Result};

use super::Direction;

type EncapsulateKey = unsafe extern "C" fn(
    CK_SESSION_HANDLE,
    CK_MECHANISM_PTR,
    CK_OBJECT_HANDLE,
    CK_ATTRIBUTE_PTR,
    CK_ULONG,
    CK_BYTE_PTR,
    CK_ULONG_PTR,
    CK_OBJECT_HANDLE_PTR,
) -> CK_RV;

type DecapsulateKey = unsafe extern "C" fn(
    CK_SESSION_HANDLE,
    CK_MECHANISM_PTR,
    CK_OBJECT_HANDLE,
    CK_ATTRIBUTE_PTR,
    CK_ULONG,
    CK_BYTE_PTR,
    CK_ULONG,
    CK_OBJECT_HANDLE_PTR,
) -> CK_RV;

pub(super) enum Call {
    Encapsulate(EncapsulateKey),
    Decapsulate(DecapsulateKey),
}
impl Call {
    pub(super) fn resolve(
        functions: crate::interfaces::KemFunctions,
        direction: &Direction<'_>,
    ) -> Result<Self> {
        Ok(match direction {
            Direction::Encapsulate(_) => Self::Encapsulate(functions.encapsulate.ok_or(
                Error::Rejected(crate::RejectionReason::KeyEncapsulation(
                    crate::KeyEncapsulationRejection::CEncapsulateKeyUnavailable,
                )),
            )?),
            Direction::Decapsulate(_, _) => Self::Decapsulate(functions.decapsulate.ok_or(
                Error::Rejected(crate::RejectionReason::KeyEncapsulation(
                    crate::KeyEncapsulationRejection::CDecapsulateKeyUnavailable,
                )),
            )?),
        })
    }
}
