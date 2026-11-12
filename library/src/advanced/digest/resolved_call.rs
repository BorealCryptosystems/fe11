// SPDX-License-Identifier: Apache-2.0
//! Digest function selection, before the retained frame is marked active.

use super::{Error, Result, Step};
use crate::native::functions::resolve;
use fe11_sys::*;

type Init = unsafe extern "C" fn(CK_SESSION_HANDLE, CK_MECHANISM_PTR) -> CK_RV;
type Single = unsafe extern "C" fn(
    CK_SESSION_HANDLE,
    CK_BYTE_PTR,
    CK_ULONG,
    CK_BYTE_PTR,
    CK_ULONG_PTR,
) -> CK_RV;
type Update = unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) -> CK_RV;
type Final = unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV;

pub(super) enum Call {
    Init(Init),
    Single(Single),
    Update { call: Update, index: usize },
    Final(Final),
}

impl Call {
    pub(super) fn resolve(table: &crate::interfaces::CommonFunctions, step: Step) -> Result<Self> {
        Ok(match step {
            Step::Init => Self::Init(resolve(table.C_DigestInit, "C_DigestInit")?),
            Step::Single => Self::Single(resolve(table.C_Digest, "C_Digest")?),
            Step::Update(index) => Self::Update {
                call: resolve(table.C_DigestUpdate, "C_DigestUpdate")?,
                index,
            },
            Step::Final => Self::Final(resolve(table.C_DigestFinal, "C_DigestFinal")?),
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::DigestContinuation(
                    crate::DigestContinuationRejection::OperationNotActive,
                )))
            }
        })
    }
}
