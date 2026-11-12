// SPDX-License-Identifier: Apache-2.0
//! A selected cipher entry resolved before the operation is armed.

use super::{Error, Result, Stage};
use fe11_sys::*;

type Init = unsafe extern "C" fn(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE) -> CK_RV;
type Data = unsafe extern "C" fn(
    CK_SESSION_HANDLE,
    CK_BYTE_PTR,
    CK_ULONG,
    CK_BYTE_PTR,
    CK_ULONG_PTR,
) -> CK_RV;
type Final = unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV;

pub(super) enum Call {
    Init(Init),
    Data { call: Data, index: usize },
    Final(Final),
}

fn unavailable() -> Error {
    Error::Rejected(crate::RejectionReason::CipherContinuation(
        crate::CipherContinuationRejection::SelectedBlockCipherFunctionUnavailable,
    ))
}

impl Call {
    pub(super) fn resolve(
        table: &crate::interfaces::CommonFunctions,
        decrypt: bool,
        stage: Stage,
    ) -> Result<Self> {
        // The enum carries the chosen signature and fragment index together.
        // No later phase transition can select a different nullable table entry.
        Ok(match (decrypt, stage) {
            (false, Stage::Init(_)) => Self::Init(table.C_EncryptInit.ok_or_else(unavailable)?),
            (true, Stage::Init(_)) => Self::Init(table.C_DecryptInit.ok_or_else(unavailable)?),
            (false, Stage::Single) => Self::Data {
                call: table.C_Encrypt.ok_or_else(unavailable)?,
                index: 0,
            },
            (true, Stage::Single) => Self::Data {
                call: table.C_Decrypt.ok_or_else(unavailable)?,
                index: 0,
            },
            (false, Stage::Update { index, .. }) => Self::Data {
                call: table.C_EncryptUpdate.ok_or_else(unavailable)?,
                index,
            },
            (true, Stage::Update { index, .. }) => Self::Data {
                call: table.C_DecryptUpdate.ok_or_else(unavailable)?,
                index,
            },
            (false, Stage::Final) => Self::Final(table.C_EncryptFinal.ok_or_else(unavailable)?),
            (true, Stage::Final) => Self::Final(table.C_DecryptFinal.ok_or_else(unavailable)?),
            _ => return Err(unavailable()),
        })
    }
}
