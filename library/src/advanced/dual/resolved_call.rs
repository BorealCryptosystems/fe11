// SPDX-License-Identifier: Apache-2.0
//! One selected combined-operation function, resolved before activity publication.
use super::{DualStep, Error, Mode, Result};
use crate::native::functions::resolve;
use fe11_sys::*;

type DigestInit = unsafe extern "C" fn(CK_SESSION_HANDLE, CK_MECHANISM_PTR) -> CK_RV;
type KeyInit = unsafe extern "C" fn(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE) -> CK_RV;
type Update = unsafe extern "C" fn(
    CK_SESSION_HANDLE,
    CK_BYTE_PTR,
    CK_ULONG,
    CK_BYTE_PTR,
    CK_ULONG_PTR,
) -> CK_RV;
type Output = unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV;
type Input = unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) -> CK_RV;

pub(super) enum Call {
    DigestInit(DigestInit),
    AuthInit(KeyInit),
    CipherInit(KeyInit),
    Update { call: Update, index: usize },
    CipherFinal(Output),
    Residual(Input),
    AuthFinal(Output),
    VerifyFinal(Input),
}

impl Call {
    pub(super) fn resolve(
        table: &crate::interfaces::CommonFunctions,
        mode: Mode,
        step: DualStep,
    ) -> Result<Self> {
        Ok(match step {
            DualStep::AuthInit => match mode {
                Mode::DigestEncrypt | Mode::DecryptDigest => {
                    Self::DigestInit(resolve(table.C_DigestInit, "C_DigestInit")?)
                }
                Mode::SignEncrypt => Self::AuthInit(resolve(table.C_SignInit, "C_SignInit")?),
                Mode::DecryptVerify => Self::AuthInit(resolve(table.C_VerifyInit, "C_VerifyInit")?),
            },
            DualStep::CipherInit => Self::CipherInit(if mode.decrypt() {
                resolve(table.C_DecryptInit, "C_DecryptInit")?
            } else {
                resolve(table.C_EncryptInit, "C_EncryptInit")?
            }),
            DualStep::Update(index) => Self::Update {
                call: match mode {
                    Mode::DigestEncrypt => {
                        resolve(table.C_DigestEncryptUpdate, "C_DigestEncryptUpdate")?
                    }
                    Mode::DecryptDigest => {
                        resolve(table.C_DecryptDigestUpdate, "C_DecryptDigestUpdate")?
                    }
                    Mode::SignEncrypt => resolve(table.C_SignEncryptUpdate, "C_SignEncryptUpdate")?,
                    Mode::DecryptVerify => {
                        resolve(table.C_DecryptVerifyUpdate, "C_DecryptVerifyUpdate")?
                    }
                },
                index,
            },
            DualStep::CipherFinal => Self::CipherFinal(if mode.decrypt() {
                resolve(table.C_DecryptFinal, "C_DecryptFinal")?
            } else {
                resolve(table.C_EncryptFinal, "C_EncryptFinal")?
            }),
            DualStep::Residual => Self::Residual(if mode.mac() {
                resolve(table.C_VerifyUpdate, "C_VerifyUpdate")?
            } else {
                resolve(table.C_DigestUpdate, "C_DigestUpdate")?
            }),
            DualStep::AuthFinal => match mode {
                Mode::DigestEncrypt | Mode::DecryptDigest => {
                    Self::AuthFinal(resolve(table.C_DigestFinal, "C_DigestFinal")?)
                }
                Mode::SignEncrypt => Self::AuthFinal(resolve(table.C_SignFinal, "C_SignFinal")?),
                Mode::DecryptVerify => {
                    Self::VerifyFinal(resolve(table.C_VerifyFinal, "C_VerifyFinal")?)
                }
            },
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::CombinedOperations(
                    crate::CombinedOperationsRejection::DualNotActive,
                )))
            }
        })
    }
}
