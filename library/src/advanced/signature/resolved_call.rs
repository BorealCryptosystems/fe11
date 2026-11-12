// SPDX-License-Identifier: Apache-2.0
//! The selected signature entry and its exact C argument shape.
use super::{Error, Kind, MessageRoute, Result, Stage};
use crate::native::{functions::resolve, Native};
use fe11_sys::*;

type Init = unsafe extern "C" fn(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE) -> CK_RV;
type SignatureInit = unsafe extern "C" fn(
    CK_SESSION_HANDLE,
    CK_MECHANISM_PTR,
    CK_OBJECT_HANDLE,
    CK_BYTE_PTR,
    CK_ULONG,
) -> CK_RV;
type Input = unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) -> CK_RV;
type Sign = unsafe extern "C" fn(
    CK_SESSION_HANDLE,
    CK_BYTE_PTR,
    CK_ULONG,
    CK_BYTE_PTR,
    CK_ULONG_PTR,
) -> CK_RV;
type SignFinal = unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV;
type Verify =
    unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG) -> CK_RV;
type Final = unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV;

pub(super) enum Call {
    Init(Init),
    SignatureInit(SignatureInit),
    Input(Input),
    Sign(Sign),
    SignFinal(SignFinal),
    Verify(Verify),
    VerifyFinal(Input),
    Final(Final),
}

impl Call {
    pub(super) fn resolve(
        native: &Native,
        kind: Kind,
        stage: Stage,
        route: MessageRoute,
    ) -> Result<Self> {
        let table = &native.table;
        let signature = native.verify_signature.as_ref();
        Ok(match (kind, stage, route) {
            (Kind::Sign, Stage::Init, _) => Self::Init(resolve(table.C_SignInit, "C_SignInit")?),
            (Kind::Verify, Stage::Init, _) => {
                Self::Init(resolve(table.C_VerifyInit, "C_VerifyInit")?)
            }
            (Kind::VerifySignature, Stage::Init, _) => Self::SignatureInit(resolve(
                signature.and_then(|f| f.init),
                "C_VerifySignatureInit",
            )?),
            (Kind::Sign, Stage::Update, _) => {
                Self::Input(resolve(table.C_SignUpdate, "C_SignUpdate")?)
            }
            (Kind::Verify, Stage::Update, _) => {
                Self::Input(resolve(table.C_VerifyUpdate, "C_VerifyUpdate")?)
            }
            (Kind::VerifySignature, Stage::Update, _) => Self::Input(resolve(
                signature.and_then(|f| f.update),
                "C_VerifySignatureUpdate",
            )?),
            (Kind::Sign, Stage::Terminal, MessageRoute::Single) => {
                Self::Sign(resolve(table.C_Sign, "C_Sign")?)
            }
            (Kind::Sign, Stage::Terminal, MessageRoute::Multipart) => {
                Self::SignFinal(resolve(table.C_SignFinal, "C_SignFinal")?)
            }
            (Kind::Verify, Stage::Terminal, MessageRoute::Single) => {
                Self::Verify(resolve(table.C_Verify, "C_Verify")?)
            }
            (Kind::Verify, Stage::Terminal, MessageRoute::Multipart) => {
                Self::VerifyFinal(resolve(table.C_VerifyFinal, "C_VerifyFinal")?)
            }
            (Kind::VerifySignature, Stage::Terminal, MessageRoute::Single) => Self::Input(resolve(
                signature.and_then(|f| f.single),
                "C_VerifySignature",
            )?),
            (Kind::VerifySignature, Stage::Terminal, MessageRoute::Multipart) => Self::Final(
                resolve(signature.and_then(|f| f.finish), "C_VerifySignatureFinal")?,
            ),
            _ => {
                return Err(Error::Rejected(
                    crate::RejectionReason::SignatureContinuation(
                        crate::SignatureContinuationRejection::SignatureNotActive,
                    ),
                ))
            }
        })
    }
}
