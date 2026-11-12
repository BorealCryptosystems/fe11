// SPDX-License-Identifier: Apache-2.0
//! Selected recovery function and its output contract, resolved before dispatch.
use super::{Error, Kind, RecoverOutputPlan, Result, Stage};
use fe11_sys::*;

type Init = unsafe extern "C" fn(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE) -> CK_RV;
type Output = unsafe extern "C" fn(
    CK_SESSION_HANDLE,
    CK_BYTE_PTR,
    CK_ULONG,
    CK_BYTE_PTR,
    CK_ULONG_PTR,
) -> CK_RV;

pub(super) enum Call {
    Init(Init),
    Output {
        call: Output,
        plan: RecoverOutputPlan,
    },
}

fn missing(reason: crate::OperationRecoveryRejection) -> Error {
    Error::Rejected(crate::RejectionReason::OperationRecovery(reason))
}

impl Call {
    pub(super) fn resolve(
        table: &crate::interfaces::CommonFunctions,
        kind: Kind,
        stage: Stage,
    ) -> Result<Self> {
        use crate::OperationRecoveryRejection as Reason;
        Ok(match (kind, stage) {
            (Kind::Sign, Stage::Init(_)) => Self::Init(
                table
                    .C_SignRecoverInit
                    .ok_or_else(|| missing(Reason::CSignRecoverInitUnavailable))?,
            ),
            (Kind::Verify, Stage::Init(_)) => Self::Init(
                table
                    .C_VerifyRecoverInit
                    .ok_or_else(|| missing(Reason::CVerifyRecoverInitUnavailable))?,
            ),
            (Kind::Sign, Stage::Output(plan)) => Self::Output {
                call: table
                    .C_SignRecover
                    .ok_or_else(|| missing(Reason::CSignRecoverUnavailable))?,
                plan,
            },
            (Kind::Verify, Stage::Output(plan)) => Self::Output {
                call: table
                    .C_VerifyRecover
                    .ok_or_else(|| missing(Reason::CVerifyRecoverUnavailable))?,
                plan,
            },
            _ => return Err(missing(Reason::RecoveryResultIncomplete)),
        })
    }
}
