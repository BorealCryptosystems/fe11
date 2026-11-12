// SPDX-License-Identifier: Apache-2.0
//! State-transfer call selection without a post-dispatch nullable lookup.
use super::{Direction, Error, Phase, Result};
use fe11_sys::*;

type Info = unsafe extern "C" fn(CK_SESSION_HANDLE, CK_SESSION_INFO_PTR) -> CK_RV;
type Capture = unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV;
type Restore = unsafe extern "C" fn(
    CK_SESSION_HANDLE,
    CK_BYTE_PTR,
    CK_ULONG,
    CK_OBJECT_HANDLE,
    CK_OBJECT_HANDLE,
) -> CK_RV;

pub(super) enum Call {
    Info(Info),
    Size(Capture),
    Bytes(Capture),
    Restore {
        call: Restore,
        encryption: CK_OBJECT_HANDLE,
        authentication: CK_OBJECT_HANDLE,
    },
}

impl Call {
    pub(super) fn resolve(
        table: &crate::interfaces::CommonFunctions,
        phase: Phase,
        direction: Direction,
    ) -> Result<Self> {
        let capture = || {
            table.C_GetOperationState.ok_or(Error::Rejected(
                crate::RejectionReason::OperationState(
                    crate::OperationStateRejection::CGetOperationStateUnavailable,
                ),
            ))
        };
        Ok(match phase {
            Phase::Info => Self::Info(table.C_GetSessionInfo.ok_or(Error::Rejected(
                crate::RejectionReason::OperationState(
                    crate::OperationStateRejection::CGetSessionInfoUnavailable,
                ),
            ))?),
            Phase::Size => Self::Size(capture()?),
            Phase::Bytes => Self::Bytes(capture()?),
            Phase::Restore => {
                let call = table.C_SetOperationState.ok_or(Error::Rejected(
                    crate::RejectionReason::Restoration(
                        crate::RestorationRejection::CSetOperationStateUnavailable,
                    ),
                ))?;
                let Direction::Restore {
                    encryption,
                    authentication,
                    ..
                } = direction
                else {
                    return Err(Error::Rejected(crate::RejectionReason::OperationState(
                        crate::OperationStateRejection::StateIoNotActive,
                    )));
                };
                Self::Restore {
                    call,
                    encryption,
                    authentication,
                }
            }
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::OperationState(
                    crate::OperationStateRejection::StateIoNotActive,
                )))
            }
        })
    }
}
