// SPDX-License-Identifier: Apache-2.0
//! Non-null native entry selected while the message phase is still unchanged.
use super::{invalid, CapacityStorage, DataKind, Phase};
use crate::{interfaces::MessageFunctions, native::message_signature::types, Error, Result};

pub(super) enum SignatureFunction {
    Sign(types::Sign),
    Verify(types::Verify),
}

pub(super) enum Call {
    Init(types::Init),
    Begin(types::Begin),
    Data(SignatureFunction),
    Final(types::Final),
}

impl Call {
    pub(super) fn resolve(f: MessageFunctions, verify: bool, phase: &Phase) -> Result<Self> {
        let missing = || {
            Error::Unsupported(crate::UnsupportedReason::NativeMessages(
                crate::NativeMessagesUnsupported::MessageSignatureFunctionTuple,
            ))
        };
        Ok(match phase {
            Phase::Init => {
                Self::Init(if verify { f.verify_init } else { f.sign_init }.ok_or_else(missing)?)
            }
            Phase::Begin(_) => {
                Self::Begin(if verify { f.verify_begin } else { f.sign_begin }.ok_or_else(missing)?)
            }
            Phase::Final => Self::Final(
                if verify {
                    f.verify_finish
                } else {
                    f.sign_finish
                }
                .ok_or_else(missing)?,
            ),
            Phase::Data(call)
            | Phase::Capacity {
                call,
                storage: CapacityStorage::Prepared,
                ..
            } => {
                let single = call.kind == DataKind::Single;
                Self::Data(if verify {
                    SignatureFunction::Verify(
                        if single {
                            f.verify_message
                        } else {
                            f.verify_next
                        }
                        .ok_or_else(missing)?,
                    )
                } else {
                    SignatureFunction::Sign(
                        if single { f.sign_message } else { f.sign_next }.ok_or_else(missing)?,
                    )
                })
            }
            _ => return Err(invalid()),
        })
    }
}
