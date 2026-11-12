// SPDX-License-Identifier: Apache-2.0
//! A non-null function and its operand position for one message signature step.
use super::MessageStep;
use crate::{interfaces::MessageFunctions, native::message_signature::types, Error, Result};

pub(super) enum SignatureFunction {
    Sign(types::Sign),
    Verify(types::Verify),
}
pub(super) enum Call {
    Init(types::Init),
    Begin(types::Begin),
    Data {
        native: SignatureFunction,
        index: usize,
        part: usize,
        last: bool,
    },
    Final(types::Final),
}
impl Call {
    pub(super) fn resolve(
        f: MessageFunctions,
        verify: bool,
        step: MessageStep,
        last: bool,
    ) -> Result<Self> {
        let missing = || {
            Error::Rejected(crate::RejectionReason::SignatureMessages(
                crate::SignatureMessagesRejection::MessageFunctionsUnavailable,
            ))
        };
        Ok(match step {
            MessageStep::Init => {
                Self::Init(if verify { f.verify_init } else { f.sign_init }.ok_or_else(missing)?)
            }
            MessageStep::Begin(_) => {
                Self::Begin(if verify { f.verify_begin } else { f.sign_begin }.ok_or_else(missing)?)
            }
            MessageStep::Finish => Self::Final(
                if verify {
                    f.verify_finish
                } else {
                    f.sign_finish
                }
                .ok_or_else(missing)?,
            ),
            MessageStep::Single(index)
            | MessageStep::Next(index, _)
            | MessageStep::StreamUpdate(index)
            | MessageStep::StreamLast(index) => {
                let single = matches!(step, MessageStep::Single(_));
                let part = match step {
                    MessageStep::Next(_, part) => part,
                    _ => 0,
                };
                let native = if verify {
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
                };
                Self::Data {
                    native,
                    index,
                    part,
                    last,
                }
            }
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::SignatureMessages(
                    crate::SignatureMessagesRejection::MessageNotActive,
                )))
            }
        })
    }
}
