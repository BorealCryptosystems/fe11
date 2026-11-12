// SPDX-License-Identifier: Apache-2.0
//! Resolve the exact AEAD phase before recording or publishing native effects.
use super::{call::types, AeadStep};
use crate::{interfaces::MessageFunctions, Error, Result};

pub(super) enum Call {
    Init(types::Init),
    Begin {
        native: types::Begin,
        index: usize,
    },
    Single {
        native: types::Single,
        index: usize,
    },
    Next {
        native: types::Next,
        index: usize,
        part: usize,
    },
    Final(types::Final),
}
impl Call {
    pub(super) fn resolve(f: MessageFunctions, decrypt: bool, step: AeadStep) -> Result<Self> {
        let missing = || {
            Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::AeadMessageMessageFunctionsUnavailable,
            ))
        };
        Ok(match step {
            AeadStep::Init => Self::Init(
                if decrypt {
                    f.decrypt_init
                } else {
                    f.encrypt_init
                }
                .ok_or_else(missing)?,
            ),
            AeadStep::Begin(index) => Self::Begin {
                native: if decrypt {
                    f.decrypt_begin
                } else {
                    f.encrypt_begin
                }
                .ok_or_else(missing)?,
                index,
            },
            AeadStep::Single(index) => Self::Single {
                native: if decrypt {
                    f.decrypt_message
                } else {
                    f.encrypt_message
                }
                .ok_or_else(missing)?,
                index,
            },
            AeadStep::Next(index, part) => Self::Next {
                native: if decrypt {
                    f.decrypt_next
                } else {
                    f.encrypt_next
                }
                .ok_or_else(missing)?,
                index,
                part,
            },
            AeadStep::StreamUpdate(index) | AeadStep::StreamLast(index) => Self::Next {
                native: if decrypt {
                    f.decrypt_next
                } else {
                    f.encrypt_next
                }
                .ok_or_else(missing)?,
                index,
                part: 0,
            },
            AeadStep::Finish => Self::Final(
                if decrypt {
                    f.decrypt_finish
                } else {
                    f.encrypt_finish
                }
                .ok_or_else(missing)?,
            ),
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                    crate::AeadMessagesRejection::AeadMessageNotActive,
                )))
            }
        })
    }
}
