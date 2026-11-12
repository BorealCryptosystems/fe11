// SPDX-License-Identifier: Apache-2.0
//! Describe AEAD direction, message position and terminal state.
//! Native function selection follows the current message boundary.

use super::*;

impl AeadMessageOperation {
    pub(in crate::advanced) fn cipher_kind(&self) -> CipherKind {
        self.kind
    }

    pub(in crate::advanced) fn encrypting(&self) -> bool {
        !self.decrypt
    }

    pub(in crate::advanced) fn carried_messages(&self) -> usize {
        self.restart_at
    }

    pub(in crate::advanced) fn set_terminal(&mut self) {
        self.step = AeadStep::Done;
        self.activity = NativeActivity::Closed;
    }

    pub(in crate::advanced) fn function(&self) -> Result<&'static str> {
        Ok(match (self.decrypt, self.dispatch_step()) {
            (false, AeadStep::Init) => "C_MessageEncryptInit",
            (true, AeadStep::Init) => "C_MessageDecryptInit",
            (false, AeadStep::Single(_)) => "C_EncryptMessage",
            (true, AeadStep::Single(_)) => "C_DecryptMessage",
            (false, AeadStep::Begin(_)) => "C_EncryptMessageBegin",
            (true, AeadStep::Begin(_)) => "C_DecryptMessageBegin",
            (false, AeadStep::Next(..) | AeadStep::StreamUpdate(_) | AeadStep::StreamLast(_)) => {
                "C_EncryptMessageNext"
            }
            (true, AeadStep::Next(..) | AeadStep::StreamUpdate(_) | AeadStep::StreamLast(_)) => {
                "C_DecryptMessageNext"
            }
            (false, AeadStep::Finish) => "C_MessageEncryptFinal",
            (true, AeadStep::Finish) => "C_MessageDecryptFinal",
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                    crate::AeadMessagesRejection::AeadMessageNotActive,
                )))
            }
        })
    }

    pub(super) fn output_index(&self) -> Option<usize> {
        match self.dispatch_step() {
            AeadStep::Single(i)
            | AeadStep::Next(i, _)
            | AeadStep::StreamUpdate(i)
            | AeadStep::StreamLast(i) => Some(i),
            _ => None,
        }
    }

    pub(super) fn last(&self) -> bool {
        match self.dispatch_step() {
            AeadStep::Single(_) | AeadStep::StreamLast(_) => true,
            AeadStep::Next(i, j) => j + 1 == self.frames[i].inputs.len(),
            _ => false,
        }
    }

    pub(super) fn poison_if_active(&self, entry: &SessionEntry) {
        if !self.activity.locally_retirable() {
            entry.poisoned.store(true, Ordering::Release);
        }
    }

    pub(in crate::advanced) fn initialization_refused(&self) -> bool {
        self.activity == NativeActivity::InitializationRefused
    }

    pub(in crate::advanced) fn native_inactive(&self) -> bool {
        matches!(
            self.activity,
            NativeActivity::Inactive | NativeActivity::Closed
        )
    }

    pub(in crate::advanced) fn nominal(&self) -> bool {
        matches!(self.outcome, AeadOutcome::Nominal)
            && self.step != AeadStep::Failed
            && self.buffer_request().is_none()
    }

    pub(in crate::advanced) fn message_count(&self) -> usize {
        self.frames.len()
    }

    pub(in crate::advanced) fn pending(&self) -> bool {
        self.activity == NativeActivity::Pending
    }

    pub(in crate::advanced) fn active_categories(&self) -> CK_FLAGS {
        if self.activity.locally_retirable() {
            0
        } else if self.decrypt {
            CKF_MESSAGE_DECRYPT
        } else {
            CKF_MESSAGE_ENCRYPT
        }
    }

    /// Project the current retained call. Scheduling stays in the owner, so
    /// future caller-fed input can use the same native dispatch without changing
    /// parameter addresses, output offsets or Single/Next argument semantics.
    pub(super) fn call_operands(
        &mut self,
        selected: resolved_call::Call,
        output_length: CK_ULONG,
        flags: CK_FLAGS,
    ) -> call::Call<'_> {
        match selected {
            resolved_call::Call::Init(native) => call::Call::Init {
                native,
                mechanism: &mut self.mechanism,
                key: self.key.handle,
            },
            resolved_call::Call::Begin { native, index } => {
                let frame = &mut self.frames[index];
                let aad_length = frame.aad.capacity() as CK_ULONG;
                call::Call::Begin {
                    native,
                    parameters: &mut frame.params,
                    aad: frame.aad.as_mut(),
                    aad_length,
                }
            }
            resolved_call::Call::Single { native, index } => {
                let part = 0;
                let frame = &mut self.frames[index];
                let output = &mut self
                    .outputs
                    .as_mut()
                    .expect("retained AEAD outputs")
                    .entries[index]
                    .bytes;
                let input = if let Some(input) = self.input.as_mut() {
                    input
                        .fragment
                        .as_mut()
                        .expect("preflighted AEAD stream fragment")
                } else {
                    &mut frame.inputs[part]
                };
                let input_length = input.capacity() as CK_ULONG;
                *frame.length = output_length;
                let data = call::Data {
                    parameters: &mut frame.params,
                    input: input.as_mut(),
                    input_length,
                    output: &mut output.as_mut()[frame.used..],
                    length: &mut frame.length,
                };

                let aad_length = frame.aad.capacity() as CK_ULONG;
                call::Call::Single {
                    native,
                    data,
                    aad: frame.aad.as_mut(),
                    aad_length,
                }
            }
            resolved_call::Call::Next {
                native,
                index,
                part,
            } => {
                let frame = &mut self.frames[index];
                let output = &mut self
                    .outputs
                    .as_mut()
                    .expect("retained AEAD outputs")
                    .entries[index]
                    .bytes;
                let input = if let Some(input) = self.input.as_mut() {
                    input
                        .fragment
                        .as_mut()
                        .expect("preflighted AEAD stream fragment")
                } else {
                    &mut frame.inputs[part]
                };
                let input_length = input.capacity() as CK_ULONG;
                *frame.length = output_length;
                let data = call::Data {
                    parameters: &mut frame.params,
                    input: input.as_mut(),
                    input_length,
                    output: &mut output.as_mut()[frame.used..],
                    length: &mut frame.length,
                };

                call::Call::Next {
                    native,
                    data,
                    flags,
                }
            }
            resolved_call::Call::Final(native) => call::Call::Final { native },
        }
    }
}

impl crate::symmetric::memory::RetainedStorage for AeadMessageOperation {
    fn retain_credits(
        &self,
        retained: &mut crate::symmetric::memory::RetainedBytes,
    ) -> crate::Result<()> {
        super::super::key_roles::Roles::retain_unique(self.key.writer_roles(), [], retained)?;
        self.key.retain_credits(retained)?;
        self.input.retain_credits(retained)?;
        self.retired_fragment.retain_credits(retained)?;
        self.retired_output.retain_credits(retained)?;
        self.retired_queued.retain_credits(retained)?;
        self.init.retain_credits(retained)?;
        self.frames.retain_credits(retained)?;
        self.outputs.retain_credits(retained)?;
        self._metadata.retain_credits(retained)?;
        Ok(())
    }
}
