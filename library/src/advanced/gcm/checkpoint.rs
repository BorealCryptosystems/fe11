// SPDX-License-Identifier: Apache-2.0
//! Borrowed AEAD projection: no replay, input reconstruction or allocation.
use super::{AeadMessageOperation, AeadOutcome, AeadStep, InitBinding, InitReference};
use crate::advanced::record::aead_messages::{
    self, Boundary, Call, Header, Initial, Row, Seed, Selection, Target,
};
use crate::advanced::{record, NativeActivity};
use crate::{Error, Result};
pub(in crate::advanced) mod capture;
mod reconstruction;
pub(in crate::advanced) use reconstruction::{RecordPlan, Storage};

fn unavailable() -> Error {
    Error::Rejected(crate::RejectionReason::AeadMessages(
        crate::AeadMessagesRejection::AeadStreamCheckpointBoundary,
    ))
}

pub(super) fn data_call(step: AeadStep) -> Result<Call> {
    match step {
        AeadStep::Single(index) => Ok(Call::Single(index)),
        AeadStep::StreamUpdate(index) => Ok(Call::Update(index)),
        AeadStep::StreamLast(index) => Ok(Call::Last(index)),
        _ => Err(unavailable()),
    }
}

impl AeadMessageOperation {
    pub(super) fn stream_boundary(&self) -> Result<Boundary> {
        if self.input.is_none()
            || self.retired_fragment.is_some()
            || self.retired_output.is_some()
            || self.activity != NativeActivity::Active
            || !matches!(self.outcome, AeadOutcome::Nominal)
            || self.restart_at != 0
        {
            return Err(unavailable());
        }
        Ok(match self.step {
            AeadStep::Ready => Boundary::Ready,
            AeadStep::Begin(index) => Boundary::Begin(index),
            AeadStep::Receive(index) => Boundary::Receive(index),
            AeadStep::Single(_) | AeadStep::StreamUpdate(_) | AeadStep::StreamLast(_) => {
                Boundary::Data(data_call(self.step)?)
            }
            AeadStep::Output(pending) => pending.record_boundary()?,
            AeadStep::Finish => Boundary::Finish,
            _ => return Err(unavailable()),
        })
    }

    pub(super) fn stream_header(&self) -> Result<Header<'_>> {
        let boundary = self.stream_boundary()?;
        self.validate_binding()?;
        let initial = match &self.init {
            InitBinding::Declared(_) => {
                return Err(Error::Unsupported(crate::UnsupportedReason::AeadMessages(
                    crate::AeadMessagesUnsupported::DeclaredGcmMessageStateCapture,
                )))
            }
            InitBinding::WithoutParameters => Initial::None,
            InitBinding::Shared {
                prepared_message,
                seed,
                nonce,
                tag,
                ..
            } => Initial::Shared {
                target: match prepared_message {
                    InitReference::Seed => Target::Seed,
                    InitReference::Message(index) => Target::Message(*index),
                },
                seed: seed
                    .as_ref()
                    .map(|seed| -> Result<_> {
                        Ok(Seed {
                            selection: Selection::from_live(&seed.origin)?,
                            declared_length: seed.declared_length,
                            expected_tag: seed.expected_tag.as_ref().map(|tag| tag.as_slice()),
                        })
                    })
                    .transpose()?,
                nonce: nonce.as_slice(),
                tag: tag.as_slice(),
            },
        };
        Ok(Header {
            route: self.route,
            boundary,
            initial,
            fragment: self
                .input
                .as_ref()
                .ok_or_else(unavailable)?
                .fragment
                .as_ref()
                .map(|bytes| bytes.as_slice()),
        })
    }

    pub(super) fn stream_row(&self, index: usize) -> Result<Row<'_>> {
        let frame = self.frames.get(index).ok_or_else(unavailable)?;
        let output = self
            .outputs
            .as_ref()
            .ok_or_else(unavailable)?
            .entries
            .get(index)
            .ok_or_else(unavailable)?;
        if !frame.inputs.is_empty() {
            return Err(unavailable());
        }
        // The prefix has an established native extent, even when plaintext is
        // not yet authenticated. No tail bytes are presented as produced data.
        let bytes = output
            .bytes
            .initialized_storage()
            .get(..frame.used)
            .ok_or_else(unavailable)?;
        Ok(Row {
            disposition: output.disposition,
            accepted_input: frame.accepted_input,
            selection: Selection::from_live(&frame.origin)?,
            declared_length: frame.expected,
            aad: frame.aad.as_slice(),
            nonce: output.nonce.as_slice(),
            tag: output.tag.as_slice(),
            expected_tag: frame.expected_tag.as_ref().map(|tag| tag.as_slice()),
            observed_nonce: frame.observed_nonce.as_ref().map(|nonce| nonce.as_slice()),
            output: bytes,
            capacity: output.bytes.capacity(),
            native_length: usize::try_from(*frame.length).map_err(|_| unavailable())?,
        })
    }

    pub(super) fn write_stream_messages(
        &self,
        writer: &mut record::Writer<'_>,
        limits: record::Limits,
    ) -> Result<()> {
        let header = self.stream_header()?;
        if self.outputs.as_ref().ok_or_else(unavailable)?.entries.len() != self.frames.len() {
            return Err(unavailable());
        }
        aead_messages::write(writer, limits, header, self.frames.len(), |index| {
            self.stream_row(index)
        })
    }
}

use super::*;

impl AeadMessageOperation {
    pub(in crate::advanced) fn checkpoint_header(
        &self,
    ) -> Result<(record::Descriptor, record::KeyBindings<'_>)> {
        extension::ensure_standard(&self.init)?;
        let descriptor = record::Descriptor {
            input: self
                .input
                .as_ref()
                .map_or(crate::advanced::input::InputState::closed(), |input| {
                    input.state
                }),
            family: if self.decrypt {
                Family::MessageDecrypt
            } else {
                Family::MessageEncrypt
            },
            profile: self.key.checkpoint_profile()?,
            phase: record::Function::from_name(if self.input.is_some() {
                self.stream_boundary()?.function(self.decrypt)
            } else if self.complete() {
                if self.decrypt {
                    "C_MessageDecryptFinal"
                } else {
                    "C_MessageEncryptFinal"
                }
            } else {
                self.function()?
            })?,
            mechanism: self.kind.mechanism() as u64,
            size: 0,
            active_flags: 0,
            validation_requested: false,
            digest_bits: None,
            cipher_options: None,
            carried_messages: self.restart_at,
        };
        Ok((
            descriptor,
            record::KeyBindings {
                cipher: Some(self.key.checkpoint_key(record::KeyRole::Cipher)?),
                authentication: None,
            },
        ))
    }

    pub(in crate::advanced) fn write_checkpoint_messages(
        &self,
        budget: &Arc<Budget>,
        writer: &mut super::super::record::Writer<'_>,
        limits: super::super::record::Limits,
    ) -> Result<()> {
        if self.input.is_some() {
            self.write_stream_messages(writer, limits)
        } else {
            self.write_messages(budget, writer, limits, false)
        }
    }

    pub(in crate::advanced) fn write_recovery_section(
        &self,
        budget: &Arc<Budget>,
        writer: &mut record::Writer<'_>,
        limits: record::Limits,
    ) -> Result<()> {
        extension::ensure_standard(&self.init)?;
        if !self.decrypt {
            return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::RecoveryRequiresAeadMessageDecryption,
            )));
        }
        let keys = record::KeyBindings {
            cipher: Some(self.key.checkpoint_key(record::KeyRole::Cipher)?),
            authentication: None,
        };
        writer.u8(self.key.checkpoint_profile()?)?;
        writer.u64(self.kind.mechanism() as u64)?;
        keys.write(writer)?;
        self.write_messages(budget, writer, limits, true)
    }

    pub(super) fn write_messages(
        &self,
        _budget: &Arc<Budget>,
        writer: &mut super::super::record::Writer<'_>,
        limits: super::super::record::Limits,
        recovery: bool,
    ) -> Result<()> {
        use super::super::record::{Message, MessageState, Messages, NonceOrigin, Parameters};
        if self.input.is_some()
            || self.pending() && !recovery
            || self.step == AeadStep::Failed
            || !matches!(self.outcome, AeadOutcome::Nominal)
        {
            return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::AeadMessageMessageCheckpointUnavailable,
            )));
        }
        if recovery && !self.decrypt {
            return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::RecoveryRequiresAeadMessageDecryption,
            )));
        }
        let outputs = &self
            .outputs
            .as_ref()
            .ok_or(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::AeadMessageOutputsAbsent,
            )))?
            .entries;
        if outputs.len() != self.frames.len() {
            return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::AeadMessageOutputShape,
            )));
        }
        let state = record::aead_batch::State {
            declared: None,
            output: if recovery {
                None
            } else if let AeadStep::Output(pending) = self.step {
                Some(pending.batch_record()?)
            } else {
                None
            },
        };
        Messages::write_generated_aead(
            writer,
            self.frames.len(),
            limits,
            state,
            |index| Ok(self.frames[index].expected),
            |i| {
                let frame = &self.frames[i];
                let output = &outputs[i];
                let mut parts = self.queued_fragments(i)?;
                // A capacity request retains the same unconsumed call. Fresh decryption uses
                // that position only to identify the completed prefix; it never
                // transfers the old native state or retries an encryption nonce.
                let (mut state, mut next_fragment) = match self.dispatch_step() {
                    AeadStep::Finish | AeadStep::Done => (MessageState::Finished, parts.len()),
                    AeadStep::Init if i < self.restart_at => (MessageState::Finished, parts.len()),
                    AeadStep::Single(current)
                    | AeadStep::Begin(current)
                    | AeadStep::Next(current, _)
                        if i < current =>
                    {
                        (MessageState::Finished, parts.len())
                    }
                    AeadStep::Next(current, fragment) if i == current => {
                        (MessageState::Engaged, fragment)
                    }
                    _ => (MessageState::Planned, 0),
                };
                // Explicit recovery restarts the unfinished message from inputs, without reading
                // its output allocation or native-owned nonce/tag parameters.
                if recovery && state != MessageState::Finished {
                    state = MessageState::Planned;
                    next_fragment = 0;
                }
                // Completed inputs cannot be used by continuation or recovery. Keep the
                // declared CCM length in the header, but no input history in the
                // portable record. Output and its original message index survive.
                if state == MessageState::Finished {
                    parts = record::Fragments::Slices(&[]);
                    next_fragment = 0;
                }
                let generated = !self.decrypt && frame.origin.generated();
                let origin = if generated {
                    NonceOrigin::Backend
                } else {
                    NonceOrigin::Provided
                };
                let nonce = if !generated || recovery {
                    Some(frame.origin.iv())
                } else if matches!(self.step, AeadStep::Output(_))
                    && self.dispatch_step() == AeadStep::Single(i)
                {
                    // A size refusal may have updated native parameter targets.
                    // Keep their exact bytes without declaring nonce generation
                    // successful; the resumed call still owns those parameters.
                    Some(output.nonce.as_slice())
                } else if state == MessageState::Planned {
                    None
                } else {
                    Some(
                        frame
                            .observed_nonce
                            .as_ref()
                            .ok_or(Error::Rejected(crate::RejectionReason::AeadMessages(
                                crate::AeadMessagesRejection::CheckpointGeneratedNonceUnknown,
                            )))?
                            .as_slice(),
                    )
                };
                let result = if recovery && state != MessageState::Finished {
                    &[]
                } else {
                    output
                        .bytes
                        .as_slice()
                        .get(..frame.used)
                        .ok_or(Error::Rejected(crate::RejectionReason::AeadMessages(
                            crate::AeadMessagesRejection::CheckpointGcmResultRange,
                        )))?
                };
                Ok(Message {
                    route: self.route,
                    params: Parameters {
                        digest_output: None,
                        cipher_extension: None,
                        digest_extension: None,
                        signature: None,
                        digest_oid: None,
                        message_init: Some(self.init.layout()?),
                        counter_bits: None,
                        iv_generator: Some(frame.origin.generator()? as u64),
                        iv_fixed_bits: Some(frame.origin.fixed_bits()),
                        iv_initial: Some(frame.origin.iv()),
                        nonce,
                        aad: Some(frame.aad.as_slice()),
                        tag_bits: frame.origin.tag_bits() as u32,
                        hash: None,
                        mgf: None,
                        salt: None,
                    },
                    origin,
                    state,
                    fragments: parts,
                    next_fragment,
                    produced: result.len(),
                    expected: output.bytes.capacity(),
                    result,
                    // These are the owned parameter bytes, not an authenticity
                    // assertion; state marks whether the message is finished.
                    tag_or_signature: if recovery {
                        Some(
                            frame
                                .expected_tag
                                .as_ref()
                                .ok_or(Error::Rejected(crate::RejectionReason::AeadMessages(
                                    crate::AeadMessagesRejection::DecryptionTagAbsent,
                                )))?
                                .as_slice(),
                        )
                    } else {
                        Some(output.tag.as_slice())
                    },
                    residual_start: 0,
                    residual_length: 0,
                })
            },
        )
    }
}
