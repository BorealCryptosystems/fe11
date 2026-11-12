// SPDX-License-Identifier: Apache-2.0
//! Caller-fed AEAD input and established-return accounting.
//!
//! The native call borrows only the retained fragment. Consumed fragments move
//! out through poll's retirement owner, so erasure and budget wakeups occur
//! after session and operation possession has ended. Plaintext outputs remain
//! in the AEAD owner until its native authentication sequence completes.
use super::{AeadMessageOperation, AeadStep};
use crate::advanced::input::{InputState, Submission};
use crate::{bounds, symmetric::memory::Buffer, Error, Result};

#[derive(Default)]
pub(in crate::advanced) struct ReleasedInput {
    _fragment: Option<Buffer>,
    _output: Option<Buffer>,
    _queued: super::queued_input::Retired,
}

// The pointer itself is included in AeadMessageOperation. This separately
// charged heap leaf is allocated during aggregate preparation, never after C.
pub(super) const DIAGNOSTIC_BYTES: usize = std::mem::size_of::<Error>();

pub(super) struct Input {
    pub state: InputState,
    pub fragment: Option<Buffer>,
    diagnostic: Option<Box<Error>>,
}

impl Input {
    pub(super) fn new() -> Self {
        Self::restored(InputState::open(), None)
    }

    /// Called during destination preparation, outside native possession, after
    /// the owner recipe has admitted DIAGNOSTIC_BYTES with its other storage.
    pub(super) fn restored(state: InputState, fragment: Option<Buffer>) -> Self {
        Self {
            state,
            fragment,
            diagnostic: Some(Box::new(Error::Rejected(
                crate::RejectionReason::AeadMessages(
                    crate::AeadMessagesRejection::AeadDiagnosticNotUsed,
                ),
            ))),
        }
    }

    /// A local integrity failure makes the owner permanently non-dispatchable.
    /// Its one reserved leaf can therefore leave with the public error. Only a
    /// static placeholder is overwritten; no allocation or heap drop occurs.
    pub(super) fn native_and_local_failure(
        &mut self,
        function: &'static str,
        code: u64,
        local: Error,
    ) -> Error {
        let mut cause = self
            .diagnostic
            .take()
            .expect("prepared AEAD failure diagnostic");
        *cause = local;
        Error::NativeAndLocalFailure {
            function,
            code,
            cause,
        }
    }
}

impl AeadMessageOperation {
    fn current_input_bytes(&self) -> Result<Option<usize>> {
        if !matches!(
            self.dispatch_step(),
            AeadStep::Single(_) | AeadStep::StreamUpdate(_) | AeadStep::StreamLast(_)
        ) {
            return Ok(None);
        }
        self.input
            .as_ref()
            .map(|input| {
                input
                    .fragment
                    .as_ref()
                    .map(Buffer::capacity)
                    .ok_or(Error::Rejected(crate::RejectionReason::AeadMessages(
                        crate::AeadMessagesRejection::AeadStreamFragmentAbsent,
                    )))
            })
            .transpose()
    }

    /// Preflight both input transitions and the greatest output delta before C.
    /// A future returned length can then be committed without losing a native
    /// effect to counter overflow. The caller still validates its actual bound.
    pub(super) fn input_submission(&self, output_capacity: usize) -> Result<Option<Submission>> {
        let Some(bytes) = self.current_input_bytes()? else {
            return Ok(None);
        };
        if self.retired_fragment.is_some() || self.retired_output.is_some() {
            return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::AeadReturnedInputNotRetired,
            )));
        }
        bounds::ck_length(bytes)?;
        let index =
            self.output_index()
                .ok_or(Error::Rejected(crate::RejectionReason::AeadMessages(
                    crate::AeadMessagesRejection::AeadStreamFragmentAbsent,
                )))?;
        self.frames[index].accepted_after(bytes)?;
        let input = self.input.as_ref().expect("checked caller-fed AEAD input");
        let submission = input.state.submission(bytes, false)?;
        submission.completed.produced(output_capacity)?;
        Ok(Some(submission))
    }

    pub(super) fn complete_input(&mut self, produced: usize) -> Result<()> {
        let Some(bytes) = self.current_input_bytes()? else {
            return Ok(());
        };
        if self.retired_fragment.is_some() || self.retired_output.is_some() {
            return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::AeadReturnedInputNotRetired,
            )));
        }
        let index = self.output_index().expect("data submission has a row");
        let input = self.input.as_mut().expect("checked caller-fed AEAD input");
        self.retired_fragment = input.complete(&mut self.frames[index], bytes, produced)?;
        Ok(())
    }

    pub(super) fn terminal_input(&self, index: usize) -> Result<Option<u128>> {
        if self.input.is_some() {
            let bytes = self.current_input_bytes()?.ok_or(Error::Rejected(
                crate::RejectionReason::AeadMessages(
                    crate::AeadMessagesRejection::AeadStreamFragmentAbsent,
                ),
            ))?;
            self.frames[index].accepted_after(bytes)
        } else {
            // Queued rows retain the original full length, including after
            // consumed fragments have been erased.
            Ok(Some(self.frames[index].expected as u128))
        }
    }

    pub(in crate::advanced) fn take_released_input(&mut self) -> ReleasedInput {
        ReleasedInput {
            _fragment: self.retired_fragment.take(),
            _output: self.retired_output.take(),
            _queued: std::mem::take(&mut self.retired_queued),
        }
    }
}

impl crate::symmetric::memory::RetainedStorage for Input {
    fn retain_credits(
        &self,
        retained: &mut crate::symmetric::memory::RetainedBytes,
    ) -> crate::Result<()> {
        self.fragment.retain_credits(retained)?;
        Ok(())
    }
}

use super::*;

impl Request<'_> {
    pub(super) fn data_len(&self) -> Result<usize> {
        self.parts.iter().try_fold(0usize, |total, part| {
            total.checked_add(part.len()).ok_or(Error::Rejected(
                crate::RejectionReason::AeadMessages(
                    crate::AeadMessagesRejection::AeadMessageLengthOverflow,
                ),
            ))
        })
    }
}

impl Requests<'_> {
    pub(super) fn len(&self) -> usize {
        match self {
            Self::StreamEncrypt { messages, .. } => messages.len(),
            Self::StreamDecrypt { messages, .. } => messages.len(),
            Self::Encrypt(x) => x.len(),
            Self::Decrypt(x) => x.len(),
            Self::CcmEncrypt(x) => x.len(),
            Self::CcmDecrypt(x) => x.len(),
            Self::Prepared { entries, .. } => entries.len(),
        }
    }

    pub(super) fn get(&self, i: usize) -> Request<'_> {
        match self {
            Self::StreamEncrypt { messages, .. } => Request {
                nonce: Selection::Stream(messages[i].nonce),
                aad: messages[i].aad,
                parts: messages[i].parts,
                tag: None,
            },
            Self::StreamDecrypt { messages, .. } => Request {
                nonce: Selection::Stream(messages[i].nonce),
                aad: messages[i].aad,
                parts: messages[i].parts,
                tag: Some(messages[i].tag),
            },
            Self::Encrypt(x) => Request {
                nonce: Selection::Gcm(x[i].nonce.clone()),
                aad: x[i].aad,
                parts: x[i].parts,
                tag: None,
            },
            Self::Decrypt(x) => Request {
                nonce: Selection::Gcm(x[i].nonce.clone()),
                aad: x[i].aad,
                parts: x[i].parts,
                tag: Some(x[i].tag),
            },
            Self::CcmEncrypt(x) => Request {
                nonce: Selection::Ccm {
                    nonce: x[i].nonce.clone(),
                    mac_length: x[i].mac_length,
                },
                aad: x[i].aad,
                parts: x[i].parts,
                tag: None,
            },
            Self::CcmDecrypt(x) => Request {
                nonce: Selection::Ccm {
                    nonce: x[i].nonce.clone(),
                    mac_length: x[i].mac.len() as u64,
                },
                aad: x[i].aad,
                parts: x[i].parts,
                tag: Some(x[i].mac),
            },
            Self::Prepared { entries, .. } => entries[i].clone(),
        }
    }

    pub(super) fn decrypt(&self) -> bool {
        match self {
            Self::StreamDecrypt { .. } | Self::Decrypt(_) | Self::CcmDecrypt(_) => true,
            Self::Prepared { decrypt, .. } => *decrypt,
            _ => false,
        }
    }

    pub(super) fn kind(&self) -> CipherKind {
        match self {
            Self::StreamEncrypt { kind, .. } | Self::StreamDecrypt { kind, .. } => *kind,
            Self::Encrypt(_) | Self::Decrypt(_) => CipherKind::Gcm,
            Self::CcmEncrypt(_) | Self::CcmDecrypt(_) => CipherKind::Ccm,
            Self::Prepared { kind, .. } => *kind,
        }
    }

    pub(super) fn validate_init(&self, layout: MessageInitLayout) -> Result<()> {
        if self.len() == 0 {
            return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::EmptyAeadMessageSequence,
            )));
        }
        if self.kind().stream() && layout != MessageInitLayout::InitWithoutParameters {
            return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::StreamAeadMessageinitHasNoParameters,
            )));
        }
        if layout == MessageInitLayout::InitWithOwnedMessageParameters {
            let first = self.get(0).nonce;
            for index in 1..self.len() {
                first.fixed_scalars(&self.get(index).nonce)?;
            }
        }
        Ok(())
    }

    pub(super) fn validate(
        &self,
        limits: crate::InputLimits,
        ceiling: crate::CryptoLimits,
    ) -> Result<()> {
        limits.validate(ceiling, &[])?;
        if self.len() == 0 || self.len() > limits.maximum_parts {
            return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::AeadMessageMessageCount,
            )));
        }
        let mut count = 0usize;
        let mut total = 0usize;
        for i in 0..self.len() {
            let request = self.get(i);
            if request.nonce.kind() != self.kind() {
                return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                    crate::AeadMessagesRejection::MixedAeadMessageSelections,
                )));
            }
            let data = request.data_len()?;
            request
                .nonce
                .validate(request.aad.len(), data, self.decrypt())?;
            let tag_bytes = request.nonce.tag_bytes()?;
            if self.decrypt() && request.tag.map_or(true, |tag| tag.len() != tag_bytes) {
                return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                    crate::AeadMessagesRejection::AeadMessageDecryptParameters,
                )));
            }
            limits.validate(ceiling, request.parts)?;
            bounds::ck_length(request.aad.len())?;
            count = count
                .checked_add(request.parts.len().max(1))
                .ok_or(Error::Rejected(crate::RejectionReason::AeadMessages(
                    crate::AeadMessagesRejection::AeadMessagePartOverflow,
                )))?;
            total = total
                .checked_add(request.aad.len())
                .and_then(|n| {
                    n.checked_add(request.nonce.iv().len())
                        .and_then(|n| n.checked_add(request.tag.map_or(0, |tag| tag.len())))
                })
                .ok_or(Error::Rejected(crate::RejectionReason::AeadMessages(
                    crate::AeadMessagesRejection::AeadMessageInputOverflow,
                )))?;
            for part in request.parts {
                total = total.checked_add(part.len()).ok_or(Error::Rejected(
                    crate::RejectionReason::AeadMessages(
                        crate::AeadMessagesRejection::AeadMessageInputOverflow,
                    ),
                ))?;
            }
            // IV uniqueness is the caller's per-key/session obligation. A batch
            // comparison is not a lifetime uniqueness guarantee or native policy.
        }
        if count > limits.maximum_parts || total > limits.maximum_total_bytes {
            return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::AeadMessageBatchCeiling,
            )));
        }
        Ok(())
    }
}

impl super::Frame {
    pub(super) fn accepted_after(&self, bytes: usize) -> Result<Option<u128>> {
        self.accepted_input
            .map(|total| {
                total.checked_add(bytes as u128).ok_or(Error::Rejected(
                    crate::RejectionReason::AeadMessages(
                        crate::AeadMessagesRejection::AeadMessageLengthOverflow,
                    ),
                ))
            })
            .transpose()
    }
}

impl Input {
    /// Commit only an established successful data call. The caller retains the
    /// returned fragment until it can erase storage outside operation guards.
    pub(super) fn complete(
        &mut self,
        frame: &mut super::Frame,
        bytes: usize,
        produced: usize,
    ) -> Result<Option<Buffer>> {
        let state = self.state.accepted(bytes, false)?.produced(produced)?;
        let accepted = frame.accepted_after(bytes)?;
        self.state = state;
        frame.accepted_input = accepted;
        Ok(self.fragment.take())
    }
}
