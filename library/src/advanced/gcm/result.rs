// SPDX-License-Identifier: Apache-2.0
//! A message refusal does not finish its initialized parent or release plaintext.
use super::{AeadMessageOperation, AeadStep};
use crate::{Error, Result};

/// Exact refusal of one message within a caller-fed AEAD process.
/// No parent Final or successful authentication is implied by this observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MessageAeadRejection {
    /// Native Single, Begin or Next function that refused the message.
    pub function: &'static str,
    /// Unchanged native return value.
    pub code: u64,
}

/// Parent/message phases establish completion separately. A candidate output
/// is publishable only once those phases have completed successfully. Refused
/// output retains its established byte count, but never its bytes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::advanced) enum Disposition {
    Candidate,
    Rejected {
        rejection: MessageAeadRejection,
        discarded_output: usize,
    },
}

impl Disposition {
    pub(super) fn candidate(self) -> bool {
        matches!(self, Self::Candidate)
    }

    pub(super) fn rejection(self) -> Option<MessageAeadRejection> {
        match self {
            Self::Candidate => None,
            Self::Rejected { rejection, .. } => Some(rejection),
        }
    }

    pub(in crate::advanced) fn discarded_output(self) -> usize {
        match self {
            Self::Candidate => 0,
            Self::Rejected {
                discarded_output, ..
            } => discarded_output,
        }
    }
}

impl AeadMessageOperation {
    /// The caller has established ordinary return and validated all retained
    /// native descriptors. The rejected row remains indexed, but its output and
    /// returned fragment move to poll's owner for erasure outside possession.
    pub(super) fn refuse_message(&mut self, function: &'static str, code: u64) -> Result<()> {
        let index = match self.step {
            AeadStep::Single(index)
            | AeadStep::Begin(index)
            | AeadStep::StreamUpdate(index)
            | AeadStep::StreamLast(index) => index,
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                    crate::AeadMessagesRejection::AeadRefusalPhase,
                )))
            }
        };
        if self.retired_fragment.is_some() || self.retired_output.is_some() {
            return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::AeadReturnedStorageNotRetired,
            )));
        }
        let input =
            self.input
                .as_mut()
                .ok_or(Error::Rejected(crate::RejectionReason::AeadMessages(
                    crate::AeadMessagesRejection::AeadCallerFedRefusal,
                )))?;
        let output = &mut self
            .outputs
            .as_mut()
            .expect("retained AEAD outputs")
            .entries[index];
        let frame = &mut self.frames[index];
        output.disposition = Disposition::Rejected {
            rejection: MessageAeadRejection { function, code },
            discarded_output: frame.used,
        };
        self.retired_output = Some(output.bytes.take());
        self.retired_fragment = input.fragment.take();
        // Issued calls were counted before C. Refused input and the failed
        // call's output length are not successful byte observations.
        input.state.retained_submission = false;
        frame.used = 0;
        *frame.length = 0;
        self.step = AeadStep::Ready;
        Ok(())
    }
}

use super::*;

impl GcmCiphertexts {
    /// Refusal at this submission index, without any output from that message.
    /// None means either a successful entry or an index outside this result.
    pub fn rejection(&self, index: usize) -> Option<crate::MessageAeadRejection> {
        self.0
            .entries
            .get(index)
            .and_then(|output| output.disposition.rejection())
    }

    /// Local Init representation shared by this completed message sequence.
    pub fn message_init(&self) -> crate::CallerSelectedInitLayout {
        crate::CallerSelectedInitLayout::gcm(self.0.init)
    }

    /// Number of submitted messages, including individually refused entries.
    pub fn len(&self) -> usize {
        self.0.entries.len()
    }

    /// Whether the batch is empty.
    pub fn is_empty(&self) -> bool {
        self.0.entries.is_empty()
    }

    /// Borrow one complete result in input order.
    /// Returns None for a refused message; inspect rejection at the same index.
    pub fn get(&self, i: usize) -> Option<GcmCiphertext<'_>> {
        self.0
            .entries
            .get(i)
            .filter(|o| o.disposition.candidate())
            .map(|o| GcmCiphertext {
                ciphertext: o.bytes.as_slice(),
                nonce: o.nonce.as_slice(),
                tag: o.tag.as_slice(),
                tag_bits: o.tag_bits,
            })
    }
}

impl GcmPlaintexts {
    /// Refusal at this submission index, without any output from that message.
    /// None means either a successful entry or an index outside this result.
    pub fn rejection(&self, index: usize) -> Option<crate::MessageAeadRejection> {
        self.0
            .entries
            .get(index)
            .and_then(|output| output.disposition.rejection())
    }

    /// Local Init representation shared by this completed message sequence.
    pub fn message_init(&self) -> crate::CallerSelectedInitLayout {
        crate::CallerSelectedInitLayout::gcm(self.0.init)
    }

    /// Native tag length selected for this message. Zero means no authentication;
    /// completion only establishes success of the exact native request.
    pub fn tag_bits(&self, i: usize) -> Option<u64> {
        self.0.entries.get(i).map(|output| output.tag_bits)
    }

    /// Number of submitted messages, including individually refused entries.
    pub fn len(&self) -> usize {
        self.0.entries.len()
    }

    /// Whether the batch is empty.
    pub fn is_empty(&self) -> bool {
        self.0.entries.is_empty()
    }

    /// Borrow GCM plaintext. A zero-bit tag provides no authentication.
    /// Copies by the caller are not erased here.
    /// Returns None for a refused message; inspect rejection at the same index.
    pub fn get(&self, i: usize) -> Option<&[u8]> {
        self.0
            .entries
            .get(i)
            .filter(|o| o.disposition.candidate())
            .map(|o| o.bytes.as_slice())
    }
}

impl AeadMessageOperation {
    pub(in crate::advanced) fn result(
        &mut self,
        _entry: &SessionEntry,
    ) -> Result<OperationProgress> {
        if !self.complete() {
            return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::AeadMessageNotComplete,
            )));
        }
        if matches!(self.outcome, AeadOutcome::Closing { .. }) {
            return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::AeadMessageResultWithheldAfterFailure,
            )));
        }
        // Completed owned output remains evidence of that call, even if
        // the key or context was withdrawn before local publication.
        if let AeadOutcome::Rejected(rejection) = &self.outcome {
            let rejection = *rejection;
            return Ok(match self.kind {
                CipherKind::Gcm => OperationProgress::InvalidCiphertext(rejection),
                CipherKind::Ccm => OperationProgress::CcmInvalidCiphertext(rejection.into()),
                CipherKind::ChaChaPoly1305 | CipherKind::SalsaPoly1305 => {
                    OperationProgress::StreamAeadInvalidCiphertext(rejection.into())
                }
            });
        }
        if let InitBinding::Declared(initialization) = &mut self.init {
            if let Err(error) = initialization.finish() {
                // Parent Final has ended native access. Invalid output lengths
                // cannot become valid on a later poll. Withhold this result and
                // prevent reuse of its transferred diagnostic, even if another
                // retained control temporarily prevents terminal retirement.
                self.step = AeadStep::Failed;
                return Err(error);
            }
        }
        let outputs =
            self.outputs
                .take()
                .ok_or(Error::Rejected(crate::RejectionReason::AeadMessages(
                    crate::AeadMessagesRejection::AeadMessageAlreadyPublished,
                )))?;
        if matches!(self.init, InitBinding::Declared(_)) {
            // Move the independent Init graph only after native parent termination.
            // Its output regions and credits live as long as the published result.
            if let InitBinding::Declared(initialization) =
                std::mem::replace(&mut self.init, InitBinding::WithoutParameters)
            {
                return Ok(extension::result(outputs, initialization));
            }
            return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::DeclaredGcmResultOwnership,
            )));
        }
        Ok(match (self.kind, self.decrypt) {
            (CipherKind::Gcm, false) => OperationProgress::GcmCiphertexts(GcmCiphertexts(outputs)),
            (CipherKind::Gcm, true) => OperationProgress::GcmPlaintexts(GcmPlaintexts(outputs)),
            (CipherKind::Ccm, false) => OperationProgress::CcmCiphertexts(CcmCiphertexts(outputs)),
            (CipherKind::Ccm, true) => OperationProgress::CcmPlaintexts(CcmPlaintexts(outputs)),
            (CipherKind::ChaChaPoly1305, false) => OperationProgress::StreamAeadCiphertexts(
                StreamAeadCiphertexts(outputs, crate::StreamAeadAlgorithm::ChaCha20),
            ),
            (CipherKind::SalsaPoly1305, false) => OperationProgress::StreamAeadCiphertexts(
                StreamAeadCiphertexts(outputs, crate::StreamAeadAlgorithm::Salsa20),
            ),
            (CipherKind::ChaChaPoly1305, true) => OperationProgress::StreamAeadPlaintexts(
                StreamAeadPlaintexts(outputs, crate::StreamAeadAlgorithm::ChaCha20),
            ),
            (CipherKind::SalsaPoly1305, true) => OperationProgress::StreamAeadPlaintexts(
                StreamAeadPlaintexts(outputs, crate::StreamAeadAlgorithm::Salsa20),
            ),
        })
    }
}
