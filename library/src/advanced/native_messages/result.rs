// SPDX-License-Identifier: Apache-2.0
//! Completed generic outputs without retaining the operation's key role leases.
use super::{Initialization, Message, MessageOutput, NativeMessageOperation};
use crate::mechanism_extension::OwnedGraph;
use crate::symmetric::memory::Credit;
use crate::{Error, MechanismLayoutProvenance, Result, Verification};
use std::mem::size_of;

/// An operational refusal for one native message, separate from a signature
/// verification verdict. The original error is also returned at the call boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeMessageRejection {
    /// Native function which refused this message.
    pub function: &'static str,
    /// Exact native return value.
    pub code: u64,
}

/// Outputs of an explicitly finished native message process. No output is
/// published before parent Final and the requested observations have completed.
/// Owned buffers are erased on drop; caller-made copies are outside that scope.
pub struct NativeMessageResults {
    initialization: Box<Initialization>,
    messages: Vec<Message>,
    verification: Option<Verification>,
    provenance: MechanismLayoutProvenance,
    _metadata: Credit,
}

// SAFETY: this owner is published only after native Final and established
// memory return. All graph/descriptor pointers target its stable heap allocations;
// moving the result moves no referent and no method can dispatch C. Accessors
// expose only bounded immutable slices. This restores the Send guarantee of
// the former completed Call without granting Sync or changing live-owner rules.
unsafe impl Send for NativeMessageResults {}

impl NativeMessageResults {
    /// Number of submitted messages, including operational refusals and invalid signatures.
    pub fn len(&self) -> usize {
        self.messages.len()
    }

    /// Whether the caller finished the parent without submitting any message.
    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }

    /// One signature's exact produced bytes. None for a refused row, verification or bad index.
    pub fn signature(&self, message: usize) -> Option<&[u8]> {
        let row = self.messages.get(message)?;
        if row.rejection.is_some() {
            return None;
        }
        let MessageOutput::Sign(Some(output)) = &row.output else {
            return None;
        };
        let length = output.produced?;
        output
            .bytes
            .as_slice()
            .get(output.offset..output.offset.checked_add(length)?)
    }

    /// Cumulative verification verdict; None for a signing process. An invalid
    /// earlier message remains invalid even if later messages verify correctly.
    /// None also means an operational refusal prevented an aggregate verdict;
    /// per-message codes and refusals remain available separately.
    pub fn verification(&self) -> Option<&Verification> {
        self.verification.as_ref()
    }

    /// Operational refusal for this row; does not classify the signature itself.
    pub fn rejection(&self, message: usize) -> Option<NativeMessageRejection> {
        self.messages.get(message)?.rejection
    }

    /// Exact native verification code for one completed message, including
    /// CKR_OK, CKR_SIGNATURE_INVALID or CKR_SIGNATURE_LEN_RANGE.
    pub fn verification_code(&self, message: usize) -> Option<u64> {
        let row = self.messages.get(message)?;
        if row.rejection.is_some() {
            return None;
        }
        match &row.output {
            MessageOutput::Verify { verdict } => verdict.map(|value| value as u64),
            MessageOutput::Sign(_) => None,
        }
    }

    /// Output from the parent's initialization parameter graph.
    pub fn parameter_output(&self, index: usize) -> Option<&[u8]> {
        self.initialization.output(index)
    }

    /// Output from one message's Begin graph, when supplied. None for a refused row.
    pub fn begin_parameter_output(&self, message: usize, index: usize) -> Option<&[u8]> {
        self.messages
            .get(message)
            .filter(|row| row.rejection.is_none())?
            .begin
            .as_ref()?
            .graph
            .output(index)
    }

    /// Output from a data call's graph, preserving the caller's part order.
    /// None for an operationally refused row, including its earlier parts.
    pub fn part_parameter_output(
        &self,
        message: usize,
        part: usize,
        index: usize,
    ) -> Option<&[u8]> {
        self.messages
            .get(message)
            .filter(|row| row.rejection.is_none())?
            .parts
            .get(part)?
            .graph
            .output(index)
    }

    /// ABI layout provenance, never an algorithm support or certification claim.
    pub fn provenance(&self) -> MechanismLayoutProvenance {
        self.provenance
    }
}

impl NativeMessageOperation {
    pub(in crate::advanced) fn result(
        &mut self,
        _entry: &crate::module::SessionEntry,
    ) -> Result<crate::OperationProgress> {
        // Completed owned output remains evidence of that call, even if
        // the key or context was withdrawn before local publication.
        if !self.complete() || !self.native_inactive() || self.initialization.is_none() {
            return Err(Error::Rejected(crate::RejectionReason::NativeMessages(
                crate::NativeMessagesRejection::GenericMessageResultNotAvailable,
            )));
        }
        for message in self.messages.iter().filter(|row| row.rejection.is_none()) {
            match &message.output {
                MessageOutput::Sign(Some(output)) if !self.verify => {
                    let produced = output.produced.ok_or(Error::Rejected(
                        crate::RejectionReason::NativeMessages(
                            crate::NativeMessagesRejection::MessageSignatureNotCompleted,
                        ),
                    ))?;
                    if produced > output.capacity()? {
                        return Err(Error::Rejected(crate::RejectionReason::NativeMessages(
                            crate::NativeMessagesRejection::MessageSignatureResultExtent,
                        )));
                    }
                }
                MessageOutput::Verify { verdict: Some(_) } if self.verify => {}
                _ => {
                    return Err(Error::Rejected(crate::RejectionReason::NativeMessages(
                        crate::NativeMessagesRejection::GenericMessageResultShape,
                    )))
                }
            }
        }
        let mut provenance = self.binding.primary.contract.provenance();
        for parameters in self
            .messages
            .iter()
            .flat_map(|message| message.begin.iter().chain(message.parts.iter()))
        {
            if parameters.contract.as_ref().is_some_and(|contract| {
                contract.provenance() == MechanismLayoutProvenance::CallerAssertedLayout
            }) {
                provenance = MechanismLayoutProvenance::CallerAssertedLayout;
            }
        }
        // Retain only heap metadata that moves to the result. The remaining
        // resident-owner charge and all key role leases leave with the ledger.
        let metadata_bytes = self
            .messages
            .capacity()
            .checked_mul(size_of::<Message>())
            .and_then(|bytes| {
                bytes.checked_add(size_of::<Initialization>() - size_of::<OwnedGraph>())
            })
            .ok_or(Error::Rejected(crate::RejectionReason::NativeMessages(
                crate::NativeMessagesRejection::GenericResultAccounting,
            )))?;
        let metadata = self._metadata.split(metadata_bytes)?;
        let verification = (self.verify && self.messages.iter().all(|row| row.rejection.is_none()))
            .then_some(if self.invalid_seen {
                Verification::Invalid
            } else {
                Verification::Valid
            });
        Ok(crate::OperationProgress::NativeMessages(
            NativeMessageResults {
                initialization: self
                    .initialization
                    .take()
                    .expect("checked initialization output"),
                messages: std::mem::take(&mut self.messages),
                verification,
                provenance,
                _metadata: metadata,
            },
        ))
    }
}
