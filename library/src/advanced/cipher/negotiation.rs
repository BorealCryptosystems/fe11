// SPDX-License-Identifier: Apache-2.0
//! Explicit output negotiation preserves the native input step until consumed.
use super::{CipherOperation, Direction, OutputObserver, Stage};
use crate::{bounds, symmetric::memory::Buffer, Error, Result};

/// Select storage for the first standalone cipher output call.
/// Later calls use the unfilled remainder of that storage. A size query or
/// insufficient buffer stops progress until the caller explicitly selects space.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CipherOutputPlan {
    /// Preallocate the capacity derived from the selected mechanism and input.
    /// This is the behavior of methods without an explicit output plan.
    MechanismBound,
    /// Supply a non-NULL output buffer of this capacity, including zero.
    Buffer {
        /// Number of output bytes to reserve before native initialization.
        capacity: usize,
    },
    /// Submit a NULL output pointer and report the native required capacity.
    /// This does not consume the input or publish output bytes.
    LengthOnly,
}

/// Native size information for one cipher output call, including AEAD messages.
/// This is a storage request, not a cryptographic result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CipherBufferRequest {
    /// Exact function that reported the size.
    pub function: &'static str,
    /// CKR_OK for a size query, or CKR_BUFFER_TOO_SMALL.
    pub code: u64,
    /// Required capacity for this call, as reported without clamping.
    pub required: usize,
    /// Capacity supplied to this call, excluding previously produced bytes.
    /// A length-only query supplies zero.
    pub previous_capacity: usize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum OutputStep {
    Single,
    Update { index: usize, offset: usize },
    Final,
}
impl OutputStep {
    pub(super) fn from_stage(stage: Stage) -> Result<Self> {
        match stage {
            Stage::Single => Ok(Self::Single),
            Stage::Update { index, offset } => Ok(Self::Update { index, offset }),
            Stage::Final => Ok(Self::Final),
            Stage::Query(step) | Stage::Waiting { step, .. } => Ok(step),
            _ => Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::CipherOutputStepUnavailable,
            ))),
        }
    }
    pub(super) fn stage(self) -> Stage {
        match self {
            Self::Single => Stage::Single,
            Self::Update { index, offset } => Stage::Update { index, offset },
            Self::Final => Stage::Final,
        }
    }
    pub(super) fn function(self, direction: Direction) -> &'static str {
        match self {
            Self::Single => direction.single(),
            Self::Update { .. } => direction.update(),
            Self::Final => direction.final_call(),
        }
    }
}

impl CipherOperation {
    pub(super) fn park_observer(&mut self, expected: CipherBufferRequest) -> Result<()> {
        let Stage::Waiting { request, .. } = &self.stage else {
            return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::CipherIsNotWaitingForStorage,
            )));
        };
        if *request != expected || self.observer != OutputObserver::Ticket {
            return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::CipherObservationOwnershipChanged,
            )));
        }
        self.observer = OutputObserver::Session;
        Ok(())
    }

    pub(super) fn take_observer(&mut self) -> Result<()> {
        if self.observer != OutputObserver::Session {
            return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::CipherTicketAlreadyHeldByCaller,
            )));
        }
        self.observer = OutputObserver::Ticket;
        Ok(())
    }

    pub(in crate::advanced) fn buffer_request(&self) -> Option<CipherBufferRequest> {
        match self.stage {
            Stage::Waiting { request, .. } => Some(request),
            _ => None,
        }
    }

    pub(in crate::advanced) fn output_preparation(
        &self,
        capacity: usize,
    ) -> Result<(CipherBufferRequest, usize)> {
        let Stage::Waiting { request, .. } = self.stage else {
            return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::CipherIsNotWaitingForStorage,
            )));
        };
        if self.pending() {
            return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::CipherOutputStillReferencedByPendingCall,
            )));
        }
        bounds::ck_length(capacity)?;
        let total = self.used.checked_add(capacity).ok_or(Error::Rejected(
            crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::CipherOutputCapacityOverflow,
            ),
        ))?;
        let previous = self.frame.output.as_ref().ok_or(Error::Rejected(
            crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::CipherOutputAbsent,
            ),
        ))?;
        previous.as_slice().get(..self.used).ok_or(Error::Rejected(
            crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::CipherRetainedOutputRange,
            ),
        ))?;
        Ok((request, total))
    }

    pub(in crate::advanced) fn attach_output(
        &mut self,
        capacity: usize,
        mut output: Buffer,
    ) -> Result<Option<Buffer>> {
        let (_, total) = self.output_preparation(capacity)?;
        if output.as_slice().len() != total {
            return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::CipherOutputCapacityOverflow,
            )));
        }
        let Stage::Waiting { step, .. } = self.stage else {
            unreachable!("validated output wait")
        };
        let previous = self
            .frame
            .output
            .as_ref()
            .expect("validated retained output");
        output.as_mut()[..self.used].copy_from_slice(&previous.as_slice()[..self.used]);
        let old = self.frame.output.replace(output);
        *self.frame.length = bounds::ck_length(capacity)?;
        self.stage = step.stage();
        Ok(old)
    }
}

/// Compatibility spelling for the AES convenience methods.
pub type AesOutputPlan = CipherOutputPlan;
/// Compatibility spelling for native AES size reports.
pub type AesBufferRequest = CipherBufferRequest;
