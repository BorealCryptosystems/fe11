// SPDX-License-Identifier: Apache-2.0
//! Input closure and established stream progress, independent of native phase.
use super::record::{Reader, Writer};
use crate::{Error, Result};

/// Whether an operation may receive another explicit input submission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamInputStatus {
    /// Absence of a fragment is temporary; polling cannot imply Final.
    Open,
    /// The caller or complete-input facade has explicitly closed the input.
    Closed,
}

/// Logical progress of an owned stream. These are checked counters, not quotas.
/// Native CK_ULONG conversion applies to each individual call, not these totals.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StreamProgress {
    /// Input submissions issued, including those whose native call is refused.
    /// Retrying a retained capacity request does not submit another fragment.
    pub submissions: u64,
    /// Caller bytes accepted by native input calls with established success.
    /// The unknown bytes absorbed by C_DigestKey are not guessed or read back.
    pub input_bytes: u128,
    /// Successful C_DigestKey calls, tracked separately from caller byte counts.
    pub key_inputs: u64,
    /// Native output bytes established by successful output calls.
    pub output_bytes: u128,
    /// Output bytes already transferred to the caller, never republished.
    pub delivered_bytes: u128,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct InputState {
    pub incremental: bool,
    pub retained_submission: bool,
    pub status: StreamInputStatus,
    pub progress: StreamProgress,
}

pub(super) struct Submission {
    pub issued: InputState,
    pub completed: InputState,
}

impl InputState {
    pub const fn closed() -> Self {
        Self {
            incremental: false,
            retained_submission: false,
            status: StreamInputStatus::Closed,
            progress: StreamProgress {
                submissions: 0,
                input_bytes: 0,
                key_inputs: 0,
                output_bytes: 0,
                delivered_bytes: 0,
            },
        }
    }
    pub const fn open() -> Self {
        Self {
            incremental: true,
            status: StreamInputStatus::Open,
            ..Self::closed()
        }
    }
    pub fn is_open(self) -> bool {
        self.status == StreamInputStatus::Open
    }

    /// Compute both transitions before C, so overflow cannot lose an effect.
    /// Callers commit issued immediately before dispatch and completed only
    /// after established success. Neither transition retains input history.
    pub fn submission(self, bytes: usize, key: bool) -> Result<Submission> {
        let mut issued = self;
        if !issued.retained_submission {
            issued.progress.submissions =
                issued
                    .progress
                    .submissions
                    .checked_add(1)
                    .ok_or(Error::Rejected(crate::RejectionReason::OperationOwnership(
                        crate::OperationOwnershipRejection::StreamSubmissionCounterExhausted,
                    )))?;
        }
        issued.retained_submission = true;
        let mut completed = issued;
        completed.retained_submission = false;
        completed.progress.input_bytes = completed
            .progress
            .input_bytes
            .checked_add(bytes as u128)
            .ok_or(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::StreamInputCounterExhausted,
            )))?;
        if key {
            completed.progress.key_inputs =
                completed
                    .progress
                    .key_inputs
                    .checked_add(1)
                    .ok_or(Error::Rejected(crate::RejectionReason::OperationOwnership(
                        crate::OperationOwnershipRejection::StreamKeyCounterExhausted,
                    )))?;
        }
        Ok(Submission { issued, completed })
    }

    /// Commit bytes only once their native submission has completed.
    pub fn accepted(self, bytes: usize, key: bool) -> Result<Self> {
        let mut next = self;
        next.retained_submission = false;
        next.progress.input_bytes =
            next.progress
                .input_bytes
                .checked_add(bytes as u128)
                .ok_or(Error::Rejected(crate::RejectionReason::OperationOwnership(
                    crate::OperationOwnershipRejection::StreamInputCounterExhausted,
                )))?;
        if key {
            next.progress.key_inputs =
                next.progress
                    .key_inputs
                    .checked_add(1)
                    .ok_or(Error::Rejected(crate::RejectionReason::OperationOwnership(
                        crate::OperationOwnershipRejection::StreamKeyCounterExhausted,
                    )))?;
        }
        Ok(next)
    }

    pub fn produced(self, bytes: usize) -> Result<Self> {
        let mut next = self;
        next.progress.output_bytes = next
            .progress
            .output_bytes
            .checked_add(bytes as u128)
            .ok_or(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::StreamOutputCounterExhausted,
            )))?;
        Ok(next)
    }

    pub fn delivered(self, bytes: usize) -> Result<Self> {
        let mut next = self;
        next.progress.delivered_bytes = next
            .progress
            .delivered_bytes
            .checked_add(bytes as u128)
            .filter(|n| *n <= self.progress.output_bytes)
            .ok_or(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::StreamOutputDeliveryPosition,
            )))?;
        Ok(next)
    }

    pub fn close(&mut self) {
        self.status = StreamInputStatus::Closed;
    }

    pub fn write(self, writer: &mut Writer<'_>) -> Result<()> {
        writer.u8(match self.status {
            StreamInputStatus::Open => 1,
            StreamInputStatus::Closed => 0,
        })?;
        writer.u8(u8::from(self.incremental))?;
        writer.u8(u8::from(self.retained_submission))?;
        writer.u64(self.progress.submissions)?;
        writer.u64(self.progress.key_inputs)?;
        for count in [
            self.progress.input_bytes,
            self.progress.output_bytes,
            self.progress.delivered_bytes,
        ] {
            writer.u64((count >> 64) as u64)?;
            writer.u64(count as u64)?;
        }
        Ok(())
    }

    pub fn read(reader: &mut Reader<'_>) -> Result<Self> {
        let status = match reader.u8()? {
            0 => StreamInputStatus::Closed,
            1 => StreamInputStatus::Open,
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                    crate::OperationOwnershipRejection::StreamInputClosureEncoding,
                )))
            }
        };
        let incremental = reader.boolean(crate::RejectionReason::OperationOwnership(
            crate::OperationOwnershipRejection::StreamIncrementalRoute,
        ))?;
        let retained_submission = reader.boolean(crate::RejectionReason::OperationOwnership(
            crate::OperationOwnershipRejection::StreamRetainedInput,
        ))?;
        if status == StreamInputStatus::Open && !incremental {
            return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::OpenCompleteInputStream,
            )));
        }
        let submissions = reader.u64()?;
        let key_inputs = reader.u64()?;
        let mut counts = [0u128; 3];
        for count in &mut counts {
            *count = ((reader.u64()? as u128) << 64) | reader.u64()? as u128;
        }
        if key_inputs > submissions
            || counts[2] > counts[1]
            || retained_submission && submissions == 0
        {
            return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::StreamProgressEncoding,
            )));
        }
        Ok(Self {
            incremental,
            retained_submission,
            status,
            progress: StreamProgress {
                submissions,
                key_inputs,
                input_bytes: counts[0],
                output_bytes: counts[1],
                delivered_bytes: counts[2],
            },
        })
    }
}
