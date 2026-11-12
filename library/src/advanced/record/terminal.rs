// SPDX-License-Identifier: Apache-2.0
//! Completed crypto results with one outstanding terminal observation.
use super::{Descriptor, KeyBindings, Limits, MessageState, Messages, ValidationRecord};
use crate::advanced::record::Family;
use crate::advanced::MessageRoute;
use crate::{Error, Result};
impl Descriptor {
    pub(in crate::advanced) fn validate_terminal(
        self,
        keys: &KeyBindings<'_>,
        messages: &Messages<'_>,
        validation: Option<&ValidationRecord<'_>>,
        limits: Limits,
        valid: bool,
    ) -> Result<()> {
        if self.family == Family::NativeMessages {
            return Err(Error::Rejected(
                crate::RejectionReason::AsynchronousExecution(
                    crate::AsynchronousExecutionRejection::GenericMessageAsynchronousModeUnavailable,
                ),
            ));
        }
        messages.require_typed()?;
        if let Some(state) = messages.aead_batch() {
            // A terminal result cannot also own an unconsumed native call.
            // Check the header before dispatching any other family adapter.
            if state.output.is_some() {
                return Err(Error::Rejected(crate::RejectionReason::OperationRecord(
                    crate::OperationRecordRejection::TerminalAeadCapacityContinuation,
                )));
            }
            state.validate(self, messages, false)?;
        }
        if let Some(stream) = messages.stream() {
            return stream.validate(self, keys, messages, validation, limits, false, Some(valid));
        }
        if messages.output().is_some() {
            return Err(Error::Rejected(crate::RejectionReason::OperationRecord(
                crate::OperationRecordRejection::TerminalMessageOutputContinuation,
            )));
        }
        if self.family == Family::Signature {
            return Err(Error::Rejected(
                crate::RejectionReason::AsynchronousExecution(
                    crate::AsynchronousExecutionRejection::SignatureAsynchronousModeUnavailable,
                ),
            ));
        }
        for message in messages.iter() {
            if message?.params.signature.is_some() {
                return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                    crate::CheckpointFormatRejection::SignatureParametersOnAnotherFamily,
                )));
            }
        }
        if self.family.is_cipher() {
            if !valid {
                return Err(Error::Rejected(crate::RejectionReason::OperationRecord(
                    crate::OperationRecordRejection::FailedAesOwnerHasNoTerminalResult,
                )));
            }
            return crate::advanced::cipher::checkpoint::validate(
                self, keys, messages, validation, limits, true,
            );
        }
        if self.family.is_recover() {
            if !valid {
                return Err(Error::Rejected(crate::RejectionReason::OperationRecord(
                    crate::OperationRecordRejection::FailedRecoveryMustNotContainATerminalResult,
                )));
            }
            return crate::advanced::recover::checkpoint::validate(
                self, keys, messages, validation, limits, true,
            );
        }
        self.keys(keys, limits)?;
        crate::advanced::messages::pss::record_selection(self, messages)?;
        if let Some(selection) =
            crate::advanced::dual::authentication::record_selection(self, messages)?
        {
            crate::advanced::dual::authentication::check_record_key(selection, keys)?;
        }
        if !valid && !matches!(self.family, Family::MessageVerify | Family::DecryptVerify)
            || self.active_flags != 0
            || self.carried_messages > messages.len()
            || self.carried_messages != 0 && self.family != Family::MessageDecrypt
        {
            return Err(Error::Rejected(crate::RejectionReason::OperationRecord(
                crate::OperationRecordRejection::TerminalResultDisposition,
            )));
        }
        let terminal = match self.family {
            Family::Digest => {
                crate::advanced::digest::DigestSelection::from_descriptor(self)?.terminal_function()
            }
            Family::DigestEncrypt | Family::DecryptDigest => "C_DigestFinal",
            Family::MessageEncrypt => "C_MessageEncryptFinal",
            Family::MessageDecrypt => "C_MessageDecryptFinal",
            Family::MessageSign => "C_MessageSignFinal",
            Family::MessageVerify => "C_MessageVerifyFinal",
            Family::SignEncrypt => "C_SignFinal",
            Family::DecryptVerify => "C_VerifyFinal",
            Family::SignRecover => "C_SignRecover",
            Family::VerifyRecover => "C_VerifyRecover",
            Family::CipherEncrypt
            | Family::CipherDecrypt
            | Family::Signature
            | Family::NativeMessages => {
                return Err(Error::Rejected(crate::RejectionReason::OperationRecord(
                    crate::OperationRecordRejection::AesRequiresPhaseSpecificTerminalValidation,
                )))
            }
        };
        if self.phase.name() != terminal {
            return Err(Error::Rejected(crate::RejectionReason::OperationRecord(
                crate::OperationRecordRejection::TerminalCompletedFunction,
            )));
        }
        let first = messages.iter().next().ok_or(Error::Rejected(
            crate::RejectionReason::OperationRecord(
                crate::OperationRecordRejection::TerminalEmptyResult,
            ),
        ))??;
        let classic = self.family == Family::Digest || self.family.is_dual();
        if classic && messages.len() != 1 {
            return Err(Error::Rejected(crate::RejectionReason::OperationRecord(
                crate::OperationRecordRejection::TerminalClassicBatch,
            )));
        }
        let mut finished = 0usize;
        let mut planned_suffix = false;
        for (index, message) in messages.iter().enumerate() {
            let m = message?;
            self.message_mode(&m, limits, true, messages.aead_row_layout(index)?)?;
            if m.route != first.route || m.state == MessageState::Engaged {
                return Err(Error::Rejected(crate::RejectionReason::OperationRecord(
                    crate::OperationRecordRejection::TerminalMessageProgression,
                )));
            }
            if m.state == MessageState::Finished {
                if planned_suffix {
                    return Err(Error::Rejected(crate::RejectionReason::OperationRecord(
                        crate::OperationRecordRejection::TerminalNoncontiguousProcessedPrefix,
                    )));
                }
                finished += 1;
            } else if valid || self.family != Family::MessageVerify {
                return Err(Error::Rejected(crate::RejectionReason::OperationRecord(
                    crate::OperationRecordRejection::TerminalUnfinishedResult,
                )));
            } else {
                planned_suffix = true;
            }
            if self.family.is_dual() {
                let input = m.fragments.iter().try_fold(0usize, |n, p| {
                    n.checked_add(p?.len()).ok_or(Error::Rejected(
                        crate::RejectionReason::OperationRecord(
                            crate::OperationRecordRejection::TerminalInputLength,
                        ),
                    ))
                })?;
                let (min, max) = crate::advanced::dual::output_bounds(
                    input,
                    matches!(self.family, Family::DecryptDigest | Family::DecryptVerify),
                    self.mechanism,
                    ((m.params.tag_bits + 7) / 8) as usize,
                )?;
                if valid
                    && (m.produced < min
                        || m.produced > max
                        || m.residual_start.checked_add(m.residual_length) != Some(m.produced))
                {
                    return Err(Error::Rejected(crate::RejectionReason::OperationRecord(
                        crate::OperationRecordRejection::TerminalCipherResultLength,
                    )));
                }
                if !valid
                    && (!m.result.is_empty()
                        || m.produced != 0
                        || m.residual_start != 0
                        || m.residual_length != 0)
                {
                    return Err(Error::Rejected(crate::RejectionReason::OperationRecord(
                        crate::OperationRecordRejection::InvalidTerminalPlaintextDisclosure,
                    )));
                }
            }
        }
        if finished == 0 || self.carried_messages > finished {
            return Err(Error::Rejected(crate::RejectionReason::OperationRecord(
                crate::OperationRecordRejection::TerminalProcessedPrefix,
            )));
        }
        if matches!(self.family, Family::MessageSign | Family::MessageVerify) {
            // The final processed row is the refused verification, if any.
            // Finished here means processed, not cryptographically accepted.
            let rejected = if valid { None } else { Some(finished - 1) };
            self.validate_message_progress(messages, false, rejected)?;
        }
        // Verification signatures are preserved as supplied. Their semantic
        // acceptance is the native module's result, not a local width rule.
        let report = validation.ok_or(Error::Rejected(crate::RejectionReason::Restoration(
            crate::RestorationRejection::TerminalReportAbsent,
        )))?;
        let maximum = if self.family == Family::Digest {
            1
        } else if self.family.is_dual() {
            2
        } else {
            messages.len().checked_add(1).ok_or(Error::Rejected(
                crate::RejectionReason::OperationRecord(
                    crate::OperationRecordRejection::TerminalReportCapacity,
                ),
            ))?
        };
        if report.maximum() != maximum {
            return Err(Error::Rejected(crate::RejectionReason::OperationRecord(
                crate::OperationRecordRejection::TerminalReportCapacity,
            )));
        }
        let mut prior = report.iter();
        if self.family.is_dual() {
            let expected = if matches!(self.family, Family::DecryptDigest | Family::DecryptVerify) {
                "C_DecryptFinal"
            } else {
                "C_EncryptFinal"
            };
            let observation =
                prior
                    .next()
                    .ok_or(Error::Rejected(crate::RejectionReason::OperationRecord(
                        crate::OperationRecordRejection::TerminalCipherObservationAbsent,
                    )))??;
            if observation.function != expected || observation.message_index.is_some() {
                return Err(Error::Rejected(crate::RejectionReason::OperationRecord(
                    crate::OperationRecordRejection::TerminalCipherCorrelation,
                )));
            }
        } else if self.family != Family::Digest {
            let expected = match (self.family, first.route) {
                (Family::MessageEncrypt, MessageRoute::Single) => "C_EncryptMessage",
                (Family::MessageEncrypt, MessageRoute::Multipart) => "C_EncryptMessageNext",
                (Family::MessageDecrypt, MessageRoute::Single) => "C_DecryptMessage",
                (Family::MessageDecrypt, MessageRoute::Multipart) => "C_DecryptMessageNext",
                (Family::MessageSign, MessageRoute::Single) => "C_SignMessage",
                (Family::MessageSign, MessageRoute::Multipart) => "C_SignMessageNext",
                (Family::MessageVerify, MessageRoute::Single) => "C_VerifyMessage",
                (Family::MessageVerify, MessageRoute::Multipart) => "C_VerifyMessageNext",
                _ => unreachable!(),
            };
            for index in self.carried_messages..finished {
                let observation = prior.next().ok_or(Error::Rejected(
                    crate::RejectionReason::OperationRecord(
                        crate::OperationRecordRejection::TerminalMessageObservationAbsent,
                    ),
                ))??;
                if observation.function != expected || observation.message_index != Some(index) {
                    return Err(Error::Rejected(crate::RejectionReason::OperationRecord(
                        crate::OperationRecordRejection::TerminalMessageCorrelation,
                    )));
                }
            }
        }
        if prior.next().is_some() {
            return Err(Error::Rejected(crate::RejectionReason::OperationRecord(
                crate::OperationRecordRejection::TerminalUnexpectedObservation,
            )));
        }
        Ok(())
    }
}
