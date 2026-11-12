// SPDX-License-Identifier: Apache-2.0
//! Validate complete, detached and recovery checkpoint representations.
//! Message progress, mode and descriptor associations must agree before restoration.

use super::*;

impl Descriptor {
    pub(in crate::advanced) fn validate_detached(
        self,
        keys: &KeyBindings<'_>,
        messages: &Messages<'_>,
        validation: Option<&ValidationRecord<'_>>,
        limits: Limits,
    ) -> Result<Option<usize>> {
        if self.family == Family::NativeMessages {
            return Err(Error::Rejected(
                crate::RejectionReason::AsynchronousExecution(
                    crate::AsynchronousExecutionRejection::GenericMessageAsynchronousModeUnavailable,
                ),
            ));
        }
        messages.require_typed()?;
        if self.family.is_cipher() {
            return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                crate::CheckpointFormatRejection::NativeBlockCipherAsynchronousModeUnavailable,
            )));
        }
        if self.family.is_recover() {
            return Err(Error::Rejected(
                crate::RejectionReason::AsynchronousExecution(
                    crate::AsynchronousExecutionRejection::SignatureRecoveryAsynchronousModeUnavailable,
                ),
            ));
        }
        if self.family == Family::MessageEncrypt {
            return Err(Error::Rejected(
                crate::RejectionReason::AsynchronousExecution(
                    crate::AsynchronousExecutionRejection::GcmMessageEncryptionDetachmentDeferred,
                ),
            ));
        }
        self.validate_mode(keys, messages, validation, limits, true)?;
        if let Some(stream) = messages.stream() {
            return if self.family == Family::MessageSign && stream.boundary.terminal_message() {
                Ok(Some(
                    messages
                        .iter()
                        .last()
                        .ok_or(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                            crate::CheckpointFormatRejection::DetachedActiveMessageAbsent,
                        )))??
                        .expected,
                ))
            } else {
                Ok(None)
            };
        }
        let phase = self.phase.name();
        let capacity = match self.family {
            Family::Digest => {
                if matches!(phase, "C_Digest" | "C_DigestFinal") {
                    Some(self.size)
                } else {
                    None
                }
            }
            Family::MessageDecrypt => {
                if matches!(phase, "C_DecryptMessage" | "C_DecryptMessageNext") {
                    let m = messages
                        .iter()
                        .find_map(|m| match m {
                            Ok(m) if m.state != MessageState::Finished => Some(Ok(m)),
                            Err(e) => Some(Err(e)),
                            _ => None,
                        })
                        .ok_or(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                            crate::CheckpointFormatRejection::DetachedActiveMessageAbsent,
                        )))??;
                    Some(
                        (if messages.aead_batch().is_some() {
                            m.expected
                        } else {
                            m.expected.max(1)
                        })
                        .checked_sub(m.produced)
                        .ok_or(Error::Rejected(
                            crate::RejectionReason::CheckpointFormat(
                                crate::CheckpointFormatRejection::DetachedOutputProgression,
                            ),
                        ))?,
                    )
                } else {
                    None
                }
            }
            Family::MessageSign => {
                if matches!(phase, "C_SignMessage" | "C_SignMessageNext") {
                    let message = messages
                        .iter()
                        .find_map(|message| match message {
                            Ok(message) if message.state != MessageState::Finished => {
                                Some(Ok(message))
                            }
                            Err(error) => Some(Err(error)),
                            _ => None,
                        })
                        .ok_or(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                            crate::CheckpointFormatRejection::DetachedActiveMessageAbsent,
                        )))??;
                    let terminal = phase == "C_SignMessage"
                        || message.next_fragment.checked_add(1)
                            == Some(message.fragments.len().max(1));
                    terminal.then_some(message.expected)
                } else {
                    None
                }
            }
            Family::MessageVerify => None,
            Family::DigestEncrypt
            | Family::DecryptDigest
            | Family::SignEncrypt
            | Family::DecryptVerify => {
                let m = messages.iter().next().ok_or(Error::Rejected(
                    crate::RejectionReason::CheckpointFormat(
                        crate::CheckpointFormatRejection::DetachedMessageAbsent,
                    ),
                ))??;
                let phase_kind = if matches!(phase, "C_DigestInit" | "C_SignInit" | "C_VerifyInit")
                {
                    PhaseKind::Initial
                } else {
                    self.phase_kind(m.route)?
                };
                if matches!(phase_kind, PhaseKind::Update | PhaseKind::CipherFinal) {
                    let input = m.fragments.iter().try_fold(0usize, |n, b| {
                        n.checked_add(b?.len()).ok_or(Error::Rejected(
                            crate::RejectionReason::CheckpointFormat(
                                crate::CheckpointFormatRejection::DetachedInputLength,
                            ),
                        ))
                    })?;
                    Some(
                        input
                            .checked_add(32)
                            .and_then(|n| n.checked_sub(m.produced))
                            .ok_or(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                                crate::CheckpointFormatRejection::DetachedOutputCapacity,
                            )))?,
                    )
                } else if phase_kind == PhaseKind::AuthenticationFinal
                    && self.family != Family::DecryptVerify
                {
                    Some(
                        crate::advanced::dual::authentication::Authentication::from_record(
                            self, &m,
                        )?
                        .length(),
                    )
                } else {
                    None
                }
            }
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                    crate::CheckpointFormatRejection::DetachedCryptographicFamily,
                )))
            }
        };
        if let Some(n) = capacity {
            if n > limits.bytes {
                return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                    crate::CheckpointFormatRejection::DetachedOutputCeiling,
                )));
            }
            bounds::ck_length(n)?;
        }
        Ok(capacity)
    }

    /// Recovery is a fresh decryption plan, never a native continuation phase.
    pub(in crate::advanced) fn validate_recovery(
        self,
        keys: &KeyBindings<'_>,
        messages: &Messages<'_>,
        limits: Limits,
    ) -> Result<()> {
        if let Some(state) = messages.aead_batch() {
            state.validate(self, messages, false)?;
            if state.output.is_some() {
                return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                    crate::CheckpointFormatRejection::RecoveryCannotRetainANativeCapacityCall,
                )));
            }
        }
        if self.family != Family::MessageDecrypt
            || messages.output().is_some()
            || messages.stream().is_some()
        {
            return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                crate::CheckpointFormatRejection::RecoveryFamilyOrOutputContinuation,
            )));
        }
        self.keys(keys, limits)?;
        let mut route = None;
        for (index, m) in messages.iter().enumerate() {
            let m = m?;
            self.message(&m, limits, messages.aead_row_layout(index)?)?;
            if m.state == MessageState::Engaged {
                return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                    crate::CheckpointFormatRejection::RecoveryUnauthenticatedProgression,
                )));
            }
            if route.is_some_and(|prior| prior != m.route) {
                return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                    crate::CheckpointFormatRejection::RecoveryMixedRoutes,
                )));
            }
            route = Some(m.route);
        }
        Ok(())
    }

    pub(in crate::advanced) fn validate(
        self,
        keys: &KeyBindings<'_>,
        messages: &Messages<'_>,
        validation: Option<&ValidationRecord<'_>>,
        limits: Limits,
    ) -> Result<()> {
        self.validate_mode(keys, messages, validation, limits, false)
    }

    // Detached describes an already submitted call, including Init. Saved keeps
    // its stricter requirement that initialization has completed successfully.
    /// Establish the relationship between retained rows and logical counters
    /// before a restored owner may dispatch. These are consistency checks on
    /// the record, not cryptographic acceptance conditions or stream quotas.
    pub(in crate::advanced::record) fn validate_message_progress(
        self,
        messages: &Messages<'_>,
        detached: bool,
        rejected_message: Option<usize>,
    ) -> Result<()> {
        if self.input.incremental
            || self.input.is_open()
            || self.input.progress.key_inputs != 0
            || self.input.progress.delivered_bytes != 0
        {
            return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                crate::CheckpointFormatRejection::RecordBufferedMessageInputState,
            )));
        }
        let mut bytes = 0u128;
        let mut submissions = 0u64;
        let mut output = 0u128;
        for (index, message) in messages.iter().enumerate() {
            let message = message?;
            // A terminal verification refusal counts as a submission, but its
            // last data call did not establish successful input consumption.
            // Single submitted the entire row; Multipart submitted only its
            // last fragment. Earlier successful Next calls remain counted.
            let accepted_fragments = if rejected_message == Some(index) {
                match message.route {
                    MessageRoute::Single => 0,
                    MessageRoute::Multipart => message.next_fragment.saturating_sub(1),
                }
            } else {
                message.next_fragment
            };
            for fragment in message.fragments.iter().take(accepted_fragments) {
                bytes = bytes
                    .checked_add(fragment?.len() as u128)
                    .ok_or(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                        crate::CheckpointFormatRejection::RecordMessageByteCounter,
                    )))?;
            }
            let completed = match (message.route, message.state) {
                (_, MessageState::Planned) => 0,
                (MessageRoute::Single, MessageState::Finished) => 1,
                (MessageRoute::Multipart, MessageState::Finished) => message.fragments.len().max(1),
                (MessageRoute::Multipart, MessageState::Engaged) => message.next_fragment,
                (MessageRoute::Single, MessageState::Engaged) => {
                    return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                        crate::CheckpointFormatRejection::RecordSingleMessageProgress,
                    )))
                }
            };
            submissions = submissions
                .checked_add(u64::try_from(completed).map_err(|_| {
                    Error::Rejected(crate::RejectionReason::CheckpointFormat(
                        crate::CheckpointFormatRejection::RecordMessageSubmissionWidth,
                    ))
                })?)
                .ok_or(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                    crate::CheckpointFormatRejection::RecordMessageSubmissionCounter,
                )))?;
            output = output
                .checked_add(message.produced as u128)
                .ok_or(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                    crate::CheckpointFormatRejection::RecordMessageOutputCounter,
                )))?;
        }
        let detached_data = detached
            && matches!(
                self.phase.name(),
                "C_SignMessage" | "C_VerifyMessage" | "C_SignMessageNext" | "C_VerifyMessageNext"
            );
        // An issued data call is either detached or retained for explicit
        // output replacement. Init/Begin/Final never add data submissions.
        // validate_mode checked the output continuation's family and phase.
        let retained_data = detached_data || messages.output().is_some();
        if self.input.retained_submission != retained_data {
            return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                crate::CheckpointFormatRejection::RecordRetainedMessageSubmission,
            )));
        }
        if retained_data {
            submissions = submissions.checked_add(1).ok_or(Error::Rejected(
                crate::RejectionReason::CheckpointFormat(
                    crate::CheckpointFormatRejection::RecordMessageSubmissionCounter,
                ),
            ))?;
        }
        if self.input.progress.submissions != submissions
            || self.input.progress.input_bytes != bytes
            || self.input.progress.output_bytes != output
        {
            return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                crate::CheckpointFormatRejection::RecordMessageProgressMismatch,
            )));
        }
        Ok(())
    }

    pub(super) fn validate_mode(
        self,
        keys: &KeyBindings<'_>,
        messages: &Messages<'_>,
        validation: Option<&ValidationRecord<'_>>,
        limits: Limits,
        detached: bool,
    ) -> Result<()> {
        if self.family == Family::NativeMessages {
            if detached {
                return Err(Error::Rejected(
                    crate::RejectionReason::AsynchronousExecution(
                        crate::AsynchronousExecutionRejection::GenericMessageAsynchronousModeUnavailable,
                    ),
                ));
            }
            return messages
                .native()
                .ok_or(Error::Rejected(crate::RejectionReason::Restoration(
                    crate::RestorationRejection::GenericMessageArchiveBodyAbsent,
                )))?
                .validate_sections(self, keys, validation);
        }
        if let Some(aead) = messages.aead() {
            if detached {
                return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                    crate::CheckpointFormatRejection::CallerFedAeadAsynchronousModeUnavailable,
                )));
            }
            return aead.validate_sections(self, keys, validation, limits);
        }
        messages.require_typed()?;
        if let Some(state) = messages.aead_batch() {
            state.validate(self, messages, detached)?;
        }
        if let Some(stream) = messages.stream() {
            return stream.validate(self, keys, messages, validation, limits, detached, None);
        }
        if let Some(output) = messages.output() {
            output.validate(self, messages, detached)?;
        }
        for message in messages.iter() {
            let message = message?;
            if self.family != Family::Digest && message.params.digest_output.is_some() {
                return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                    crate::CheckpointFormatRejection::DigestOutputOnAnotherFamily,
                )));
            }
            if !self.family.is_cipher() && message.params.cipher_extension.is_some() {
                return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                    crate::CheckpointFormatRejection::CipherGraphOnAnotherRecordFamily,
                )));
            }
        }
        if self.family == Family::Signature {
            if detached {
                return Err(Error::Rejected(
                    crate::RejectionReason::AsynchronousExecution(
                        crate::AsynchronousExecutionRejection::SignatureAsynchronousModeUnavailable,
                    ),
                ));
            }
            return super::super::signature::validate(self, keys, messages, validation, limits);
        }
        for message in messages.iter() {
            if message?.params.signature.is_some() {
                return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                    crate::CheckpointFormatRejection::SignatureParametersOnAnotherFamily,
                )));
            }
        }
        if self.digest_bits.is_some()
            && (self.family != Family::Digest || self.cipher_options.is_some())
        {
            return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                crate::CheckpointFormatRejection::DigestParametersOnAnotherRecordFamily,
            )));
        }
        if !self.family.is_cipher() && self.cipher_options.is_some() {
            return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                crate::CheckpointFormatRejection::CipherOptionsOnAnotherRecordFamily,
            )));
        }
        if self.family.is_cipher() {
            if detached {
                return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                    crate::CheckpointFormatRejection::NativeBlockCipherAsynchronousModeUnavailable,
                )));
            }
            return crate::advanced::cipher::checkpoint::validate(
                self, keys, messages, validation, limits, false,
            );
        }
        if self.family.is_recover() {
            if detached {
                return Err(Error::Rejected(
                    crate::RejectionReason::AsynchronousExecution(
                        crate::AsynchronousExecutionRejection::SignatureRecoveryAsynchronousModeUnavailable,
                    ),
                ));
            }
            return crate::advanced::recover::checkpoint::validate(
                self, keys, messages, validation, limits, false,
            );
        }
        self.keys(keys, limits)?;
        crate::advanced::messages::pss::record_selection(self, messages)?;
        if let Some(selection) =
            crate::advanced::dual::authentication::record_selection(self, messages)?
        {
            crate::advanced::dual::authentication::check_record_key(selection, keys)?;
        }
        if self.carried_messages > messages.len()
            || self.carried_messages != 0 && self.family != Family::MessageDecrypt
        {
            return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                crate::CheckpointFormatRejection::RecordCarriedPrefix,
            )));
        }
        let first = messages.iter().next().ok_or(Error::Rejected(
            crate::RejectionReason::CheckpointFormat(
                crate::CheckpointFormatRejection::RecordEmptyOperation,
            ),
        ))??;
        let initial = match self.family {
            Family::Digest => "C_DigestInit",
            Family::MessageEncrypt => "C_MessageEncryptInit",
            Family::MessageDecrypt => "C_MessageDecryptInit",
            Family::MessageSign => "C_MessageSignInit",
            Family::MessageVerify => "C_MessageVerifyInit",
            Family::DigestEncrypt | Family::DecryptDigest => "C_DigestInit",
            Family::SignEncrypt => "C_SignInit",
            Family::DecryptVerify => "C_VerifyInit",
            Family::SignRecover => "C_SignRecoverInit",
            Family::VerifyRecover => "C_VerifyRecoverInit",
            Family::CipherEncrypt => "C_EncryptInit",
            Family::CipherDecrypt => "C_DecryptInit",
            Family::Signature | Family::NativeMessages => {
                return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                    crate::CheckpointFormatRejection::NativeSignatureValidationDispatch,
                )));
            }
        };
        let phase = if detached && self.phase.name() == initial {
            PhaseKind::Initial
        } else {
            self.phase_kind(first.route)?
        };
        if matches!(self.family, Family::MessageSign | Family::MessageVerify) {
            self.validate_message_progress(messages, detached, None)?;
        }
        if (self.family == Family::Digest || self.dual()) && messages.len() != 1 {
            return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                crate::CheckpointFormatRejection::RecordClassicBatch,
            )));
        }
        let mut finished = 0;
        let mut active = false;
        for (index, message) in messages.iter().enumerate() {
            let m = message?;
            if index < self.carried_messages && m.state != MessageState::Finished {
                return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                    crate::CheckpointFormatRejection::RecordCarriedMessageUnfinished,
                )));
            }
            self.message(&m, limits, messages.aead_row_layout(index)?)?;
            if m.route != first.route {
                return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                    crate::CheckpointFormatRejection::RecordMixedRoutes,
                )));
            }
            if phase == PhaseKind::Initial
                && index >= self.carried_messages
                && (m.state != MessageState::Planned
                    || m.next_fragment != 0
                    || m.produced != 0
                    || m.residual_start != 0
                    || m.residual_length != 0)
            {
                return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                    crate::CheckpointFormatRejection::RecordInitialProgression,
                )));
            }
            if self.family == Family::Digest || self.dual() {
                if m.state
                    != if phase == PhaseKind::Initial {
                        MessageState::Planned
                    } else {
                        MessageState::Engaged
                    }
                {
                    return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                        crate::CheckpointFormatRejection::RecordInactiveClassicOperation,
                    )));
                }
                match phase {
                    PhaseKind::SingleOrBegin if m.next_fragment != 0 || m.produced != 0 => {
                        return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                            crate::CheckpointFormatRejection::RecordSingleDigestProgression,
                        )))
                    }
                    PhaseKind::Update
                        if m.next_fragment >= m.fragments.len().max(usize::from(self.dual())) =>
                    {
                        return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                            crate::CheckpointFormatRejection::RecordUpdateProgression,
                        )))
                    }
                    PhaseKind::CipherInit if m.next_fragment != 0 || m.produced != 0 => {
                        return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                            crate::CheckpointFormatRejection::RecordCipherInitProgression,
                        )))
                    }
                    PhaseKind::Final
                    | PhaseKind::CipherFinal
                    | PhaseKind::Residual
                    | PhaseKind::AuthenticationFinal
                        if m.next_fragment != m.fragments.len() =>
                    {
                        return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                            crate::CheckpointFormatRejection::RecordFinalProgression,
                        )))
                    }
                    _ => {}
                }
                if self.dual() {
                    let auth = match self.family {
                        Family::SignEncrypt => CKF_SIGN,
                        Family::DecryptVerify => CKF_VERIFY,
                        _ => CKF_DIGEST,
                    };
                    let flags = if phase == PhaseKind::Initial {
                        0
                    } else {
                        auth | if matches!(phase, PhaseKind::Update | PhaseKind::CipherFinal) {
                            if self.decrypt() {
                                CKF_DECRYPT
                            } else {
                                CKF_ENCRYPT
                            }
                        } else {
                            0
                        }
                    };
                    if self.active_flags != flags as u64
                        || phase == PhaseKind::Residual && m.residual_length == 0
                        || matches!(
                            phase,
                            PhaseKind::Update | PhaseKind::CipherInit | PhaseKind::CipherFinal
                        ) && (m.residual_start != 0 || m.residual_length != 0)
                    {
                        return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                            crate::CheckpointFormatRejection::RecordDualActiveState,
                        )));
                    }
                    if matches!(phase, PhaseKind::Residual | PhaseKind::AuthenticationFinal) {
                        let input = m.fragments.iter().try_fold(0usize, |n, b| {
                            n.checked_add(b?.len()).ok_or(Error::Rejected(
                                crate::RejectionReason::CheckpointFormat(
                                    crate::CheckpointFormatRejection::RecordInputLength,
                                ),
                            ))
                        })?;
                        let (min, max) = crate::advanced::dual::output_bounds(
                            input,
                            self.decrypt(),
                            self.mechanism,
                            ((m.params.tag_bits + 7) / 8) as usize,
                        )?;
                        if m.produced < min
                            || m.produced > max
                            || m.residual_start.checked_add(m.residual_length) != Some(m.produced)
                        {
                            return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                                crate::CheckpointFormatRejection::RecordFinalizedCipherLength,
                            )));
                        }
                    }
                }
            } else if m.state == MessageState::Finished {
                finished += 1;
            } else if !active {
                active = true;
                if phase == PhaseKind::Final
                    || phase == PhaseKind::SingleOrBegin && m.state != MessageState::Planned
                    || phase == PhaseKind::Update
                        && (m.state != MessageState::Engaged
                            || m.next_fragment >= m.fragments.len().max(1))
                {
                    return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                        crate::CheckpointFormatRejection::RecordActiveMessagePhase,
                    )));
                }
            }
        }
        if self.family != Family::Digest
            && !self.dual()
            && (phase == PhaseKind::Final) != (finished == messages.len())
            && !(phase == PhaseKind::Initial
                && self.family == Family::MessageDecrypt
                && self.carried_messages == messages.len())
        {
            return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                crate::CheckpointFormatRejection::RecordBatchFinalPhase,
            )));
        }
        if self.validation_requested && validation.is_none() {
            return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                crate::CheckpointFormatRejection::RecordRequiredValidationAbsent,
            )));
        }
        if let Some(v) = validation {
            let maximum = if self.family == Family::Digest {
                1
            } else if self.dual() {
                2
            } else {
                messages.len().checked_add(1).ok_or(Error::Rejected(
                    crate::RejectionReason::CheckpointFormat(
                        crate::CheckpointFormatRejection::RecordValidationCapacity,
                    ),
                ))?
            };
            if v.maximum() != maximum {
                return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                    crate::CheckpointFormatRejection::RecordValidationOwnerCapacity,
                )));
            }
            let mut observations = v.iter();
            if self.dual() && matches!(phase, PhaseKind::Residual | PhaseKind::AuthenticationFinal)
            {
                let o = observations.next().ok_or(Error::Rejected(
                    crate::RejectionReason::CheckpointFormat(
                        crate::CheckpointFormatRejection::RecordMissingCipherObservation,
                    ),
                ))??;
                if o.function != self.cipher_final() || o.message_index.is_some() {
                    return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                        crate::CheckpointFormatRejection::RecordCipherObservationAssociation,
                    )));
                }
            } else if !self.dual() && self.family != Family::Digest {
                let name = match (self.family, first.route) {
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
                for i in self.carried_messages..finished {
                    let o = observations.next().ok_or(Error::Rejected(
                        crate::RejectionReason::CheckpointFormat(
                            crate::CheckpointFormatRejection::RecordMissingMessageObservation,
                        ),
                    ))??;
                    if o.function != name || o.message_index != Some(i) {
                        return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                            crate::CheckpointFormatRejection::RecordMessageObservationAssociation,
                        )));
                    }
                }
            }
            if observations.next().is_some() {
                return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                    crate::CheckpointFormatRejection::RecordUnexpectedValidationObservation,
                )));
            }
        }
        Ok(())
    }
}
