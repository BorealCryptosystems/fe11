// SPDX-License-Identifier: Apache-2.0
//! Interpret checkpoint families, phases and message dimensions.
//! Descriptor relationships are validated before rebuilding an operation owner.

use super::*;

impl Descriptor {
    pub(super) fn decrypt(self) -> bool {
        matches!(
            self.family,
            Family::MessageDecrypt | Family::DecryptDigest | Family::DecryptVerify
        )
    }

    pub(super) fn dual(self) -> bool {
        self.family.is_dual()
    }

    pub(super) fn cipher_final(self) -> &'static str {
        if self.decrypt() {
            "C_DecryptFinal"
        } else {
            "C_EncryptFinal"
        }
    }

    pub(super) fn auth_final(self) -> &'static str {
        match self.family {
            Family::SignEncrypt => "C_SignFinal",
            Family::DecryptVerify => "C_VerifyFinal",
            _ => "C_DigestFinal",
        }
    }

    pub(super) fn phase_kind(self, route: MessageRoute) -> Result<PhaseKind> {
        let p = self.phase.name();
        if self.family == Family::Digest {
            return match p {
                "C_Digest" if route == MessageRoute::Single => Ok(PhaseKind::SingleOrBegin),
                "C_DigestUpdate" if route == MessageRoute::Multipart => Ok(PhaseKind::Update),
                "C_DigestFinal" if route == MessageRoute::Multipart => Ok(PhaseKind::Final),
                _ => Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                    crate::CheckpointFormatRejection::RecordDigestPhase,
                ))),
            };
        }
        if self.dual() {
            if p == if self.decrypt() {
                "C_DecryptInit"
            } else {
                "C_EncryptInit"
            } {
                return Ok(PhaseKind::CipherInit);
            }
            let update = match self.family {
                Family::DigestEncrypt => "C_DigestEncryptUpdate",
                Family::DecryptDigest => "C_DecryptDigestUpdate",
                Family::SignEncrypt => "C_SignEncryptUpdate",
                Family::DecryptVerify => "C_DecryptVerifyUpdate",
                _ => unreachable!(),
            };
            if p == update {
                return Ok(PhaseKind::Update);
            }
            if p == self.cipher_final() {
                return Ok(PhaseKind::CipherFinal);
            }
            if self.decrypt()
                && p == if self.family == Family::DecryptVerify {
                    "C_VerifyUpdate"
                } else {
                    "C_DigestUpdate"
                }
            {
                return Ok(PhaseKind::Residual);
            }
            if p == self.auth_final() {
                return Ok(PhaseKind::AuthenticationFinal);
            }
            return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                crate::CheckpointFormatRejection::RecordDualPhase,
            )));
        }
        let (single, begin, next, finalize) = match self.family {
            Family::MessageEncrypt => (
                "C_EncryptMessage",
                "C_EncryptMessageBegin",
                "C_EncryptMessageNext",
                "C_MessageEncryptFinal",
            ),
            Family::MessageDecrypt => (
                "C_DecryptMessage",
                "C_DecryptMessageBegin",
                "C_DecryptMessageNext",
                "C_MessageDecryptFinal",
            ),
            Family::MessageSign => (
                "C_SignMessage",
                "C_SignMessageBegin",
                "C_SignMessageNext",
                "C_MessageSignFinal",
            ),
            Family::MessageVerify => (
                "C_VerifyMessage",
                "C_VerifyMessageBegin",
                "C_VerifyMessageNext",
                "C_MessageVerifyFinal",
            ),
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                    crate::CheckpointFormatRejection::RecordOperationFamily,
                )))
            }
        };
        if p == finalize {
            Ok(PhaseKind::Final)
        } else if p == single && route == MessageRoute::Single
            || p == begin && route == MessageRoute::Multipart
        {
            Ok(PhaseKind::SingleOrBegin)
        } else if p == next && route == MessageRoute::Multipart {
            Ok(PhaseKind::Update)
        } else {
            Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                crate::CheckpointFormatRejection::RecordMessagePhase,
            )))
        }
    }

    pub(super) fn message(
        self,
        m: &Message<'_>,
        limits: Limits,
        layout: super::super::aead_batch::RowLayout,
    ) -> Result<()> {
        self.message_mode(m, limits, false, layout)
    }

    pub(in crate::advanced::record) fn message_mode(
        self,
        m: &Message<'_>,
        limits: Limits,
        terminal: bool,
        layout: super::super::aead_batch::RowLayout,
    ) -> Result<()> {
        if self.dual() && self.mechanism == CKM_AES_CTR as u64 {
            crate::advanced::dual::cipher::counter_width(m.params.counter_bits.ok_or(
                Error::Rejected(crate::RejectionReason::CheckpointFormat(
                    crate::CheckpointFormatRejection::RecordCtrCounterWidthAbsent,
                )),
            )?)?;
        } else if m.params.counter_bits.is_some() {
            return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                crate::CheckpointFormatRejection::RecordCounterWidthOnNonCtrOperation,
            )));
        }
        if m.params.message_init.is_some()
            && !matches!(self.family, Family::MessageEncrypt | Family::MessageDecrypt)
        {
            return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                crate::CheckpointFormatRejection::RecordInitLayoutForANonAeadMessageFamily,
            )));
        }

        let dual_authentication = if self.dual() {
            Some(crate::advanced::dual::authentication::Authentication::from_record(self, m)?)
        } else {
            None
        };
        let p = &m.params;
        if self.family != Family::Digest && p.digest_extension.is_some() {
            return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                crate::CheckpointFormatRejection::DigestExtensionOnAnotherFamily,
            )));
        }
        if self.family != Family::Digest && p.digest_oid.is_some() {
            return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                crate::CheckpointFormatRejection::DigestOidOnANonDigestRecord,
            )));
        }
        let ccm_parameters = self.mechanism == CKM_AES_CCM as u64;
        let stream_parameters = crate::symmetric::poly1305::is_stream_aead(self.mechanism);
        let aead_parameters =
            self.mechanism == CKM_AES_GCM as u64 || ccm_parameters || stream_parameters;
        if aead_parameters {
            let initial =
                p.iv_initial
                    .ok_or(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                        crate::CheckpointFormatRejection::RecordInitialIvAbsent,
                    )))?;
            let generator =
                p.iv_generator
                    .ok_or(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                        crate::CheckpointFormatRejection::RecordIvGeneratorAbsent,
                    )))?;
            let fixed = p.iv_fixed_bits.ok_or(Error::Rejected(
                crate::RejectionReason::CheckpointFormat(
                    crate::CheckpointFormatRejection::RecordIvFixedBitsAbsent,
                ),
            ))?;
            let message_decrypt = self.family == Family::MessageDecrypt;
            if initial.is_empty()
                || initial.len() as u64 > u32::MAX as u64
                || (!message_decrypt && fixed > initial.len() as u64 * 8)
                || p.tag_bits > 128
                || CK_ULONG::try_from(generator).is_err()
                || CK_ULONG::try_from(fixed).is_err()
                || (m.origin == NonceOrigin::Backend)
                    != (!message_decrypt && generator != CKG_NO_GENERATE as u64)
                || self.dual() && (generator != 0 || fixed != 0)
                || p.nonce.is_some_and(|nonce| nonce.len() != initial.len())
            {
                return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                    crate::CheckpointFormatRejection::RecordAeadParameterSelection,
                )));
            }
            if let Some(actual) = p.nonce {
                crate::advanced::record::aead_messages::Selection {
                    nonce: initial,
                    generator,
                    fixed_bits: fixed,
                    tag_bits: p.tag_bits as u64,
                }
                .validate_nonce(actual, message_decrypt)?;
            }
        } else if p.iv_initial.is_some() || p.iv_generator.is_some() || p.iv_fixed_bits.is_some() {
            return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                crate::CheckpointFormatRejection::RecordNonAeadNonceSelection,
            )));
        }
        if stream_parameters {
            let initial =
                p.iv_initial
                    .ok_or(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                        crate::CheckpointFormatRejection::RecordStreamAeadNonce,
                    )))?;
            crate::StreamAeadNonce::from_record(self.mechanism, initial)?;
            if p.tag_bits != 128
                || p.iv_generator != Some(0)
                || p.iv_fixed_bits != Some(0)
                || p.message_init != Some(crate::MessageInitLayout::InitWithoutParameters)
                || m.origin != NonceOrigin::Provided
                || p.nonce != Some(initial)
            {
                return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                    crate::CheckpointFormatRejection::RecordStreamAeadParameters,
                )));
            }
        }
        let input = m.fragments.iter().try_fold(0usize, |n, b| {
            n.checked_add(b?.len())
                .filter(|n| *n <= limits.bytes)
                .ok_or(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                    crate::CheckpointFormatRejection::RecordInputLength,
                )))
        })?;
        // Only the CCM native parameter uses the original declared length.
        // Retained fragments and allocations continue to use their actual size.
        let declared_input = layout.declared_input.unwrap_or(input);
        if ccm_parameters {
            if p.tag_bits % 8 != 0 {
                return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                    crate::CheckpointFormatRejection::RecordCcmMacAlignment,
                )));
            }
            let initial =
                p.iv_initial
                    .ok_or(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                        crate::CheckpointFormatRejection::RecordCcmInitialNonce,
                    )))?;
            crate::symmetric::validate_ccm_fields(
                crate::symmetric::AeadParameterLayout::Message,
                initial.len(),
                p.iv_generator
                    .ok_or(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                        crate::CheckpointFormatRejection::RecordCcmGenerator,
                    )))?,
                p.iv_fixed_bits.ok_or(Error::Rejected(
                    crate::RejectionReason::CheckpointFormat(
                        crate::CheckpointFormatRejection::RecordCcmFixedBits,
                    ),
                ))?,
                p.aad.map_or(0, |a| a.len()),
                p.tag_bits as u64 / 8,
                declared_input,
                self.family == Family::MessageDecrypt,
            )?;
        }
        if self.family == Family::Digest {
            let selection = crate::advanced::digest::DigestSelection::from_descriptor(self)?;
            let output = p.digest_output.ok_or(Error::Rejected(
                crate::RejectionReason::CheckpointFormat(
                    crate::CheckpointFormatRejection::DigestOutputStorageAbsent,
                ),
            ))?;
            if output.capacity > limits.bytes {
                return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                    crate::CheckpointFormatRejection::DigestOutputStorageLimit,
                )));
            }
            if let Some(required) = p.digest_output.and_then(|output| output.waiting) {
                crate::bounds::ck_length(required)?;
                let single = selection.route() == MessageRoute::Single;
                // Single retries the same issued input; Final submits no input.
                // Multipart totals can include already retired fragments/keys,
                // so they are not reconstructed from the remaining message.
                let invalid_submission = if single {
                    !self.input.retained_submission
                        || self.input.incremental
                        || self.input.progress.submissions != 1
                        || self.input.progress.input_bytes != 0
                        || self.input.progress.key_inputs != 0
                } else {
                    self.input.retained_submission
                };
                if terminal
                    || self.input.is_open()
                    || self.phase.name() != selection.terminal_function()
                    || invalid_submission
                {
                    return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                        crate::CheckpointFormatRejection::DigestOutputWaitIsNotARetainedTerminal,
                    )));
                }
            }
            if m.origin != NonceOrigin::None
                || m.route != selection.route()
                || (selection.route() == MessageRoute::Single
                    && if terminal {
                        m.fragments.len() != 0 || m.next_fragment != 0
                    } else {
                        m.fragments.len() != 1 || m.next_fragment != 0
                    })
                || self.input.is_open() && (terminal || selection.route() == MessageRoute::Single)
                || self.input.progress.output_bytes != m.produced as u128
                || self.input.progress.delivered_bytes != 0
                || p.nonce.is_some()
                || p.aad.is_some()
                || p.tag_bits != 0
                || matches!(
                    selection,
                    crate::advanced::digest::DigestSelection::Extension { .. }
                ) != p.digest_extension.is_some()
                || selection.has_oid() != p.digest_oid.is_some()
                || p.hash != Some(self.mechanism)
                || p.mgf.is_some()
                || p.salt.is_some()
                || m.expected != output.capacity
                || if terminal {
                    !selection.accepts_length(m.produced)
                } else {
                    m.produced != 0
                }
                || m.tag_or_signature.is_some()
            {
                return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                    crate::CheckpointFormatRejection::RecordDigestParameters,
                )));
            }
        } else if matches!(self.family, Family::MessageSign | Family::MessageVerify) {
            if p.nonce.is_some() || p.aad.is_some() || m.origin != NonceOrigin::None {
                return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                    crate::CheckpointFormatRejection::RecordSignatureParameters,
                )));
            }
            self.signature_parameters(p)?;
            let signed = self.family == Family::MessageSign;
            let finished = m.state == MessageState::Finished;
            // The common Message validator already requires produced <=
            // expected and produced == result.len(). A native result is not
            // rejected for differing from the convenience API's initial size.
            if !signed && (m.expected != 0 || m.produced != 0)
                || signed && !finished && m.produced != 0
            {
                return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                    crate::CheckpointFormatRejection::RecordSignatureResult,
                )));
            }
            if !signed || finished {
                if m.tag_or_signature.map_or(true, |s| s.len() > limits.bytes)
                    || signed && m.tag_or_signature != Some(m.result)
                {
                    return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                        crate::CheckpointFormatRejection::RecordSignatureAssociation,
                    )));
                }
            } else if m.tag_or_signature.is_some() {
                return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                    crate::CheckpointFormatRejection::RecordPrematureSignature,
                )));
            }
        } else {
            let aead = aead_parameters;
            // Message AAD is independent of the nonce/parameter structure.
            // Dual operations still emit the classic GCM layout below.
            if let Some(aad) = p.aad {
                crate::bounds::ck_length(aad.len())?;
            }
            if (aead && p.tag_bits > 128 || !aead && p.tag_bits != 0)
                || p.mgf.is_some()
                || p.salt.is_some()
                || !self.dual() && p.hash.is_some()
                || p.aad.is_some() != aead
                || self.dual()
                    && self.mechanism == CKM_AES_GCM as u64
                    && p.aad.is_some_and(|a| a.len() as u128 > u32::MAX as u128)
            {
                return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                    crate::CheckpointFormatRejection::RecordCipherParameters,
                )));
            }
            if m.origin == NonceOrigin::None
                || self.decrypt() && m.origin != NonceOrigin::Provided
                || self.dual() && m.origin != NonceOrigin::Provided
                || p.nonce.is_some_and(|n| {
                    if aead {
                        n.is_empty() || n.len() as u64 > u32::MAX as u64
                    } else {
                        n.len()
                            != if self.mechanism == CKM_AES_ECB as u64 {
                                0
                            } else {
                                16
                            }
                    }
                })
                || p.nonce.is_none()
                    && !(m.origin == NonceOrigin::Backend && m.state == MessageState::Planned)
            {
                return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                    crate::CheckpointFormatRejection::RecordCipherNonce,
                )));
            }
            if self.dual() {
                if m.route != MessageRoute::Multipart
                    || m.expected
                        != crate::advanced::dual::output_bounds(
                            input,
                            self.decrypt(),
                            self.mechanism,
                            ((p.tag_bits + 7) / 8) as usize,
                        )?
                        .1
                {
                    return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                        crate::CheckpointFormatRejection::RecordDualCapacity,
                    )));
                }
                if self.family == Family::DecryptVerify || terminal {
                    if m.tag_or_signature.map_or(true, |t| {
                        t.len()
                            != dual_authentication
                                .expect("dual selection checked above")
                                .length()
                    }) {
                        return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                            crate::CheckpointFormatRejection::RecordExpectedMac,
                        )));
                    }
                } else if m.tag_or_signature.is_some() {
                    return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                        crate::CheckpointFormatRejection::RecordPrematureDualAuthentication,
                    )));
                }
            } else {
                // Historical archives derive storage from input length. Tag 7
                // carries its actual capacity; the row decoder bounds every
                // retained byte by that capacity and the archive byte limit.
                if !layout.output_capacity && m.expected != input
                    || m.tag_or_signature
                        .map_or(true, |t| t.len() != ((p.tag_bits + 7) / 8) as usize)
                {
                    return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                        crate::CheckpointFormatRejection::RecordAeadOutput,
                    )));
                }
                let consumed =
                    m.fragments
                        .iter()
                        .take(m.next_fragment)
                        .try_fold(0usize, |n, b| {
                            n.checked_add(b?.len()).ok_or(Error::Rejected(
                                crate::RejectionReason::CheckpointFormat(
                                    crate::CheckpointFormatRejection::RecordConsumedLength,
                                ),
                            ))
                        })?;
                // Message AEAD carries its tag separately: a successful row
                // preserves the text length, independent of allocated capacity.
                if m.state == MessageState::Finished && m.produced != declared_input {
                    return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                        crate::CheckpointFormatRejection::RecordAeadOutput,
                    )));
                }
                if !layout.output_capacity && m.produced > consumed {
                    return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                        crate::CheckpointFormatRejection::RecordOutputPrecedesInput,
                    )));
                }
            }
        }
        if !self.dual() && (m.residual_start != 0 || m.residual_length != 0) {
            return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                crate::CheckpointFormatRejection::RecordUnexpectedResidual,
            )));
        }
        Ok(())
    }
}
