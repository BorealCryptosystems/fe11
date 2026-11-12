// SPDX-License-Identifier: Apache-2.0
//! Rebuild private typed owners; no native calls or archive authentication.
mod plan;
pub(super) mod resources;
use super::continuation::Continuation;
use super::restoration_keys::BoundKeys;
use super::{dual, gcm, messages, record, validation, OperationBody};
use crate::advanced::record::Family;

use crate::symmetric::memory::{Buffer, Credit};
use crate::{Error, Result};

pub(super) fn output(buffer: &mut Buffer, bytes: &[u8], complete: bool) -> Result<()> {
    buffer
        .as_mut()
        .get_mut(..bytes.len())
        .ok_or(Error::Rejected(crate::RejectionReason::Restoration(
            crate::RestorationRejection::ReconstructionOutputCapacity,
        )))?
        .copy_from_slice(bytes);
    if complete {
        buffer.set_length(bytes.len())?;
    }
    Ok(())
}

// Each prepared family owns stable data but no destination key lease. Binding
// transfers the separately admitted leases without allocating or invoking C.
enum PreparedBody {
    NativeMessages(super::native_messages::checkpoint::PreparedCheckpoint),
    Signature(super::signature::checkpoint::PreparedCheckpoint),
    Digest(super::digest::snapshot::PreparedCheckpoint),
    Cipher(super::cipher::checkpoint::PreparedCheckpoint),
    Recover(super::recover::checkpoint::PreparedCheckpoint),
    AeadMessages(gcm::PreparedAead),
    Messages(messages::PreparedMac),
    Dual(dual::PreparedDual),
}
pub(super) struct PreparedContinuation {
    body: PreparedBody,
    validation: Option<validation::Capture>,
    encrypting: bool,
}
impl PreparedContinuation {
    pub(super) fn into_dual_recovery(
        self,
    ) -> Result<(dual::PreparedDual, Option<validation::Capture>)> {
        let PreparedBody::Dual(body) = self.body else {
            return Err(Error::Rejected(crate::RejectionReason::Restoration(
                crate::RestorationRejection::RecoveryPreparationFamily,
            )));
        };
        Ok((body, self.validation))
    }
    pub(super) fn into_aead_recovery(
        self,
    ) -> Result<(gcm::PreparedAead, Option<validation::Capture>)> {
        let PreparedBody::AeadMessages(body) = self.body else {
            return Err(Error::Rejected(crate::RejectionReason::Restoration(
                crate::RestorationRejection::RecoveryPreparationFamily,
            )));
        };
        Ok((body.into_fresh(), self.validation))
    }

    /// Keep both input owners in the caller until every family and role check
    /// succeeds. Its slots must precede session access in local drop order.
    pub(super) fn bind_retained(
        prepared: &mut Option<Self>,
        keys: &mut Option<BoundKeys>,
    ) -> Result<Continuation> {
        let body =
            prepared
                .as_ref()
                .ok_or(Error::Rejected(crate::RejectionReason::Restoration(
                    crate::RestorationRejection::ReconstructionCandidateAbsent,
                )))?;
        let bound = keys
            .as_ref()
            .ok_or(Error::Rejected(crate::RejectionReason::Restoration(
                crate::RestorationRejection::ReconstructionKeysAbsent,
            )))?;
        body.check_binding(bound)?;
        let body = prepared.take().expect("checked reconstruction candidate");
        let bound = keys.take().expect("checked reconstruction keys");
        Ok(body.bind_checked(bound))
    }
    fn check_binding(&self, keys: &BoundKeys) -> Result<()> {
        // Keep the original family-error order. Surplus roles are rejected only
        // after that family's required inputs have passed their own checks.
        let surplus = match &self.body {
            PreparedBody::NativeMessages(body) => {
                body.check_binding(keys.native_messages())?;
                keys.encryption.is_some()
                    || keys.authentication.is_some()
                    || keys.extension.is_some()
            }
            PreparedBody::Signature(body) => {
                body.check_binding(keys.classic_signature())?;
                keys.encryption.is_some()
                    || keys.authentication.is_some()
                    || keys.extension.is_some()
            }
            PreparedBody::Digest(body) => {
                body.check_binding(keys.extension.as_ref())?;
                keys.encryption.is_some()
                    || keys.authentication.is_some()
                    || keys.signature.is_some()
            }
            PreparedBody::Cipher(body) => {
                body.check_binding(keys.encryption.as_ref(), keys.extension.as_ref())?;
                keys.authentication.is_some() || keys.signature.is_some()
            }
            PreparedBody::Recover(_) => {
                keys.authentication.as_ref().ok_or(Error::Rejected(
                    crate::RejectionReason::Restoration(
                        crate::RestorationRejection::RecoveryDestinationKeyAbsent,
                    ),
                ))?;
                keys.encryption.is_some() || keys.signature.is_some() || keys.extension.is_some()
            }
            PreparedBody::AeadMessages(_) => {
                keys.encryption.as_ref().ok_or(Error::Rejected(
                    crate::RejectionReason::Restoration(
                        crate::RestorationRejection::ReconstructionCipherKey,
                    ),
                ))?;
                keys.authentication.is_some()
                    || keys.signature.is_some()
                    || keys.extension.is_some()
            }
            PreparedBody::Messages(_) => {
                keys.authentication.as_ref().ok_or(Error::Rejected(
                    crate::RejectionReason::Restoration(
                        crate::RestorationRejection::ReconstructionAuthenticationKey,
                    ),
                ))?;
                keys.encryption.is_some() || keys.signature.is_some() || keys.extension.is_some()
            }
            PreparedBody::Dual(body) => {
                keys.encryption.as_ref().ok_or(Error::Rejected(
                    crate::RejectionReason::Restoration(
                        crate::RestorationRejection::ReconstructionCipherKey,
                    ),
                ))?;
                body.check_binding(keys.authentication.as_ref())?;
                keys.signature.is_some() || keys.extension.is_some()
            }
        };
        if surplus {
            return Err(Error::Rejected(crate::RejectionReason::Restoration(
                crate::RestorationRejection::CheckpointDestinationRoles,
            )));
        }
        Ok(())
    }
    // Only check_binding callers may transfer these exact, unchanged inputs.
    fn bind_checked(self, mut keys: BoundKeys) -> Continuation {
        let body = match self.body {
            PreparedBody::NativeMessages(body) => OperationBody::NativeMessages(
                body.bind_checked(
                    keys.take_native_messages()
                        .expect("validated message binding"),
                ),
            ),
            PreparedBody::Signature(body) => OperationBody::Signature(
                body.bind_checked(
                    keys.take_classic_signature()
                        .expect("validated signature binding"),
                ),
            ),
            PreparedBody::Digest(body) => {
                OperationBody::Digest(body.bind_checked(keys.extension.take()))
            }
            PreparedBody::Cipher(body) => OperationBody::Cipher(
                body.bind_checked(keys.encryption.take(), keys.extension.take()),
            ),
            PreparedBody::Recover(body) => OperationBody::Recover(
                body.bind(keys.authentication.take().expect("validated recovery key")),
            ),
            PreparedBody::AeadMessages(body) => OperationBody::AeadMessages(
                body.bind(keys.encryption.take().expect("validated cipher key")),
            ),
            PreparedBody::Messages(body) => OperationBody::Messages(
                body.bind(
                    keys.authentication
                        .take()
                        .expect("validated authentication key"),
                ),
            ),
            PreparedBody::Dual(body) => OperationBody::Dual(body.bind_checked(
                keys.encryption.take().expect("validated cipher key"),
                keys.authentication.take(),
            )),
        };
        Continuation {
            body,
            validation: self.validation,
            encrypting: self.encrypting,
        }
    }
}
/// A destination retains either its stable preparation or its reconstructed
/// continuation. Post-reconstruction validation may refuse without discarding
/// the newly bound keys under session access. Transferred is only a move sentinel.
pub(super) enum DestinationContinuation {
    Prepared(PreparedContinuation),
    Bound(Continuation),
    Transferred,
}
impl DestinationContinuation {
    pub(super) fn bind(&mut self, keys: &mut BoundKeys) -> Result<()> {
        let Self::Prepared(prepared) = self else {
            return Err(Error::Rejected(crate::RejectionReason::Restoration(
                crate::RestorationRejection::DestinationContinuationAlreadyBound,
            )));
        };
        prepared.check_binding(keys)?;
        let Self::Prepared(prepared) = std::mem::replace(self, Self::Transferred) else {
            unreachable!("checked destination preparation")
        };
        let keys = std::mem::replace(keys, BoundKeys::new(None, None));
        *self = Self::Bound(prepared.bind_checked(keys));
        Ok(())
    }
    pub(super) fn bind_detached(
        &mut self,
        keys: &mut BoundKeys,
        record: &record::DetachedRecord<'_>,
    ) -> Result<()> {
        check_keys(record.descriptor, &record.keys, &record.messages, keys)?;
        self.bind(keys)?;
        let Self::Bound(result) = self else {
            unreachable!("successfully bound destination continuation")
        };
        finish_detached(result, record)
    }
    /// Consume only after binding and any detached-state checks have succeeded.
    pub(super) fn into_bound(self) -> Continuation {
        match self {
            Self::Bound(result) => result,
            _ => unreachable!("validated destination continuation"),
        }
    }
}
fn finish_detached(result: &mut Continuation, record: &record::DetachedRecord<'_>) -> Result<()> {
    if let Some(valid) = record.terminal {
        // A completed message process can contain zero messages. Only
        // classic digest/dual owners consume a first-row payload here.
        let first = || -> Result<record::Message<'_>> {
            record.messages.iter().next().ok_or(Error::Rejected(
                crate::RejectionReason::Restoration(
                    crate::RestorationRejection::TerminalMessageAbsent,
                ),
            ))?
        };
        match &mut result.body {
            OperationBody::Digest(body) => {
                let first = first()?;
                output(&mut body.frame.output, first.result, true)?;
                *body.frame.length = crate::bounds::ck_length(first.result.len())?;
                body.step = super::digest::Step::Complete;
                body.activity = super::operation::NativeActivity::Closed;
            }
            OperationBody::Messages(body) => body.set_terminal(valid),
            OperationBody::AeadMessages(body) => body.set_terminal(),
            OperationBody::Recover(body) => body.set_terminal(),
            OperationBody::Cipher(body) => body.set_terminal(),
            OperationBody::Dual(body) => body.set_terminal(
                valid,
                first()?.tag_or_signature.ok_or(Error::Rejected(
                    crate::RejectionReason::Restoration(
                        crate::RestorationRejection::TerminalAuthenticationAbsent,
                    ),
                ))?,
            )?,
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::Restoration(
                    crate::RestorationRejection::TerminalFamily,
                )))
            }
        }
        result
            .validation
            .as_mut()
            .ok_or(Error::Rejected(crate::RejectionReason::Restoration(
                crate::RestorationRejection::TerminalReportAbsent,
            )))?
            .restore_terminal(record.descriptor.phase.name())?;
    } else {
        let actual = match &result.body {
            OperationBody::Digest(body) => body.joined_capacity()?,
            OperationBody::Messages(body) => body.joined_capacity()?,
            OperationBody::AeadMessages(body) => body.joined_capacity()?,
            OperationBody::Dual(body) => body.joined_capacity()?,
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::Restoration(
                    crate::RestorationRejection::DetachedReconstructionOwner,
                )))
            }
        };
        if actual != record.capacity {
            return Err(Error::Rejected(crate::RejectionReason::Restoration(
                crate::RestorationRejection::DetachedReconstructedCapacity,
            )));
        }
    }
    Ok(())
}
fn check_keys(
    descriptor: record::Descriptor,
    bindings: &record::KeyBindings<'_>,
    messages: &record::Messages<'_>,
    keys: &BoundKeys,
) -> Result<()> {
    let dual = super::dual::authentication::record_selection(descriptor, messages)?;
    let mac = dual.and_then(|a| a.mac());
    for (expected, actual, profile, size) in [
        (
            bindings.cipher,
            keys.encryption.as_ref(),
            super::dual::authentication::cipher_profile(descriptor)?,
            0,
        ),
        (
            bindings.authentication,
            keys.authentication.as_ref(),
            if descriptor.family.is_recover() {
                1
            } else {
                mac.map_or(descriptor.profile, |a| a.profile())
            },
            descriptor.size,
        ),
    ] {
        match (expected, actual) {
            (Some(e), Some(a)) => a.check_checkpoint(e, profile, size)?,
            (None, None) => {}
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::Restoration(
                    crate::RestorationRejection::CheckpointDestinationRoles,
                )))
            }
        }
    }
    Ok(())
}

/// Pure destination recipe. A containing import/rejoin can admit it together
/// with native state, output negotiation and publication metadata.
pub(super) struct Recipe<'a> {
    body: plan::Plan<'a>,
    validation: Option<ValidationPlan<'a>>,
    encrypting: bool,
}
enum ValidationPlan<'a> {
    Archived(record::ValidationRecord<'a>),
    Fresh(usize),
}
impl ValidationPlan<'_> {
    fn maximum(&self) -> usize {
        match self {
            Self::Archived(record) => record.maximum(),
            Self::Fresh(maximum) => *maximum,
        }
    }
}
pub(super) struct Unbound<'a> {
    body: plan::Storage<'a>,
    validation: Option<validation::CaptureStorage>,
}
impl<'a> Recipe<'a> {
    fn new(
        descriptor: record::Descriptor,
        messages: &record::Messages<'a>,
        validation: Option<&record::ValidationRecord<'a>>,
        ceilings: crate::CryptoLimits,
        pending: bool,
    ) -> Result<Self> {
        ceilings.validate()?;
        Ok(Self {
            body: plan::Plan::new(descriptor, messages, ceilings, pending)?,
            validation: validation.copied().map(ValidationPlan::Archived),
            encrypting: if descriptor.family == Family::Signature {
                messages
                    .iter()
                    .next()
                    .ok_or(Error::Rejected(crate::RejectionReason::Restoration(
                        crate::RestorationRejection::SignatureMessageAbsent,
                    )))??
                    .params
                    .signature
                    .ok_or(Error::Rejected(crate::RejectionReason::Restoration(
                        crate::RestorationRejection::SignatureParametersAbsent,
                    )))?
                    .mutates_key
            } else if descriptor.family.is_cipher() {
                descriptor.family == Family::CipherEncrypt
                    || messages
                        .iter()
                        .next()
                        .transpose()?
                        .and_then(|message| message.params.cipher_extension)
                        .is_some_and(|extension| extension.mutates_key)
            } else {
                matches!(
                    descriptor.family,
                    Family::MessageEncrypt
                        | Family::DigestEncrypt
                        | Family::SignEncrypt
                        | Family::CipherEncrypt
                )
            },
        })
    }
    pub(super) fn checkpoint(
        descriptor: record::Descriptor,
        bindings: &record::KeyBindings<'_>,
        messages: &record::Messages<'a>,
        validation: Option<&record::ValidationRecord<'a>>,
        limits: record::Limits,
        ceilings: crate::CryptoLimits,
    ) -> Result<Self> {
        descriptor.validate(bindings, messages, validation, limits)?;
        Self::new(descriptor, messages, validation, ceilings, false)
    }
    /// Import preparation supplies the rebound Init graph and explicit call
    /// declarations. Serialized pointers/handles alone never authorize execution.
    pub(super) fn native_checkpoint(
        session: &'a crate::Session,
        descriptor: record::Descriptor,
        bindings: &record::KeyBindings<'_>,
        messages: &record::Messages<'a>,
        validation: Option<&record::ValidationRecord<'a>>,
        limits: record::Limits,
        ceilings: crate::CryptoLimits,
        initialization: super::native_messages::restoration::InitializationPlan<'a>,
        declarations: &'a [Option<&'a crate::MechanismExtension>],
    ) -> Result<Self> {
        if descriptor.family != Family::NativeMessages {
            return Err(Error::Rejected(crate::RejectionReason::Restoration(
                crate::RestorationRejection::GenericMessageReconstructionFamily,
            )));
        }
        descriptor.validate(bindings, messages, validation, limits)?;
        ceilings.validate()?;
        let record =
            messages
                .native()
                .ok_or(Error::Rejected(crate::RejectionReason::Restoration(
                    crate::RestorationRejection::GenericMessageArchiveBodyAbsent,
                )))?;
        Ok(Self {
            body: plan::Plan::NativeMessages(super::native_messages::checkpoint::RecordPlan::new(
                session,
                descriptor,
                record,
                initialization,
                declarations,
                ceilings,
            )?),
            validation: validation.copied().map(ValidationPlan::Archived),
            encrypting: record.header.writer,
        })
    }
    pub(super) fn detached(
        record: &record::DetachedRecord<'a>,
        limits: record::Limits,
        ceilings: crate::CryptoLimits,
    ) -> Result<Self> {
        if let Some(valid) = record.terminal {
            record.descriptor.validate_terminal(
                &record.keys,
                &record.messages,
                record.validation.as_ref(),
                limits,
                valid,
            )?;
        } else {
            if record.capture {
                return Err(Error::Rejected(crate::RejectionReason::Restoration(
                    crate::RestorationRejection::CaptureRecordIsNotAnActiveCryptographicOperation,
                )));
            }
            let capacity = record.descriptor.validate_detached(
                &record.keys,
                &record.messages,
                record.validation.as_ref(),
                limits,
            )?;
            if capacity != record.capacity
                || record.function.name() != record.descriptor.phase.name()
            {
                return Err(Error::Rejected(crate::RejectionReason::Restoration(
                    crate::RestorationRejection::DetachedContinuationAssociation,
                )));
            }
        }
        Self::new(
            record.descriptor,
            &record.messages,
            record.validation.as_ref(),
            ceilings,
            record.terminal.is_none(),
        )
    }
    pub(super) fn dual_recovery(
        descriptor: record::Descriptor,
        messages: &record::Messages<'a>,
        ceilings: crate::CryptoLimits,
        capture: bool,
    ) -> Result<Self> {
        Ok(Self {
            body: plan::Plan::Dual(dual::snapshot::RecordPlan::recovery(
                descriptor, messages, ceilings,
            )?),
            validation: capture.then_some(ValidationPlan::Fresh(2)),
            encrypting: false,
        })
    }
    pub(super) fn aead_recovery(
        section: &record::RecoverySection<'a>,
        ceilings: crate::CryptoLimits,
        capture: bool,
    ) -> Result<Self> {
        let mut carried_messages = 0;
        for message in section.messages.iter() {
            if message?.state != record::MessageState::Finished {
                break;
            }
            carried_messages += 1;
        }
        let descriptor = record::Descriptor {
            input: crate::advanced::input::InputState::closed(),
            family: Family::MessageDecrypt,
            profile: section.profile,
            phase: record::Function::from_name("C_MessageDecryptInit")?,
            mechanism: section.mechanism,
            size: 0,
            active_flags: 0,
            validation_requested: false,
            digest_bits: None,
            cipher_options: None,
            carried_messages,
        };
        let mut result = Self::new(descriptor, &section.messages, None, ceilings, false)?;
        if capture {
            let maximum = section
                .messages
                .len()
                .checked_add(1)
                .ok_or(Error::Rejected(crate::RejectionReason::Restoration(
                    crate::RestorationRejection::RecoveryValidationCapacity,
                )))?;
            result.validation = Some(ValidationPlan::Fresh(maximum));
        }
        Ok(result)
    }
    pub(super) fn allocation_bytes(&self) -> Result<usize> {
        self.body
            .allocation_bytes()?
            .checked_add(
                self.validation
                    .as_ref()
                    .map(|record| validation::Capture::allocation_bytes(record.maximum()))
                    .transpose()?
                    .unwrap_or(0),
            )
            .ok_or(Error::Rejected(crate::RejectionReason::Restoration(
                crate::RestorationRejection::ReconstructionMetadata,
            )))
    }
    pub(super) fn allocate(&self, prepaid: &mut Credit) -> Result<Unbound<'a>> {
        Ok(Unbound {
            body: self.body.allocate(prepaid)?,
            validation: self
                .validation
                .as_ref()
                .map(|record| validation::CaptureStorage::allocate(record.maximum()))
                .transpose()?,
        })
    }
    pub(super) fn bind(
        self,
        storage: Unbound<'a>,
        prepaid: &mut Credit,
    ) -> Result<PreparedContinuation> {
        let body = self.body.bind(storage.body, prepaid)?;
        let mut validation = storage
            .validation
            .map(|storage| storage.bind(prepaid))
            .transpose()?;
        if let (Some(target), Some(ValidationPlan::Archived(source))) =
            (&mut validation, &self.validation)
        {
            target.restore_record(source)?;
        }
        Ok(PreparedContinuation {
            body,
            validation,
            encrypting: self.encrypting,
        })
    }
}
impl Unbound<'_> {
    pub(super) fn allocated_bytes(&self) -> Result<usize> {
        self.body
            .allocated_bytes()?
            .checked_add(
                self.validation
                    .as_ref()
                    .map(validation::CaptureStorage::allocated_bytes)
                    .transpose()?
                    .unwrap_or(0),
            )
            .ok_or(Error::Rejected(crate::RejectionReason::Restoration(
                crate::RestorationRejection::ReconstructionMetadata,
            )))
    }
}


