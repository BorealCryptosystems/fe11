// SPDX-License-Identifier: Apache-2.0
//! Private, budgeted copies of completed native steps; never clone pointers.
use super::{
    function, record, restoration_keys, validation, DigestOperation, MessageRoute, Operation,
    OperationBody, StateRestoreKeys, Step,
};

use crate::advanced::record::Family;
use crate::module::SessionEntry;
use crate::symmetric::memory::{Budget, Buffer, Credit};
use crate::{Error, Result, Session};

use std::sync::Arc;

pub(super) fn copy(destination: &mut Buffer, source: &Buffer) -> Result<()> {
    if destination.capacity() != source.capacity() {
        return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
            crate::OperationOwnershipRejection::ContinuationBufferCapacity,
        )));
    }
    destination.as_mut()[..source.as_slice().len()].copy_from_slice(source.as_slice());
    destination.set_length(source.as_slice().len())
}
/// Original API fragment boundaries, independent of native single-call packing.
pub(super) struct InputLayout {
    lengths: Vec<usize>,
    first: usize,
    _credit: Credit,
}
impl crate::symmetric::memory::RetainedStorage for InputLayout {
    fn retain_credits(&self, retained: &mut crate::symmetric::memory::RetainedBytes) -> Result<()> {
        retained.add_credit(&self._credit)
    }
}

impl InputLayout {
    pub(super) fn consume_first(&mut self) {
        if self.first < self.lengths.len() {
            self.first += 1;
        }
    }

    pub(super) fn clear(&mut self) {
        self.first = self.lengths.len();
    }

    pub(super) fn lengths(&self) -> &[usize] {
        &self.lengths[self.first..]
    }
    pub(super) fn from_owned_lengths(prepaid: &mut Credit, lengths: Vec<usize>) -> Result<Self> {
        let credit = prepaid.split(Self::allocation_bytes(lengths.capacity())?)?;
        Ok(Self {
            lengths,
            first: 0,
            _credit: credit,
        })
    }

    pub(super) fn allocation_bytes(count: usize) -> Result<usize> {
        count
            .checked_mul(std::mem::size_of::<usize>())
            .ok_or(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::FragmentMetadataOverflow,
            )))
    }

    /// Borrow original fragment boundaries without allocating a view vector.
    /// The slices remain within the caller's source guard and never enter a waiter.
    pub(super) fn fragments<'a>(
        &'a self,
        inputs: &'a [Buffer],
        route: MessageRoute,
    ) -> Result<record::Fragments<'a>> {
        if route == MessageRoute::Single {
            if inputs.len() != 1 {
                return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                    crate::OperationOwnershipRejection::SingleMessageBufferCount,
                )));
            }
            let bytes = inputs[0].as_slice();
            let mut offset = 0usize;
            for length in self.lengths() {
                let end = offset.checked_add(*length).ok_or(Error::Rejected(
                    crate::RejectionReason::OperationOwnership(
                        crate::OperationOwnershipRejection::FragmentBoundaryOverflow,
                    ),
                ))?;
                bytes.get(offset..end).ok_or(Error::Rejected(
                    crate::RejectionReason::OperationOwnership(
                        crate::OperationOwnershipRejection::FragmentBoundaryRange,
                    ),
                ))?;
                offset = end;
            }
            if offset != bytes.len() {
                return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                    crate::OperationOwnershipRejection::FragmentTotalMismatch,
                )));
            }
            Ok(record::Fragments::Packed {
                bytes,
                lengths: self.lengths(),
            })
        } else if self.lengths().is_empty() {
            if !inputs.is_empty() && (inputs.len() != 1 || !inputs[0].as_slice().is_empty()) {
                return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                    crate::OperationOwnershipRejection::EmptyMessageBufferShape,
                )));
            }
            Ok(record::Fragments::Slices(&[]))
        } else {
            if inputs.len() != self.lengths().len() {
                return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                    crate::OperationOwnershipRejection::MultipartBufferCount,
                )));
            }
            for (input, length) in inputs.iter().zip(self.lengths()) {
                if input.as_slice().len() != *length {
                    return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                        crate::OperationOwnershipRejection::MultipartBoundaryMismatch,
                    )));
                }
            }
            Ok(record::Fragments::Buffers(inputs))
        }
    }
}
impl DigestOperation {
    pub(super) fn write_checkpoint_messages(
        &self,
        _budget: &Arc<Budget>,
        writer: &mut record::Writer<'_>,
        limits: record::Limits,
    ) -> Result<()> {
        use record::{Message, MessageState, Messages, NonceOrigin, Parameters};
        if self.activity.pending() || self.step == Step::Failed {
            return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::DigestCheckpointUnavailable,
            )));
        }
        let parts = record::Fragments::Buffers(&self.frame.parts);
        let (state, next_fragment) = match self.step {
            Step::Init => (MessageState::Planned, 0),
            Step::Single | Step::OutputRequired { single: true, .. } => (MessageState::Engaged, 0),
            Step::Update(n) => (MessageState::Engaged, n),
            Step::Final | Step::OutputRequired { single: false, .. } => {
                (MessageState::Engaged, parts.len())
            }
            Step::Complete => (MessageState::Finished, parts.len()),
            Step::Failed => {
                return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                    crate::OperationOwnershipRejection::DigestCheckpointUnavailable,
                )))
            }
        };
        let result = if self.step == Step::Complete {
            self.frame.output.as_slice()
        } else {
            &[]
        };
        if self.step == Step::Complete
            && (*self.frame.length as u128 != result.len() as u128
                || !self.frame.selection.accepts_length(result.len()))
        {
            return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::DigestCheckpointResultLength,
            )));
        }
        let message = Message {
            route: self.frame.selection.route(),
            params: Parameters {
                digest_output: Some(record::digest_output::DigestOutput {
                    capacity: self.frame.output.capacity(),
                    waiting: match self.step {
                        Step::OutputRequired { required, .. } => Some(required),
                        _ => None,
                    },
                }),
                cipher_extension: None,
                digest_extension: self
                    .frame
                    .extension
                    .as_ref()
                    .map(|extension| extension.record(self.step)),
                signature: None,
                digest_oid: self.frame.oid_bytes(),
                message_init: None,
                counter_bits: None,
                iv_generator: None,
                iv_fixed_bits: None,
                iv_initial: None,
                nonce: None,
                aad: None,
                tag_bits: 0,
                hash: Some(self.frame.selection.mechanism_number()),
                mgf: None,
                salt: None,
            },
            origin: NonceOrigin::None,
            state,
            fragments: parts,
            next_fragment,
            produced: result.len(),
            expected: self.frame.output.capacity(),
            result,
            tag_or_signature: None,
            residual_start: 0,
            residual_length: 0,
        };
        Messages::write(writer, &[message], limits)
    }
}
pub(super) struct Continuation {
    pub(super) body: OperationBody,
    pub(super) validation: Option<validation::Capture>,
    pub(super) encrypting: bool,
}
impl Continuation {
    pub(super) fn write_checkpoint(
        &self,
        budget: &Arc<Budget>,
        writer: &mut record::Writer<'_>,
        limits: record::Limits,
    ) -> Result<()> {
        Self::write_parts(&self.body, self.validation.as_ref(), budget, writer, limits)
    }
    pub(super) fn write_parts(
        body: &OperationBody,
        validation: Option<&validation::Capture>,
        budget: &Arc<Budget>,
        writer: &mut record::Writer<'_>,
        limits: record::Limits,
    ) -> Result<()> {
        let (descriptor, keys) = Self::header(body)?;
        descriptor.write(writer)?;
        keys.write(writer)?;
        Self::write_body(body, budget, writer, limits)?;
        validation::Capture::write_checkpoint(validation, writer, limits)
    }
    pub(super) fn header(
        body: &OperationBody,
    ) -> Result<(record::Descriptor, record::KeyBindings<'_>)> {
        Ok(match body {
            OperationBody::Digest(d) => (
                record::Descriptor {
                    input: d.input,
                    family: Family::Digest,
                    profile: d.frame.selection.checkpoint_profile(),
                    phase: record::Function::from_name(if d.step == Step::Complete {
                        d.frame.selection.terminal_function()
                    } else {
                        function(d.step)?
                    })?,
                    mechanism: d.frame.selection.mechanism_number(),
                    size: d.frame.selection.length(),
                    active_flags: 0,
                    validation_requested: d.validation_requested,
                    digest_bits: d.frame.selection.parameter().map(|bits| bits as u64),
                    cipher_options: None,
                    carried_messages: 0,
                },
                record::KeyBindings {
                    cipher: None,
                    authentication: None,
                },
            ),
            OperationBody::Messages(d) => d.checkpoint_header()?,
            OperationBody::AeadMessages(d) => d.checkpoint_header()?,
            OperationBody::Dual(d) => d.checkpoint_header()?,
            OperationBody::Recover(d) => d.checkpoint_header()?,
            OperationBody::Signature(d) => d.checkpoint_header()?,
            OperationBody::NativeMessages(d) => d.checkpoint_header()?,
            OperationBody::Cipher(d) => d.checkpoint_header()?,
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                    crate::OperationOwnershipRejection::CheckpointFamilyNotSerializable,
                )))
            }
        })
    }
    pub(super) fn write_body(
        body: &OperationBody,
        budget: &Arc<Budget>,
        writer: &mut record::Writer<'_>,
        limits: record::Limits,
    ) -> Result<()> {
        match body {
            OperationBody::Digest(d) => d.write_checkpoint_messages(budget, writer, limits)?,
            OperationBody::Messages(d) => d.write_checkpoint_messages(budget, writer, limits)?,
            OperationBody::AeadMessages(d) => {
                d.write_checkpoint_messages(budget, writer, limits)?
            }
            OperationBody::Dual(d) => d.write_checkpoint_messages(budget, writer, limits)?,
            OperationBody::Recover(d) => d.write_checkpoint_messages(budget, writer, limits)?,
            OperationBody::Signature(d) => d.write_checkpoint_messages(budget, writer, limits)?,
            OperationBody::NativeMessages(d) => d.write_checkpoint_messages(writer, limits)?,
            OperationBody::Cipher(d) => d.write_checkpoint_messages(budget, writer, limits)?,
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                    crate::OperationOwnershipRejection::CheckpointFamilyNotSerializable,
                )))
            }
        }
        Ok(())
    }

    pub(super) fn restore_keys(
        &self,
        session: &Session,
        keys: StateRestoreKeys<'_>,
        permits: &mut [Option<crate::registry::ReadPermit>],
        candidate: &mut Option<restoration_keys::BoundKeys>,
    ) -> Result<restoration_keys::BoundKeys> {
        if candidate.is_some() {
            return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::CapturedKeyCandidateAlreadyOccupied,
            )));
        }
        // All families build into this owner, including their partial readers.
        // The caller retains it until session access has been released.
        *candidate = Some(restoration_keys::BoundKeys::new(None, None));
        let bound = candidate.as_mut().expect("captured key candidate");
        match &self.body {
            OperationBody::Digest(body)
                if keys.encryption.is_none() && keys.authentication.is_none() =>
            {
                bound.extension =
                    super::digest::extension::captured_contract(session, body, keys.extension)?;
                Ok(())
            }
            OperationBody::Messages(body) => body.restore_keys(session, keys, permits, bound),
            OperationBody::AeadMessages(body) => body.restore_keys(session, keys, permits, bound),
            OperationBody::Dual(body) => body.restore_keys(session, keys, permits, bound),
            OperationBody::Recover(body) => body.restore_keys(session, keys, permits, bound),
            OperationBody::Cipher(body) => body.restore_keys(session, keys, permits, bound),
            _ => Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::RestorationKeyRoles,
            ))),
        }?;
        Ok(candidate.take().expect("complete captured key candidate"))
    }
    /// The caller retains the returned old owners until all possession ends.
    pub(super) fn bind_restored(
        &mut self,
        keys: restoration_keys::BoundKeys,
    ) -> restoration_keys::BoundKeys {
        match &mut self.body {
            OperationBody::Messages(body) => body.bind_restored(keys),
            OperationBody::AeadMessages(body) => body.bind_restored(keys),
            OperationBody::Dual(body) => body.bind_restored(keys),
            OperationBody::Recover(body) => body.bind_restored(keys),
            OperationBody::Signature(body) => body.bind_restored(keys),
            OperationBody::Cipher(body) => body.bind_restored(keys),
            _ => keys,
        }
    }

    pub(super) fn check_capture(op: &Operation, entry: &SessionEntry) -> Result<()> {
        // The snapshot owner will record the current epoch. Establish that it
        // still describes this operation before copying even a keyless digest.
        // Otherwise capture could relabel work invalidated by contextual logout.
        op.check_authentication(entry)?;
        if op.rejoin().is_some()
            || op.detachment().is_some()
            || op.cancellation.is_withdrawn()
            || op.continuation_status.is_frozen()
            || op.cancel.is_submitted()
            || op.state_io().is_some()
            || op.joined.is_some()
            || op.body.pending()
            || op.body.complete()
            || op.validation.as_ref().is_some_and(|v| v.waiting())
        {
            return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::OperationNotCapturable,
            )));
        }
        Ok(())
    }
}

impl crate::symmetric::memory::RetainedStorage for Continuation {
    fn retain_credits(
        &self,
        retained: &mut crate::symmetric::memory::RetainedBytes,
    ) -> crate::Result<()> {
        match &self.body {
            OperationBody::Digest(owner) => owner.retain_credits(retained)?,
            OperationBody::Messages(owner) => owner.retain_credits(retained)?,
            OperationBody::AeadMessages(owner) => owner.retain_credits(retained)?,
            OperationBody::Dual(owner) => owner.retain_credits(retained)?,
            OperationBody::Cipher(owner) => owner.retain_credits(retained)?,
            OperationBody::Signature(owner) => owner.retain_credits(retained)?,
            OperationBody::NativeMessages(owner) => owner.retain_credits(retained)?,
            OperationBody::Recover(owner) => owner.retain_credits(retained)?,
            OperationBody::Control | OperationBody::Admission(_) => {
                return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                    crate::OperationOwnershipRejection::OperationHasNoSavedContinuation,
                )));
            }
        }
        self.validation.retain_credits(retained)
    }
}
