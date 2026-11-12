// SPDX-License-Identifier: Apache-2.0
//! Recovery continuation: one native input and an explicit output negotiation state.
use super::{
    continuation, record, restoration_keys, KeyLease, Kind, MessageRoute, NativeActivity,
    PreparedRecover, RecoverMechanism, RecoverOperation, RecoverOutputPlan, RecoveryBufferRequest,
    Stage, StateKeyReference, StateRestoreKeys,
};
use crate::module::SessionEntry;
use crate::symmetric::memory::{Budget, Buffer, Credit};
use crate::{bounds, Error, Result, Session};

use fe11_sys::{CKR_BUFFER_TOO_SMALL, CKR_OK, CK_MECHANISM, CK_MECHANISM_TYPE};
use std::sync::Arc;

/// Metadata-only request: no key lease, guarded reference or native pointer.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::advanced) struct SnapshotShape {
    mechanism: RecoverMechanism,
    input_length: usize,
    plan: RecoverOutputPlan,
    output_capacity: Option<usize>,
    maximum_output: usize,
}
pub(in crate::advanced) struct PreparedSnapshot {
    frame: PreparedRecover,
    shape: SnapshotShape,
}
/// Entire byte allocation set for this snapshot, without source leases or
/// readable buffers. The capture driver admits all capacities before binding.
pub(in crate::advanced) struct SnapshotStorage {
    shape: SnapshotShape,
    input: crate::symmetric::memory::UnboundBuffer,
    expected: crate::symmetric::memory::UnboundBuffer,
    output: crate::symmetric::memory::UnboundBuffer,
}
impl SnapshotStorage {
    pub(in crate::advanced) fn allocated_bytes(&self) -> Result<usize> {
        PreparedRecover::metadata_bytes()
            .checked_add(self.input.allocated())
            .and_then(|n| n.checked_add(self.expected.allocated()))
            .and_then(|n| n.checked_add(self.output.allocated()))
            .ok_or(Error::Rejected(crate::RejectionReason::OperationRecovery(
                crate::OperationRecoveryRejection::RecoveryFrameAccountingOverflow,
            )))
    }
    pub(in crate::advanced) fn bind(self, prepaid: &mut Credit) -> Result<PreparedSnapshot> {
        let selected = self.shape.mechanism.native()?;
        let input_length = bounds::ck_length(self.shape.input_length)?;
        let length = bounds::ck_length(self.shape.output_capacity.unwrap_or(0))?;
        let credit = prepaid.split(PreparedRecover::metadata_bytes())?;
        Ok(PreparedSnapshot {
            frame: PreparedRecover {
                selected,
                mechanism: Box::new(CK_MECHANISM {
                    mechanism: selected,
                    pParameter: std::ptr::null_mut(),
                    ulParameterLen: 0,
                }),
                input: self.input.bind(prepaid)?,
                expected: self.expected.bind(prepaid)?,
                output: Some(self.output.bind(prepaid)?),
                input_length,
                length: Box::new(length),
                maximum_output: self.shape.maximum_output,
                completion_diagnostic: crate::error::CompletionStorage::allocate()?,
                _credit: credit,
            },
            shape: self.shape,
        })
    }
}
impl SnapshotShape {
    pub(super) fn for_request(
        mechanism: RecoverMechanism,
        input_length: usize,
        plan: RecoverOutputPlan,
        maximum_output: usize,
    ) -> Result<Self> {
        PreparedRecover::allocation_bytes_for_length(
            mechanism,
            input_length,
            plan,
            maximum_output,
        )?;
        Ok(Self {
            mechanism,
            input_length,
            plan,
            output_capacity: Some(match plan {
                RecoverOutputPlan::Buffer { capacity } => capacity,
                RecoverOutputPlan::LengthOnly => 0,
            }),
            maximum_output,
        })
    }
    fn storage_plan(self) -> RecoverOutputPlan {
        RecoverOutputPlan::Buffer {
            capacity: self.output_capacity.unwrap_or(0),
        }
    }
    pub(in crate::advanced) fn allocation_bytes(self) -> Result<usize> {
        PreparedRecover::allocation_bytes_for_length(
            self.mechanism,
            self.input_length,
            self.storage_plan(),
            self.maximum_output,
        )
    }
    pub(in crate::advanced) fn allocate(self) -> Result<SnapshotStorage> {
        use crate::symmetric::memory::UnboundBuffer;
        self.allocation_bytes()?;
        Ok(SnapshotStorage {
            shape: self,
            input: UnboundBuffer::allocate(self.input_length)?,
            expected: UnboundBuffer::allocate(self.input_length)?,
            output: UnboundBuffer::allocate(self.output_capacity.unwrap_or(0))?,
        })
    }
}
impl PreparedSnapshot {
    pub(super) fn fill_request(mut self, input: &[u8]) -> Result<PreparedRecover> {
        if input.len() != self.shape.input_length {
            return Err(Error::Rejected(crate::RejectionReason::OperationRecovery(
                crate::OperationRecoveryRejection::RecoverySnapshotShapeChanged,
            )));
        }
        self.frame.input.as_mut().copy_from_slice(input);
        self.frame.expected.as_mut().copy_from_slice(input);
        Ok(self.frame)
    }
    pub(in crate::advanced) fn copy_from(
        mut self,
        source: &RecoverOperation,
        entry: &SessionEntry,
    ) -> Result<RecoverOperation> {
        if self.shape != source.snapshot_shape(entry)? {
            return Err(Error::Rejected(crate::RejectionReason::OperationRecovery(
                crate::OperationRecoveryRejection::RecoverySnapshotShapeChanged,
            )));
        }
        continuation::copy(&mut self.frame.input, &source.input)?;
        continuation::copy(&mut self.frame.expected, &source.input)?;
        let mut result = self
            .frame
            .bind(source.key.duplicate()?, source.kind, self.shape.plan);
        if let (Some(target), Some(original)) = (&mut result.output, &source.output) {
            continuation::copy(target, original)?;
        }
        if source.output.is_none() {
            result.output = None;
        }
        *result.length = *source.length;
        result.stage = source.stage;
        result.activity = source.activity;
        Ok(result)
    }
}
use record::{Descriptor, Family, KeyBindings, Limits, Message, MessageState, Messages};

// These codes describe output negotiation, not an algorithm or a native phase.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Profile {
    Buffer,
    Query,
    SizeReported,
    TooSmall,
}
impl Profile {
    fn wire(self) -> u8 {
        match self {
            Self::Buffer => 1,
            Self::Query => 2,
            Self::SizeReported => 3,
            Self::TooSmall => 4,
        }
    }
    fn read(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Buffer),
            2 => Ok(Self::Query),
            3 => Ok(Self::SizeReported),
            4 => Ok(Self::TooSmall),
            _ => Err(Error::Rejected(crate::RejectionReason::OperationRecovery(
                crate::OperationRecoveryRejection::RecoveryRecordOutputProfile,
            ))),
        }
    }
    fn waiting(self) -> bool {
        matches!(self, Self::SizeReported | Self::TooSmall)
    }
}
impl Kind {
    fn family(self) -> Family {
        match self {
            Self::Sign => Family::SignRecover,
            Self::Verify => Family::VerifyRecover,
        }
    }
    fn from_family(family: Family) -> Result<Self> {
        match family {
            Family::SignRecover => Ok(Self::Sign),
            Family::VerifyRecover => Ok(Self::Verify),
            _ => Err(Error::Rejected(crate::RejectionReason::OperationRecovery(
                crate::OperationRecoveryRejection::RecoveryRecordFamily,
            ))),
        }
    }
}

pub(in crate::advanced) fn validate(
    d: Descriptor,
    keys: &KeyBindings<'_>,
    messages: &Messages<'_>,
    validation: Option<&record::ValidationRecord<'_>>,
    limits: Limits,
    terminal: bool,
) -> Result<()> {
    let kind = Kind::from_family(d.family)?;
    let profile = Profile::read(d.profile)?;
    if keys.cipher.is_some()
        || keys.authentication.is_none()
        || d.size > limits.bytes
        || d.active_flags != 0
        || d.validation_requested
        || d.carried_messages != 0
        || d.phase.name() != kind.output()
        || messages.len() != 1
    {
        return Err(Error::Rejected(crate::RejectionReason::OperationRecovery(
            crate::OperationRecoveryRejection::RecoveryRecordDescriptor,
        )));
    }
    // A recovery key need not expose CKA_CLASS. Its lifetime and explicit
    // authentication role are retained; the module decides key suitability.
    CK_MECHANISM_TYPE::try_from(d.mechanism).map_err(|_| {
        Error::Rejected(crate::RejectionReason::OperationRecovery(
            crate::OperationRecoveryRejection::RecoveryRecordMechanismWidth,
        ))
    })?;
    bounds::ck_length(d.size)?;
    let m = messages.iter().next().ok_or(Error::Rejected(
        crate::RejectionReason::OperationRecovery(
            crate::OperationRecoveryRejection::RecoveryRecordInputAbsent,
        ),
    ))??;
    m.validate(limits)?;
    let params = &m.params;
    if params.digest_oid.is_some() {
        return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
            crate::CipherContinuationRejection::DigestOidOnNonDigestOwner,
        )));
    }
    if m.route != MessageRoute::Single
        || m.fragments.len() != 1
        || m.origin != record::NonceOrigin::None
        || m.tag_or_signature.is_some()
        || m.residual_start != 0
        || m.residual_length != 0
        || params.digest_extension.is_some()
        || params.message_init.is_some()
        || params.counter_bits.is_some()
        || params.iv_generator.is_some()
        || params.iv_fixed_bits.is_some()
        || params.iv_initial.is_some()
        || params.nonce.is_some()
        || params.aad.is_some()
        || params.tag_bits != 0
        || params.hash.is_some()
        || params.mgf.is_some()
        || params.salt.is_some()
    {
        return Err(Error::Rejected(crate::RejectionReason::OperationRecovery(
            crate::OperationRecoveryRejection::RecoveryRecordParameterContract,
        )));
    }
    if terminal {
        if profile != Profile::Buffer
            || m.state != MessageState::Finished
            || m.next_fragment != 1
            || m.expected != d.size
            || m.produced > d.size
        {
            return Err(Error::Rejected(crate::RejectionReason::OperationRecovery(
                crate::OperationRecoveryRejection::RecoveryTerminalOutput,
            )));
        }
    } else if m.state != MessageState::Engaged
        || m.next_fragment != 0
        || m.produced != 0
        || !m.result.is_empty()
        || !profile.waiting() && m.expected != d.size
        || matches!(profile, Profile::Query | Profile::SizeReported) && d.size != 0
    {
        return Err(Error::Rejected(crate::RejectionReason::OperationRecovery(
            crate::OperationRecoveryRejection::RecoveryRecordProgression,
        )));
    }
    if let Some(report) = validation {
        if report.maximum() != 1 || report.iter().next().is_some() {
            return Err(Error::Rejected(crate::RejectionReason::OperationRecovery(
                crate::OperationRecoveryRejection::RecoveryRecordPrematureObservation,
            )));
        }
    } else if terminal {
        return Err(Error::Rejected(crate::RejectionReason::OperationRecovery(
            crate::OperationRecoveryRejection::RecoveryTerminalObservationAbsent,
        )));
    }
    Ok(())
}
impl RecoverOperation {
    fn projection(&self) -> Result<(Profile, usize, usize)> {
        if self.pending() {
            return Err(Error::Rejected(crate::RejectionReason::OperationRecovery(
                crate::OperationRecoveryRejection::RecoveryRecordPending,
            )));
        }
        Ok(match self.stage {
            Stage::Output(RecoverOutputPlan::Buffer { capacity }) => {
                (Profile::Buffer, capacity, capacity)
            }
            Stage::Output(RecoverOutputPlan::LengthOnly) => (Profile::Query, 0, 0),
            Stage::Waiting(request) => (
                if request.code == CKR_OK as u64 {
                    Profile::SizeReported
                } else {
                    Profile::TooSmall
                },
                request.previous_capacity,
                request.required,
            ),
            Stage::Done => {
                let output = self.output.as_ref().ok_or(Error::Rejected(
                    crate::RejectionReason::OperationRecovery(
                        crate::OperationRecoveryRejection::RecoveryResultConsumed,
                    ),
                ))?;
                (Profile::Buffer, output.capacity(), output.capacity())
            }
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::OperationRecovery(
                    crate::OperationRecoveryRejection::RecoveryRecordPhase,
                )))
            }
        })
    }
    pub(in crate::advanced) fn checkpoint_header(&self) -> Result<(Descriptor, KeyBindings<'_>)> {
        let (profile, capacity, _) = self.projection()?;
        Ok((
            Descriptor {
                input: crate::advanced::input::InputState::closed(),
                family: self.kind.family(),
                profile: profile.wire(),
                phase: record::Function::from_name(self.kind.output())?,
                mechanism: self.selected as u64,
                size: capacity,
                active_flags: 0,
                validation_requested: false,
                digest_bits: None,
                cipher_options: None,
                carried_messages: 0,
            },
            KeyBindings {
                cipher: None,
                authentication: Some(self.key.checkpoint_key(record::KeyRole::Authentication)?),
            },
        ))
    }
    pub(in crate::advanced) fn write_checkpoint_messages(
        &self,
        _budget: &Arc<Budget>,
        writer: &mut record::Writer<'_>,
        limits: Limits,
    ) -> Result<()> {
        let (_, _, expected) = self.projection()?;
        let terminal = self.complete();
        let result = if terminal {
            self.output
                .as_ref()
                .ok_or(Error::Rejected(crate::RejectionReason::OperationRecovery(
                    crate::OperationRecoveryRejection::RecoveryResultConsumed,
                )))?
                .as_slice()
        } else {
            &[]
        };
        let parts = [self.input.as_slice()];
        let m = Message {
            route: MessageRoute::Single,
            params: record::Parameters {
                digest_output: None,
                cipher_extension: None,
                digest_extension: None,
                signature: None,
                digest_oid: None,
                message_init: None,
                counter_bits: None,
                iv_generator: None,
                iv_fixed_bits: None,
                iv_initial: None,
                nonce: None,
                aad: None,
                tag_bits: 0,
                hash: None,
                mgf: None,
                salt: None,
            },
            origin: record::NonceOrigin::None,
            state: if terminal {
                MessageState::Finished
            } else {
                MessageState::Engaged
            },
            fragments: record::Fragments::Slices(&parts),
            next_fragment: usize::from(terminal),
            produced: result.len(),
            expected,
            result,
            tag_or_signature: None,
            residual_start: 0,
            residual_length: 0,
        };
        Messages::write(writer, &[m], limits)
    }
    pub(in crate::advanced) fn snapshot_shape(
        &self,
        entry: &SessionEntry,
    ) -> Result<SnapshotShape> {
        self.key.check(entry)?;
        self.projection()?;
        let plan = match self.stage {
            Stage::Output(plan) => plan,
            Stage::Waiting(_) => RecoverOutputPlan::LengthOnly,
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::OperationRecovery(
                    crate::OperationRecoveryRejection::RecoveryNotCapturable,
                )))
            }
        };
        Ok(SnapshotShape {
            mechanism: RecoverMechanism::Parameterless(self.selected as u64),
            input_length: self.input.as_slice().len(),
            plan,
            output_capacity: self.output.as_ref().map(Buffer::capacity),
            maximum_output: self.maximum_output,
        })
    }

    pub(in crate::advanced) fn set_terminal(&mut self) {
        self.stage = Stage::Done;
        self.activity = NativeActivity::Inactive;
    }
    pub(in crate::advanced) fn restore_keys(
        &self,
        session: &Session,
        keys: StateRestoreKeys<'_>,
        permits: &mut [Option<crate::registry::ReadPermit>],
        bound: &mut restoration_keys::BoundKeys,
    ) -> Result<()> {
        if keys.encryption.is_some() {
            return Err(Error::Rejected(crate::RejectionReason::OperationRecovery(
                crate::OperationRecoveryRejection::UnexpectedRecoveryCipherKey,
            )));
        }
        let key = keys.authentication.ok_or(Error::Rejected(
            crate::RejectionReason::OperationRecovery(
                crate::OperationRecoveryRejection::RecoveryAuthenticationKeyRequired,
            ),
        ))?;
        if !matches!(key.reference, StateKeyReference::Recovery(_)) {
            return Err(Error::Rejected(crate::RejectionReason::OperationRecovery(
                crate::OperationRecoveryRejection::RecoveryReferenceRequired,
            )));
        }
        let lease = self.key.rebind_selected_retained(
            session,
            key.reference,
            self.selected,
            None,
            permits,
            &mut bound.authentication,
        )?;
        bound.native_authentication = match key.encoding {
            crate::advanced::StateKeyEncoding::Supplied => lease.handle,
            crate::advanced::StateKeyEncoding::Embedded => fe11_sys::CK_INVALID_HANDLE,
        };
        bound.authentication = Some(lease);
        Ok(())
    }
    /// Return the previous lease for destruction after restore possession ends.
    pub(in crate::advanced) fn bind_restored(
        &mut self,
        mut keys: restoration_keys::BoundKeys,
    ) -> restoration_keys::BoundKeys {
        let replacement = keys
            .authentication
            .take()
            .expect("validated recovery key role");
        keys.authentication = Some(std::mem::replace(&mut self.key, replacement));
        keys
    }
}

/// The archive remains borrowed while the complete reconstruction graph is
/// admitted; no key, input copy or pointer table is retained by this recipe.
pub(in crate::advanced) struct RecordPlan<'a> {
    descriptor: Descriptor,
    message: record::Message<'a>,
    input: &'a [u8],
    kind: Kind,
    profile: Profile,
    output: RecoverOutputPlan,
    shape: SnapshotShape,
}
impl<'a> RecordPlan<'a> {
    pub(in crate::advanced) fn new(
        descriptor: Descriptor,
        messages: &record::Messages<'a>,
        ceilings: crate::CryptoLimits,
        pending: bool,
    ) -> Result<Self> {
        if pending {
            return Err(Error::Rejected(
                crate::RejectionReason::AsynchronousExecution(
                    crate::AsynchronousExecutionRejection::SignatureRecoveryAsynchronousModeUnavailable,
                ),
            ));
        }
        let message = messages.iter().next().ok_or(Error::Rejected(
            crate::RejectionReason::OperationRecovery(
                crate::OperationRecoveryRejection::RecoveryRecordInputAbsent,
            ),
        ))??;
        if message.fragments.len() != 1 {
            return Err(Error::Rejected(crate::RejectionReason::OperationRecovery(
                crate::OperationRecoveryRejection::RecoveryRecordInputCount,
            )));
        }
        let input = message.fragments.iter().next().ok_or(Error::Rejected(
            crate::RejectionReason::OperationRecovery(
                crate::OperationRecoveryRejection::RecoveryRecordInputAbsent,
            ),
        ))??;
        crate::InputLimits {
            maximum_parts: ceilings.maximum_parts,
            maximum_total_bytes: ceilings.maximum_total_bytes,
        }
        .validate(ceilings, &[input])?;
        let kind = Kind::from_family(descriptor.family)?;
        let profile = Profile::read(descriptor.profile)?;
        let output = if profile == Profile::Buffer {
            RecoverOutputPlan::Buffer {
                capacity: descriptor.size,
            }
        } else {
            RecoverOutputPlan::LengthOnly
        };
        let shape = SnapshotShape::for_request(
            RecoverMechanism::Parameterless(descriptor.mechanism),
            input.len(),
            output,
            ceilings.maximum_total_bytes,
        )?;
        Ok(Self {
            descriptor,
            message,
            input,
            kind,
            profile,
            output,
            shape,
        })
    }
    pub(in crate::advanced) fn allocation_bytes(&self) -> Result<usize> {
        self.shape.allocation_bytes()
    }
    pub(in crate::advanced) fn allocate(&self) -> Result<SnapshotStorage> {
        self.shape.allocate()
    }
    pub(in crate::advanced) fn bind(
        self,
        storage: SnapshotStorage,
        prepaid: &mut Credit,
    ) -> Result<PreparedCheckpoint> {
        let prepared = storage.bind(prepaid)?.fill_request(self.input)?;
        PreparedCheckpoint::finish(
            prepared,
            self.kind,
            self.profile,
            self.output,
            &self.message,
            self.descriptor,
        )
    }
}

/// Rebuilt signature-recovery storage, not yet authorized to use a key.
pub(in crate::advanced) struct PreparedCheckpoint {
    prepared: PreparedRecover,
    kind: Kind,
    plan: RecoverOutputPlan,
    stage: Stage,
}
impl PreparedCheckpoint {
    fn finish(
        mut prepared: PreparedRecover,
        kind: Kind,
        profile: Profile,
        plan: RecoverOutputPlan,
        m: &record::Message<'_>,
        d: Descriptor,
    ) -> Result<Self> {
        let stage = if profile.waiting() {
            prepared.output = None;
            *prepared.length = bounds::ck_length(m.expected)?;
            Stage::Waiting(RecoveryBufferRequest {
                function: kind.output(),
                code: if profile == Profile::SizeReported {
                    CKR_OK as u64
                } else {
                    CKR_BUFFER_TOO_SMALL as u64
                },
                required: m.expected,
                previous_capacity: d.size,
            })
        } else {
            Stage::Output(plan)
        };
        if m.state == MessageState::Finished {
            let output = prepared.output.as_mut().ok_or(Error::Rejected(
                crate::RejectionReason::OperationRecovery(
                    crate::OperationRecoveryRejection::RecoveryTerminalBufferAbsent,
                ),
            ))?;
            if m.result.len() > output.capacity() {
                return Err(Error::Rejected(crate::RejectionReason::OperationRecovery(
                    crate::OperationRecoveryRejection::RecoveryTerminalCapacity,
                )));
            }
            output.as_mut()[..m.result.len()].copy_from_slice(m.result);
            output.set_length(m.result.len())?;
            *prepared.length = bounds::ck_length(m.result.len())?;
        }
        Ok(Self {
            prepared,
            kind,
            plan,
            stage,
        })
    }
    pub(in crate::advanced) fn bind(self, key: KeyLease) -> RecoverOperation {
        let mut result = self.prepared.bind(key, self.kind, self.plan);
        result.stage = self.stage;
        result.activity = NativeActivity::Active;
        result
    }
}
