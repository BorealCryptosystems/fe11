// SPDX-License-Identifier: Apache-2.0
//! Persist pending input and native position, never consumed message history.
use super::{Kind, SignatureOperation, SignatureOutputPlan, Stage};
use crate::advanced::record::{
    self,
    signature::{Graph, SignatureParameters, SignaturePhase},
};
use crate::mechanism_extension::graph::{
    recipe, snapshot::SnapshotRecipe, GraphStorage, OwnedGraph,
};
use crate::native::derivation::{InputBytes, InputBytesStorage};
use crate::symmetric::memory::Budget;
use crate::symmetric::memory::{Buffer, Credit, UnboundBuffer};
use crate::{Error, MechanismLayoutProvenance, Result};
use fe11_sys::{CK_MECHANISM, CK_ULONG};
use std::sync::Arc;

impl Kind {
    pub(super) fn profile(self) -> u8 {
        match self {
            Self::Sign => 1,
            Self::Verify => 2,
            Self::VerifySignature => 3,
        }
    }
    pub(super) fn from_profile(profile: u8) -> Result<Self> {
        match profile {
            1 => Ok(Self::Sign),
            2 => Ok(Self::Verify),
            3 => Ok(Self::VerifySignature),
            _ => Err(Error::Rejected(crate::RejectionReason::OperationRecord(
                crate::OperationRecordRejection::SignatureRecordKind,
            ))),
        }
    }
}

pub(in crate::advanced) struct RecordPlan<'a> {
    descriptor: record::Descriptor,
    message: record::Message<'a>,
    parameters: SignatureParameters<'a>,
    recipe: SnapshotRecipe<'a>,
    fragment: Option<&'a [u8]>,
}
pub(in crate::advanced) struct Storage<'a> {
    graph: GraphStorage<'a>,
    fragment: Option<InputBytesStorage>,
    signature: Option<InputBytesStorage>,
    output: Option<UnboundBuffer>,
}
pub(in crate::advanced) struct PreparedCheckpoint {
    kind: Kind,
    route: crate::MessageRoute,
    input: super::InputState,
    stage: Stage,
    mechanism: Box<CK_MECHANISM>,
    graph: OwnedGraph,
    fragment: Option<InputBytes>,
    signature: Option<InputBytes>,
    output: Option<Buffer>,
    output_offset: usize,
    length: Box<CK_ULONG>,
    plan: SignatureOutputPlan,
    maximum_output: usize,
    completion_diagnostic: crate::error::CompletionStorage,
    credit: Credit,
}
// SAFETY: all pointers target this owner's stable allocations. No native call
// is possible before a destination binding is installed in the operation ledger.
unsafe impl Send for PreparedCheckpoint {}

fn total(parts: &[usize]) -> Result<usize> {
    parts
        .iter()
        .try_fold(0usize, |n, value| n.checked_add(*value))
        .ok_or(Error::Rejected(
            crate::RejectionReason::SignatureContinuation(
                crate::SignatureContinuationRejection::SignatureReconstructionAccounting,
            ),
        ))
}
impl<'a> RecordPlan<'a> {
    pub(in crate::advanced) fn new(
        descriptor: record::Descriptor,
        messages: &record::Messages<'a>,
        ceilings: crate::CryptoLimits,
        pending: bool,
    ) -> Result<Self> {
        if pending {
            return Err(Error::Rejected(
                crate::RejectionReason::AsynchronousExecution(
                    crate::AsynchronousExecutionRejection::SignatureAsynchronousModeUnavailable,
                ),
            ));
        }
        let message = messages.iter().next().ok_or(Error::Rejected(
            crate::RejectionReason::Restoration(
                crate::RestorationRejection::SignatureMessageAbsent,
            ),
        ))??;
        let parameters = message.params.signature.ok_or(Error::Rejected(
            crate::RejectionReason::Restoration(
                crate::RestorationRejection::SignatureParametersAbsent,
            ),
        ))?;
        let recipe = SnapshotRecipe::decode(parameters.graph.encoded()?)?;
        let fragment = message.fragments.iter().next().transpose()?;
        let limits = crate::InputLimits {
            maximum_parts: ceilings.maximum_parts,
            maximum_total_bytes: ceilings.maximum_total_bytes,
        };
        if let Some(fragment) = fragment {
            limits.validate(ceilings, &[fragment])?;
        }
        if let Some(signature) = message.tag_or_signature {
            crate::bounds::ck_length(signature.len())?;
        }
        Ok(Self {
            descriptor,
            message,
            parameters,
            recipe,
            fragment,
        })
    }
    pub(in crate::advanced) fn allocation_bytes(&self) -> Result<usize> {
        total(&[
            OwnedGraph::recipe_bytes(&self.recipe)?,
            self.fragment
                .map_or(0, <[u8]>::len)
                .checked_mul(2)
                .ok_or(Error::Rejected(
                    crate::RejectionReason::SignatureContinuation(
                        crate::SignatureContinuationRejection::SignatureInputAccounting,
                    ),
                ))?,
            self.message
                .tag_or_signature
                .map_or(0, <[u8]>::len)
                .checked_mul(2)
                .ok_or(Error::Rejected(
                    crate::RejectionReason::SignatureContinuation(
                        crate::SignatureContinuationRejection::SignatureInputAccounting,
                    ),
                ))?,
            self.parameters
                .output_capacity
                .map(|capacity| super::output_storage_bytes(self.descriptor.mechanism, capacity))
                .transpose()?
                .unwrap_or(0),
            super::preparation::metadata_bytes(),
        ])
    }
    pub(in crate::advanced) fn allocate(&self) -> Result<Storage<'a>> {
        Ok(Storage {
            graph: GraphStorage::allocate_input(recipe::Input::Snapshot(self.recipe))?,
            fragment: self
                .fragment
                .map(|input| InputBytesStorage::allocate(input.len()))
                .transpose()?,
            signature: self
                .message
                .tag_or_signature
                .map(|input| InputBytesStorage::allocate(input.len()))
                .transpose()?,
            output: self
                .parameters
                .output_capacity
                .map(|capacity| {
                    UnboundBuffer::allocate(super::output_storage_bytes(
                        self.descriptor.mechanism,
                        capacity,
                    )?)
                })
                .transpose()?,
        })
    }
    pub(in crate::advanced) fn bind(
        self,
        storage: Storage<'a>,
        prepaid: &mut Credit,
    ) -> Result<PreparedCheckpoint> {
        let mut graph = storage.graph.bind(prepaid)?;
        let fragment = storage
            .fragment
            .zip(self.fragment)
            .map(|(storage, bytes)| storage.bind(bytes, prepaid))
            .transpose()?;
        let signature = storage
            .signature
            .zip(self.message.tag_or_signature)
            .map(|(storage, bytes)| storage.bind(bytes, prepaid))
            .transpose()?;
        let mut output = storage
            .output
            .map(|storage| -> Result<_> {
                let mut output = storage.bind(prepaid)?;
                output.set_length(0)?;
                Ok(output)
            })
            .transpose()?;
        let output_offset = output
            .as_mut()
            .map(|buffer| super::output_offset(self.descriptor.mechanism, buffer))
            .transpose()?
            .unwrap_or(0);
        let kind = Kind::from_profile(self.descriptor.profile)?;
        let stage = match self.parameters.phase {
            SignaturePhase::Ready => Stage::Ready,
            SignaturePhase::Update => Stage::Update,
            SignaturePhase::Terminal => Stage::Terminal,
            SignaturePhase::Waiting {
                code,
                required,
                previous_capacity,
            } => Stage::Waiting(super::SignatureBufferRequest {
                function: kind.terminal(self.message.route),
                code,
                required,
                previous_capacity,
            }),
        };
        let (pointer, length) = graph.projection();
        Ok(PreparedCheckpoint {
            kind,
            route: self.message.route,
            input: self.descriptor.input,
            stage,
            mechanism: Box::new(CK_MECHANISM {
                mechanism: fe11_sys::CK_MECHANISM_TYPE::try_from(self.descriptor.mechanism)
                    .map_err(|_| {
                        Error::Rejected(crate::RejectionReason::OperationRecord(
                            crate::OperationRecordRejection::SignatureMechanismWidth,
                        ))
                    })?,
                pParameter: pointer,
                ulParameterLen: length,
            }),
            graph,
            fragment,
            signature,
            output,
            output_offset,
            length: Box::new(CK_ULONG::try_from(self.parameters.returned_length).map_err(
                |_| {
                    Error::Rejected(crate::RejectionReason::SignatureContinuation(
                        crate::SignatureContinuationRejection::SignatureLengthWidth,
                    ))
                },
            )?),
            plan: if self.parameters.query {
                SignatureOutputPlan::LengthOnly
            } else {
                SignatureOutputPlan::Buffer {
                    capacity: self.parameters.output_capacity.unwrap_or(0),
                }
            },
            maximum_output: self.parameters.maximum_output,
            completion_diagnostic: crate::error::CompletionStorage::allocate()?,
            credit: prepaid.split(super::preparation::metadata_bytes())?,
        })
    }
}
impl Storage<'_> {
    pub(in crate::advanced) fn allocated_bytes(&self) -> Result<usize> {
        total(&[
            self.graph.allocated_bytes()?,
            self.fragment
                .as_ref()
                .map(InputBytesStorage::allocated_bytes)
                .transpose()?
                .unwrap_or(0),
            self.signature
                .as_ref()
                .map(InputBytesStorage::allocated_bytes)
                .transpose()?
                .unwrap_or(0),
            self.output.as_ref().map_or(0, UnboundBuffer::allocated),
            super::preparation::metadata_bytes(),
        ])
    }
}
impl PreparedCheckpoint {
    /// Validate the destination while the caller still owns both inputs.
    pub(in crate::advanced) fn check_binding(
        &self,
        binding: Option<&super::binding::Binding>,
    ) -> Result<()> {
        let binding = binding.ok_or(Error::Rejected(
            crate::RejectionReason::SignatureContinuation(
                crate::SignatureContinuationRejection::SignatureDestinationBindingAbsent,
            ),
        ))?;
        if binding.contract.native_mechanism() != self.mechanism.mechanism
            || binding.contract.operation() != self.kind.operation(self.route)
        {
            return Err(Error::Rejected(
                crate::RejectionReason::SignatureContinuation(crate::SignatureContinuationRejection::SignatureDestinationRepresentationChanged),
            ));
        }
        Ok(())
    }
    /// Transfer immediately after check_binding, with the same untouched inputs.
    pub(in crate::advanced) fn bind_checked(
        self,
        binding: super::binding::Binding,
    ) -> SignatureOperation {
        SignatureOperation {
            key: binding.key,
            authentication: binding.authentication,
            _roles: binding.roles,
            contract: binding.contract,
            own_revocation: binding.own_revocation,
            revocation: binding.revocation,
            kind: self.kind,
            route: self.route,
            input: self.input,
            stage: self.stage,
            observer: super::Observer::Ticket,
            mechanism: self.mechanism,
            parameters: Some(self.graph),
            fragment: self.fragment,
            signature: self.signature,
            output: self.output,
            output_offset: self.output_offset,
            returned: super::ReturnedOperands::default(),
            length: self.length,
            plan: self.plan,
            maximum_output: self.maximum_output,
            completion_diagnostic: Some(self.completion_diagnostic),
            _credit: self.credit,
            activity: super::NativeActivity::Active,
        }
    }
}

impl SignatureOperation {
    /// Return displaced ownership to the poll's retirement slot; no role is
    /// released while native/session/operation guards are held.
    pub(in crate::advanced) fn bind_restored(
        &mut self,
        mut keys: crate::advanced::restoration_keys::BoundKeys,
    ) -> crate::advanced::restoration_keys::BoundKeys {
        let mut binding = keys
            .take_classic_signature()
            .expect("validated signature destination");
        std::mem::swap(&mut self.key, &mut binding.key);
        std::mem::swap(&mut self.authentication, &mut binding.authentication);
        std::mem::swap(&mut self._roles, &mut binding.roles);
        std::mem::swap(&mut self.contract, &mut binding.contract);
        std::mem::swap(&mut self.own_revocation, &mut binding.own_revocation);
        std::mem::swap(&mut self.revocation, &mut binding.revocation);
        keys.signature =
            Some(crate::advanced::restoration_keys::SignatureBinding::Classic(binding));
        keys
    }
    pub(in crate::advanced) fn retain_refused_binding(
        &mut self,
        keys: &crate::advanced::restoration_keys::BoundKeys,
    ) {
        if let Some(binding) = keys.classic_signature() {
            if Arc::ptr_eq(&self.key, &binding.key) {
                self.own_revocation |= binding.own_revocation;
            }
        }
    }
}
impl SignatureOperation {
    fn phase(&self) -> Result<SignaturePhase> {
        Ok(match self.stage {
            Stage::Ready if self.input.is_open() => SignaturePhase::Ready,
            Stage::Ready => SignaturePhase::Terminal,
            Stage::Update => SignaturePhase::Update,
            Stage::Terminal => SignaturePhase::Terminal,
            Stage::Waiting(request) => SignaturePhase::Waiting {
                code: request.code,
                required: request.required,
                previous_capacity: request.previous_capacity,
            },
            _ => {
                return Err(Error::Rejected(
                    crate::RejectionReason::SignatureContinuation(
                        crate::SignatureContinuationRejection::SignaturePhaseNotSerializable,
                    ),
                ))
            }
        })
    }
    pub(in crate::advanced) fn checkpoint_header(
        &self,
    ) -> Result<(record::Descriptor, record::KeyBindings<'_>)> {
        let phase = self.phase()?;
        let function = match phase {
            SignaturePhase::Ready if self.route == crate::MessageRoute::Single => {
                self.kind.terminal(self.route)
            }
            SignaturePhase::Ready | SignaturePhase::Update => self.kind.update(),
            SignaturePhase::Terminal | SignaturePhase::Waiting { .. } => {
                self.kind.terminal(self.route)
            }
        };
        Ok((
            record::Descriptor {
                input: self.input,
                family: record::Family::Signature,
                profile: self.kind.profile(),
                phase: record::Function::from_name(function)?,
                mechanism: self.contract.mechanism_number(),
                size: self.retained_output_capacity().unwrap_or(0),
                active_flags: 0,
                validation_requested: false,
                carried_messages: 0,
                cipher_options: None,
                digest_bits: None,
            },
            record::KeyBindings {
                cipher: None,
                authentication: Some(record::KeyBinding {
                    role: record::KeyRole::Authentication,
                    class: None,
                    key_type: None,
                    id: None,
                }),
            },
        ))
    }
    pub(in crate::advanced) fn write_checkpoint_messages(
        &self,
        _budget: &Arc<Budget>,
        writer: &mut record::Writer<'_>,
        limits: record::Limits,
    ) -> Result<()> {
        let graph = self.parameters.as_ref().ok_or(Error::Rejected(
            crate::RejectionReason::Restoration(
                crate::RestorationRejection::SignatureParametersAbsent,
            ),
        ))?;
        let fragment = [self
            .fragment
            .as_ref()
            .map_or(&[][..], |input| input.bytes())];
        let fragments = if self.fragment.is_some() {
            &fragment[..]
        } else {
            &[][..]
        };
        let message = record::Message {
            route: self.route,
            params: record::Parameters {
                digest_output: None,
                cipher_extension: None,
                digest_extension: None,
                signature: Some(SignatureParameters {
                    graph: Graph::Live(graph),
                    edition: self.contract.constants_edition(),
                    caller_asserted: self.contract.provenance()
                        == MechanismLayoutProvenance::CallerAssertedLayout,
                    mutates_key: self.contract.mutates_key(),
                    phase: self.phase()?,
                    query: matches!(self.plan, SignatureOutputPlan::LengthOnly),
                    output_capacity: self.retained_output_capacity(),
                    maximum_output: self.maximum_output,
                    returned_length: *self.length as u64,
                }),
                message_init: None,
                counter_bits: None,
                nonce: None,
                aad: None,
                digest_oid: None,
                tag_bits: 0,
                iv_generator: None,
                iv_fixed_bits: None,
                iv_initial: None,
                hash: None,
                mgf: None,
                salt: None,
            },
            origin: record::NonceOrigin::None,
            state: record::MessageState::Engaged,
            fragments: record::Fragments::Slices(fragments),
            next_fragment: 0,
            produced: 0,
            expected: self.retained_output_capacity().unwrap_or(0),
            result: &[],
            tag_or_signature: self.signature.as_ref().map(|input| input.bytes()),
            residual_start: 0,
            residual_length: 0,
        };
        record::Messages::write(writer, &[message], limits)
    }

    // Archive resource bounds describe storage present in this continuation.
    // A caller's ceiling permits future allocations; it is not resident memory.
    fn retained_output_capacity(&self) -> Option<usize> {
        self.output.as_ref().map(|_| match self.plan {
            SignatureOutputPlan::LengthOnly => 0,
            SignatureOutputPlan::Buffer { capacity } => capacity,
        })
    }
}
