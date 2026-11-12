// SPDX-License-Identifier: Apache-2.0
//! Standalone block-cipher state owner: no digest, MAC or implicit auxiliary operation.
use super::keys::KeyLease;
use super::{
    continuation, drive, poll, record, restoration_keys, spend, validation, AdvancedSession,
    AdvancedSessionMode, MessageRoute, NativeActivity, Operation, OperationBody, OperationPacing,
    OperationProgress, OperationTicket, StateRestoreKeys,
};
use crate::module::{SessionEntry, State};

use crate::symmetric::memory::{Buffer, Credit};
use crate::{bounds, Error, Result};
use fe11_sys::{
    CKF_DECRYPT, CKF_ENCRYPT, CKM_NULL, CKR_BUFFER_TOO_SMALL, CKR_OK, CKR_PENDING, CK_FLAGS,
    CK_MECHANISM, CK_ULONG,
};

use std::sync::atomic::Ordering;

pub(super) mod snapshot;
use crate::native_return::sequence::{Completion, OutputRequest};
use crate::symmetric::cipher as plain_parameters;
mod aead;
pub(crate) mod batch;
mod extension;
mod extension_api;
pub(crate) use extension_api::begin_single as begin_native_single;
pub(in crate::advanced) mod extension_binding;
pub(in crate::advanced) mod extension_snapshot;
pub(super) mod parameters;
use parameters::{Frame as CipherFrame, Selection};
pub(crate) mod api;
pub(in crate::advanced) mod checkpoint;
mod input;
mod key_preparation;
mod lease;
mod negotiation;
mod output_storage;
use output_storage::OutputStorage;
mod resolved_call;
mod retirement;
mod shadow;
mod synchronous;
pub use input::CipherStreamChunk;
pub use lease::CipherKeyReference;
use lease::CipherLease;
use negotiation::OutputStep;
pub use negotiation::{AesBufferRequest, AesOutputPlan, CipherBufferRequest, CipherOutputPlan};

pub(super) use retirement::ReturnedOperands;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Direction {
    Encrypt,
    Decrypt,
}
impl Direction {
    fn decrypts(self) -> bool {
        self == Self::Decrypt
    }
    fn init(self) -> &'static str {
        match self {
            Self::Encrypt => "C_EncryptInit",
            Self::Decrypt => "C_DecryptInit",
        }
    }
    fn single(self) -> &'static str {
        match self {
            Self::Encrypt => "C_Encrypt",
            Self::Decrypt => "C_Decrypt",
        }
    }
    fn update(self) -> &'static str {
        match self {
            Self::Encrypt => "C_EncryptUpdate",
            Self::Decrypt => "C_DecryptUpdate",
        }
    }
    fn final_call(self) -> &'static str {
        match self {
            Self::Encrypt => "C_EncryptFinal",
            Self::Decrypt => "C_DecryptFinal",
        }
    }
    fn category(self) -> CK_FLAGS {
        match self {
            Self::Encrypt => CKF_ENCRYPT,
            Self::Decrypt => CKF_DECRYPT,
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    Init(CipherOutputPlan),
    Single,
    Update {
        index: usize,
        offset: usize,
    },
    Final,
    Query(OutputStep),
    Waiting {
        step: OutputStep,
        request: CipherBufferRequest,
    },
    Done,
    Failed,
}

// A synchronous convenience call cannot return its local ticket through Result.
// An error after initialization may hand that capability back to the session.
// Taking it transitions to Ticket exactly once, under the operation mutex.
#[derive(Clone, Copy, PartialEq, Eq)]
enum OutputObserver {
    Ticket,
    Session,
}

/// All allocation and copying happens here, before acquiring the native key lease.
/// Moving this prepared value never moves an allocation referenced by C.
struct PreparedCipher {
    direction: Direction,
    route: MessageRoute,
    parameters: CipherFrame,
    inputs: super::fragment_queue::FragmentQueue,
    expected: shadow::Shadow,
    retirement: retirement::Pool,
    layout: continuation::InputLayout,
    output: Option<Buffer>,
    length: Box<CK_ULONG>,
    minimum: usize,
    maximum: usize,
    completion_diagnostic: Option<crate::error::CompletionStorage>,
    _credit: Credit,
}
// Pure sizing shared by admission and construction; no handle or credit is used.
struct CipherStorage {
    total: usize,
    minimum: usize,
    maximum: usize,
    output_capacity: usize,
    count: usize,
    metadata: usize,
    peak: usize,
}
impl CipherStorage {
    fn for_request(
        direction: Direction,
        route: MessageRoute,
        selection: Selection<'_>,
        parts: &[&[u8]],
        plan: CipherOutputPlan,
    ) -> Result<Self> {
        let total = parts
            .iter()
            .try_fold(0usize, |n, part| n.checked_add(part.len()))
            .ok_or(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::CipherInputLengthOverflow,
            )))?;
        Self::for_shape(
            direction,
            route,
            selection,
            parts.len(),
            total,
            OutputStorage::Initial(plan),
            false,
        )
    }
    fn for_shape(
        direction: Direction,
        route: MessageRoute,
        selection: Selection<'_>,
        fragments: usize,
        total: usize,
        output: OutputStorage,
        incremental: bool,
    ) -> Result<Self> {
        let plan = output.plan();
        selection.validate_route(route)?;
        let mechanism = selection.mechanism_number();
        if !matches!(selection, Selection::Extension(_))
            && !plain_parameters::block_cipher(mechanism)
            && !parameters::is_aead(mechanism)
        {
            return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::StandaloneNativeCipherParametersRequired,
            )));
        }
        if matches!(selection, Selection::Extension(_))
            && matches!(plan, CipherOutputPlan::MechanismBound)
        {
            return Err(Error::Rejected(
                crate::RejectionReason::CipherContinuation(crate::CipherContinuationRejection::ExtensionCipherRequiresAnExplicitBufferOrLengthQuery),
            ));
        }
        if route == MessageRoute::Single {
            bounds::ck_length(total)?;
        }
        // Multipart lends each checked fragment, not this host-side sum.
        // Future stream input is unknown: reserve caller-selected storage and
        // let Update/Final report their native capacity, without evaluating
        // complete-message padding/alignment against an empty initial prefix.
        let (minimum, maximum) = if incremental {
            (
                0,
                match plan {
                    CipherOutputPlan::Buffer { capacity } => capacity,
                    _ => 0,
                },
            )
        } else {
            selection.output_bounds(total, direction.decrypts())?
        };
        let output_capacity = match plan {
            CipherOutputPlan::MechanismBound => maximum.max(total),
            CipherOutputPlan::Buffer { capacity } => capacity,
            CipherOutputPlan::LengthOnly => 0,
        };
        output.validate(output_capacity)?;
        let count = if route == MessageRoute::Single {
            1
        } else {
            fragments.max(1)
        };
        let metadata = count
            .checked_mul(std::mem::size_of::<Buffer>())
            .and_then(|n| n.checked_add(std::mem::size_of::<CipherOperation>()))
            .and_then(|n| n.checked_add(std::mem::size_of::<CK_MECHANISM>()))
            .and_then(|n| n.checked_add(std::mem::size_of::<CK_ULONG>()))
            .and_then(|n| n.checked_add(crate::error::CompletionStorage::allocation_bytes()))
            .and_then(|n| n.checked_add(selection.parameter_bytes()))
            .and_then(|n| {
                n.checked_sub(if matches!(selection, Selection::Extension(_)) {
                    std::mem::size_of::<crate::mechanism_extension::OwnedGraph>()
                } else {
                    0
                })
            })
            .ok_or(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::CipherFrameAccountingOverflow,
            )))?;
        // Reserve the complete known graph once: waiting for a second grant
        // while retaining the first can deadlock a bounded shared budget.
        let peak = total
            .checked_mul(2)
            .and_then(|n| n.checked_add(output_capacity))
            .and_then(|n| n.checked_add(selection.iv_bytes().len().checked_mul(2)?))
            .and_then(|n| n.checked_add(metadata))
            .and_then(|n| n.checked_add(retirement::Storage::required_bytes(count, true).ok()?))
            .and_then(|n| n.checked_add(selection.additional_buffer_bytes().ok()?))
            .and_then(|n| {
                n.checked_add(continuation::InputLayout::allocation_bytes(fragments).ok()?)
            })
            .ok_or(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::CipherFrameAccountingOverflow,
            )))?;
        Ok(Self {
            total,
            minimum,
            maximum,
            output_capacity,
            count,
            metadata,
            peak,
        })
    }
}

impl PreparedCipher {
    fn unchanged(&self) -> bool {
        let mut offset = 0usize;
        for input in &self.inputs {
            let Some(end) = offset.checked_add(input.as_slice().len()) else {
                return false;
            };
            if self.expected.as_slice().get(offset..end) != Some(input.as_slice()) {
                return false;
            }
            offset = end;
        }
        offset == self.expected.as_slice().len()
    }
    fn fragment_unchanged(&self, index: usize, offset: usize) -> bool {
        let Some(input) = self.inputs.get(index) else {
            return false;
        };
        let Some(end) = offset.checked_add(input.as_slice().len()) else {
            return false;
        };
        self.expected.as_slice().get(offset..end) == Some(input.as_slice())
    }
}

pub(super) struct CipherOperation {
    observer: OutputObserver,
    input: super::input::InputState,
    key: CipherLease,
    frame: PreparedCipher,
    returned: ReturnedOperands,
    stage: Stage,
    used: usize,
    activity: NativeActivity,
}
// SAFETY: every native pointer addresses owned stable allocations. The registry
// retains the whole frame and key lease until a function-specific termination
// proof. Its operation mutex serializes calls and observation of native output.
unsafe impl Send for CipherOperation {}
impl CipherOperation {
    fn new(key: CipherLease, frame: PreparedCipher, plan: CipherOutputPlan) -> Self {
        Self {
            observer: OutputObserver::Ticket,
            input: super::input::InputState::closed(),
            key,
            frame,
            returned: ReturnedOperands::default(),
            stage: Stage::Init(plan),
            used: 0,
            activity: NativeActivity::Inactive,
        }
    }
    pub(super) fn check_key(&self, entry: &SessionEntry) -> Result<()> {
        self.key.check(entry)
    }
    pub(super) fn complete(&self) -> bool {
        self.stage == Stage::Done
    }
    pub(super) fn pending(&self) -> bool {
        self.activity.pending()
    }
    pub(super) fn initialization_refused(&self) -> bool {
        self.activity == NativeActivity::InitializationRefused
    }

    pub(super) fn native_inactive(&self) -> bool {
        self.activity.inactive()
    }
    pub(super) fn encrypting(&self) -> bool {
        !self.frame.direction.decrypts() || self.extension_mutates_key()
    }
    pub(super) fn active_categories(&self) -> CK_FLAGS {
        if self.activity.locally_retirable() {
            0
        } else {
            self.frame.direction.category()
        }
    }
    pub(super) fn next_function(&self) -> Option<&'static str> {
        Some(match self.stage {
            Stage::Init(_) => self.frame.direction.init(),
            Stage::Single => self.frame.direction.single(),
            Stage::Update { .. } => self.frame.direction.update(),
            Stage::Final => self.frame.direction.final_call(),
            Stage::Query(step) => step.function(self.frame.direction),
            Stage::Waiting { .. } | Stage::Done | Stage::Failed => return None,
        })
    }
    pub(super) fn validation_point(&self) -> Option<validation::Point> {
        if matches!(self.stage, Stage::Single | Stage::Final) {
            Some(validation::Point {
                function: self.next_function()?,
                message_index: None,
            })
        } else {
            None
        }
    }
    pub(super) fn result(&mut self, _entry: &SessionEntry) -> Result<OperationProgress> {
        // Completed owned output remains evidence of that call, even if
        // the key or context was withdrawn before local publication.
        if !self.complete() {
            return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::CipherResultIncomplete,
            )));
        }

        let output = self.frame.output.take().ok_or(Error::Rejected(
            crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::CipherResultAlreadyPublished,
            ),
        ))?;
        self.frame
            .parameters
            .publish(output, self.frame.direction.decrypts())
    }
    pub(super) fn drive(
        &mut self,
        s: &State,
        entry: &SessionEntry,
        remaining: &mut usize,
    ) -> Result<()> {
        if self.pending() {
            return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::NativeCipherAsynchronousModeUnavailable,
            )));
        }
        loop {
            if matches!(self.stage, Stage::Final | Stage::Query(OutputStep::Final))
                && self.input.is_open()
            {
                return Ok(());
            }
            let Some(function) = self.next_function() else {
                return Ok(());
            };
            if !spend(remaining) {
                return Ok(());
            }
            self.key.check(entry)?;
            let query = matches!(self.stage, Stage::Query(_));
            let stage = match self.stage {
                Stage::Query(step) => step.stage(),
                stage => stage,
            };
            let decrypt = self.frame.direction.decrypts();
            let native_call = resolved_call::Call::resolve(&s.native.table, decrypt, stage)?;
            self.frame.parameters.validate()?;
            let input_unchanged = match stage {
                Stage::Update { index, offset } => self.frame.fragment_unchanged(index, offset),
                _ => self.frame.unchanged(),
            };
            if !input_unchanged {
                return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                    crate::CipherContinuationRejection::CipherInputChangedBeforeDispatch,
                )));
            }
            let output = self.frame.output.as_mut().ok_or(Error::Rejected(
                crate::RejectionReason::CipherContinuation(
                    crate::CipherContinuationRejection::CipherOutputAbsent,
                ),
            ))?;
            let available = output
                .capacity()
                .checked_sub(self.used)
                .ok_or(Error::Rejected(crate::RejectionReason::CipherContinuation(
                    crate::CipherContinuationRejection::CipherOutputOffset,
                )))?;
            *self.frame.length = if query {
                0
            } else {
                bounds::ck_length(available)?
            };
            let output_pointer = if query {
                std::ptr::null_mut()
            } else {
                // Buffer owns a valid non-NULL pointer even for zero capacity.
                output.as_mut()[self.used..].as_mut_ptr()
            };
            let input_length = match stage {
                Stage::Single => bounds::ck_length(self.frame.inputs[0].as_slice().len())?,
                Stage::Update { index, .. } => {
                    bounds::ck_length(self.frame.inputs[index].as_slice().len())?
                }
                _ => 0,
            };
            if !query {
                self.check_retirement(stage)?;
            }
            let submission = if !query && matches!(stage, Stage::Single | Stage::Update { .. }) {
                Some(self.input.submission(input_length as usize, false)?)
            } else {
                None
            };
            if !query {
                self.input.produced(available)?;
            }
            s.native.record(function)?;
            if matches!(stage, Stage::Init(_)) {
                self.key.arm_for_native_call();
            }
            if let Some(submission) = submission {
                self.input = submission.issued;
            }
            self.activity = NativeActivity::Active;
            // SAFETY: preparation bounds every range; all descriptors, input,
            // output and length are retained by this registered stable owner.
            let rv = unsafe {
                match native_call {
                    resolved_call::Call::Init(init) => init(
                        entry.handle,
                        self.frame.parameters.mechanism_mut(),
                        self.key.handle(),
                    ),
                    resolved_call::Call::Data { call, index } => call(
                        entry.handle,
                        self.frame.inputs[index].as_mut().as_mut_ptr(),
                        input_length,
                        output_pointer,
                        &mut *self.frame.length,
                    ),
                    resolved_call::Call::Final(call) => {
                        call(entry.handle, output_pointer, &mut *self.frame.length)
                    }
                }
            };
            use crate::native_return::protocol::{PendingInspection, SequencePhase};
            let v = s.native.table.version;
            let phase = if matches!(stage, Stage::Init(_)) {
                SequencePhase::Initialize
            } else {
                SequencePhase::Continue(if query {
                    OutputRequest::LengthOnly
                } else {
                    OutputRequest::Buffer
                })
            };
            let inspected = PendingInspection::returned(function, rv, |scope| {
                s.apply_session_failure(entry, rv, scope);
            })
            .inspect(|| {
                let unchanged = match stage {
                    Stage::Update { index, offset } => self.frame.fragment_unchanged(index, offset),
                    _ => self.frame.unchanged(),
                };
                if self.frame.parameters.validate_after_call().is_err() || !unchanged {
                    return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                        crate::CipherContinuationRejection::CipherNativeInputIdentity,
                    )));
                }
                if rv == CKR_OK && !query && !matches!(stage, Stage::Init(_)) {
                    bounds::final_length(*self.frame.length, available).map_err(|_| {
                        Error::Rejected(crate::RejectionReason::CipherContinuation(
                            crate::CipherContinuationRejection::CipherNativeOutputLength,
                        ))
                    })?;
                }
                Ok(())
            });
            let size = if matches!(stage, Stage::Init(_)) {
                None
            } else {
                crate::NativeOutputSize::buffer_refusal(
                    function,
                    rv,
                    if query { 0 } else { available },
                    || *self.frame.length,
                )
            };
            let initialization_refused =
                inspected.initialization_refused((v.major, v.minor), phase);
            let completion = inspected.completion((v.major, v.minor), phase);
            let result = inspected.resolve(|result, cause| {
                self.stage = Stage::Failed;
                self.activity = NativeActivity::Active;
                s.native.mark_uncertain();
                if result.code() == CKR_OK {
                    cause
                } else {
                    self.frame
                        .completion_diagnostic
                        .take()
                        .expect("one terminal cipher boundary failure")
                        .bind(result.function())
                        .boundary_with_output(result.code(), size, cause)
                }
            })?;
            if rv == CKR_PENDING {
                self.activity = NativeActivity::Pending;
                s.native.mark_uncertain();
                return result.check(true);
            }
            self.activity = if initialization_refused {
                NativeActivity::InitializationRefused
            } else if completion == Completion::Terminated {
                NativeActivity::Inactive
            } else {
                NativeActivity::Active
            };
            if completion == Completion::Uncertain {
                self.stage = Stage::Failed;
                entry.poisoned.store(true, Ordering::Release);
                return result.check(true).and(Err(Error::Rejected(
                    crate::RejectionReason::CipherContinuation(
                        crate::CipherContinuationRejection::CipherOutcomeUncertain,
                    ),
                )));
            }
            if !matches!(stage, Stage::Init(_))
                && (rv == CKR_BUFFER_TOO_SMALL || query && rv == CKR_OK)
            {
                // Neither return consumes this input nor establishes termination.
                // Preserve the native size exactly; allocation is a caller choice.
                let required = usize::try_from(*self.frame.length).map_err(|_| {
                    Error::Rejected(crate::RejectionReason::CipherContinuation(
                        crate::CipherContinuationRejection::CipherRequiredLengthWidth,
                    ))
                })?;
                let step = OutputStep::from_stage(stage)?;
                self.stage = Stage::Waiting {
                    step,
                    request: CipherBufferRequest {
                        function,
                        code: rv as u64,
                        required,
                        previous_capacity: if query { 0 } else { available },
                    },
                };
                return Ok(());
            }
            if rv != CKR_OK {
                self.stage = Stage::Failed;
                return result.check(true);
            }
            match stage {
                Stage::Init(plan) => {
                    let step = if self.frame.route == MessageRoute::Single {
                        OutputStep::Single
                    } else if self.frame.inputs.is_empty() {
                        OutputStep::Final
                    } else {
                        OutputStep::Update {
                            index: 0,
                            offset: 0,
                        }
                    };
                    self.stage = if plan == CipherOutputPlan::LengthOnly {
                        Stage::Query(step)
                    } else {
                        step.stage()
                    };
                }
                Stage::Single | Stage::Update { .. } | Stage::Final => {
                    let produced = match bounds::final_length(*self.frame.length, available) {
                        Ok(n) => n,
                        Err(_) => {
                            self.stage = Stage::Failed;
                            self.activity = NativeActivity::Active;
                            s.native.mark_uncertain();
                            return Err(Error::Rejected(
                                crate::RejectionReason::CipherContinuation(
                                    crate::CipherContinuationRejection::CipherNativeOutputLength,
                                ),
                            ));
                        }
                    };
                    if self.frame.parameters.kind() == CKM_NULL {
                        let expected = match stage {
                            Stage::Single => self.frame.inputs[0].as_slice(),
                            Stage::Update { index, .. } => self.frame.inputs[index].as_slice(),
                            Stage::Final => &[],
                            _ => unreachable!(),
                        };
                        if self
                            .frame
                            .output
                            .as_ref()
                            .unwrap()
                            .as_slice()
                            .get(self.used..self.used + produced)
                            != Some(expected)
                        {
                            self.stage = Stage::Failed;
                            return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(crate::CipherContinuationRejection::CkmNullChangedTheCurrentInput)));
                        }
                    }
                    self.used += produced; // produced <= capacity - previous used.
                    self.input = self.input.produced(produced)?;
                    if matches!(stage, Stage::Single | Stage::Update { .. }) {
                        self.input = self.input.accepted(input_length as usize, false)?;
                    }
                    if let Stage::Update { index, .. } = stage {
                        if index != 0 {
                            return Err(Error::Rejected(
                                crate::RejectionReason::CipherContinuation(
                                    crate::CipherContinuationRejection::CipherQueuedInputCursor,
                                ),
                            ));
                        }
                        // Erase the consumed witness prefix without moving its suffix.
                        // Storage stays credited until its transfer out of possession.
                        self.frame
                            .expected
                            .discard_prefix_retained(input_length as usize)?;
                        self.retire_first_input();
                        self.frame.layout.consume_first();
                        self.stage = if self.frame.inputs.is_empty() {
                            Stage::Final
                        } else {
                            Stage::Update {
                                index: 0,
                                offset: 0,
                            }
                        };
                    } else {
                        if completion != Completion::Terminated {
                            self.stage = Stage::Failed;
                            return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(crate::CipherContinuationRejection::CipherTerminalCompletionUnproven)));
                        }
                        let shape = self.frame.parameters.selection().and_then(|selection| {
                            selection.terminal_lengths(
                                self.input.progress.input_bytes,
                                self.input.progress.output_bytes,
                                self.frame.direction.decrypts(),
                                self.frame.parameters.options(),
                            )
                        });
                        let cause = match shape {
                            Ok(true) => None,
                            Ok(false) => Some(Error::Rejected(
                                crate::RejectionReason::CipherContinuation(
                                    crate::CipherContinuationRejection::CipherResultLengthOutsideMechanismContract,
                                ),
                            )),
                            Err(error) => Some(error),
                        };
                        if let Some(cause) = cause {
                            self.stage = Stage::Failed;
                            return self
                                .frame
                                .completion_diagnostic
                                .take()
                                .expect("one terminal cipher publication failure")
                                .bind(function)
                                .finish_native(rv, Err(cause));
                        }

                        if let Err(error) = self.frame.parameters.finish_parameters() {
                            self.stage = Stage::Failed;
                            self.activity = NativeActivity::Active;
                            s.native.mark_uncertain();
                            return Err(error);
                        }
                        self.frame.output.as_mut().unwrap().set_length(self.used)?;
                        self.retire_terminal_inputs();
                        self.frame.layout.clear();
                        self.stage = Stage::Done;
                    }
                }
                _ => unreachable!(),
            }

            self.key.check(entry)?;
        }
    }
}

impl crate::symmetric::memory::RetainedStorage for PreparedCipher {
    fn retain_credits(&self, retained: &mut crate::symmetric::memory::RetainedBytes) -> Result<()> {
        self.parameters.retain_credits(retained)?;
        self.inputs.retain_credits(retained)?;
        self.expected.retain_credits(retained)?;
        self.retirement.retain_credits(retained)?;
        self.layout.retain_credits(retained)?;
        self.output.retain_credits(retained)?;
        self._credit.retain_credits(retained)?;
        Ok(())
    }
}

impl crate::symmetric::memory::RetainedStorage for CipherOperation {
    fn retain_credits(&self, retained: &mut crate::symmetric::memory::RetainedBytes) -> Result<()> {
        super::key_roles::Roles::retain_unique(self.key.writer_roles(), [], retained)?;
        self.key.retain_credits(retained)?;
        self.frame.retain_credits(retained)?;
        self.returned.retain_credits(retained)?;
        Ok(())
    }
}
