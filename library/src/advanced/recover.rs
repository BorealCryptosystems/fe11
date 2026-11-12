// SPDX-License-Identifier: Apache-2.0
//! Traditional signatures with data recovery; no hash or message-API substitution.
use super::keys::KeyLease;
use super::{
    continuation, drive, poll, preparation, record, restoration_keys, spend, validation,
    AdvancedSession, AdvancedSessionMode, MessageRoute, NativeActivity, Operation, OperationBody,
    OperationPacing, OperationProgress, OperationTicket, StateKeyReference, StateRestoreKeys,
};
use crate::module::{SessionEntry, State};
use crate::native_return::sequence::{Completion, OutputRequest};
use crate::symmetric::memory::{Buffer, Credit};
use crate::{bounds, Error, Result};
use fe11_sys::{
    CKF_SIGN_RECOVER, CKF_VERIFY_RECOVER, CKM_RSA_9796, CKM_RSA_PKCS, CKM_RSA_X_509,
    CKR_BUFFER_TOO_SMALL, CKR_OK, CKR_PENDING, CK_FLAGS, CK_MECHANISM, CK_MECHANISM_TYPE, CK_ULONG,
};
use std::sync::atomic::Ordering;
mod api;
pub(in crate::advanced) mod checkpoint;

/// Explicit parameterless mechanism for native signature recovery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoverMechanism {
    /// CKM_RSA_PKCS; native PKCS#1 v1.5 encoding, without a library hash.
    RsaPkcs,
    /// CKM_RSA_X_509; native raw RSA representation.
    RsaX509,
    /// CKM_RSA_9796; support is decided by the module.
    Rsa9796,
    /// Exact identifier with NULL/0 parameters. The caller selects this ABI
    /// representation; it is not a generic encoding of parameterized mechanisms.
    Parameterless(u64),
}
impl RecoverMechanism {
    fn native(self) -> Result<CK_MECHANISM_TYPE> {
        let value = match self {
            Self::RsaPkcs => CKM_RSA_PKCS as u64,
            Self::RsaX509 => CKM_RSA_X_509 as u64,
            Self::Rsa9796 => CKM_RSA_9796 as u64,
            Self::Parameterless(value) => value,
        };
        value.try_into().map_err(|_| {
            Error::Rejected(crate::RejectionReason::OperationRecovery(
                crate::OperationRecoveryRejection::RecoveryMechanismWidth,
            ))
        })
    }
}
/// Choose whether the first output call supplies storage or only requests size.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoverOutputPlan {
    /// Supply a non-NULL buffer, including when capacity is zero.
    Buffer {
        /// Writable output capacity in bytes, charged to the configured budget.
        capacity: usize,
    },
    /// Submit a NULL output pointer. A successful size query leaves the native
    /// operation active and requires an explicit capacity selection before poll.
    LengthOnly,
}
/// A native size result, distinct from a completed signature or verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryBufferRequest {
    /// Exact function that reported the size.
    pub function: &'static str,
    /// Exact CKR_OK for a query, or CKR_BUFFER_TOO_SMALL for a supplied buffer.
    pub code: u64,
    /// Required byte count reported by the module, without clamping.
    pub required: usize,
    /// Capacity supplied in that call; zero for a length-only query.
    pub previous_capacity: usize,
}
/// Complete native signature or recovered message with retained memory credit.
pub struct RecoveryOutput(Buffer);
impl RecoveryOutput {
    /// Borrow the completed bytes. Caller copies are outside this owner's erasure.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    Sign,
    Verify,
}
impl Kind {
    fn init(self) -> &'static str {
        match self {
            Self::Sign => "C_SignRecoverInit",
            Self::Verify => "C_VerifyRecoverInit",
        }
    }
    fn output(self) -> &'static str {
        match self {
            Self::Sign => "C_SignRecover",
            Self::Verify => "C_VerifyRecover",
        }
    }
    fn category(self) -> CK_FLAGS {
        match self {
            Self::Sign => CKF_SIGN_RECOVER,
            Self::Verify => CKF_VERIFY_RECOVER,
        }
    }
}
#[derive(Clone, Copy)]
enum Stage {
    Init(RecoverOutputPlan),
    Output(RecoverOutputPlan),
    Waiting(RecoveryBufferRequest),
    Done,
    Failed,
}
pub(super) struct RecoverOperation {
    key: KeyLease,
    kind: Kind,
    selected: CK_MECHANISM_TYPE,
    mechanism: Box<CK_MECHANISM>,
    input: Buffer,
    expected: Buffer,
    input_length: CK_ULONG,
    output: Option<Buffer>,
    length: Box<CK_ULONG>,
    stage: Stage,
    activity: NativeActivity,
    maximum_output: usize,
    completion_diagnostic: Option<crate::error::CompletionStorage>,
    _credit: Credit,
}
// SAFETY: all pointers refer to stable owned allocations; the registry retains
// the complete frame and key lease on an uncompleted return. Access is serialized.
unsafe impl Send for RecoverOperation {}

impl crate::symmetric::memory::RetainedStorage for RecoverOperation {
    fn retain_credits(&self, retained: &mut crate::symmetric::memory::RetainedBytes) -> Result<()> {
        self.key.retain_credits(retained)?;
        self.input.retain_credits(retained)?;
        self.expected.retain_credits(retained)?;
        self.output.retain_credits(retained)?;
        // Metadata credit already covers the stable mechanism and length boxes.
        // Visit it once; scalar handles and negotiation state allocate nothing.
        self._credit.retain_credits(retained)
    }
}

// Preparation owns every native allocation before a key or session is held.
struct PreparedRecover {
    selected: CK_MECHANISM_TYPE,
    mechanism: Box<CK_MECHANISM>,
    input: Buffer,
    expected: Buffer,
    input_length: CK_ULONG,
    output: Option<Buffer>,
    length: Box<CK_ULONG>,
    maximum_output: usize,
    completion_diagnostic: crate::error::CompletionStorage,
    _credit: Credit,
}
impl PreparedRecover {
    fn metadata_bytes() -> usize {
        std::mem::size_of::<RecoverOperation>()
            + std::mem::size_of::<CK_MECHANISM>()
            + std::mem::size_of::<CK_ULONG>()
            + crate::error::CompletionStorage::allocation_bytes()
    }

    fn allocation_bytes_for_length(
        mechanism: RecoverMechanism,
        input_length: usize,
        plan: RecoverOutputPlan,
        maximum_output: usize,
    ) -> Result<usize> {
        mechanism.native()?;
        let capacity = match plan {
            RecoverOutputPlan::Buffer { capacity } => capacity,
            RecoverOutputPlan::LengthOnly => 0,
        };
        if capacity > maximum_output {
            return Err(Error::Rejected(crate::RejectionReason::OperationRecovery(
                crate::OperationRecoveryRejection::RecoveryOutputCeiling,
            )));
        }
        bounds::ck_length(input_length)?;
        bounds::ck_length(capacity)?;
        input_length
            .checked_mul(2)
            .and_then(|n| n.checked_add(capacity))
            .and_then(|n| n.checked_add(Self::metadata_bytes()))
            .ok_or(Error::Rejected(crate::RejectionReason::OperationRecovery(
                crate::OperationRecoveryRejection::RecoveryFrameAccountingOverflow,
            )))
    }

    fn bind(self, key: KeyLease, kind: Kind, plan: RecoverOutputPlan) -> RecoverOperation {
        let Self {
            selected,
            mechanism,
            input,
            expected,
            input_length,
            output,
            length,
            maximum_output,
            completion_diagnostic,
            _credit,
        } = self;
        RecoverOperation {
            key,
            kind,
            stage: Stage::Init(plan),
            activity: NativeActivity::Inactive,
            selected,
            mechanism,
            input,
            expected,
            input_length,
            output,
            length,
            maximum_output,
            completion_diagnostic: Some(completion_diagnostic),
            _credit,
        }
    }
}
impl RecoverOperation {
    pub(super) fn check_key(&self, entry: &SessionEntry) -> Result<()> {
        self.key.check(entry)
    }
    pub(super) fn complete(&self) -> bool {
        matches!(self.stage, Stage::Done)
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
    pub(super) fn active_categories(&self) -> CK_FLAGS {
        if self.activity.locally_retirable() {
            0
        } else {
            self.kind.category()
        }
    }
    pub(super) fn buffer_request(&self) -> Option<RecoveryBufferRequest> {
        match self.stage {
            Stage::Waiting(request) => Some(request),
            _ => None,
        }
    }
    pub(super) fn next_function(&self) -> Option<&'static str> {
        match self.stage {
            Stage::Init(_) => Some(self.kind.init()),
            Stage::Output(_) => Some(self.kind.output()),
            _ => None,
        }
    }
    pub(super) fn validation_point(&self) -> Option<validation::Point> {
        matches!(self.stage, Stage::Output(RecoverOutputPlan::Buffer { .. })).then_some(
            validation::Point {
                function: self.kind.output(),
                message_index: None,
            },
        )
    }
    pub(super) fn output_preparation(&self, capacity: usize) -> Result<RecoveryBufferRequest> {
        let Stage::Waiting(request) = self.stage else {
            return Err(Error::Rejected(crate::RejectionReason::OperationRecovery(
                crate::OperationRecoveryRejection::RecoveryIsNotWaitingForStorage,
            )));
        };
        if capacity > self.maximum_output {
            return Err(Error::Rejected(crate::RejectionReason::OperationRecovery(
                crate::OperationRecoveryRejection::RecoveryOutputCeiling,
            )));
        }
        bounds::ck_length(capacity)?;
        if self.pending() {
            return Err(Error::Rejected(
                crate::RejectionReason::AsynchronousExecution(
                    crate::AsynchronousExecutionRejection::SignatureRecoveryAsynchronousModeUnavailable,
                ),
            ));
        }
        Ok(request)
    }
    pub(super) fn attach_output(
        &mut self,
        capacity: usize,
        output: Buffer,
    ) -> Result<Option<Buffer>> {
        self.output_preparation(capacity)?;
        if output.as_slice().len() != capacity {
            return Err(Error::Rejected(crate::RejectionReason::OperationRecovery(
                crate::OperationRecoveryRejection::RecoveryOutputCeiling,
            )));
        }
        let old = self.output.replace(output);
        *self.length = bounds::ck_length(capacity)?;
        self.stage = Stage::Output(RecoverOutputPlan::Buffer { capacity });
        Ok(old)
    }
    pub(super) fn result(&mut self, _entry: &SessionEntry) -> Result<OperationProgress> {
        // Completed owned output remains evidence of that call, even if
        // the key or context was withdrawn before local publication.
        if !self.complete() {
            return Err(Error::Rejected(crate::RejectionReason::OperationRecovery(
                crate::OperationRecoveryRejection::RecoveryResultIncomplete,
            )));
        }
        let output = RecoveryOutput(self.output.take().ok_or(Error::Rejected(
            crate::RejectionReason::OperationRecovery(
                crate::OperationRecoveryRejection::RecoveryResultAlreadyPublished,
            ),
        ))?);
        Ok(match self.kind {
            Kind::Sign => OperationProgress::RecoveredSignature(output),
            Kind::Verify => OperationProgress::RecoveredMessage(output),
        })
    }
    pub(super) fn drive(
        &mut self,
        s: &State,
        entry: &SessionEntry,
        remaining: &mut usize,
    ) -> Result<()> {
        if self.pending() {
            return Err(Error::Rejected(
                crate::RejectionReason::AsynchronousExecution(
                    crate::AsynchronousExecutionRejection::SignatureRecoveryAsynchronousModeUnavailable,
                ),
            ));
        }
        loop {
            let Some(function) = self.next_function() else {
                return Ok(());
            };
            if !spend(remaining) {
                return Ok(());
            }
            self.key.check(entry)?;
            let stage = self.stage;
            // Copy the selected entry before arming the native owner.
            let native_call = resolved_call::Call::resolve(&s.native.table, self.kind, stage)?;
            s.native.record(function)?;
            self.activity = NativeActivity::Active;
            // SAFETY: registered owner retains the mechanism, input, output,
            // length slot and admitted key for every possible native return.
            let rv = unsafe {
                match native_call {
                    resolved_call::Call::Init(call) => {
                        call(entry.handle, &mut *self.mechanism, self.key.handle)
                    }
                    resolved_call::Call::Output { call, plan } => {
                        let out = match plan {
                            RecoverOutputPlan::LengthOnly => std::ptr::null_mut(),
                            RecoverOutputPlan::Buffer { .. } => self
                                .output
                                .as_mut()
                                .expect("prepared recovery output")
                                .as_mut()
                                .as_mut_ptr(),
                        };
                        call(
                            entry.handle,
                            self.input.as_mut().as_mut_ptr(),
                            self.input_length,
                            out,
                            &mut *self.length,
                        )
                    }
                }
            };
            use crate::native_return::protocol::{PendingInspection, SequencePhase};
            let version = s.native.table.version;
            let version = (version.major, version.minor);
            let phase = match stage {
                Stage::Init(_) => SequencePhase::Initialize,
                Stage::Output(plan) => {
                    SequencePhase::Continue(if matches!(plan, RecoverOutputPlan::LengthOnly) {
                        OutputRequest::LengthOnly
                    } else {
                        OutputRequest::Buffer
                    })
                }
                _ => unreachable!(),
            };
            let inspected = PendingInspection::returned(function, rv, |scope| {
                s.apply_session_failure(entry, rv, scope);
            })
            .inspect(|| {
                if self.mechanism.mechanism != self.selected
                    || !self.mechanism.pParameter.is_null()
                    || self.mechanism.ulParameterLen != 0
                    || self.input.as_slice() != self.expected.as_slice()
                {
                    return Err(Error::Rejected(crate::RejectionReason::OperationRecovery(
                        crate::OperationRecoveryRejection::RecoveryNativeInputIdentity,
                    )));
                }
                if let Stage::Output(RecoverOutputPlan::Buffer { capacity }) = stage {
                    if rv == CKR_OK {
                        bounds::final_length(*self.length, capacity).map_err(|_| {
                            Error::Rejected(crate::RejectionReason::OperationRecovery(
                                crate::OperationRecoveryRejection::RecoveryOutputCapacity,
                            ))
                        })?;
                    }
                }
                Ok(())
            });
            let size = if let Stage::Output(plan) = stage {
                let capacity = match plan {
                    RecoverOutputPlan::Buffer { capacity } => capacity,
                    RecoverOutputPlan::LengthOnly => 0,
                };
                crate::NativeOutputSize::buffer_refusal(function, rv, capacity, || *self.length)
            } else {
                None
            };
            let initialization_refused = inspected.initialization_refused(version, phase);
            let completion = inspected.completion(version, phase);
            let result = inspected.resolve(|result, cause| {
                self.activity = NativeActivity::Active;
                self.stage = Stage::Failed;
                s.native.mark_uncertain();
                if result.code() == CKR_OK {
                    cause
                } else {
                    self.completion_diagnostic
                        .take()
                        .expect("one terminal recovery boundary failure")
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
                entry.poisoned.store(true, Ordering::Release);
                self.stage = Stage::Failed;
                return result.check(true).and(Err(Error::Rejected(
                    crate::RejectionReason::OperationRecovery(
                        crate::OperationRecoveryRejection::RecoveryOutcomeUncertain,
                    ),
                )));
            }
            match stage {
                Stage::Init(plan) if rv == CKR_OK => {
                    self.stage = Stage::Output(plan);
                    if let Err(error) = self.key.check(entry) {
                        entry.poisoned.store(true, Ordering::Release);
                        return Err(error);
                    }
                }
                Stage::Output(plan)
                    if rv == CKR_BUFFER_TOO_SMALL
                        || rv == CKR_OK && matches!(plan, RecoverOutputPlan::LengthOnly) =>
                {
                    let required = match usize::try_from(*self.length) {
                        Ok(required) => required,
                        Err(_) => {
                            self.stage = Stage::Failed;
                            return Err(Error::Rejected(
                                crate::RejectionReason::OperationRecovery(
                                    crate::OperationRecoveryRejection::RecoveryReportedLengthWidth,
                                ),
                            ));
                        }
                    };
                    let previous_capacity = match plan {
                        RecoverOutputPlan::Buffer { capacity } => capacity,
                        RecoverOutputPlan::LengthOnly => 0,
                    };
                    // A returned query/BUFFER_TOO_SMALL has released its buffers.
                    // Discard any partial output before a later allocation attempt.
                    drop(self.output.take());
                    self.stage = Stage::Waiting(RecoveryBufferRequest {
                        function,
                        code: rv as u64,
                        required,
                        previous_capacity,
                    });
                    return Ok(());
                }
                Stage::Output(RecoverOutputPlan::Buffer { capacity }) if rv == CKR_OK => {
                    if bounds::final_length(*self.length, capacity).is_err() {
                        self.activity = NativeActivity::Active;
                        self.stage = Stage::Failed;
                        s.native.mark_uncertain();
                        return Err(Error::Rejected(crate::RejectionReason::OperationRecovery(
                            crate::OperationRecoveryRejection::RecoveryOutputCapacity,
                        )));
                    }
                    self.output
                        .as_mut()
                        .expect("prepared recovery output")
                        .set_length(*self.length as usize)?;
                    self.stage = Stage::Done;
                }
                _ => {
                    self.stage = Stage::Failed;
                    if !self.activity.locally_retirable() {
                        entry.poisoned.store(true, Ordering::Release);
                    }
                    return result.check(!self.activity.locally_retirable());
                }
            }
        }
    }
}

mod resolved_call;
