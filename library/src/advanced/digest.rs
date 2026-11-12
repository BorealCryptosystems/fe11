// SPDX-License-Identifier: Apache-2.0
//! Digest selection binds native mechanism, output width and public result shape.
pub(super) mod snapshot;

use super::{
    asynchronous, drive, record, spend, validation, AdvancedSessionMode, MessageRoute,
    NativeActivity, Operation, OperationBody, OperationProgress, OperationTicket,
    SessionValidation,
};

use crate::{
    bounds,
    module::{SessionEntry, State},
    symmetric::memory::{Buffer, Credit},
    Error, Result, Session,
};

use fe11_sys::{
    CKM_GOSTR3411, CKM_NULL, CKM_SHA256, CKM_SHA512_T, CKR_OK, CKR_PENDING, CK_ASYNC_DATA,
    CK_MECHANISM, CK_MECHANISM_TYPE, CK_ULONG,
};
use std::sync::atomic::Ordering;

pub(crate) mod batch;
mod control;
pub(super) mod extension;
pub(super) mod extension_snapshot;

// Legacy entry points retain their fixed-array result and checkpoint profile.
// A typed SHA-256 request is distinct: it must stay typed across save/restore.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DigestSelection {
    GostOid(MessageRoute),
    LegacySha256,
    Typed(crate::HashAlgorithm),
    Native(crate::NativeDigestAlgorithm),
    NativeSingle(crate::NativeDigestAlgorithm),
    Extension {
        mechanism: CK_MECHANISM_TYPE,
        capacity: usize,
        route: MessageRoute,
    },
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Step {
    Init,
    Single,
    Update(usize),
    Final,
    /// The terminal call is retained until the caller supplies new storage.
    OutputRequired {
        single: bool,
        required: usize,
    },
    Complete,
    Failed,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::advanced) enum Observer {
    Ticket,
    Session,
}

pub(super) struct DigestOperation {
    pub(super) observer: Observer,
    pub(super) input: super::input::InputState,
    pub(super) frame: DigestFrame,
    pub(super) step: Step,
    pub(super) activity: NativeActivity,
    pub(super) validation_requested: bool,
}
pub(super) struct DigestFrame {
    pub(super) selection: DigestSelection,
    pub(super) extension: Option<extension::Parameters>,
    pub(super) parameter: Option<Box<CK_ULONG>>,
    pub(super) oid: Option<crate::native::derivation::InputBytes>,
    pub(super) mechanism: Box<CK_MECHANISM>,
    pub(super) parts: super::fragment_queue::FragmentQueue,
    retirement: super::fragment_retirement::Pool,
    returned: super::fragment_retirement::ReturnedOperands,
    pub(super) output: Buffer,
    pub(super) length: Box<CK_ULONG>,
    pub(super) completion: Box<CK_ASYNC_DATA>,
    pub(super) name: [u8; 32],
    completion_diagnostic: Option<crate::error::CompletionStorage>,
    pub(super) _metadata: Credit,
}
// SAFETY: all pointed-to memory belongs to this frame and is stable. The frame
// is accessed only under module/token/session possession and its own mutex.
// While pending, no Rust read/write of provider-owned buffers is permitted.
unsafe impl Send for DigestFrame {}
impl DigestFrame {
    pub(super) fn metadata_bytes(parts: &[&[u8]], selection: DigestSelection) -> Result<usize> {
        Self::metadata_bytes_for_count(parts.len(), selection)
    }
    pub(super) fn metadata_bytes_for_count(
        count: usize,
        selection: DigestSelection,
    ) -> Result<usize> {
        // OwnedGraph carries its own inline metadata credit when selected.
        let fixed = std::mem::size_of::<Self>()
            - usize::from(matches!(selection, DigestSelection::Extension { .. }))
                * std::mem::size_of::<crate::mechanism_extension::OwnedGraph>()
            + usize::from(selection.parameter().is_some()) * std::mem::size_of::<CK_ULONG>()
            + std::mem::size_of::<CK_MECHANISM>()
            + std::mem::size_of::<CK_ULONG>()
            + std::mem::size_of::<CK_ASYNC_DATA>()
            + crate::error::CompletionStorage::allocation_bytes();
        count
            .checked_mul(std::mem::size_of::<Buffer>())
            .and_then(|n| n.checked_add(fixed))
            .and_then(|n| {
                n.checked_add(
                    super::fragment_retirement::Storage::required_bytes(count, false).ok()?,
                )
            })
            .ok_or(Error::Rejected(crate::RejectionReason::DigestContinuation(
                crate::DigestContinuationRejection::OperationMetadataLength,
            )))
    }
    pub(super) fn allocation_bytes(parts: &[&[u8]], selection: DigestSelection) -> Result<usize> {
        if selection.route() == MessageRoute::Single && parts.len() != 1 {
            return Err(Error::Rejected(crate::RejectionReason::DigestContinuation(
                crate::DigestContinuationRejection::SingleDigestInputCount,
            )));
        }
        parts
            .iter()
            .try_fold(Self::metadata_bytes(parts, selection)?, |total, part| {
                total.checked_add(part.len()).ok_or(Error::Rejected(
                    crate::RejectionReason::DigestContinuation(
                        crate::DigestContinuationRejection::DigestInputSize,
                    ),
                ))
            })?
            .checked_add(selection.length())
            .ok_or(Error::Rejected(crate::RejectionReason::DigestContinuation(
                crate::DigestContinuationRejection::DigestStorageSize,
            )))
    }
    pub(super) fn allocation_bytes_with_oid(
        parts: &[&[u8]],
        selection: DigestSelection,
        oid: Option<&[u8]>,
    ) -> Result<usize> {
        if selection.has_oid() != oid.is_some() {
            return Err(Error::Rejected(crate::RejectionReason::DigestContinuation(
                crate::DigestContinuationRejection::DigestOidSelection,
            )));
        }
        let oid_bytes = oid.map_or(0, <[u8]>::len);
        bounds::ck_length(oid_bytes)?;
        Self::allocation_bytes(parts, selection)?
            .checked_add(oid_bytes.checked_mul(2).ok_or(Error::Rejected(
                crate::RejectionReason::DigestContinuation(
                    crate::DigestContinuationRejection::DigestOidAccounting,
                ),
            ))?)
            .ok_or(Error::Rejected(crate::RejectionReason::DigestContinuation(
                crate::DigestContinuationRejection::DigestGraphAccounting,
            )))
    }
    pub(super) fn oid_bytes(&self) -> Option<&[u8]> {
        self.oid
            .as_ref()
            .map(crate::native::derivation::InputBytes::bytes)
    }
    pub(super) fn unchanged(&self) -> bool {
        if let Some(extension) = &self.extension {
            return matches!(self.selection, DigestSelection::Extension { .. })
                && self.parameter.is_none()
                && self.oid.is_none()
                && extension.unchanged(&self.mechanism);
        }
        if matches!(self.selection, DigestSelection::Extension { .. }) {
            return false;
        }
        if let Some(oid) = &self.oid {
            return self.selection.has_oid()
                && self.parameter.is_none()
                && self.mechanism.mechanism == self.selection.mechanism()
                && self.mechanism.pParameter == oid.expected_pointer().cast()
                && self.mechanism.ulParameterLen == oid.length()
                && oid.unchanged();
        }
        if self.selection.has_oid() {
            return false;
        }
        let parameter_unchanged = match (self.selection.parameter(), &self.parameter) {
            (None, None) => {
                self.mechanism.pParameter.is_null() && self.mechanism.ulParameterLen == 0
            }
            (Some(expected), Some(actual)) => {
                **actual == expected
                    && self.mechanism.pParameter == (&**actual as *const CK_ULONG).cast_mut().cast()
                    && self.mechanism.ulParameterLen == std::mem::size_of::<CK_ULONG>() as CK_ULONG
            }
            _ => false,
        };
        self.mechanism.mechanism == self.selection.mechanism() && parameter_unchanged
    }

    // Credit is the first parameter so fallible construction drops the later
    // owned buffers/diagnostic before their metadata charge. The completed
    // frame uses the corresponding field order (metadata last).
    fn from_buffers(
        metadata: Credit,
        selection: DigestSelection,
        inputs: Vec<Buffer>,
        retirement: super::fragment_retirement::Pool,
        mut oid: Option<crate::native::derivation::InputBytes>,
        output: Buffer,
        completion_diagnostic: crate::error::CompletionStorage,
    ) -> Result<Self> {
        let mut parameter = selection.parameter().map(Box::new);
        let (pointer, parameter_length) = match parameter.as_mut() {
            Some(value) => (
                (&mut **value as *mut CK_ULONG).cast(),
                std::mem::size_of::<CK_ULONG>() as CK_ULONG,
            ),
            None => oid.as_mut().map_or((std::ptr::null_mut(), 0), |bytes| {
                (bytes.pointer().cast(), bytes.length())
            }),
        };
        Ok(Self {
            selection,
            extension: None,
            mechanism: Box::new(CK_MECHANISM {
                mechanism: selection.mechanism(),
                pParameter: pointer,
                ulParameterLen: parameter_length,
            }),
            parameter,
            oid,
            parts: inputs.into(),
            retirement,
            returned: super::fragment_retirement::ReturnedOperands::default(),
            length: Box::new(bounds::ck_length(output.capacity())?),
            output,
            completion: Box::new(crate::native::output::async_data()),
            name: [0; 32],
            completion_diagnostic: Some(completion_diagnostic),
            _metadata: metadata,
        })
    }
}

pub(super) fn function(step: Step) -> Result<&'static str> {
    match step {
        Step::Init => Ok("C_DigestInit"),
        Step::Single | Step::OutputRequired { single: true, .. } => Ok("C_Digest"),
        Step::Update(_) => Ok("C_DigestUpdate"),
        Step::Final | Step::OutputRequired { single: false, .. } => Ok("C_DigestFinal"),
        _ => Err(Error::Rejected(crate::RejectionReason::DigestContinuation(
            crate::DigestContinuationRejection::OperationNotActive,
        ))),
    }
}
impl DigestOperation {
    pub(in crate::advanced) fn take_returned_operands(
        &mut self,
    ) -> super::fragment_retirement::ReturnedOperands {
        std::mem::take(&mut self.frame.returned)
    }

    pub(super) fn joined_capacity(&self) -> Result<Option<usize>> {
        if !self.activity.pending() {
            return Err(Error::Rejected(crate::RejectionReason::DigestContinuation(
                crate::DigestContinuationRejection::DigestOperationNotJoinable,
            )));
        }
        function(self.step)?;
        Ok(if matches!(self.step, Step::Single | Step::Final) {
            Some(self.frame.output.capacity())
        } else {
            None
        })
    }
    pub(super) fn accept_joined(
        &mut self,
        s: &State,
        entry: &SessionEntry,
        result: asynchronous::JoinedResult,
    ) -> Result<()> {
        self.joined_capacity()?;
        let name = function(self.step)?;
        self.activity = NativeActivity::Active;
        let target = if matches!(self.step, Step::Single | Step::Final) {
            Some(self.frame.output.as_mut())
        } else {
            None
        };
        let observed = result.observed;
        let (_, length) = match result.project(name, target) {
            Ok(value) => value,
            Err(error) => {
                self.step = Step::Failed;
                s.native.mark_uncertain();
                return Err(error);
            }
        };
        if let Some(length) = length {
            *self.frame.length = length as CK_ULONG;
        }
        complete_step(
            s,
            entry,
            self,
            crate::native_return::protocol::PendingInspection::forwarded(observed),
        )
    }
}

pub(super) fn drive_digest(
    s: &State,
    entry: &SessionEntry,
    op: &mut DigestOperation,
    observe: bool,
    remaining: &mut usize,
) -> Result<()> {
    if op.step == Step::Failed {
        return Err(Error::Rejected(crate::RejectionReason::DigestContinuation(
            crate::DigestContinuationRejection::OperationFailedExplicitCleanupRequired,
        )));
    }
    if op.step == Step::Complete {
        return Ok(());
    }
    if let Some(size) = return_size::remembered(op.step, op.frame.output.capacity()) {
        // A repeated observation consumes neither input nor another native call.
        // Use the saved request, not the previously lent native length slot.
        return Err(size.buffer_too_small());
    }
    if op.activity.pending() {
        if !observe || !spend(remaining) {
            return Ok(());
        }
        let name = function(op.step)?;
        let call = s
            .native
            .asynchronous
            .and_then(|f| f.complete)
            .ok_or(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::CAsyncCompleteUnavailable,
            )))?;
        op.frame.name.fill(0);
        op.frame.name[..name.len()].copy_from_slice(name.as_bytes());
        // C_AsyncComplete itself is a synchronous observation. pResult is null
        // for functions without output, exactly as in the normative example.
        let result = if matches!(op.step, Step::Single | Step::Final) {
            &mut *op.frame.completion as *mut CK_ASYNC_DATA
        } else {
            std::ptr::null_mut()
        };
        s.native.record("C_AsyncComplete")?;
        // SAFETY: function name and result storage remain live in the owned frame.
        let rv = unsafe { call(entry.handle, op.frame.name.as_mut_ptr(), result) };
        let observed =
            crate::native_return::protocol::PendingInspection::completed(name, rv, |scope| {
                s.native.observe_async_return(rv);
                if rv != CKR_PENDING {
                    s.apply_session_failure(entry, rv, scope);
                }
            })
            .inspect(|| {
                if matches!(op.step, Step::Single | Step::Final) {
                    if op.frame.completion.ulVersion != 0 {
                        return Err(Error::Rejected(crate::RejectionReason::DigestContinuation(
                            crate::DigestContinuationRejection::AsynchronousResultVersion,
                        )));
                    }
                    if op.frame.completion.pValue != op.frame.output.as_mut().as_mut_ptr().cast()
                        || rv == CKR_OK
                            && op.frame.completion.ulValue as u128
                                > op.frame.output.capacity() as u128
                    {
                        return Err(Error::Rejected(crate::RejectionReason::DigestContinuation(
                            crate::DigestContinuationRejection::AsynchronousResultIdentity,
                        )));
                    }
                }
                Ok(())
            })
            .resolve(|result, cause| {
                op.activity = NativeActivity::Active;
                op.step = Step::Failed;
                s.native.mark_uncertain();
                if result.code() == CKR_OK {
                    cause
                } else {
                    op.frame
                        .completion_diagnostic
                        .take()
                        .expect("one terminal digest observation failure")
                        .bind(result.function())
                        .boundary_failure(result.code(), cause)
                }
            })?;
        if rv == CKR_PENDING {
            return Ok(());
        }
        if rv == CKR_OK
            && matches!(op.step, Step::Single | Step::Final)
            && op.frame.completion.ulVersion != 0
        {
            s.native.mark_uncertain();
            op.step = Step::Failed;
            return Err(Error::Rejected(crate::RejectionReason::DigestContinuation(
                crate::DigestContinuationRejection::AsynchronousResultVersion,
            )));
        }
        if rv == CKR_OK && matches!(op.step, Step::Single | Step::Final) {
            let result = &op.frame.completion;
            if result.ulVersion != 0
                || result.pValue != op.frame.output.as_mut().as_mut_ptr().cast()
                || result.ulValue as u128 > op.frame.output.capacity() as u128
            {
                s.native.mark_uncertain();
                op.step = Step::Failed;
                return Err(Error::Rejected(crate::RejectionReason::DigestContinuation(
                    crate::DigestContinuationRejection::AsynchronousResultIdentity,
                )));
            }
            *op.frame.length = result.ulValue;
        }
        op.activity = NativeActivity::Active;
        complete_step(
            s,
            entry,
            op,
            crate::native_return::protocol::PendingInspection::forwarded(observed),
        )?;
    }
    while !matches!(op.step, Step::Complete | Step::Failed) {
        // No queued fragment is not an end-of-input request. Only an explicit
        // finish (or the complete-input facade) authorizes native Final.
        if op.step == Step::Final && op.input.is_open() {
            return Ok(());
        }
        if !spend(remaining) {
            return Ok(());
        }
        entry.snapshot.check()?;
        if s.native.is_uncertain() {
            return Err(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                crate::ModuleLifecycleRejection::NativeStateUncertain,
            )));
        }
        let name = function(op.step)?;
        // Resolve the next input and its ABI width before recording/arming it.
        // Init and Final carry no input; their unused length remains zero.
        let input_length = match op.step {
            Step::Single => bounds::ck_length(op.frame.parts[0].capacity())?,
            Step::Update(index) => bounds::ck_length(op.frame.parts[index].capacity())?,
            _ => 0,
        };
        let retired_count = match op.step {
            Step::Single => 1,
            Step::Update(index) => index.checked_add(1).ok_or(Error::Rejected(
                crate::RejectionReason::DigestContinuation(
                    crate::DigestContinuationRejection::DigestInputRetirementCount,
                ),
            ))?,
            _ => 0,
        };
        op.frame.retirement.check(retired_count, 0)?;
        let submission = if matches!(op.step, Step::Single | Step::Update(_)) {
            Some(op.input.submission(input_length as usize, false)?)
        } else {
            None
        };
        if matches!(op.step, Step::Single | Step::Final) {
            op.input.produced(op.frame.output.capacity())?;
        }
        let native_call = resolved_call::Call::resolve(&s.native.table, op.step)?;
        s.native.record(name)?;
        if let Some(submission) = submission {
            op.input = submission.issued;
        }
        op.activity = NativeActivity::Active;
        // SAFETY: every pointer belongs to the installed frame. No allocation or
        // relocation of its buffers/parameters occurs between Init and Final.
        let rv = unsafe {
            match native_call {
                resolved_call::Call::Init(call) => call(entry.handle, &mut *op.frame.mechanism),
                resolved_call::Call::Single(call) => {
                    let input = &mut op.frame.parts[0];
                    call(
                        entry.handle,
                        input.as_mut().as_mut_ptr(),
                        input_length,
                        op.frame.output.as_mut().as_mut_ptr(),
                        &mut *op.frame.length,
                    )
                }
                resolved_call::Call::Update { call, index: i } => {
                    let input = &mut op.frame.parts[i];
                    call(entry.handle, input.as_mut().as_mut_ptr(), input_length)
                }
                resolved_call::Call::Final(call) => call(
                    entry.handle,
                    op.frame.output.as_mut().as_mut_ptr(),
                    &mut *op.frame.length,
                ),
            }
        };
        if rv == CKR_PENDING {
            op.activity = NativeActivity::Pending;
            if entry.mode != AdvancedSessionMode::Asynchronous {
                s.native.mark_uncertain();
                return Err(Error::Native {
                    function: name,
                    code: rv as u64,
                    may_have_effect: true,
                });
            }
            return Ok(());
        }
        complete_step(
            s,
            entry,
            op,
            crate::native_return::protocol::PendingInspection::returned(name, rv, |scope| {
                s.apply_session_failure(entry, rv, scope);
            }),
        )?;
    }
    Ok(())
}
pub(super) fn complete_step(
    s: &State,
    entry: &SessionEntry,
    op: &mut DigestOperation,
    returned: crate::native_return::protocol::PendingInspection,
) -> Result<()> {
    let rv = returned.code();
    let name = returned.function();
    let init = op.step == Step::Init;
    use crate::native_return::protocol::SequencePhase;
    use crate::native_return::sequence::{Completion, OutputRequest};
    let size = if matches!(op.step, Step::Single | Step::Final) {
        returned.direct_output_size(op.frame.output.capacity(), || *op.frame.length)
    } else {
        None
    };
    let inspected = returned.inspect(|| {
        if !op.frame.unchanged() {
            return Err(Error::Rejected(crate::RejectionReason::DigestContinuation(
                crate::DigestContinuationRejection::DigestNativeParameterIdentity,
            )));
        }
        if rv == CKR_OK && matches!(op.step, Step::Single | Step::Final) {
            bounds::final_length(*op.frame.length, op.frame.output.capacity()).map_err(|_| {
                Error::Rejected(crate::RejectionReason::DigestContinuation(
                    crate::DigestContinuationRejection::DigestOutputCapacity,
                ))
            })?;
        }
        Ok(())
    });
    let version = s.native.table.version;
    let phase = if init {
        SequencePhase::Initialize
    } else {
        SequencePhase::Continue(OutputRequest::Buffer)
    };
    let initialization_refused =
        inspected.initialization_refused((version.major, version.minor), phase);
    let completion = inspected.completion((version.major, version.minor), phase);
    op.activity = if initialization_refused {
        NativeActivity::InitializationRefused
    } else if completion == Completion::Terminated {
        NativeActivity::Closed
    } else {
        NativeActivity::Active
    };
    let result = inspected.resolve(|result, cause| {
        op.activity = NativeActivity::Active;
        s.native.mark_uncertain();
        op.step = Step::Failed;
        if result.code() == CKR_OK {
            cause
        } else {
            // This terminal local failure consumes the same prepaid leaf as
            // other terminal Digest publication failures. No retry follows it.
            op.frame
                .completion_diagnostic
                .take()
                .expect("one terminal digest completion failure")
                .bind(result.function())
                .boundary_with_output(result.code(), size, cause)
        }
    })?;
    if !result.memory_returned() {
        op.step = Step::Failed;
        s.native.mark_uncertain();
        entry.poisoned.store(true, Ordering::Release);
        return result.check(true);
    }
    if size.is_some() && matches!(op.step, Step::Single | Step::Final) {
        let required = usize::try_from(*op.frame.length).map_err(|_| {
            Error::Rejected(crate::RejectionReason::DigestContinuation(
                crate::DigestContinuationRejection::DigestRequiredCapacityWidth,
            ))
        })?;
        op.step = Step::OutputRequired {
            single: op.step == Step::Single,
            required,
        };
        // PKCS#11 retains this operation on BUFFER_TOO_SMALL. The input and graph
        // stay owned; only an explicit storage replacement permits another call.
        op.activity = NativeActivity::Active;
        return Err(size
            .expect("defined digest capacity observation")
            .buffer_too_small());
    }
    if rv != CKR_OK {
        op.step = Step::Failed;
        if !op.activity.locally_retirable() {
            entry.poisoned.store(true, Ordering::Release);
        }
        return result.check(!(init && op.activity.locally_retirable()));
    }
    if let Step::Single | Step::Update(_) = op.step {
        let index = match op.step {
            Step::Update(index) => index,
            _ => 0,
        };
        op.input = op
            .input
            .accepted(op.frame.parts[index].as_slice().len(), false)?;
        // The completed prefix is absent from subsequent calls and snapshots.
        // Prepaid nodes keep its bytes/credit until poll drops them outside all
        // access guards, including when a later call in this batch fails.
        for _ in 0..=index {
            let input = op.frame.parts.pop_front();
            op.frame.retirement.input(input, &mut op.frame.returned);
        }
    }
    op.step = match op.step {
        Step::Init if op.frame.selection.route() == MessageRoute::Single => Step::Single,
        Step::Init if !op.frame.parts.is_empty() => Step::Update(0),
        Step::Init => Step::Final,
        Step::Update(_) if !op.frame.parts.is_empty() => Step::Update(0),
        Step::Update(_) => Step::Final,
        Step::Single | Step::Final => {
            if !op.frame.selection.accepts_length(*op.frame.length as usize) {
                op.step = Step::Failed;
                return op
                    .frame
                    .completion_diagnostic
                    .take()
                    .expect("one terminal digest completion failure")
                    .bind(name)
                    .finish(Err(Error::Rejected(
                        crate::RejectionReason::ClassicalSignatures(
                            crate::ClassicalSignaturesRejection::DigestOutputLength,
                        ),
                    )));
            }
            if let Some(extension) = &mut op.frame.extension {
                if let Err(error) = extension.finish() {
                    op.activity = NativeActivity::Active;
                    op.step = Step::Failed;
                    s.native.mark_uncertain();
                    return Err(error);
                }
            }
            // NULL digest has a caller-selected capacity and an independent
            // returned length. Preserve only the confirmed bytes at publication.
            op.frame.output.set_length(*op.frame.length as usize)?;
            op.input = op.input.produced(*op.frame.length as usize)?;
            Step::Complete
        }
        _ => {
            return Err(Error::Rejected(crate::RejectionReason::DigestContinuation(
                crate::DigestContinuationRejection::DuplicateOperationCompletion,
            )))
        }
    };
    Ok(())
}

impl crate::symmetric::memory::RetainedStorage for DigestOperation {
    fn retain_credits(&self, retained: &mut crate::symmetric::memory::RetainedBytes) -> Result<()> {
        self.frame.retain_credits(retained)?;
        Ok(())
    }
}

impl crate::symmetric::memory::RetainedStorage for DigestFrame {
    fn retain_credits(&self, retained: &mut crate::symmetric::memory::RetainedBytes) -> Result<()> {
        self.extension.retain_credits(retained)?;
        self.oid.retain_credits(retained)?;
        self.parts.retain_credits(retained)?;
        self.retirement.retain_credits(retained)?;
        self.returned.retain_credits(retained)?;
        self.output.retain_credits(retained)?;
        self._metadata.retain_credits(retained)?;
        Ok(())
    }
}

mod preparation;
mod selection;
pub(super) use preparation::start;
pub(super) use preparation::start_open;
pub(super) use preparation::start_open_with_oid;
use preparation::start_retained;
use preparation::start_with_input;
pub(super) use preparation::start_with_oid;

mod resolved_call;

mod return_size;
