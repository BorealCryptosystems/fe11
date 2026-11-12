// SPDX-License-Identifier: Apache-2.0
//! Owned protocol frames. The operation ledger must retain these before dispatch.
//! This layer does not authorize a continuation or define a persistent encoding.
//!
//! These adapters describe PKCS#11 native asynchronous call storage and its
//! reconstruction/retention boundaries. Their presence does not enable
//! asynchronous session creation. Synchronous cooperative operations and current
//! validation-flag observations have their own admission contracts.

use super::{record, Operation, OperationBody};

use crate::module::{SessionEntry, State};

use crate::symmetric::memory::{Buffer, Credit};
use crate::{bounds, Error, Result};

use fe11_sys::{
    CKR_FUNCTION_NOT_SUPPORTED, CKR_GENERAL_ERROR, CKR_OK, CKR_OPERATION_NOT_INITIALIZED,
    CKR_PENDING, CKR_STATE_UNSAVEABLE, CK_ASYNC_DATA, CK_BYTE_PTR, CK_INVALID_HANDLE,
    CK_OBJECT_HANDLE, CK_RV, CK_ULONG,
};

use zeroize::Zeroize;
mod fixed;
use fixed::FixedOutput;

fn name(function: &'static str) -> Result<Box<[u8; 40]>> {
    // Closed native function names, never caller-controlled strings or C pointers.
    record::Function::from_name(function)?;
    let mut result = Box::new([0; 40]);
    result[..function.len()].copy_from_slice(function.as_bytes());
    Ok(result)
}

pub(super) fn completed_objects(
    result: &CK_ASYNC_DATA,
    pair: bool,
) -> Result<(CK_OBJECT_HANDLE, CK_OBJECT_HANDLE)> {
    if result.ulVersion != 0
        || result.hObject == CK_INVALID_HANDLE
        || pair
            && (result.hAdditionalObject == CK_INVALID_HANDLE
                || result.hObject == result.hAdditionalObject)
    {
        return Err(Error::Rejected(
            crate::RejectionReason::AsynchronousExecution(
                crate::AsynchronousExecutionRejection::AsynchronousObjectHandles,
            ),
        ));
    }
    Ok((
        result.hObject,
        if pair {
            result.hAdditionalObject
        } else {
            CK_INVALID_HANDLE
        },
    ))
}

pub(super) fn pending_function(operation: &Operation) -> Result<&'static str> {
    let function = if let Some(control) = operation.state_io() {
        if !control.pending() {
            return Err(Error::Rejected(
                crate::RejectionReason::AsynchronousExecution(
                    crate::AsynchronousExecutionRejection::StateControlNotPending,
                ),
            ));
        }
        control.function()?
    } else if operation.validation_pending() {
        "C_GetSessionValidationFlags"
    } else {
        if !operation.body.pending() {
            return Err(Error::Rejected(
                crate::RejectionReason::AsynchronousExecution(
                    crate::AsynchronousExecutionRejection::OperationNotPending,
                ),
            ));
        }
        match &operation.body {
                OperationBody::Digest(body) => super::function(body.step)?,
                OperationBody::Messages(body) => body.function()?,
                OperationBody::AeadMessages(body) => body.function()?,
                OperationBody::Dual(body) => body.function()?,
                OperationBody::Admission(body) => body.function()?,
                OperationBody::NativeMessages(_) => {
                    return Err(Error::Rejected(
                        crate::RejectionReason::AsynchronousExecution(
                            crate::AsynchronousExecutionRejection::GenericMessageAsynchronousModeUnavailable,
                        ),
                    ))
                }
                OperationBody::Cipher(_) => {
                    return Err(Error::Rejected(
                        crate::RejectionReason::AsynchronousExecution(
                            crate::AsynchronousExecutionRejection::NativeAesAsynchronousModeUnavailable,
                        ),
                    ))
                }
                OperationBody::Recover(_) => return Err(Error::Rejected(
                    crate::RejectionReason::AsynchronousExecution(
                        crate::AsynchronousExecutionRejection::SignatureRecoveryAsynchronousModeUnavailable,
                    ),
                )),
                OperationBody::Signature(_) => {
                    return Err(Error::Rejected(
                        crate::RejectionReason::AsynchronousExecution(
                            crate::AsynchronousExecutionRejection::SignatureAsynchronousModeUnavailable,
                        ),
                    ))
                }
                OperationBody::Control => {
                    return Err(Error::Rejected(
                        crate::RejectionReason::AsynchronousExecution(
                            crate::AsynchronousExecutionRejection::ControlNotDetachable,
                        ),
                    ))
                }
            }
    };
    Ok(function)
}

pub(super) struct GetId {
    name: Box<[u8; 40]>,
    id: Box<CK_ULONG>,
    phase: GetIdPhase,
    _credit: Credit,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum GetIdPhase {
    Prepared,
    Issued,
    Returned(CK_RV),
}
impl GetId {
    /// Derive the native function from the tracked owner. This gate reads only
    /// Rust progression metadata, never a provider-owned pending output.
    pub(super) fn checked_function(operation: &Operation) -> Result<&'static str> {
        if operation.state_io().is_none() {
            if let Some(capture) = &operation.validation {
                capture.check_detachment(operation.body.message_count())?;
            }
        }
        // Encryption retains one output owner across Init/Begin/Final:
        // allowing one of those steps to detach would split its output owner.
        if operation.state_io().is_none()
            && !operation.validation_pending()
            && matches!(&operation.body,OperationBody::AeadMessages(body) if body.encrypting())
        {
            return Err(Error::Rejected(
                crate::RejectionReason::AsynchronousExecution(
                    crate::AsynchronousExecutionRejection::GcmMessageEncryptionDetachmentDeferred,
                ),
            ));
        }
        if operation.cancellation.is_withdrawn()
            || operation.continuation_status.is_frozen() && operation.restore_owner().is_none()
            || operation.cancel.is_submitted()
            || operation
                .joined
                .as_ref()
                .is_some_and(|c| c.phase != JoinPhase::Attached)
        {
            return Err(Error::Rejected(
                crate::RejectionReason::AsynchronousExecution(
                    crate::AsynchronousExecutionRejection::OperationNotDetachable,
                ),
            ));
        }
        if let Some(control) = operation.state_io() {
            control.check_detachment()?;
        }
        if let OperationBody::Admission(body) = &operation.body {
            body.check_detachment()?;
        }
        pending_function(operation)
    }

    pub(super) fn allocation_bytes() -> usize {
        std::mem::size_of::<Self>() + 40 + std::mem::size_of::<CK_ULONG>()
    }
    /// The caller revalidates the owner-derived function under possession before
    /// installation. This constructor only owns stable, undispatched storage.
    pub(super) fn new_prepaid(prepaid: &mut Credit, function: &'static str) -> Result<Self> {
        let credit = prepaid.split(Self::allocation_bytes())?;
        Ok(Self {
            name: name(function)?,
            id: Box::new(0),
            phase: GetIdPhase::Prepared,
            _credit: credit,
        })
    }

    /// Caller must own the original pending frame and retain this control on
    /// PENDING/GENERAL_ERROR. A refusal never releases the original operation.
    pub(super) fn dispatch(&mut self, s: &State, entry: &SessionEntry) -> Result<CK_ULONG> {
        if self.phase != GetIdPhase::Prepared {
            return Err(Error::Rejected(
                crate::RejectionReason::AsynchronousExecution(
                    crate::AsynchronousExecutionRejection::AsynchronousIdentifierAlreadyRequested,
                ),
            ));
        }
        let call = s
            .native
            .asynchronous
            .and_then(|f| f.get_id)
            .ok_or(Error::Rejected(
                crate::RejectionReason::AsynchronousExecution(
                    crate::AsynchronousExecutionRejection::CAsyncGetIDUnavailable,
                ),
            ))?;
        entry.snapshot.check()?;
        if s.native.is_uncertain() {
            return Err(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                crate::ModuleLifecycleRejection::NativeStateUncertain,
            )));
        }
        s.native.record("C_AsyncGetID")?;
        self.phase = GetIdPhase::Issued;
        // SAFETY: stable owned name and identifier, under session possession.
        let rv = unsafe { call(entry.handle, self.name.as_mut_ptr(), &mut *self.id) };
        self.phase = GetIdPhase::Returned(rv);
        s.native.observe_async_return(rv);
        let result =
            crate::native_return::protocol::PendingInspection::returned("C_AsyncGetID", rv, |_| {
                // These ordinary refusals do not invalidate the original call.
                if rv != CKR_OK
                    && !matches!(
                        rv,
                        CKR_STATE_UNSAVEABLE
                            | CKR_OPERATION_NOT_INITIALIZED
                            | CKR_FUNCTION_NOT_SUPPORTED
                    )
                {
                    s.apply_session_failure(entry, rv, crate::native_return::failure_scope(rv));
                }
            })
            .inspect(|| Ok(()))
            .resolve(|_, cause| cause)?;
        if self.retains_native_memory() {
            s.native.mark_uncertain();
        }
        result.check(false)?;
        Ok(*self.id) // zero is not assigned a special meaning by PKCS#11.
    }
    pub(super) fn retains_native_memory(&self) -> bool {
        match self.phase {
            GetIdPhase::Prepared => false,
            GetIdPhase::Issued => true,
            GetIdPhase::Returned(rv) => !crate::native_return::async_memory_returned(rv as u64),
        }
    }
    pub(super) fn execution_incomplete(&self) -> bool {
        matches!(
            self.phase,
            GetIdPhase::Issued | GetIdPhase::Returned(CKR_PENDING)
        )
    }
}

impl Drop for GetId {
    fn drop(&mut self) {
        self.id.as_mut().zeroize();
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum JoinPhase {
    Prepared,
    Issued,
    Attached,
    Complete,
    Failed,
    Uncertain,
    ReturnedUncertain,
    Consumed,
}
pub(super) struct JoinedCall {
    function: &'static str,
    name: Box<[u8; 40]>,
    id: CK_ULONG,
    output: Option<Buffer>,
    fixed: Option<FixedOutput>,
    result: Box<CK_ASYNC_DATA>,
    phase: JoinPhase,
    return_value: CK_RV,
    observed: Option<crate::native_return::protocol::ReturnCode>,
    return_diagnostic: Option<crate::error::CompletionStorage>,
    _credit: Credit,
}
// SAFETY: native pointers only reference stable owned allocations. The ledger
// owns this frame while attached/uncertain; its session and frame guards exclude
// concurrent access. Output bytes are not read before terminal completion.
unsafe impl Send for JoinedCall {}
pub(super) struct JoinedResult {
    function: &'static str,
    pub(super) return_value: CK_RV,
    pub(super) observed: crate::native_return::protocol::ReturnCode,
    pub(super) output: Option<Buffer>,
    fixed: Option<FixedOutput>,
    pub(super) value: CK_ULONG,
    pub(super) object: CK_OBJECT_HANDLE,
    pub(super) additional_object: CK_OBJECT_HANDLE,
}
impl JoinedResult {
    /// Object handles are scalar outputs defined by CK_ASYNC_DATA, never bytes
    /// or handles decoded from a persisted record. No output is accepted on error.
    pub(super) fn project_objects(
        self,
        function: &'static str,
        pair: bool,
    ) -> Result<(CK_RV, Option<(CK_OBJECT_HANDLE, CK_OBJECT_HANDLE)>)> {
        if self.function != function
            || self.return_value == CKR_PENDING
            || self.output.is_some()
            || self.fixed.is_some()
        {
            return Err(Error::Rejected(
                crate::RejectionReason::AsynchronousExecution(
                    crate::AsynchronousExecutionRejection::JoinedObjectResultShape,
                ),
            ));
        }
        if self.return_value != CKR_OK {
            return Ok((self.return_value, None));
        }
        let descriptor = CK_ASYNC_DATA {
            ulVersion: 0,
            pValue: std::ptr::null_mut(),
            ulValue: 0,
            hObject: self.object,
            hAdditionalObject: self.additional_object,
        };
        Ok((
            self.return_value,
            Some(completed_objects(&descriptor, pair)?),
        ))
    }
    /// Consume a terminal result into the exact owner's output region. A native
    /// failure has no publishable bytes; it is returned to the owner's existing
    /// mechanism-specific transition. This never resumes or retries native work.
    /// A returned length is the exact checked conversion of `self.value`, a
    /// CK_ULONG. Owners may store it back into a CK_ULONG without narrowing a
    /// caller-supplied usize; no arithmetic or capacity substitution occurs.
    pub(super) fn project(
        self,
        function: &'static str,
        target: Option<&mut [u8]>,
    ) -> Result<(CK_RV, Option<usize>)> {
        if self.function != function || self.return_value == CKR_PENDING || self.fixed.is_some() {
            return Err(Error::Rejected(
                crate::RejectionReason::AsynchronousExecution(
                    crate::AsynchronousExecutionRejection::JoinedResultFunctionOrPhase,
                ),
            ));
        }
        if self.return_value != CKR_OK {
            if self.output.is_some() {
                return Err(Error::Rejected(
                    crate::RejectionReason::AsynchronousExecution(
                        crate::AsynchronousExecutionRejection::FailedJoinedOutput,
                    ),
                ));
            }
            return Ok((self.return_value, None));
        }
        match (self.output, target) {
            (None, None) => Ok((self.return_value, None)),
            (Some(output), Some(target)) => {
                let length = bounds::final_length(self.value, target.len())?;
                if output.capacity() != target.len() || output.as_slice().len() != length {
                    return Err(Error::Rejected(
                        crate::RejectionReason::AsynchronousExecution(
                            crate::AsynchronousExecutionRejection::JoinedResultOutputShape,
                        ),
                    ));
                }
                target[..length].copy_from_slice(output.as_slice());
                Ok((self.return_value, Some(length)))
            }
            _ => Err(Error::Rejected(
                crate::RejectionReason::AsynchronousExecution(
                    crate::AsynchronousExecutionRejection::JoinedResultOutputKind,
                ),
            )),
        }
    }
}
impl JoinedCall {
    pub(super) fn check_prepared(
        &self,
        function: &'static str,
        capacity: Option<usize>,
    ) -> Result<()> {
        if self.phase != JoinPhase::Prepared
            || self.function != function
            || self.capacity() != capacity
        {
            return Err(Error::Rejected(
                crate::RejectionReason::AsynchronousExecution(
                    crate::AsynchronousExecutionRejection::JoinedPreparedOwnerLayout,
                ),
            ));
        }
        Ok(())
    }
    fn capacity(&self) -> Option<usize> {
        self.fixed
            .as_ref()
            .map(FixedOutput::capacity)
            .or_else(|| self.output.as_ref().map(Buffer::capacity))
    }
    fn output_pointer(&mut self) -> CK_BYTE_PTR {
        if let Some(fixed) = &mut self.fixed {
            fixed.pointer()
        } else {
            self.output
                .as_mut()
                .map_or(std::ptr::null_mut(), |b| b.as_mut().as_mut_ptr())
        }
    }
    /// Install in the ledger before calling; OK means attached, never completed.
    pub(super) fn attach(&mut self, s: &State, entry: &SessionEntry) -> Result<()> {
        if self.phase != JoinPhase::Prepared {
            return Err(Error::Rejected(
                crate::RejectionReason::AsynchronousExecution(
                    crate::AsynchronousExecutionRejection::AsynchronousJoinAlreadyAttempted,
                ),
            ));
        }
        let call = s
            .native
            .asynchronous
            .and_then(|f| f.join)
            .ok_or(Error::Rejected(
                crate::RejectionReason::AsynchronousExecution(
                    crate::AsynchronousExecutionRejection::CAsyncJoinUnavailable,
                ),
            ))?;
        let length = bounds::ck_length(self.capacity().unwrap_or(0))?;
        entry.snapshot.check()?;
        if s.native.is_uncertain() {
            return Err(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                crate::ModuleLifecycleRejection::NativeStateUncertain,
            )));
        }
        s.native.record("C_AsyncJoin")?;
        let pointer = self.output_pointer();
        self.phase = JoinPhase::Issued;
        // SAFETY: new output is already owned; original ID is a scalar, and the
        // exact function name remains stable through later completion polls.
        let rv = unsafe {
            call(
                entry.handle,
                self.name.as_mut_ptr(),
                self.id,
                pointer,
                length,
            )
        };
        s.native.observe_async_return(rv);
        self.phase = match rv {
            CKR_OK => JoinPhase::Attached,
            CKR_PENDING => JoinPhase::Uncertain,
            CKR_GENERAL_ERROR => JoinPhase::ReturnedUncertain,
            _ => JoinPhase::Failed,
        };
        let result =
            crate::native_return::protocol::PendingInspection::returned("C_AsyncJoin", rv, |_| {
                if rv != CKR_OK {
                    s.apply_session_failure(entry, rv, crate::native_return::failure_scope(rv));
                }
            })
            .inspect(|| Ok(()))
            .resolve(|_, cause| cause)?;
        if matches!(rv, CKR_PENDING | CKR_GENERAL_ERROR) {
            s.native.mark_uncertain();
        }
        result.check(false)
    }
    /// One completion observation; never repeats Join or the original call.
    pub(super) fn poll(&mut self, s: &State, entry: &SessionEntry) -> Result<bool> {
        if self.phase != JoinPhase::Attached {
            return Err(Error::Rejected(
                crate::RejectionReason::AsynchronousExecution(
                    crate::AsynchronousExecutionRejection::AsynchronousJoinNotAttached,
                ),
            ));
        }
        let call = s
            .native
            .asynchronous
            .and_then(|f| f.complete)
            .ok_or(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::CAsyncCompleteUnavailable,
            )))?;
        entry.snapshot.check()?;
        if s.native.is_uncertain() {
            return Err(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                crate::ModuleLifecycleRejection::NativeStateUncertain,
            )));
        }
        let fixed_length = self
            .fixed
            .as_ref()
            .map(|fixed| bounds::ck_length(fixed.capacity()))
            .transpose()?;
        s.native.record("C_AsyncComplete")?;
        self.phase = JoinPhase::Issued;
        // Scalars/object handles also arrive through CK_ASYNC_DATA. A no-output
        // call may ignore the initialized structure; no fabricated value is used.
        let rv = unsafe { call(entry.handle, self.name.as_mut_ptr(), &mut *self.result) };
        // Preserve the observed target code even when boundary validation
        // prevents take/project from ever being reached.
        self.return_value = rv;
        s.native.observe_async_return(rv);
        let observed = crate::native_return::protocol::PendingInspection::completed(
            self.function,
            rv,
            |scope| {
                // PENDING is a valid observation of the attached call. It retains
                // both frames and is not an unexpected synchronous failure.
                if rv != CKR_PENDING {
                    s.apply_session_failure(entry, rv, scope);
                }
            },
        )
        .inspect(|| {
            if self.result.ulVersion != 0
                || self.capacity().is_some() && self.result.pValue != self.output_pointer()
            {
                return Err(Error::Rejected(
                    crate::RejectionReason::AsynchronousExecution(
                        crate::AsynchronousExecutionRejection::JoinedAsynchronousOutputIdentity,
                    ),
                ));
            }
            if rv == CKR_OK {
                if fixed_length.is_some_and(|length| self.result.ulValue != length) {
                    return Err(Error::Rejected(
                        crate::RejectionReason::AsynchronousExecution(
                            crate::AsynchronousExecutionRejection::JoinedFixedOutputLength,
                        ),
                    ));
                }
                if let Some(output) = &self.output {
                    bounds::final_length(self.result.ulValue, output.capacity())?;
                }
            }
            Ok(())
        })
        .resolve(|result, cause| {
            self.phase = JoinPhase::ReturnedUncertain;
            s.native.mark_uncertain();
            if result.code() == CKR_OK {
                cause
            } else {
                self.return_diagnostic
                    .take()
                    .expect("one terminal joined-call boundary failure")
                    .bind(result.function())
                    .boundary_failure(result.code(), cause)
            }
        })?;
        if rv == CKR_PENDING {
            self.phase = JoinPhase::Attached;
            return Ok(false);
        }
        if !crate::native_return::async_memory_returned(rv as u64) {
            // Keep the joined output in this ledger owner. A returned
            // GENERAL_ERROR is not a transferable result and must not reach
            // take(), which releases failed outputs. The original pending
            // operation remains independently owned by Operation as well.
            self.phase = JoinPhase::ReturnedUncertain;
            s.native.mark_uncertain();
            return Err(Error::Native {
                function: self.function,
                code: rv as u64,
                may_have_effect: true,
            });
        }
        if self.result.ulVersion != 0
            || self.capacity().is_some() && self.result.pValue != self.output_pointer()
        {
            self.phase = JoinPhase::ReturnedUncertain;
            s.native.mark_uncertain();
            return Err(Error::Rejected(
                crate::RejectionReason::AsynchronousExecution(
                    crate::AsynchronousExecutionRejection::JoinedAsynchronousOutputIdentity,
                ),
            ));
        }
        if rv == CKR_OK {
            if let Some(fixed_length) = fixed_length {
                if self.result.ulValue != fixed_length {
                    self.phase = JoinPhase::ReturnedUncertain;
                    s.native.mark_uncertain();
                    return Err(Error::Rejected(
                        crate::RejectionReason::AsynchronousExecution(
                            crate::AsynchronousExecutionRejection::JoinedFixedOutputLength,
                        ),
                    ));
                }
            }
            if let Some(output) = &mut self.output {
                let length = match bounds::final_length(self.result.ulValue, output.capacity()) {
                    Ok(n) => n,
                    Err(e) => {
                        self.phase = JoinPhase::ReturnedUncertain;
                        s.native.mark_uncertain();
                        return Err(e);
                    }
                };
                if let Err(error) = output.set_length(length) {
                    self.phase = JoinPhase::ReturnedUncertain;
                    s.native.mark_uncertain();
                    return Err(error);
                }
            }
        }
        // Preserve native return for the owning mechanism's result semantics.
        // An error result must never publish partially written output bytes.
        self.return_value = rv;
        self.observed = Some(observed);
        self.phase = JoinPhase::Complete;
        Ok(true)
    }
    pub(super) fn take(&mut self) -> Result<JoinedResult> {
        if self.phase != JoinPhase::Complete
            || !crate::native_return::async_memory_returned(self.return_value as u64)
        {
            return Err(Error::Rejected(
                crate::RejectionReason::AsynchronousExecution(
                    crate::AsynchronousExecutionRejection::JoinedResultUnavailable,
                ),
            ));
        }
        let observed = self.observed.ok_or(Error::Rejected(
            crate::RejectionReason::AsynchronousExecution(
                crate::AsynchronousExecutionRejection::JoinedResultUnavailable,
            ),
        ))?;
        self.phase = JoinPhase::Consumed;
        let output = self.output.take();
        let output = if self.return_value == CKR_OK {
            output
        } else {
            drop(output);
            None
        };
        let fixed = self.fixed.take();
        let fixed = if self.return_value == CKR_OK {
            fixed
        } else {
            drop(fixed);
            None
        };
        // Refusal outputs are not observations. The sentinels below remain
        // inaccessible through projection, which returns (rv, None) first.
        let (value, object, additional_object) = if self.return_value == CKR_OK {
            (
                self.result.ulValue,
                self.result.hObject,
                self.result.hAdditionalObject,
            )
        } else {
            (0, CK_INVALID_HANDLE, CK_INVALID_HANDLE)
        };
        Ok(JoinedResult {
            function: self.function,
            return_value: self.return_value,
            observed,
            output,
            fixed,
            value,
            object,
            additional_object,
        })
    }

    pub(super) fn consumed(&self) -> bool {
        self.phase == JoinPhase::Consumed
    }
    pub(super) fn execution_incomplete(&self) -> bool {
        matches!(
            self.phase,
            JoinPhase::Issued | JoinPhase::Attached | JoinPhase::Uncertain
        )
    }
}

impl Drop for JoinedCall {
    fn drop(&mut self) {
        self.id.zeroize();
    }
}

/// Function/output layout is decided before any part of a transfer is retained.
#[derive(Clone, Copy)]
pub(super) struct JoinPlan {
    function: &'static str,
    id: CK_ULONG,
    capacity: Option<usize>,
    output_length: Option<usize>,
    metadata: usize,
}
pub(super) struct JoinStorage {
    plan: JoinPlan,
    output: Option<crate::symmetric::memory::UnboundBuffer>,
}
impl JoinPlan {
    pub(super) fn new(
        function: &'static str,
        id: CK_ULONG,
        capacity: Option<usize>,
    ) -> Result<Self> {
        // Complete eligibility and known graph sizing before any reservation.
        record::Function::from_name(function)?;
        let fixed_bytes = FixedOutput::allocation_bytes(function, capacity)?;
        if let Some(capacity) = capacity {
            bounds::ck_length(capacity)?;
        }
        let output_length = if fixed_bytes.is_some() {
            None
        } else {
            capacity
        };
        let metadata = std::mem::size_of::<JoinedCall>()
            .checked_add(40 + std::mem::size_of::<CK_ASYNC_DATA>())
            .and_then(|n| n.checked_add(crate::error::CompletionStorage::allocation_bytes()))
            .and_then(|n| n.checked_add(fixed_bytes.unwrap_or(0)))
            .ok_or(Error::Rejected(
                crate::RejectionReason::AsynchronousExecution(
                    crate::AsynchronousExecutionRejection::JoinedStorageAccounting,
                ),
            ))?;
        Ok(Self {
            function,
            id,
            capacity,
            output_length,
            metadata,
        })
    }
    pub(super) fn allocation_bytes(&self) -> Result<usize> {
        self.metadata
            .checked_add(self.output_length.unwrap_or(0))
            .ok_or(Error::Rejected(
                crate::RejectionReason::AsynchronousExecution(
                    crate::AsynchronousExecutionRejection::JoinedStorageAccounting,
                ),
            ))
    }
    pub(super) fn allocate(self) -> Result<JoinStorage> {
        Ok(JoinStorage {
            output: self
                .output_length
                .map(crate::symmetric::memory::UnboundBuffer::allocate)
                .transpose()?,
            plan: self,
        })
    }
}
impl JoinStorage {
    pub(super) fn allocated_bytes(&self) -> Result<usize> {
        self.plan
            .metadata
            .checked_add(self.output.as_ref().map_or(0, |buffer| buffer.allocated()))
            .ok_or(Error::Rejected(
                crate::RejectionReason::AsynchronousExecution(
                    crate::AsynchronousExecutionRejection::JoinedStorageAccounting,
                ),
            ))
    }
    pub(super) fn bind(self, prepaid: &mut Credit) -> Result<JoinedCall> {
        let mut credit = prepaid.split(self.allocated_bytes()?)?;
        let output = self
            .output
            .map(|buffer| buffer.bind(&mut credit))
            .transpose()?;
        let fixed = FixedOutput::new_prepaid(&mut credit, self.plan.function, self.plan.capacity)?;
        Ok(JoinedCall {
            function: self.plan.function,
            name: name(self.plan.function)?,
            id: self.plan.id,
            output,
            fixed,
            result: Box::new(crate::native::output::async_data()),
            phase: JoinPhase::Prepared,
            return_value: CKR_PENDING,
            observed: None,
            return_diagnostic: Some(crate::error::CompletionStorage::allocate()?),
            _credit: credit,
        })
    }
}
