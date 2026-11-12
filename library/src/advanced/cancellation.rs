// SPDX-License-Identifier: Apache-2.0
//! Explicit native cancellation, with a separate retained control frame.

use super::{
    ownership, preparation, AdvancedSession, AdvancedSessionMode, Operation, OperationBody,
};
use crate::{
    module::{SessionEntry, State},
    symmetric::memory::Credit,
    Error, Result,
};
use fe11_sys::{
    CKF_DECAPSULATE, CKF_DECRYPT, CKF_DERIVE, CKF_DIGEST, CKF_ENCAPSULATE, CKF_ENCRYPT,
    CKF_FIND_OBJECTS, CKF_GENERATE, CKF_GENERATE_KEY_PAIR, CKF_MESSAGE_DECRYPT,
    CKF_MESSAGE_ENCRYPT, CKF_MESSAGE_SIGN, CKF_MESSAGE_VERIFY, CKF_SIGN, CKF_SIGN_RECOVER,
    CKF_UNWRAP, CKF_VERIFY, CKF_VERIFY_RECOVER, CKF_WRAP, CKR_OK, CKR_PENDING, CK_FLAGS, CK_RV,
};
use std::sync::atomic::Ordering;
const CATEGORIES: CK_FLAGS = CKF_FIND_OBJECTS
    | CKF_ENCRYPT
    | CKF_DECRYPT
    | CKF_DIGEST
    | CKF_SIGN
    | CKF_SIGN_RECOVER
    | CKF_VERIFY
    | CKF_VERIFY_RECOVER
    | CKF_GENERATE
    | CKF_GENERATE_KEY_PAIR
    | CKF_WRAP
    | CKF_UNWRAP
    | CKF_DERIVE
    | CKF_ENCAPSULATE
    | CKF_DECAPSULATE
    | CKF_MESSAGE_ENCRYPT
    | CKF_MESSAGE_DECRYPT
    | CKF_MESSAGE_SIGN
    | CKF_MESSAGE_VERIFY;
/// Explicit PKCS#11 operation categories, never mechanism capabilities such as
/// HW, MULTI_MESSAGE or EXTENSION. Zero is the normative no-op request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CancellationFlags(CK_FLAGS);
impl CancellationFlags {
    /// No operation is cancelled.
    pub const NONE: Self = Self(0);
    /// Cancel a digest.
    pub const DIGEST: Self = Self(CKF_DIGEST);
    /// Cancel a classic encryption operation or its dual half.
    pub const ENCRYPT: Self = Self(CKF_ENCRYPT);
    /// Cancel a classic decryption operation or its dual half.
    pub const DECRYPT: Self = Self(CKF_DECRYPT);
    /// Cancel a classic signature/MAC operation or its dual half.
    pub const SIGN: Self = Self(CKF_SIGN);
    /// Cancel a classic verification operation or its dual half.
    pub const VERIFY: Self = Self(CKF_VERIFY);
    /// Cancel message encryption.
    pub const MESSAGE_ENCRYPT: Self = Self(CKF_MESSAGE_ENCRYPT);
    /// Cancel message decryption.
    pub const MESSAGE_DECRYPT: Self = Self(CKF_MESSAGE_DECRYPT);
    /// Cancel message signing/MAC.
    pub const MESSAGE_SIGN: Self = Self(CKF_MESSAGE_SIGN);
    /// Cancel message verification.
    pub const MESSAGE_VERIFY: Self = Self(CKF_MESSAGE_VERIFY);
    /// Combine explicit categories in a single native cancellation request.
    /// A partial native failure does not identify which categories remain.
    pub fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
    /// Validate standard operation-category bits without dispatching.
    pub fn from_bits(bits: u64) -> Result<Self> {
        let native = CK_FLAGS::try_from(bits).map_err(|_| {
            Error::Rejected(crate::RejectionReason::Cancellation(
                crate::CancellationRejection::CancellationFlagRange,
            ))
        })?;
        if native & !CATEGORIES != 0 {
            return Err(Error::Rejected(crate::RejectionReason::Cancellation(
                crate::CancellationRejection::CancellationFlagCategory,
            )));
        }
        Ok(Self(native))
    }
    /// Exact standard bitset. This never reports native handles.
    pub fn bits(self) -> u64 {
        self.0 as u64
    }
}
/// Outcome of one explicit cancellation or one completion observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CancellationProgress {
    /// Native cancellation is pending; the original operation and the control
    /// retain their buffers. Observe with poll_cancellation, not a new cancel.
    Pending,
    /// The requested cancellation completed successfully.
    Complete {
        /// Tracked categories that may remain active. After a previous partial
        /// failure this is conservative, not a probe of the native session.
        remaining: CancellationFlags,
    },
}
/// The physical inline slot is charged once, for the shell's entire lifetime.
/// Taking a terminal control returns the slot to Available without returning
/// its credit; another explicit cancellation must not compete with its target.
pub(super) struct CancellationSlot {
    state: CancellationSlotState,
    _credit: Credit,
}
enum CancellationSlotState {
    Available,
    Submitted(CancelControl),
}
impl crate::symmetric::memory::RetainedStorage for CancellationSlot {
    fn retain_credits(&self, retained: &mut crate::symmetric::memory::RetainedBytes) -> Result<()> {
        // Cancellation control is inline and precredited even while available.
        crate::symmetric::memory::RetainedStorage::retain_credits(&self._credit, retained)
    }
}
impl CancellationSlot {
    pub(super) fn allocation_bytes() -> usize {
        std::mem::size_of::<Self>()
    }

    pub(super) fn from_prepaid(prepaid: &mut Credit) -> Result<Self> {
        Ok(Self {
            state: CancellationSlotState::Available,
            _credit: prepaid.split(Self::allocation_bytes())?,
        })
    }

    pub(super) fn is_submitted(&self) -> bool {
        matches!(self.state, CancellationSlotState::Submitted(_))
    }

    fn submit(&mut self, flags: CK_FLAGS) {
        debug_assert!(!self.is_submitted());
        self.state = CancellationSlotState::Submitted(CancelControl {
            flags,
            call: CancellationCall::Issued,
            name: *b"C_SessionCancel\0",
        });
    }

    pub(super) fn execution_incomplete(&self) -> bool {
        matches!(
            &self.state,
            CancellationSlotState::Submitted(CancelControl {
                call: CancellationCall::Issued | CancellationCall::Pending,
                ..
            })
        )
    }

    fn as_mut(&mut self) -> Option<&mut CancelControl> {
        match &mut self.state {
            CancellationSlotState::Available => None,
            CancellationSlotState::Submitted(control) => Some(control),
        }
    }

    fn take(&mut self) -> Option<CancelControl> {
        match std::mem::replace(&mut self.state, CancellationSlotState::Available) {
            CancellationSlotState::Available => None,
            CancellationSlotState::Submitted(control) => Some(control),
        }
    }
}
pub(super) struct CancelControl {
    flags: CK_FLAGS,
    call: CancellationCall,
    // Retained native asynchronous mode defensive storage; no native asynchronous API is enabled.
    name: [u8; 16],
}

#[derive(Clone, Copy)]
enum CancellationCall {
    Issued,
    Pending,
    Returned(CK_RV),
}

impl CancelControl {
    fn record_return(&mut self, rv: CK_RV) {
        self.call = if rv == CKR_PENDING {
            CancellationCall::Pending
        } else {
            CancellationCall::Returned(rv)
        };
    }
}
impl AdvancedSession {
    /// Cancel exactly the specified native categories. The call does not retry
    /// and never substitutes CloseSession. A cancelled dual half prevents any
    /// further result publication; remaining native state needs explicit cleanup.
    pub fn cancel(&self, flags: CancellationFlags) -> Result<CancellationProgress> {
        let mut retired = None;
        let _retired_anchor;
        let mut prepared: Option<preparation::Shell> = None;
        let (s, operation, installed, call) = loop {
            let s = self.session.advanced_access()?;
            let call = s
                .native
                .messages
                .and_then(|f| f.cancel)
                .ok_or(Error::Rejected(crate::RejectionReason::Cancellation(
                    crate::CancellationRejection::CSessionCancelUnavailable,
                )))?;
            if self
                .session
                .entry
                .advanced_operation
                .load(Ordering::Acquire)
                != 0
            {
                let operation = s.operations.get(self.session.uid)?;
                break (s, operation, false, call);
            }
            if let Some(slot) = prepared.take() {
                let (token, cancel) = slot.bind(&s.lease_admission()?)?;
                let (_, operation) = s.operations.install(
                    &self.session.entry,
                    Operation::new(OperationBody::Control, token, cancel),
                )?;
                break (s, operation, true, call);
            }
            // Resource waiting must not retain the gates required by the owner
            // which may appear while this inactive cancellation is preparing.
            drop(s);
            match preparation::reserve_cancellation(
                &self.session,
                preparation::Shell::allocation_bytes(),
            )? {
                preparation::CancellationPreparation::New(mut credit) => {
                    prepared = Some(preparation::Shell::from_prepaid(&mut credit)?);
                }
                preparation::CancellationPreparation::UseCurrent => {}
            }
        };
        // Keep diagnostic credit alive until the public return, even if local
        // rollback removes the ledger entry and drops its returned owner.
        _retired_anchor = operation.clone();
        // An owner may have appeared after credit admission. Its resident slot
        // is used; the unused preparation has no native references.
        drop(prepared);
        let mut op = operation.lock().map_err(|_| Error::Poisoned)?;
        if op.rejoin().is_some() {
            return Err(Error::Busy(crate::BusyReason::Cancellation(
                crate::CancellationBusy::OperationRejoinControl,
            )));
        }
        if op.detachment().is_some() {
            return Err(Error::Busy(crate::BusyReason::Cancellation(
                crate::CancellationBusy::OperationDetachmentControl,
            )));
        }
        if op.restore_owner().is_some() {
            return Err(Error::Busy(crate::BusyReason::Cancellation(
                crate::CancellationBusy::StateRestorationActive,
            )));
        }
        if op.cancel.is_submitted() {
            return Err(Error::Busy(crate::BusyReason::Cancellation(
                crate::CancellationBusy::CancellationPending,
            )));
        }
        if let Err(error) = s
            .operations
            .claim_progress(&self.session.entry, op.id)
            .and_then(|_| s.native.record("C_SessionCancel"))
        {
            if installed {
                let diagnostic = op.prepare_retirement(error).map_err(|error| {
                    self.session.entry.poisoned.store(true, Ordering::Release);
                    error
                })?;
                drop(op);
                let cleanup = match s.operations.take_closed(&self.session.entry) {
                    Ok(owner) => {
                        retired = owner;
                        None
                    }
                    Err(error) => Some(error),
                };
                if cleanup.is_some() {
                    // A local rollback could not be proved. Retain the ledger
                    // owner and both causes; no native completion is inferred.
                    self.session.entry.poisoned.store(true, Ordering::Release);
                }
                let failure = diagnostic.finish_sequence(cleanup);
                drop(s);
                drop(retired);
                return Err(failure);
            }
            return Err(error);
        }
        // No fallible local step separates submission from the native call.
        let pending_parent = op.execution_incomplete();
        op.cancel.submit(flags.0);
        // SAFETY: session ownership and separate control are installed; arguments
        // are native scalar values and the target's allocations remain retained.
        let rv = unsafe { call(self.session.entry.handle, flags.0) };
        if pending_parent {
            s.native.observe_async_return(rv);
        } else {
            s.native.observe_runtime_return(rv);
        }
        crate::native_return::protocol::PendingInspection::returned("C_SessionCancel", rv, |_| {
            if rv != CKR_PENDING {
                s.apply_session_failure(
                    &self.session.entry,
                    rv,
                    crate::native_return::failure_scope(rv),
                );
            }
        })
        // This call has scalar operands and no native-addressable result.
        .inspect(|| Ok(()))
        .resolve(|_, cause| cause)?;
        op.cancel.as_mut().unwrap().record_return(rv);
        if rv == CKR_PENDING {
            if self.mode() != AdvancedSessionMode::Asynchronous {
                s.native.mark_uncertain();
                return Err(Error::Native {
                    function: "C_SessionCancel",
                    code: rv as u64,
                    may_have_effect: true,
                });
            }
            return Ok(CancellationProgress::Pending);
        }
        let memory_returned = if pending_parent {
            crate::native_return::async_memory_returned(rv as u64)
        } else {
            crate::native_return::call_memory_returned(rv)
        };
        finish_and_retire(
            &s,
            &self.session.entry,
            &mut op,
            rv,
            memory_returned,
            &mut retired,
        )
    }
    /// Observe one pending C_SessionCancel. This cannot reissue that function,
    /// complete the original operation or publish its output.
    pub fn poll_cancellation(&self) -> Result<CancellationProgress> {
        let mut retired = None;
        let operation;
        let s = self.session.advanced_access()?;
        operation = s.operations.get(self.session.uid)?;
        let mut op = operation.lock().map_err(|_| Error::Poisoned)?;
        let id = op.id;
        let control =
            op.cancel
                .as_mut()
                .ok_or(Error::Rejected(crate::RejectionReason::Cancellation(
                    crate::CancellationRejection::CancellationAbsent,
                )))?;
        if !matches!(control.call, CancellationCall::Pending) {
            return Err(Error::Rejected(crate::RejectionReason::Cancellation(
                crate::CancellationRejection::CancellationNotPending,
            )));
        }
        let call = s
            .native
            .asynchronous
            .and_then(|f| f.complete)
            .ok_or(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::CAsyncCompleteUnavailable,
            )))?;
        s.operations.claim_progress(&self.session.entry, id)?;
        s.native.record("C_AsyncComplete")?;
        control.call = CancellationCall::Issued;
        // SAFETY: name lives in the installed control. Cancellation has no
        // output parameters; pResult is null by the normative completion ABI.
        let rv = unsafe {
            call(
                self.session.entry.handle,
                control.name.as_mut_ptr(),
                std::ptr::null_mut(),
            )
        };
        control.record_return(rv);
        crate::native_return::protocol::PendingInspection::completed("C_SessionCancel", rv, |_| {
            s.native.observe_async_return(rv);
            if rv != CKR_PENDING {
                s.apply_session_failure(
                    &self.session.entry,
                    rv,
                    crate::native_return::failure_scope(rv),
                );
            }
        })
        // Cancellation passes a NULL result by its own completion contract.
        .inspect(|| Ok(()))
        .resolve(|_, cause| cause)?;
        if rv == CKR_PENDING {
            return Ok(CancellationProgress::Pending);
        }
        finish_and_retire(
            &s,
            &self.session.entry,
            &mut op,
            rv,
            crate::native_return::async_memory_returned(rv as u64),
            &mut retired,
        )
    }
}

/// A returned refusal can retire an otherwise empty control shell. Preserve the
/// native error, including a separate cleanup failure, and move the last ledger
/// owner to a scope outside all access guards before its destructor can run.
fn finish_and_retire(
    s: &State,
    entry: &SessionEntry,
    op: &mut Operation,
    rv: CK_RV,
    memory_returned: bool,
    retired: &mut Option<super::ledger::ClosedOperation>,
) -> Result<CancellationProgress> {
    let result = finish(s, op, rv, memory_returned);
    let release = match &result {
        Ok((_, release)) => *release,
        Err(_) => {
            memory_returned
                && !s.native.is_uncertain()
                && matches!(op.body, OperationBody::Control)
                && !op.execution_incomplete()
                && !op.uncancellable_retained()
                && op.state.as_ref().is_none()
                && op.transfer.as_ref().is_none()
                && op.joined.is_none()
        }
    };
    if !release {
        return result.map(|(progress, _)| progress);
    }
    match result {
        Ok((progress, _)) => {
            *retired = s.operations.take_closed(entry)?;
            Ok(progress)
        }
        Err(error) => {
            let diagnostic = op.prepare_retirement(error).map_err(|error| {
                entry.poisoned.store(true, Ordering::Release);
                error
            })?;
            let cleanup = match s.operations.take_closed(entry) {
                Ok(owner) => {
                    *retired = owner;
                    None
                }
                Err(error) => {
                    entry.poisoned.store(true, Ordering::Release);
                    Some(error)
                }
            };
            Err(diagnostic.finish_sequence(cleanup))
        }
    }
}
fn finish(
    s: &State,
    op: &mut Operation,
    rv: CK_RV,
    memory_returned: bool,
) -> Result<(CancellationProgress, bool)> {
    let observed =
        op.cancel
            .as_mut()
            .ok_or(Error::Rejected(crate::RejectionReason::Cancellation(
                crate::CancellationRejection::CancellationControlAbsent,
            )))?;
    if !matches!(observed.call, CancellationCall::Returned(code) if code == rv) {
        return Err(Error::Rejected(crate::RejectionReason::Cancellation(
            crate::CancellationRejection::CancellationReturnUnproven,
        )));
    }
    if !memory_returned {
        // In particular GENERAL_ERROR does not authorize moving/destroying the
        // control whose name storage may have been borrowed by AsyncComplete.
        op.cancellation = ownership::CancellationState::Withdrawn {
            remaining: op.active_categories(),
        };
        s.native.mark_uncertain();
        return Err(Error::Native {
            function: "C_SessionCancel",
            code: rv as u64,
            may_have_effect: true,
        });
    }
    let control = op
        .cancel
        .take()
        .ok_or(Error::Rejected(crate::RejectionReason::Cancellation(
            crate::CancellationRejection::CancellationControlAbsent,
        )))?;
    let active = op.active_categories();
    if rv != CKR_OK {
        // A failed multi-category cancel provides no map of partial effects.
        // Keep all original frames/leases and forbid their result publication.
        op.cancellation = ownership::CancellationState::Withdrawn { remaining: active };
        return Err(Error::Native {
            function: "C_SessionCancel",
            code: rv as u64,
            may_have_effect: true,
        });
    }
    let remaining = active & !control.flags;
    if active & control.flags != 0 {
        op.cancellation = ownership::CancellationState::Withdrawn { remaining };
    }
    let release = (matches!(op.body, OperationBody::Control)
        || op.cancellation.is_withdrawn() && remaining == 0)
        && !op.uncancellable_retained()
        && op.joined.is_none()
        && op.transfer.as_ref().is_none();
    Ok((
        CancellationProgress::Complete {
            remaining: CancellationFlags(remaining),
        },
        release,
    ))
}
