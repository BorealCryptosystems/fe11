// SPDX-License-Identifier: Apache-2.0
//! Shared operation identity, retained control owners and family dispatch.
//! Family storage and transitions stay in their respective modules.
use super::{
    admission, asynchronous, cancellation, cipher, drive_digest, dual, gcm, messages, ownership,
    recover, signature, spend, validation, AdvancedSessionMode, DigestOperation, StateProvenance,
    Step, TokenLease,
};
use crate::module::{SessionEntry, State};
use crate::{Error, Result};
use fe11_sys::{CKF_DIGEST, CK_FLAGS};
use std::sync::atomic::Ordering;
mod replacement;
pub(super) use replacement::SignatureReplacement;

// Native ownership is distinct from the next logical phase. Owners arm it
// before entering C and retain it on any unproven or uncertain completion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum NativeActivity {
    Inactive,
    Active,
    Pending,
    Closed,
    // Only this non-NULL Init attempt was refused and its memory returned.
    // This is not proof of the native session's inactivity or absence of effect.
    InitializationRefused,
}
impl NativeActivity {
    pub(super) fn restored(pending: bool) -> Self {
        if pending {
            Self::Pending
        } else {
            Self::Active
        }
    }
    pub(super) fn inactive(self) -> bool {
        matches!(self, Self::Inactive | Self::Closed)
    }
    pub(super) fn pending(self) -> bool {
        self == Self::Pending
    }
    pub(super) fn locally_retirable(self) -> bool {
        self.inactive() || self == Self::InitializationRefused
    }
}

pub(super) struct Operation {
    pub(super) provenance: Option<StateProvenance>,
    pub(super) id: u64,
    pub(super) body: OperationBody,
    pub(super) cancel: cancellation::CancellationSlot,
    retirement: crate::error::PreparedCleanupDiagnostic,
    pub(super) cancellation: ownership::CancellationState,
    pub(super) continuation_status: ownership::ContinuationStatus,
    pub(super) validation: Option<validation::Capture>,
    pub(super) state: ownership::OwnerSlot<ownership::StateControl>,
    pub(super) joined: Option<asynchronous::JoinedCall>,
    pub(super) transfer: ownership::OwnerSlot<ownership::TransferOwner>,
    // Rust drops fields in declaration order. The population must remain
    // occupied until every native/control frame and retained resource above
    // has been destroyed, including extraction followed by collective close.
    // Keep this last even if initialization order or body ownership changes.
    pub(super) _token: TokenLease,
}
impl Operation {
    /// Check a contextual login before releasing possession to await capacity.
    /// Control owners are excluded by check_context_authentication before this
    /// call. The visitor holds only immutable borrows and never waits itself.
    pub(super) fn check_authentication_budget(
        &self,
        cell: &super::ledger::OperationCell,
        budget: &std::sync::Arc<crate::symmetric::memory::Budget>,
        additional: usize,
    ) -> Result<()> {
        use crate::symmetric::memory::{RetainedBytes, RetainedStorage};
        if let OperationBody::Admission(owner) = &self.body {
            // Admission attributes its payload, shell and cell to one child
            // account. Only its poll error envelope was split off globally.
            let outside = RetainedBytes::measure(budget, |retained| {
                owner.resource_diagnostics.retain_credits(retained)
            })?;
            return outside.check_with_account(owner.resource_budget(), additional);
        }
        let retained = RetainedBytes::measure(budget, |retained| {
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
                    return Err(Error::Rejected(crate::RejectionReason::Authentication(
                        crate::AuthenticationRejection::ContextAuthenticationRequiresInitializedOperation,
                    )));
                }
            }
            self.validation.retain_credits(retained)?;
            self.cancel.retain_credits(retained)?;
            self.retirement.retain_credits(retained)?;
            self._token.retain_credits(retained)?;
            cell.retain_storage(retained)
        })?;
        retained.check(budget, additional)
    }

    pub(super) fn new(
        body: OperationBody,
        token: TokenLease,
        control: super::preparation::PreparedControl,
    ) -> Self {
        Self {
            provenance: None,
            id: 0,
            body,
            _token: token,
            cancel: control.cancellation,
            retirement: control.retirement,
            cancellation: ownership::CancellationState::Uncancelled,
            continuation_status: ownership::ContinuationStatus::Runnable,
            validation: None,
            state: ownership::OwnerSlot::default(),
            joined: None,
            transfer: ownership::OwnerSlot::default(),
        }
    }
    pub(super) fn with_validation(mut self, capture: Option<validation::Capture>) -> Self {
        self.validation = capture;
        self
    }
    pub(super) fn validation_pending(&self) -> bool {
        self.validation.as_ref().is_some_and(|c| c.pending())
    }
    pub(super) fn joined_capacity(&self) -> Result<Option<usize>> {
        if self.cancellation.is_withdrawn()
            || self.continuation_status.is_frozen()
            || self.cancel.is_submitted()
        {
            return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::JoinedCryptographicOwnerUnavailable,
            )));
        }
        if let Some(control) = self.state_io() {
            return control.joined_capacity();
        }
        if self.validation_pending() {
            return self.validation.as_ref().unwrap().joined_capacity();
        }
        match &self.body {
            OperationBody::Digest(body) => body.joined_capacity(),
            OperationBody::Messages(body) => body.joined_capacity(),
            OperationBody::AeadMessages(body) => body.joined_capacity(),
            OperationBody::Dual(body) => body.joined_capacity(),
            OperationBody::Admission(body) => body.joined_capacity(),
            _ => Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::JoinedResultRequiresItsSpecificOwner,
            ))),
        }
    }
    pub(super) fn accept_joined(
        &mut self,
        s: &State,
        entry: &SessionEntry,
        result: asynchronous::JoinedResult,
    ) -> Result<()> {
        self.joined_capacity()?;
        if let Some(control) = self.state_io_mut() {
            return control.accept_joined(s, entry, result);
        }
        if self.validation_pending() {
            return self
                .validation
                .as_mut()
                .unwrap()
                .accept_joined(s, entry, result);
        }
        let point = self.body.validation_point()?;
        match &mut self.body {
            OperationBody::Digest(body) => body.accept_joined(s, entry, result)?,
            OperationBody::Messages(body) => body.accept_joined(s, entry, result)?,
            OperationBody::AeadMessages(body) => body.accept_joined(s, entry, result)?,
            OperationBody::Dual(body) => body.accept_joined(s, entry, result)?,
            OperationBody::Admission(body) => body.accept_joined(s, entry, result)?,
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                    crate::OperationOwnershipRejection::JoinedResultRequiresItsSpecificOwner,
                )))
            }
        }
        let point = point.filter(|_| match &self.body {
            OperationBody::Messages(body) => body.observation_allowed(),
            OperationBody::NativeMessages(body) => body.observation_allowed(),
            _ => true,
        });
        if let (Some(capture), Some(point)) = (&mut self.validation, point) {
            capture.queue(point)?;
        }
        Ok(())
    }
    // Called only after destination identity/key binding and installation of
    // this operation in the ledger. Even a failed native attachment remains
    // represented here, preventing accidental polling of the original frame.
    pub(super) fn attach_join(
        &mut self,
        s: &State,
        entry: &SessionEntry,
        call: asynchronous::JoinedCall,
    ) -> Result<()> {
        if self.joined.is_some() {
            return Err(Error::Busy(crate::BusyReason::OperationOwnership(
                crate::OperationOwnershipBusy::AsynchronousJoinControl,
            )));
        }
        if entry.mode != AdvancedSessionMode::Asynchronous {
            return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::AsynchronousJoinSessionMode,
            )));
        }
        let capacity = self.joined_capacity()?;
        call.check_prepared(asynchronous::pending_function(self)?, capacity)?;
        self.joined = Some(call);
        self.joined.as_mut().unwrap().attach(s, entry)
    }
    // Keep the consumed control installed on projection/validation failure.
    // Another observation must not reuse either the result or original frame.
    pub(super) fn drive_join(
        &mut self,
        s: &State,
        entry: &SessionEntry,
        observe: bool,
        remaining: &mut usize,
    ) -> Result<bool> {
        let Some(call) = &mut self.joined else {
            return Ok(true);
        };
        if !observe || !spend(remaining) {
            return Ok(false);
        }
        if !call.poll(s, entry)? {
            return Ok(false);
        }
        let result = call.take()?;
        self.accept_joined(s, entry, result)?;
        self.joined.take();
        Ok(true)
    }
    pub(super) fn check_authentication(&self, entry: &SessionEntry) -> Result<()> {
        // Capture/transfer evidence must retain its original local context.
        // A stale observation does not poison the still-possessed native work.
        entry
            .snapshot
            .check_authentication_unchanged(self._token.authentication)
    }
    /// A continuation submits a native request, not a claim that an earlier
    /// login still authorizes it. Captures retain their own evidence bindings;
    /// this check neither transfers ownership nor rewrites a saved epoch.
    pub(super) fn check_continuation_authentication(&self, entry: &SessionEntry) -> Result<()> {
        match &self.body {
            OperationBody::Signature(body) => body.check_key(entry),
            _ => entry.snapshot.check(),
        }
    }
    pub(super) fn uncancellable_pending(&self) -> bool {
        self.detachment().is_some_and(|c| c.inspection_pending())
            || self.rejoin().is_some_and(|c| c.inspection_pending())
            || self.state_io().is_some_and(|c| c.pending())
            || self.validation_pending()
            || matches!(&self.body,OperationBody::Admission(a) if a.pending()&&a.active_categories()==0)
    }
    // A returned observation anomaly is no longer executing, but its native
    // memory cannot be retired by crypto cancellation or local error cleanup.
    pub(super) fn uncancellable_retained(&self) -> bool {
        self.uncancellable_pending()
            || self
                .validation
                .as_ref()
                .is_some_and(|capture| capture.retains_native_memory())
    }
    /// A transfer can retain a pending GetID/Join independently of its inspection
    /// and the crypto body. Finalization must inspect every simultaneous owner.
    pub(super) fn execution_incomplete(&self) -> bool {
        let transfer_pending = match self.transfer.as_ref() {
            Some(ownership::TransferOwner::Detaching(control)) => control.execution_incomplete(),
            Some(ownership::TransferOwner::Rejoining(control)) => control.execution_incomplete(),
            Some(ownership::TransferOwner::Restoring(control)) => control.execution_incomplete(),
            None => false,
        };
        self.body.pending()
            || self.uncancellable_pending()
            || self.cancel.execution_incomplete()
            || self
                .joined
                .as_ref()
                .is_some_and(|join| join.execution_incomplete())
            || transfer_pending
    }
    pub(super) fn active_categories(&self) -> CK_FLAGS {
        if let Some(remaining) = self.cancellation.remaining() {
            return remaining;
        }
        match &self.body {
            OperationBody::Control => 0,
            OperationBody::Admission(body) => body.active_categories(),
            OperationBody::Digest(body) => {
                if body.activity.locally_retirable() {
                    0
                } else {
                    CKF_DIGEST
                }
            }
            OperationBody::Messages(body) => body.active_categories(),
            OperationBody::NativeMessages(body) => body.active_categories(),
            OperationBody::AeadMessages(body) => body.active_categories(),
            OperationBody::Dual(body) => body.active_categories(),
            OperationBody::Recover(body) => body.active_categories(),
            OperationBody::Cipher(body) => body.active_categories(),
            OperationBody::Signature(body) => body.active_categories(),
        }
    }
    pub(super) fn terminal_retirable(&self) -> bool {
        let inactive = match &self.body {
            OperationBody::Admission(body) => !body.native_started(),
            OperationBody::Digest(body) => body.activity.locally_retirable(),
            OperationBody::AeadMessages(body) => {
                body.native_inactive() || body.initialization_refused()
            }
            OperationBody::Messages(body) => {
                body.native_inactive() || body.initialization_refused()
            }
            OperationBody::NativeMessages(body) => {
                body.native_inactive() || body.initialization_refused()
            }
            OperationBody::Dual(body) => body.native_inactive(),
            OperationBody::Recover(body) => body.native_inactive() || body.initialization_refused(),
            OperationBody::Cipher(body) => body.native_inactive() || body.initialization_refused(),
            OperationBody::Signature(body) => {
                body.native_inactive() || body.initialization_refused()
            }
            _ => false,
        };
        inactive
            && !self.body.pending()
            && !self.uncancellable_retained()
            && !self.cancel.is_submitted()
            && self.joined.is_none()
            && self.transfer.as_ref().is_none()
            && self.state.as_ref().is_none()
    }

    /// One terminal retirement consumes the prepaid leaves. Successful removal
    /// makes the operation unreachable; failed removal poisons its session, so
    /// a later ordinary admission cannot attempt this stage again. Do not reuse
    /// it for cancellation refusals that retain a live non-Control operation.
    pub(super) fn prepare_retirement(
        &mut self,
        error: Error,
    ) -> Result<crate::error::CleanupDiagnostic> {
        if matches!(error.without_object_marker(), Error::CleanupFailed { .. }) {
            return Err(error);
        }
        Ok(self.retirement.take(error))
    }

    // Called with the operation and session locked. A body-local closure proof
    // is insufficient while any observation/transfer still owns native memory.
    pub(super) fn retire_terminal_error(
        &mut self,
        s: &State,
        entry: &SessionEntry,
        error: Error,
    ) -> (Error, bool) {
        if self.terminal_retirable() {
            let diagnostic = match self.prepare_retirement(error) {
                Ok(diagnostic) => diagnostic,
                Err(error) => return (error, false),
            };
            if let Err(cleanup) = s.operations.release_closed(entry) {
                entry.poisoned.store(true, Ordering::Release);
                return (diagnostic.finish_sequence(Some(cleanup)), false);
            }
            return (diagnostic.finish_sequence(None), true);
        }
        (error, false)
    }
}
pub(super) enum OperationBody {
    Control,
    Admission(admission::Admission),
    Digest(DigestOperation),
    Messages(messages::MacOperation),
    NativeMessages(super::native_messages::NativeMessageOperation),
    AeadMessages(gcm::AeadMessageOperation),
    Dual(dual::DualOperation),
    Recover(recover::RecoverOperation),
    Cipher(cipher::CipherOperation),
    Signature(signature::SignatureOperation),
}

impl OperationBody {
    pub(super) fn complete(&self) -> bool {
        match self {
            Self::Control => false,
            Self::Digest(d) => d.step == Step::Complete,
            Self::Admission(d) => d.complete(),
            Self::Messages(d) => d.complete(),
            Self::NativeMessages(d) => d.complete(),
            Self::AeadMessages(d) => d.complete(),
            Self::Dual(d) => d.complete(),
            Self::Recover(d) => d.complete(),
            Self::Cipher(d) => d.complete(),
            Self::Signature(d) => d.complete(),
        }
    }
    pub(super) fn pending(&self) -> bool {
        match self {
            Self::Control => false,
            Self::Digest(d) => d.activity.pending(),
            Self::Admission(d) => d.pending(),
            Self::Messages(d) => d.pending(),
            Self::NativeMessages(d) => d.pending(),
            Self::AeadMessages(d) => d.pending(),
            Self::Dual(d) => d.pending(),
            Self::Recover(d) => d.pending(),
            Self::Cipher(d) => d.pending(),
            Self::Signature(d) => d.pending(),
        }
    }
    pub(super) fn message_count(&self) -> usize {
        match self {
            Self::Messages(body) => body.message_count(),
            Self::NativeMessages(body) => body.message_count(),
            Self::AeadMessages(body) => body.message_count(),
            _ => 0,
        }
    }
    pub(super) fn validation_point(&self) -> Result<Option<validation::Point>> {
        match self {
            Self::Digest(d) if matches!(d.step, Step::Single | Step::Final) => {
                Ok(Some(validation::Point {
                    function: d.frame.selection.terminal_function(),
                    message_index: None,
                }))
            }
            Self::Digest(_) | Self::Control | Self::Admission(_) => Ok(None),
            Self::Messages(d) => d.validation_point(),
            Self::NativeMessages(d) => d.validation_point(),
            Self::AeadMessages(d) => d.validation_point(),
            Self::Dual(d) => d.validation_point(),
            Self::Recover(d) => Ok(d.validation_point()),
            Self::Cipher(d) => Ok(d.validation_point()),
            Self::Signature(d) => Ok(d.validation_point()),
        }
    }
}
pub(super) fn drive(
    s: &State,
    entry: &SessionEntry,
    op: &mut Operation,
    observe: bool,
    remaining: &mut usize,
) -> Result<()> {
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
    if op.state_io().is_some() {
        return Err(Error::Busy(crate::BusyReason::OperationOwnership(
            crate::OperationOwnershipBusy::OperationStateControl,
        )));
    }
    if op.continuation_status.is_frozen() {
        return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
            crate::OperationOwnershipRejection::OperationContinuationTransferred,
        )));
    }
    if op.cancel.is_submitted() {
        return Err(Error::Busy(crate::BusyReason::Cancellation(
            crate::CancellationBusy::CancellationPending,
        )));
    }
    if op.cancellation.is_withdrawn() {
        return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
            crate::OperationOwnershipRejection::CancelledOperationCannotContinue,
        )));
    }
    op.check_continuation_authentication(entry)?;
    if !op.drive_join(s, entry, observe, remaining)? {
        return Ok(());
    }
    let Some(capture) = op.validation.as_mut() else {
        return drive_body(s, entry, &mut op.body, observe, remaining);
    };
    loop {
        if let Err(error) = capture.drive(s, entry, observe, remaining) {
            if validation::completed_read_refusal(&error)
                && op.body.complete()
                && !op.body.pending()
                && !capture.pending()
                && op.joined.is_none()
            {
                // The failed observation has no native owner left. Withhold the
                // requested result/report, but make the healthy session reusable.
                // Our caller still owns the Arc and session guard, so removing
                // the registry entry cannot drop or race this locked operation.
                s.operations.release_closed(entry)?;
            }
            // Between messages the native operation is still active: retain it
            // for explicit cancellation/close rather than silently skipping flags.
            return Err(error);
        }
        if capture.waiting() || op.body.complete() || *remaining == 0 {
            return Ok(());
        }
        let point = op.body.validation_point()?;
        // Interpose only for requested observations. Default eager execution
        // retains its existing driver and no validation allocations/calls.
        let mut one = 1;
        drive_body(s, entry, &mut op.body, observe, &mut one)?;
        *remaining -= 1 - one;
        if op.body.pending() || one == 1 {
            return Ok(());
        }
        // A failed message may have scheduled Final rather than completed
        // successfully. Never attach a successful validation point to it.
        let successful = match &op.body {
            OperationBody::AeadMessages(body) => body.nominal(),
            OperationBody::Messages(body) => body.observation_allowed(),
            OperationBody::NativeMessages(body) => body.observation_allowed(),
            OperationBody::Recover(body) => body.complete(),
            OperationBody::Cipher(body) => body.complete(),
            OperationBody::Signature(body) => body.complete(),
            _ => true,
        };
        if let Some(point) = point.filter(|_| successful) {
            capture.queue(point)?;
        }
    }
}
pub(super) fn drive_body(
    s: &State,
    entry: &SessionEntry,
    body: &mut OperationBody,
    observe: bool,
    remaining: &mut usize,
) -> Result<()> {
    match body {
        OperationBody::Control => Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
            crate::OperationOwnershipRejection::ControlHasNoCryptographicResult,
        ))),
        OperationBody::Admission(body) => body.drive(s, entry, observe, remaining),
        OperationBody::Digest(body) => drive_digest(s, entry, body, observe, remaining),
        OperationBody::Messages(body) => body.drive(s, entry, observe, remaining),
        OperationBody::NativeMessages(body) => body.drive(s, entry, remaining),
        OperationBody::AeadMessages(body) => body.drive(s, entry, observe, remaining),
        OperationBody::Dual(body) => body.drive(s, entry, observe, remaining),
        OperationBody::Recover(body) => body.drive(s, entry, remaining),
        OperationBody::Cipher(body) => body.drive(s, entry, remaining),
        OperationBody::Signature(body) => body.drive(s, entry, remaining),
    }
}
