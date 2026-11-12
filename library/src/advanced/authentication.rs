// SPDX-License-Identifier: Apache-2.0
//! Explicit re-authentication of a retained, initialized native operation.
use super::{function, AdvancedSession, Operation, OperationBody, OperationTicket};

use crate::module::SessionEntry;
use crate::{Error, Result, Session};

use std::sync::Arc;

impl AdvancedSession {
    /// Inspect the next native function of a retained cooperative operation.
    /// This performs no native call and exposes no handles, parameters or PIN.
    /// A pending native call or concurrent operation control returns Busy.
    /// None means the retained body has no next function; poll still owns result
    /// publication. Local acceptance can also have no next native function yet;
    /// polling completes that work before selecting any subsequent native step.
    /// This snapshot does not reserve the phase after return or
    /// assert that the active key requires or accepts contextual authentication.
    pub fn next_native_function(&self, ticket: &OperationTicket) -> Result<Option<&'static str>> {
        if !Arc::ptr_eq(&ticket.owner, &self.session.inner)
            || ticket.uid != self.session.uid
            || ticket.id == 0
        {
            return Err(Error::Rejected(crate::RejectionReason::Authentication(
                crate::AuthenticationRejection::ForeignOrConsumedOperationTicket,
            )));
        }
        let access = self.session.advanced_access()?;
        let operation = access.operations.get(self.session.uid)?;
        let operation = operation.lock().map_err(|_| Error::Poisoned)?;
        if operation.id != ticket.id {
            return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::StaleOperationTicket,
            )));
        }
        operation.check_control_access(&self.session.entry)?;
        if operation.body.complete() {
            return Ok(None);
        }
        let function = match &operation.body {
            OperationBody::Control => return Ok(None),
            OperationBody::Digest(body) => function(body.step)?,
            OperationBody::Admission(body) => return body.next_function(),
            OperationBody::Messages(body) => return body.next_function(),
            OperationBody::NativeMessages(body) => return Ok(body.next_function()),
            OperationBody::AeadMessages(body) => return body.next_function(),
            OperationBody::Recover(body) => return Ok(body.next_function()),
            OperationBody::Signature(body) => return Ok(body.next_function()),
            OperationBody::Cipher(body) => return Ok(body.next_function()),
            OperationBody::Dual(body) => body.function()?,
        };
        Ok(Some(function))
    }

    /// Re-authenticate the active key with C_Login(CKU_CONTEXT_SPECIFIC).
    ///
    /// Select Cooperative pacing before starting the operation, then call this
    /// immediately after its key-using Init and before polling its next step.
    /// The ticket, mechanism, buffers and key permissions remain owned. This
    /// method performs neither Init nor a cryptographic step, and does not
    /// change the token's USER/SO role on success.
    ///
    /// A PIN refusal is returned unchanged; another attempt requires another
    /// explicit call. ProtectedPath passes NULL, whereas Provided(empty) does
    /// not. PIN_LOCKED has the token-wide logout effect specified for context
    /// authentication. Live continuations retain their owners and can issue
    /// their next native call, whose authorization is decided by the module.
    /// Captures keep their original authentication provenance; a later login
    /// does not make a stale captured observation current again.
    pub fn login_context(
        &self,
        ticket: &OperationTicket,
        pin: impl Into<crate::PinRequest>,
    ) -> Result<()> {
        self.authenticate_context(ticket, crate::ContextAuthentication::login(pin))
    }

    /// Use C_LoginUser with an explicit owned user name for the same retained
    /// contextual operation. The selected interface must expose that function;
    /// its absence/refusal never falls back to C_Login. An empty name remains
    /// a provided, non-NULL value, distinct from selecting ordinary C_Login.
    pub fn login_context_user(
        &self,
        ticket: &OperationTicket,
        pin: impl Into<crate::PinRequest>,
        user_name: Vec<u8>,
    ) -> Result<()> {
        self.authenticate_context(
            ticket,
            crate::ContextAuthentication::login_user(pin, user_name),
        )
    }

    /// Authenticate one retained initialized operation using an owned request.
    /// Its PIN/name are erased on ordinary release, including ticket refusal.
    /// Cooperative pacing leaves the owner available between Init and use.
    pub fn authenticate_context(
        &self,
        ticket: &OperationTicket,
        authentication: crate::ContextAuthentication,
    ) -> Result<()> {
        self.session.authenticate_context(ticket, authentication)
    }
}

impl Session {
    /// Authenticate a retained initialized operation before its key-use call.
    /// The owned PIN and user name are erased on release, including refusal.
    pub fn authenticate_context(
        &self,
        ticket: &OperationTicket,
        authentication: crate::ContextAuthentication,
    ) -> Result<()> {
        let completed = self.authenticate_context_with_budget(
            ticket,
            authentication,
            &self.inner.symmetric_budget,
        )?;
        completed.result
    }

    // A synchronous facade can retain both its operation and publication
    // diagnostics. Its descendant account must cover this additional login;
    // otherwise WaitUntil could wait on credits held by the same facade.
    pub(crate) fn authenticate_context_with_budget(
        &self,
        ticket: &OperationTicket,
        authentication: crate::ContextAuthentication,
        budget: &Arc<crate::symmetric::memory::Budget>,
    ) -> Result<crate::session::ContextLoginOutcome> {
        let prepared_authentication;
        let mut authentication = Some(authentication);
        if !Arc::ptr_eq(&ticket.owner, &self.inner) || ticket.uid != self.uid || ticket.id == 0 {
            return Err(Error::Rejected(crate::RejectionReason::Authentication(
                crate::AuthenticationRejection::ForeignOrConsumedOperationTicket,
            )));
        }
        let progress = crate::session::AdmissionProgress::default();
        let mut plan = crate::session::ContextLoginPlan::new(self, authentication.as_ref())?;
        let (mut storage, access) =
            plan.prepare_retained(self, ticket.id, &progress, budget, |access, additional| {
                let cell = access.operations.get(ticket.uid)?;
                let operation = cell.lock().map_err(|_| Error::Poisoned)?;
                if operation.id != ticket.id {
                    return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                        crate::OperationOwnershipRejection::StaleOperationTicket,
                    )));
                }
                operation.check_context_authentication(&self.entry)?;
                if additional != 0 && Arc::ptr_eq(budget, &self.inner.symmetric_budget) {
                    operation.check_authentication_budget(&cell, budget, additional)?;
                }
                // Facade child accounts already include their complete retained
                // candidate; reserve_controlled_retaining checks those directly.
                // Capture under the same possession as the footprint measurement.
                self.entry.advanced_progress.observe_revision(ticket.id)
            })?;
        // The operation remains in the advanced ledger. Only the authentication
        // input belongs to the call frame; a refused login cannot destroy its parent.
        prepared_authentication = crate::session::PreparedContextLogin::from_prepared(
            self,
            &access,
            &mut authentication,
            &mut storage,
        )?;
        let mut prepared_authentication = prepared_authentication.ok_or(Error::Rejected(
            crate::RejectionReason::Authentication(
                crate::AuthenticationRejection::MissingContextualAuthentication,
            ),
        ))?;
        let result = prepared_authentication.perform(self);
        Ok(crate::session::ContextLoginOutcome {
            result,
            diagnostics: prepared_authentication.into_diagnostics(),
        })
    }
}

impl Operation {
    pub(super) fn check_control_access(&self, entry: &SessionEntry) -> Result<()> {
        self.check_continuation_authentication(entry)?;
        self.check_control_state()
    }
    /// Input/output continuation keeps the same memory owner across Logout.
    /// The module, rather than an old login observation, authorizes the call.
    pub(super) fn check_continuation_control(&self, entry: &SessionEntry) -> Result<()> {
        self.check_continuation_authentication(entry)?;
        self.check_control_state()
    }
    fn check_control_state(&self) -> Result<()> {
        if self.body.pending()
            || self.uncancellable_retained()
            || self.cancel.is_submitted()
            || self.joined.is_some()
            || self.state.as_ref().is_some()
            || self.transfer.as_ref().is_some()
            || self.continuation_status.is_frozen()
            || self.cancellation.is_withdrawn()
        {
            return Err(Error::Busy(crate::BusyReason::Authentication(
                crate::AuthenticationBusy::OperationControlInProgress,
            )));
        }
        Ok(())
    }
    fn check_context_authentication(&self, entry: &SessionEntry) -> Result<()> {
        self.check_control_access(entry)?;
        if self.active_categories() == 0 || self.body.complete() {
            return Err(Error::Rejected(crate::RejectionReason::Authentication(
                crate::AuthenticationRejection::ContextAuthenticationRequiresInitializedOperation,
            )));
        }
        Ok(())
    }
}
