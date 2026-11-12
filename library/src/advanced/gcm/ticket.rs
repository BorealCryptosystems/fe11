// SPDX-License-Identifier: Apache-2.0
//! Single-owner ticket handoff after an AEAD facade fails with work retained.
use crate::advanced::{AdvancedSession, Operation, OperationBody, OperationTicket};
use crate::{Error, Result, Session};
use std::sync::Arc;

/// Error storage belongs to the invocation root, not to the retained native
/// owner. Init refusal and later facade failure are mutually exclusive, so
/// they share one parking pair. Single-result publication has its own leaf.
pub(crate) struct Diagnostics {
    pub(super) retired_owner: Option<Arc<crate::advanced::ledger::OperationCell>>,
    pub(super) parking: crate::error::PreparedFailurePair,
    pub(super) publication: Option<crate::error::PreparedCompletion>,
}
impl Diagnostics {
    pub(super) fn preparation_bytes(publication: bool) -> usize {
        crate::error::PreparedFailurePair::preparation_bytes()
            + if publication {
                crate::error::PreparedCompletion::allocation_bytes()
            } else {
                0
            }
    }

    pub(super) fn prepare(
        prepaid: &mut crate::symmetric::memory::Credit,
        publication: Option<&'static str>,
    ) -> Result<Self> {
        Ok(Self {
            retired_owner: None,
            parking: crate::error::PreparedFailurePair::prepare(prepaid)?,
            publication: publication
                .map(|function| crate::error::PreparedCompletion::prepare(function, prepaid))
                .transpose()?,
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Observer {
    Ticket,
    Session,
}

/// Called while the existing owner is locked. It requires no session admission,
/// allocation, key check or native call, including after the session is poisoned.
pub(super) fn park_locked(
    session: &Session,
    ticket: &mut OperationTicket,
    operation: &mut Operation,
) -> Result<()> {
    if !Arc::ptr_eq(&ticket.owner, &session.inner) || ticket.uid != session.uid || ticket.id == 0 {
        return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
            crate::AeadMessagesRejection::ForeignOrConsumedAeadTicket,
        )));
    }
    if operation.id != ticket.id {
        return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
            crate::AeadMessagesRejection::StaleAeadTicket,
        )));
    }
    let OperationBody::AeadMessages(body) = &mut operation.body else {
        return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
            crate::OperationOwnershipRejection::AeadMessageTicketRequired,
        )));
    };
    if body.observer != Observer::Ticket {
        return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
            crate::AeadMessagesRejection::AeadTicketAlreadyTransferred,
        )));
    }
    body.observer = Observer::Session;
    ticket.id = 0;
    Ok(())
}

pub(super) fn retain_failure(
    session: &Session,
    ticket: &mut OperationTicket,
    held: &Arc<crate::advanced::ledger::OperationCell>,
    error: Error,
    diagnostic: &mut crate::error::PreparedFailurePair,
) -> Error {
    if ticket.id == 0 {
        return error;
    }
    let parked = (|| {
        let mut operation = held.lock().map_err(|_| Error::Poisoned)?;
        park_locked(session, ticket, &mut operation)
    })();
    match parked {
        Ok(()) => error,
        Err(cleanup) => diagnostic.finish(error, cleanup),
    }
}

impl Session {
    /// Retrieve once the ticket retained after an AEAD message facade error.
    /// This performs no native retry, cancellation or initialization. A failed
    /// operation may allow only explicit cleanup; retrieval does not assert that
    /// its native state or key remains usable. Tickets already returned to the
    /// caller cannot be retrieved a second time through this method.
    pub fn take_aead_message_ticket(&self) -> Result<OperationTicket> {
        // This is a local observer transfer, not permission to use the key or
        // module. In particular uncertainty must not strand its cleanup ticket.
        // Declare the Arc first: if concurrent cleanup retires this entry, its
        // last owner must be destroyed after our module observation guard.
        let held;
        let state = self.inner.state.observe()?;
        held = state.operations.get(self.uid)?;
        // A native Notify callback may reenter while polling owns this mutex.
        // Observation must refuse contention rather than wait on its own call.
        let mut operation = held.try_lock().map_err(|error| match error {
            std::sync::TryLockError::WouldBlock => {
                Error::Busy(crate::BusyReason::OperationOwnership(
                    crate::OperationOwnershipBusy::OperationObservationInProgress,
                ))
            }
            std::sync::TryLockError::Poisoned(_) => Error::Poisoned,
        })?;
        // Cancellation can retire the ledger entry between lookup and locking.
        // Do not return a ticket for that detached owner or a replacement entry.
        if !Arc::ptr_eq(&held, &state.operations.get(self.uid)?) {
            return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::StaleAeadMessageOwner,
            )));
        }
        let OperationBody::AeadMessages(body) = &mut operation.body else {
            return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::AeadMessageTicketRequired,
            )));
        };
        if body.observer != Observer::Session {
            return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::AeadMessageTicketUnavailable,
            )));
        }
        body.observer = Observer::Ticket;
        Ok(OperationTicket {
            owner: self.inner.clone(),
            uid: self.uid,
            id: operation.id,
            validation_report: None,
            state_provenance: None,
        })
    }
}

impl AdvancedSession {
    /// Retrieve an AEAD ticket retained after a batch-start failure, without
    /// another native call. Use the ordinary poll/cancel methods explicitly.
    pub fn take_aead_message_ticket(&self) -> Result<OperationTicket> {
        self.session.take_aead_message_ticket()
    }
}
