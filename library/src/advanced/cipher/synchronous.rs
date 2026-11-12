// SPDX-License-Identifier: Apache-2.0
//! Synchronous facades retain an exact owner until result or recovery publication.
use super::{api, CipherBufferRequest, CipherOutputPlan, Direction, OutputObserver, Selection};
use crate::advanced::{OperationBody, OperationProgress, OperationTicket, PollDiagnostics};
use crate::{Error, InputLimits, MessageRoute, Result, Session};
use std::sync::Arc;

/// Keeps the parking diagnostic credited through the facade's result projection.
pub(super) struct Facade {
    ticket: OperationTicket,
    owner: Arc<crate::advanced::ledger::OperationCell>,
    diagnostic: crate::error::PreparedFailurePair,
}

impl Facade {
    pub(super) fn start<'a>(
        session: &Session,
        key: api::CipherKey<'_>,
        parameters: impl Into<Selection<'a>>,
        direction: Direction,
        route: MessageRoute,
        parts: &[&[u8]],
        limits: InputLimits,
        retirement: &mut PollDiagnostics,
    ) -> Result<Self> {
        if let api::CipherKey::Profiled(key) = key {
            if !matches!(
                key.algorithm(),
                crate::SymmetricAlgorithm::Aes128
                    | crate::SymmetricAlgorithm::Aes192
                    | crate::SymmetricAlgorithm::Aes256
            ) {
                return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                    crate::CipherContinuationRejection::AesOperationRequiresAnAesKey,
                )));
            }
        }
        let (ticket, owner, diagnostic) = api::start_retained(
            session,
            key,
            parameters,
            direction,
            route,
            parts,
            limits,
            CipherOutputPlan::MechanismBound,
            false,
            &mut 1,
            crate::advanced::input::InputState::closed(),
            None,
            true,
            retirement,
        )?;
        Ok(Self {
            ticket,
            owner,
            diagnostic: diagnostic.expect("facade diagnostic prepared"),
        })
    }

    pub(super) fn poll<T>(
        &mut self,
        session: &Session,
        project: impl FnOnce(OperationProgress) -> Result<T>,
    ) -> Result<T> {
        let result = session.poll_cipher(&mut self.ticket).and_then(|progress| {
            if let OperationProgress::CipherBufferRequired(request) = progress {
                Err(Error::CipherBufferRequired(request))
            } else {
                project(progress)
            }
        });
        let Err(error) = result else { return result };
        if self.ticket.id == 0 {
            return Err(error);
        }
        let expected = match &error {
            Error::CipherBufferRequired(request) => Some(*request),
            _ => None,
        };
        match park(session, &mut self.ticket, &self.owner, expected) {
            Ok(()) => Err(error),
            Err(cleanup) => Err(self.diagnostic.finish(error, cleanup)),
        }
    }
}

/// Transfer observation only. The exact registered allocation is retained even
/// after a deadline or context withdrawal; no admission or native call occurs.
pub(super) fn park(
    session: &Session,
    ticket: &mut OperationTicket,
    owner: &Arc<crate::advanced::ledger::OperationCell>,
    expected: Option<CipherBufferRequest>,
) -> Result<()> {
    if !Arc::ptr_eq(&ticket.owner, &session.inner) || ticket.uid != session.uid || ticket.id == 0 {
        return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
            crate::OperationOwnershipRejection::ForeignOrConsumedCipherTicket,
        )));
    }
    let mut operation = owner.lock().map_err(|_| Error::Poisoned)?;
    if operation.id != ticket.id {
        return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
            crate::CipherContinuationRejection::StaleCipherFacadeTicket,
        )));
    }
    let OperationBody::Cipher(body) = &mut operation.body else {
        return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
            crate::CipherContinuationRejection::CipherFacadeOwnerChanged,
        )));
    };
    if let Some(request) = expected {
        body.park_observer(request)?;
    } else {
        if body.observer != OutputObserver::Ticket {
            return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::CipherFacadeObserverChanged,
            )));
        }
        body.observer = OutputObserver::Session;
    }
    ticket.id = 0;
    Ok(())
}
