// SPDX-License-Identifier: Apache-2.0
//! Provenance of a collective close, independent of its effect on sessions.

use super::*;

impl SessionCredit {
    pub(crate) fn collective_completion(&self) -> Result<Option<RecoveryCompletion>> {
        let ledger = self.ledger.upgrade().ok_or(Error::Rejected(
            crate::RejectionReason::SessionAccounting(
                crate::SessionAccountingRejection::SessionReservationAbsent,
            ),
        ))?;
        let state = ledger.state.lock().unwrap_or_else(|e| e.into_inner());
        let record = state.records.get(&self.uid).ok_or(Error::Rejected(
            crate::RejectionReason::SessionAccounting(
                crate::SessionAccountingRejection::SessionReservationAbsent,
            ),
        ))?;
        let identity = record.identity();
        if !Arc::ptr_eq(&identity.proof, &self.proof) {
            return Err(Error::Rejected(crate::RejectionReason::SessionAccounting(
                crate::SessionAccountingRejection::SessionOwnerMismatch,
            )));
        }
        match identity.close {
            CloseAttempt::Collective { ticket, completion }
                if ticket != 0 && ticket == self.proof.ticket.load(Ordering::Acquire) =>
            {
                Ok(Some(completion))
            }
            CloseAttempt::Collective { .. } => {
                Err(Error::Rejected(crate::RejectionReason::SessionAccounting(
                    crate::SessionAccountingRejection::RecoveryTicketMismatch,
                )))
            }
            CloseAttempt::Unrecorded | CloseAttempt::Individual => Ok(None),
        }
    }
}
