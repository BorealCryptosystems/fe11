// SPDX-License-Identifier: Apache-2.0
//! Commit or abandon prepared session-ledger finalization.
//! The finalization owner keeps its reservations until commit or cleanup.

use super::*;

impl Drop for FinalizedSessions {
    fn drop(&mut self) {
        if self.quarantined {
            // Finalize closed the instance, not these invalidated memory loans.
            std::mem::forget(std::mem::take(&mut self.records));
            std::mem::forget(self.image.clone());
            return;
        }
        for record in self.records.values() {
            if let Some(entry) = record.entry() {
                entry.recovery.release_closed();
            }
        }
    }
}

impl SessionSeal<'_> {
    pub(crate) fn commit(&mut self) {
        self.committed = true;
    }
}

impl Drop for SessionSeal<'_> {
    fn drop(&mut self) {
        if !self.committed {
            match self.ledger.state.lock() {
                Ok(mut state) => state.admission = self.previous,
                // A poisoned ledger cannot establish safe renewed admission.
                Err(error) => error.into_inner().admission = ReservationAdmission::Sealed,
            }
            self.ledger.wake.notify();
        }
    }
}
