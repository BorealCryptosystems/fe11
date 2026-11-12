// SPDX-License-Identifier: Apache-2.0
//! Reserve and settle session-close attempts with exact credit ownership.
//! Native closure evidence and local quota settlement are tracked separately.

use super::*;

impl SessionLedger {
    /// The module writer excludes dispatch/publication. Capture exact owners
    /// before inspecting their controls, with no operation lock under the ledger.
    pub(crate) fn finalization_candidates(&self) -> Result<Vec<Arc<crate::module::SessionEntry>>> {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        Self::validate_metadata(&state)?;
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(state.records.len())
            .map_err(|_| {
                Error::Rejected(crate::RejectionReason::SessionAccounting(
                    crate::SessionAccountingRejection::FinalizationSnapshotAllocation,
                ))
            })?;
        for record in state.records.values() {
            if matches!(record.phase(), Some(Phase::Reserved | Phase::Opening))
                || record.recovery_active()
            {
                return Err(Error::Busy(crate::BusyReason::SessionAccounting(
                    crate::SessionAccountingBusy::SessionReservationOrRecoveryActive,
                )));
            }
            entries.push(
                record
                    .entry()
                    .ok_or(Error::Busy(crate::BusyReason::SessionAccounting(
                        crate::SessionAccountingBusy::UnpublishedNativeSession,
                    )))?
                    .clone(),
            );
        }
        Ok(entries)
    }

    /// No native call occurs here. Failure leaves the entries anchored for a
    /// later local publication repair; success moves the whole map without allocation.
    pub(crate) fn take_finalized(
        &self,
        image: Arc<crate::native::image::LoadedImage>,
        quarantined: bool,
    ) -> Result<FinalizedSessions> {
        let records = {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            Self::validate_metadata(&state)?;
            if !matches!(state.admission, ReservationAdmission::Sealed)
                || state
                    .records
                    .values()
                    .any(|r| matches!(r, Record::Live { .. }))
            {
                return Err(Error::Rejected(crate::RejectionReason::SessionAccounting(
                    crate::SessionAccountingRejection::FinalizationOwnersNotSealed,
                )));
            }
            for record in state.records.values() {
                record
                    .identity()
                    .proof
                    .terminal
                    .store(RECORD_REMOVED, Ordering::Release);
                Self::close_binding(record);
            }
            state.total = Counts::default();
            state.tokens.clear();
            std::mem::take(&mut state.records)
        };
        self.wake.notify();
        Ok(FinalizedSessions {
            records,
            image,
            quarantined,
        })
    }

    // This path requires native closure evidence. Notification capacity may
    // then be reclaimed; mere withdrawal must use retire_binding instead.
    pub(super) fn close_binding(record: &Record) {
        if let Some(entry) = record.entry() {
            if let Some(notification) = &entry.notification {
                notification.close();
            }
        }
        Self::retire_binding(record);
    }

    // Withdraw only Rust dispatch. Keep pApplication and its callback graph
    // anchored: an invalid handle or numeric reuse is no native Close receipt.
    pub(super) fn retire_binding(record: &Record) {
        if let Some(entry) = record.entry() {
            entry.closed.store(true, Ordering::Release);
            entry.deferred_close.store(false, Ordering::Release);
            entry.unpublished_object.store(false, Ordering::Release);
        }
    }

    pub(super) fn begin_close(&self, uid: u64, proof: &Arc<CreditProof>) -> Result<u64> {
        let mut state = self.state.lock().map_err(|_| Error::Poisoned)?;
        let ticket = state.next_ticket.checked_add(1).ok_or(Error::Rejected(
            crate::RejectionReason::SessionAccounting(
                crate::SessionAccountingRejection::RecoveryTicketExhausted,
            ),
        ))?;
        let r = state.records.get_mut(&uid).ok_or(Error::Rejected(
            crate::RejectionReason::SessionAccounting(
                crate::SessionAccountingRejection::SessionReservationAbsent,
            ),
        ))?;
        if !Arc::ptr_eq(&r.identity().proof, proof)
            || !(r.live_native()
                || matches!(
                    r,
                    Record::RetainedReturned {
                        recovery: RetentionRecovery::AwaitingProof,
                        ..
                    }
                ))
            || matches!(r.phase(), Some(Phase::Closing | Phase::Recovering))
        {
            return Err(Error::Rejected(crate::RejectionReason::SessionAccounting(
                crate::SessionAccountingRejection::SessionCloseState,
            )));
        }
        match r {
            Record::RetainedReturned { recovery, .. } => {
                *recovery = RetentionRecovery::Closing { ticket };
            }
            _ => r.change_phase(Phase::Closing),
        }
        r.identity_mut().close = CloseAttempt::Individual;
        proof.ticket.store(ticket, Ordering::Release);
        let changed = r.entry().map(|entry| {
            entry.close_attempted.store(true, Ordering::Release);
            entry.snapshot.clone()
        });
        state.next_ticket = ticket;
        drop(state);
        if let Some(snapshot) = changed {
            snapshot.notify_admission();
        }
        Ok(ticket)
    }

    pub(super) fn complete_close(
        &self,
        uid: u64,
        proof: &Arc<CreditProof>,
        ticket: u64,
        success: bool,
    ) -> Result<()> {
        let removed = {
            let mut state = self.state.lock().map_err(|_| Error::Poisoned)?;
            if ticket == 0 || proof.ticket.load(Ordering::Acquire) != ticket {
                return Err(Error::Rejected(crate::RejectionReason::SessionAccounting(
                    crate::SessionAccountingRejection::StaleClosingTicket,
                )));
            }
            if proof.terminal.load(Ordering::Acquire) == RECORD_REMOVED {
                return Ok(());
            }
            let record = state.records.get_mut(&uid).ok_or(Error::Rejected(
                crate::RejectionReason::SessionAccounting(
                    crate::SessionAccountingRejection::SessionReservationAbsent,
                ),
            ))?;
            if !Arc::ptr_eq(&record.identity().proof, proof) || !record.closing(ticket) {
                return Err(Error::Rejected(crate::RejectionReason::SessionAccounting(
                    crate::SessionAccountingRejection::SessionClosingOwnership,
                )));
            }
            if success {
                Some(Self::remove(&mut state, uid, proof, RECORD_REMOVED)?)
            } else {
                match record {
                    Record::RetainedWithoutHandle { recovery, .. }
                    | Record::RetainedReturned { recovery, .. } => {
                        *recovery = RetentionRecovery::AwaitingProof
                    }
                    _ => record.change_phase(Phase::Quarantined),
                }
                None
            }
        };
        self.wake.notify();
        drop(removed);
        Ok(())
    }

    // The operation snapshot holds the lease strongly; this ledger is the
    // independent anchor for the exact session, including reused handles. No
    // operation mutex, callback or weak upgrade is needed under this mutex.
    pub(crate) fn prove_stranded(
        &self,
        uid: u64,
        observed: &std::sync::Weak<crate::module::SessionEntry>,
        ticket: u64,
        matches: impl FnOnce(&crate::module::SessionEntry) -> bool,
    ) -> Result<()> {
        let state = self.state.lock().map_err(|_| Error::Poisoned)?;
        let record = state.records.get(&uid).ok_or(Error::Rejected(
            crate::RejectionReason::ModuleLifecycle(
                crate::ModuleLifecycleRejection::RecoveryOwnerMismatch,
            ),
        ))?;
        let entry =
            record
                .entry()
                .ok_or(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                    crate::ModuleLifecycleRejection::RecoveryOwnerMismatch,
                )))?;
        let retained = matches!(
            record,
            Record::Live {
                phase: Phase::Quarantined,
                ..
            } | Record::RetainedWithoutHandle {
                recovery: RetentionRecovery::AwaitingProof,
                ..
            } | Record::RetainedReturned {
                recovery: RetentionRecovery::AwaitingProof,
                ..
            }
        );
        if !retained
            || ticket == 0
            || observed.as_ptr() != Arc::as_ptr(entry)
            || entry.advanced_operation.load(Ordering::Acquire) != ticket
            || !matches(entry)
        {
            return Err(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                crate::ModuleLifecycleRejection::RecoveryOwnerMismatch,
            )));
        }
        Ok(())
    }

    pub fn entries_for_close(&self) -> Result<Vec<Arc<crate::module::SessionEntry>>> {
        let state = self.state.lock().map_err(|_| Error::Poisoned)?;
        let mut entries = Vec::new();
        entries.try_reserve(state.records.len()).map_err(|_| {
            Error::Rejected(crate::RejectionReason::SessionAccounting(
                crate::SessionAccountingRejection::SessionSnapshotAllocation,
            ))
        })?;
        entries.extend(
            state
                .records
                .values()
                .filter(|r| r.live_native())
                .filter_map(|r| r.entry().cloned()),
        );
        Ok(entries)
    }
}
