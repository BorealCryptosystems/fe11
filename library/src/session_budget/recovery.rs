// SPDX-License-Identifier: Apache-2.0
//! Validated batches for session recovery and module finalization.

use super::*;

impl RecoveryBatch {
    pub(crate) fn owns_uid(&self, uid: u64) -> bool {
        uid != 0
            && self
                .items
                .iter()
                .any(|item| item.uid == uid && item.entry.is_some())
    }

    pub fn entries_for_close(&self) -> impl Iterator<Item = &Arc<crate::module::SessionEntry>> {
        self.items.iter().filter_map(|item| item.entry.as_ref())
    }
}

impl SessionLedger {
    /// Called only after the module owner proved withdrawal and synchronous
    /// return for every candidate. Sealing and identity revalidation are atomic.
    /// Native quota and graph ownership remain unchanged until Finalize OK.
    pub(crate) fn seal_recovery(
        &self,
        entries: &[Arc<crate::module::SessionEntry>],
    ) -> Result<SessionSeal<'_>> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        Self::validate_metadata(&state)?;
        if entries.len() != state.records.len() {
            return Err(Error::Rejected(crate::RejectionReason::SessionAccounting(
                crate::SessionAccountingRejection::FinalizationPopulationChanged,
            )));
        }
        for (&uid, record) in &state.records {
            let entry = record
                .entry()
                .ok_or(Error::Busy(crate::BusyReason::SessionAccounting(
                    crate::SessionAccountingBusy::UnpublishedNativeSession,
                )))?;
            if !entries
                .iter()
                .any(|e| e.credit.uid() == uid && Arc::ptr_eq(e, entry))
                || matches!(record.phase(), Some(Phase::Reserved | Phase::Opening))
                || record.recovery_active()
            {
                return Err(Error::Rejected(crate::RejectionReason::SessionAccounting(
                    crate::SessionAccountingRejection::FinalizationOwnershipChanged,
                )));
            }
        }
        let previous = state.admission;
        state.admission = ReservationAdmission::Sealed;
        // All checks precede mutation. Removing/reinserting existing keys cannot
        // allocate; no callback, payload destructor or native call occurs here.
        for entry in entries {
            let uid = entry.credit.uid();
            let record = state
                .records
                .remove(&uid)
                .expect("validated finalization owner");
            let record = match record {
                Record::Live {
                    identity,
                    entry: Some(entry),
                    ..
                } => Record::RetainedReturned {
                    identity,
                    entry,
                    recovery: RetentionRecovery::AwaitingProof,
                },
                record => record,
            };
            state.records.insert(uid, record);
        }
        drop(state);
        self.wake.notify();
        Ok(SessionSeal {
            ledger: self,
            previous,
            committed: false,
        })
    }

    pub(crate) fn prepare_generation_recovery(
        &self,
        identity: &TokenIdentity,
        generation: u64,
    ) -> Result<RecoveryBatch> {
        self.prepare_recovery_selected(identity, Some(generation))
    }

    pub(super) fn prepare_recovery_selected(
        &self,
        identity: &TokenIdentity,
        generation: Option<u64>,
    ) -> Result<RecoveryBatch> {
        let selected = |record: &Record| {
            generation.map_or(true, |generation| {
                record.identity().generation == generation
            })
        };
        let mut state = self.state.lock().map_err(|_| Error::Poisoned)?;
        let ticket = state.next_ticket.checked_add(1).ok_or(Error::Rejected(
            crate::RejectionReason::SessionAccounting(
                crate::SessionAccountingRejection::RecoveryTicketExhausted,
            ),
        ))?;
        let n = state
            .records
            .values()
            .filter(|r| {
                selected(r) && r.identity().token == *identity && r.phase() != Some(Phase::Reserved)
            })
            .count();
        let mut items = Vec::new();
        let mut removed = Vec::new();
        items.try_reserve(n).map_err(|_| {
            Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                crate::ModuleLifecycleRejection::RecoverySnapshotAllocation,
            ))
        })?;
        removed.try_reserve(n).map_err(|_| {
            Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                crate::ModuleLifecycleRejection::RecoverySnapshotAllocation,
            ))
        })?;
        for (&uid, r) in &state.records {
            if selected(r)
                && r.live_native()
                && r.identity().token.slot == identity.slot
                && r.identity().token != *identity
            {
                return Err(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                    crate::ModuleLifecycleRejection::RecoveryTokenIdentityChanged,
                )));
            }
            if selected(r) && r.identity().token == *identity && r.phase() != Some(Phase::Reserved)
            {
                items.push(Captured {
                    uid,
                    proof: r.identity().proof.clone(),
                    entry: r.entry().cloned(),
                });
            }
        }
        state.next_ticket = ticket;
        Ok(RecoveryBatch {
            ticket,
            items,
            removed,
            active: false,
            started: false,
        })
    }

    pub fn start_recovery(&self, batch: &mut RecoveryBatch) -> Result<()> {
        let mut state = self.state.lock().map_err(|_| Error::Poisoned)?;
        if batch.started {
            return Err(Error::Rejected(crate::RejectionReason::SessionAccounting(
                crate::SessionAccountingRejection::RecoveryAlreadyStarted,
            )));
        }
        for item in &batch.items {
            if item.proof.terminal.load(Ordering::Acquire) == RECORD_REMOVED {
                continue;
            }
            let record = state.records.get(&item.uid).ok_or(Error::Rejected(
                crate::RejectionReason::SessionAccounting(
                    crate::SessionAccountingRejection::RecoveryOwnerAbsent,
                ),
            ))?;
            if record.recovering(record.identity().proof.ticket.load(Ordering::Acquire)) {
                return Err(Error::Rejected(crate::RejectionReason::SessionAccounting(
                    crate::SessionAccountingRejection::RecoveryStateMismatch,
                )));
            }
            if !Arc::ptr_eq(&record.identity().proof, &item.proof) {
                return Err(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                    crate::ModuleLifecycleRejection::RecoveryOwnerMismatch,
                )));
            }
        }
        for item in &batch.items {
            if item.proof.terminal.load(Ordering::Acquire) == RECORD_REMOVED {
                continue;
            }
            let record = state
                .records
                .get_mut(&item.uid)
                .expect("checked recovery owner");
            match record {
                Record::Live { phase, .. } => *phase = Phase::Recovering,
                Record::RetainedWithoutHandle { recovery, .. }
                | Record::RetainedReturned { recovery, .. } => {
                    *recovery = RetentionRecovery::Recovering {
                        ticket: batch.ticket,
                    }
                }
            }
            record.identity_mut().close = CloseAttempt::Collective {
                ticket: batch.ticket,
                completion: RecoveryCompletion::Unproven,
            };
            item.proof.ticket.store(batch.ticket, Ordering::Release);
            if let Some(entry) = &item.entry {
                entry.close_attempted.store(true, Ordering::Release);
                entry.poisoned.store(true, Ordering::Release);
            }
        }
        batch.active = true;
        batch.started = true;
        drop(state);
        for item in &batch.items {
            if let Some(entry) = &item.entry {
                entry.snapshot.notify_admission();
            }
        }
        Ok(())
    }

    /// Persist the exact collective return before any fallible publication.
    /// Owners and quota remain anchored; a later explicit finalization can
    /// reconcile them even when the stack-owned batch is no longer available.
    pub(crate) fn record_recovery_completion(
        &self,
        batch: &RecoveryBatch,
        completion: RecoveryCompletion,
    ) -> Result<()> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if !batch.active {
            return Err(Error::Rejected(crate::RejectionReason::SessionAccounting(
                crate::SessionAccountingRejection::StaleRecoveryCompletion,
            )));
        }
        for item in &batch.items {
            if item.proof.terminal.load(Ordering::Acquire) == RECORD_REMOVED {
                continue;
            }
            let valid = state.records.get(&item.uid).is_some_and(|record|
                Arc::ptr_eq(&record.identity().proof, &item.proof)
                && record.recovering(batch.ticket)
                && matches!(record.identity().close,
                    CloseAttempt::Collective { ticket, completion: prior }
                    if ticket == batch.ticket && (prior == RecoveryCompletion::Unproven || prior == completion)));
            if !valid {
                return Err(Error::Rejected(crate::RejectionReason::SessionAccounting(
                    crate::SessionAccountingRejection::RecoveryStateMismatch,
                )));
            }
        }
        for item in &batch.items {
            if item.proof.terminal.load(Ordering::Acquire) == RECORD_REMOVED {
                continue;
            }
            let record = state
                .records
                .get_mut(&item.uid)
                .expect("validated recovery receipt owner");
            record.identity_mut().close = CloseAttempt::Collective {
                ticket: batch.ticket,
                completion,
            };
            if completion == (RecoveryCompletion::Returned { closed: true }) {
                if let Some(entry) = record.entry() {
                    entry.closed.store(true, Ordering::Release);
                }
            }
        }
        Ok(())
    }

    pub fn finish_recovery(
        &self,
        batch: &mut RecoveryBatch,
        completion: RecoveryCompletion,
    ) -> Result<()> {
        self.record_recovery_completion(batch, completion)?;
        let mut state = self.state.lock().map_err(|_| Error::Poisoned)?;
        if !batch.active {
            return Err(Error::Rejected(crate::RejectionReason::SessionAccounting(
                crate::SessionAccountingRejection::StaleRecoveryCompletion,
            )));
        }
        for item in &batch.items {
            if item.proof.terminal.load(Ordering::Acquire) == RECORD_REMOVED {
                continue;
            }
            if item.proof.ticket.load(Ordering::Acquire) != batch.ticket {
                return Err(Error::Rejected(crate::RejectionReason::SessionAccounting(
                    crate::SessionAccountingRejection::RecoveryTicketMismatch,
                )));
            }
            let record = state.records.get(&item.uid).ok_or(Error::Rejected(
                crate::RejectionReason::SessionAccounting(
                    crate::SessionAccountingRejection::RecoveryOwnerAbsent,
                ),
            ))?;
            if !Arc::ptr_eq(&record.identity().proof, &item.proof)
                || !record.recovering(batch.ticket)
            {
                return Err(Error::Rejected(crate::RejectionReason::SessionAccounting(
                    crate::SessionAccountingRejection::RecoveryStateMismatch,
                )));
            }
        }
        for item in &batch.items {
            if item.proof.terminal.load(Ordering::Acquire) == RECORD_REMOVED {
                continue;
            }
            if matches!(completion, RecoveryCompletion::Returned { closed: true }) {
                batch.removed.push(Self::remove(
                    &mut state,
                    item.uid,
                    &item.proof,
                    RECORD_REMOVED,
                )?);
            } else {
                let record = state
                    .records
                    .get_mut(&item.uid)
                    .expect("checked recovery owner");
                record.identity_mut().close = CloseAttempt::Collective {
                    ticket: batch.ticket,
                    completion,
                };
                match record {
                    Record::Live { phase, .. } => *phase = Phase::Quarantined,
                    Record::RetainedWithoutHandle { recovery, .. }
                    | Record::RetainedReturned { recovery, .. } => {
                        *recovery = RetentionRecovery::AwaitingProof
                    }
                }
            }
        }
        batch.active = false;
        drop(state);
        self.wake.notify();
        for item in &batch.items {
            if let Some(entry) = &item.entry {
                entry.snapshot.notify_admission();
            }
        }
        // The caller owns the batch outside its module/token guards. Its entries
        // and removed records are destroyed there, including Notify payloads.
        Ok(())
    }
}
