// SPDX-License-Identifier: Apache-2.0
//! Session ownership validation, handle retirement and reusable-session lookup.

use super::*;

impl SessionLedger {
    /// Reclaim only sealed ledgers with no record or outstanding quota. A zero
    /// native count alone is insufficient: retained graphs remain in records.
    /// An empty sealed ledger can never publish another reservation, so skipping
    /// it does not hide a later credit. The shared Wake outlives removed links.
    pub(super) fn retained_predecessor(&self) -> Result<Option<Arc<Self>>> {
        let mut link = self.predecessor.lock().map_err(|_| Error::Poisoned)?;
        loop {
            let Some(previous) = link.as_ref().cloned() else {
                return Ok(None);
            };
            if !previous.permanently_empty()? {
                return Ok(Some(previous));
            }
            let next = previous
                .predecessor
                .lock()
                .map_err(|_| Error::Poisoned)?
                .clone();
            // Only an empty ledger is released under this link guard; it owns
            // no application graph or callback that could reenter accounting.
            *link = next;
        }
    }

    /// Validate local ownership, UID, identity and quota arithmetic. Rust mutex
    /// poison is not native corruption, but no inconsistent metadata is accepted.
    pub(super) fn validate_metadata(state: &LedgerState) -> Result<()> {
        let mut total = Counts::default();
        for (&uid, record) in &state.records {
            let identity = record.identity();
            let reused = matches!(record, Record::RetainedWithoutHandle { .. });
            if uid == 0
                || uid > state.next_uid
                || identity.proof.terminal.load(Ordering::Acquire)
                    != if reused {
                        QUOTA_SETTLED_RETAINED
                    } else {
                        QUOTA_UNSETTLED
                    }
            {
                return Err(Error::Rejected(crate::RejectionReason::SessionAccounting(
                    crate::SessionAccountingRejection::SessionLedgerIdentityInvariant,
                )));
            }
            if let Some(entry) = record.entry() {
                if entry.credit.uid() != uid
                    || !Arc::ptr_eq(&entry.credit.proof, &identity.proof)
                    || entry.snapshot.generation != identity.generation
                    || entry.snapshot.capabilities.identity != identity.token
                {
                    return Err(Error::Rejected(crate::RejectionReason::SessionAccounting(
                        crate::SessionAccountingRejection::SessionLedgerEntryInvariant,
                    )));
                }
            }
            if !reused {
                total.total = total.total.checked_add(1).ok_or(Error::Rejected(
                    crate::RejectionReason::SessionAccounting(
                        crate::SessionAccountingRejection::SessionCountInvariant,
                    ),
                ))?;
                total.read_write = total
                    .read_write
                    .checked_add(usize::from(identity.read_write))
                    .ok_or(Error::Rejected(crate::RejectionReason::SessionAccounting(
                        crate::SessionAccountingRejection::SessionCountInvariant,
                    )))?;
                if !state.tokens.contains_key(&identity.token) {
                    return Err(Error::Rejected(crate::RejectionReason::SessionAccounting(
                        crate::SessionAccountingRejection::SessionTokenCountInvariant,
                    )));
                }
            }
        }
        if total.total != state.total.total || total.read_write != state.total.read_write {
            return Err(Error::Rejected(crate::RejectionReason::SessionAccounting(
                crate::SessionAccountingRejection::SessionCountInvariant,
            )));
        }
        for (token, count) in &state.tokens {
            let mut actual = Counts::default();
            for record in state.records.values().filter(|r| {
                !matches!(r, Record::RetainedWithoutHandle { .. }) && r.identity().token == *token
            }) {
                actual.total += 1;
                actual.read_write += usize::from(record.identity().read_write);
            }
            if actual.total != count.total
                || actual.read_write != count.read_write
                || count.total == 0
            {
                return Err(Error::Rejected(crate::RejectionReason::SessionAccounting(
                    crate::SessionAccountingRejection::SessionTokenCountInvariant,
                )));
            }
        }
        Ok(())
    }

    pub(super) fn retain_reused(state: &mut LedgerState, uid: u64) -> Result<()> {
        Self::retain_without_handle(state, uid, HandleLoss::Reused)
    }

    pub(super) fn retain_without_handle(
        state: &mut LedgerState,
        uid: u64,
        cause: HandleLoss,
    ) -> Result<()> {
        let record = state.records.get(&uid).ok_or(Error::Rejected(
            crate::RejectionReason::SessionAccounting(
                crate::SessionAccountingRejection::SessionReservationAbsent,
            ),
        ))?;
        if !matches!(
            record,
            Record::Live { entry: Some(_), .. } | Record::RetainedReturned { .. }
        ) || record.identity().proof.terminal.load(Ordering::Acquire) != QUOTA_UNSETTLED
        {
            return Err(Error::Rejected(crate::RejectionReason::SessionAccounting(
                crate::SessionAccountingRejection::SessionOwnerMismatch,
            )));
        }
        Self::settle_quota(state, uid)?;
        // Removing and reinserting the same key cannot grow the table. No owner
        // destructor or callback runs during this allocation-free conversion.
        let (identity, entry, recovery) =
            match state.records.remove(&uid).expect("checked native owner") {
                Record::Live {
                    identity,
                    entry: Some(entry),
                    phase,
                } => {
                    let ticket = identity.proof.ticket.load(Ordering::Acquire);
                    let recovery = match phase {
                        Phase::Closing => RetentionRecovery::Closing { ticket },
                        Phase::Recovering => RetentionRecovery::Recovering { ticket },
                        _ => RetentionRecovery::AwaitingProof,
                    };
                    (identity, entry, recovery)
                }
                Record::RetainedReturned {
                    identity,
                    entry,
                    recovery,
                } => (identity, entry, recovery),
                _ => unreachable!("checked native owner"),
            };
        identity
            .proof
            .terminal
            .store(QUOTA_SETTLED_RETAINED, Ordering::Release);
        let retained = Record::RetainedWithoutHandle {
            _cause: cause,
            identity,
            entry,
            recovery,
        };
        Self::retire_binding(&retained);
        state.records.insert(uid, retained);
        Ok(())
    }

    pub(super) fn release(&self, uid: u64, proof: &Arc<CreditProof>) -> Result<()> {
        let removed = {
            let mut state = self.state.lock().map_err(|_| Error::Poisoned)?;
            if proof.terminal.load(Ordering::Acquire) != QUOTA_UNSETTLED {
                return Err(Error::Rejected(crate::RejectionReason::SessionAccounting(
                    crate::SessionAccountingRejection::SessionReservationAlreadyReleased,
                )));
            }
            Self::remove(&mut state, uid, proof, RECORD_REMOVED)?
        };
        self.wake.notify();
        drop(removed);
        Ok(())
    }

    pub(crate) fn usable_for(
        &self,
        snapshot: &Arc<crate::module::TokenSnapshot>,
        rw: bool,
        client: crate::module::ClientId,
    ) -> Result<Arc<crate::module::SessionEntry>> {
        snapshot.check()?;
        self.state
            .lock()
            .map_err(|_| Error::Poisoned)?
            .records
            .values()
            .filter(|r| r.live_native())
            .filter_map(|r| r.entry())
            .find(|e| {
                e.mode == crate::AdvancedSessionMode::Synchronous
                    && e.credit.client_id() == client
                    && e.advanced_operation.load(Ordering::Acquire) == 0
                    && Arc::ptr_eq(&e.snapshot, snapshot)
                    && (!rw || e.read_write)
                    && !e.closed.load(Ordering::Acquire)
                    && !e.poisoned.load(Ordering::Acquire)
                    && !e.deferred_close.load(Ordering::Acquire)
                    && !e.close_attempted.load(Ordering::Acquire)
            })
            .cloned()
            .ok_or(Error::Rejected(crate::RejectionReason::SessionAccounting(
                crate::SessionAccountingRejection::AuthenticationRequiresSession,
            )))
    }
}
