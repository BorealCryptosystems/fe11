// SPDX-License-Identifier: Apache-2.0
//! Session quota reservation and publication after native opening.

use super::*;

impl Drop for SessionLedger {
    fn drop(&mut self) {
        let mut predecessor = self
            .predecessor
            .get_mut()
            .unwrap_or_else(|error| error.into_inner())
            .take();
        while let Some(previous) = predecessor {
            // into_inner releases this strong reference without recursively
            // destroying a shared value. If another owner remains, that owner
            // will perform the same iterative teardown when it finally leaves.
            let Some(mut ledger) = Arc::into_inner(previous) else {
                break;
            };
            predecessor = ledger
                .predecessor
                .get_mut()
                .unwrap_or_else(|error| error.into_inner())
                .take();
            // This ledger's link is already empty; its Drop cannot recurse
            // through the generation chain. Resource owners keep normal Drop.
            drop(ledger);
        }
    }
}

impl Drop for AdmissionChange<'_> {
    fn drop(&mut self) {
        self.0.notify_admission();
    }
}

impl SessionLedger {
    pub fn new(module: SessionLimit) -> Self {
        Self {
            predecessor: Mutex::new(None),
            state: Mutex::new(LedgerState::default()),
            wake: Arc::new(Wake::default()),
            module,
        }
    }

    pub fn reserve(
        self: &Arc<Self>,
        token: &TokenIdentity,
        generation: u64,
        rw: bool,
        limit: SessionLimit,
    ) -> Result<SessionCredit> {
        let mut state = self.state.lock().map_err(|_| Error::Poisoned)?;
        if matches!(state.admission, ReservationAdmission::Sealed) {
            return Err(Error::Rejected(crate::RejectionReason::SessionAccounting(
                crate::SessionAccountingRejection::ModuleSessionAdmissionClosed,
            )));
        }
        let uid = state.next_uid.checked_add(1).ok_or(Error::Rejected(
            crate::RejectionReason::SessionAccounting(
                crate::SessionAccountingRejection::SessionGenerationExhausted,
            ),
        ))?;
        let total = state.total.acquire(rw, self.module)?;
        let token_total = state
            .tokens
            .get(token)
            .copied()
            .unwrap_or_default()
            .acquire(rw, limit)?;
        let (inherited, inherited_token) = self.inherited_counts(token)?;
        // Only the active ledger can add credits. Ancestors may return credits
        // after this conservative snapshot, but can never increase it.
        total.combine(inherited)?.within(self.module)?;
        token_total.combine(inherited_token)?.within(limit)?;
        // No capacity allocation, native call, or callback after publishing counts.
        state.records.try_reserve(1).map_err(|_| {
            Error::Rejected(crate::RejectionReason::SessionAccounting(
                crate::SessionAccountingRejection::SessionRegistryAllocation,
            ))
        })?;
        if !state.tokens.contains_key(token) {
            state.tokens.try_reserve(1).map_err(|_| {
                Error::Rejected(crate::RejectionReason::SessionAccounting(
                    crate::SessionAccountingRejection::SessionRegistryAllocation,
                ))
            })?;
        }
        let proof = Arc::new(CreditProof {
            terminal: AtomicU8::new(QUOTA_UNSETTLED),
            ticket: AtomicU64::new(0),
            native_retired: std::sync::atomic::AtomicBool::new(false),
        });
        state.records.insert(
            uid,
            Record::Live {
                identity: RecordIdentity {
                    token: token.clone(),
                    generation,
                    read_write: rw,
                    proof: proof.clone(),
                    close: CloseAttempt::Unrecorded,
                },
                phase: Phase::Reserved,
                entry: None,
            },
        );
        state.next_uid = uid;
        state.tokens.insert(token.clone(), token_total);
        state.total = total;
        Ok(SessionCredit {
            ledger: Arc::downgrade(self),
            uid,
            proof,
            dispatched: false,
            client: crate::module::ClientId::OWNER,
        })
    }

    /// Called before acquiring module/token/session possession for an open.
    /// The predicate reads local validity/admission only; it never calls native
    /// code, acquires a module guard, or retries C_OpenSession.
    pub(crate) fn reserve_waiting(
        self: &Arc<Self>,
        token: &TokenIdentity,
        generation: u64,
        rw: bool,
        limit: SessionLimit,
        validate: impl Fn() -> Result<()>,
    ) -> Result<SessionCredit> {
        validate()?;
        // Zero is an explicit prohibition, not capacity another close can free.
        if self.module.total == 0
            || limit.total == 0
            || (rw && (self.module.read_write == 0 || limit.read_write == 0))
        {
            return Err(Error::Rejected(crate::RejectionReason::SessionAccounting(
                crate::SessionAccountingRejection::SessionLimit,
            )));
        }
        let admission = crate::admission_wait::current();
        if matches!(admission, crate::ResourceAdmission::Immediate) {
            return self.reserve(token, generation, rw, limit);
        }
        self.wake.acquire(&admission, || {
            validate()?;
            match self.reserve(token, generation, rw, limit) {
                Ok(credit) => Ok(Attempt::Acquired(credit)),
                Err(Error::Rejected(crate::RejectionReason::SessionAccounting(
                    crate::SessionAccountingRejection::SessionLimit,
                ))) => Ok(Attempt::Occupied(crate::BusyReason::SessionAccounting(
                    crate::SessionAccountingBusy::SessionCapacity,
                ))),
                Err(error) => Err(error),
            }
        })
    }

    pub(super) fn publish(&self, uid: u64, entry: Arc<crate::module::SessionEntry>) -> Result<()> {
        {
            let mut state = self.state.lock().map_err(|_| Error::Poisoned)?;
            let r = state.records.get(&uid).ok_or(Error::Rejected(
                crate::RejectionReason::SessionAccounting(
                    crate::SessionAccountingRejection::SessionReservationAbsent,
                ),
            ))?;
            if r.phase() != Some(Phase::Opening)
                || r.entry().is_some()
                || !Arc::ptr_eq(&r.identity().proof, &entry.credit.proof)
            {
                return Err(Error::Rejected(crate::RejectionReason::SessionAccounting(
                    crate::SessionAccountingRejection::SessionPublicationState,
                )));
            }
            let mut owners = state.records.iter().filter(|(_, r)| {
                r.native_present() && r.entry().is_some_and(|e| e.handle == entry.handle)
            });
            let old = owners.next().map(|(&id, _)| id);
            if owners.next().is_some() {
                return Err(Error::Rejected(crate::RejectionReason::SessionAccounting(
                    crate::SessionAccountingRejection::AmbiguousSessionOwner,
                )));
            }
            if let Some(old) = old {
                let record = state.records.get(&old).expect("observed owner");
                let owner = record.entry().expect("observed entry").clone();
                // A numeric handle collision is not completion evidence for an
                // async close or for the buffers it is supposed to release.
                if owner.close_pending.load(Ordering::Acquire) {
                    return Err(Error::Rejected(crate::RejectionReason::SessionAccounting(
                        crate::SessionAccountingRejection::PendingCloseHandleCollision,
                    )));
                }
                let ticket = record.identity().proof.ticket.load(Ordering::Acquire);
                let owned = record.closing(ticket) || record.recovering(ticket);
                // Quarantine is eligible only after revocation and quiescence.
                let retired = owner.native_handle_retired()
                    && !owner.recovery.has_pending_call()
                    && !owner
                        .snapshot
                        .domain
                        .advanced_count_invalid
                        .load(Ordering::Acquire)
                    && (owner.advanced_operation.load(Ordering::Acquire) == 0
                        || owner
                            .snapshot
                            .domain
                            .advanced_active
                            .load(Ordering::Acquire)
                            == 0);
                let quiet = if retired || record.phase() == Some(Phase::Quarantined) {
                    match owner.operation.try_lock() {
                        Ok(g) => Some(g),
                        Err(std::sync::TryLockError::Poisoned(p)) => Some(p.into_inner()),
                        Err(_) => None,
                    }
                } else {
                    None
                };
                if !(retired && quiet.is_some())
                    && (!owner.close_attempted.load(Ordering::Acquire)
                        || !(owned || quiet.is_some()))
                {
                    return Err(Error::Rejected(crate::RejectionReason::SessionAccounting(
                        crate::SessionAccountingRejection::LiveProviderSessionCollision,
                    )));
                }
                Self::retain_reused(&mut state, old)?;
            }
            let r = state
                .records
                .get_mut(&uid)
                .expect("checked publication reservation");
            let Record::Live {
                phase,
                entry: destination,
                ..
            } = r
            else {
                unreachable!("checked publication owner")
            };
            *destination = Some(entry);
            *phase = Phase::Open;
        };
        self.wake.notify();
        Ok(())
    }

    pub(super) fn dispatch_open(&self, uid: u64, proof: &Arc<CreditProof>) -> Result<()> {
        let mut state = self.state.lock().map_err(|_| Error::Poisoned)?;
        if matches!(state.admission, ReservationAdmission::Sealed) {
            return Err(Error::Rejected(crate::RejectionReason::SessionAccounting(
                crate::SessionAccountingRejection::ModuleSessionAdmissionClosed,
            )));
        }
        let record = state.records.get_mut(&uid).ok_or(Error::Rejected(
            crate::RejectionReason::SessionAccounting(
                crate::SessionAccountingRejection::SessionReservationAbsent,
            ),
        ))?;
        if !Arc::ptr_eq(&record.identity().proof, proof)
            || proof.terminal.load(Ordering::Acquire) != QUOTA_UNSETTLED
            || record.phase() != Some(Phase::Reserved)
        {
            return Err(Error::Rejected(crate::RejectionReason::SessionAccounting(
                crate::SessionAccountingRejection::SessionDispatchReservation,
            )));
        }
        record.change_phase(Phase::Opening);
        Ok(())
    }
}

impl SessionCredit {
    /// Withdraw dispatch before fallible accounting. This is not a release of
    /// quota or native loans; record_handle_loss publishes those separately.
    pub(crate) fn withdraw_native_handle(&self) {
        self.proof.native_retired.store(true, Ordering::Release);
    }

    pub(crate) fn retire_native_handle(&self) -> Result<()> {
        self.record_handle_loss(HandleLoss::NativeInvalid)
    }

    pub(crate) fn retire_runtime(&self) -> Result<()> {
        self.record_handle_loss(HandleLoss::RuntimeRetired)
    }

    pub(super) fn record_handle_loss(&self, cause: HandleLoss) -> Result<()> {
        self.withdraw_native_handle();
        let ledger = self.owner()?;
        let result = (|| {
            let mut state = ledger.state.lock().map_err(|_| Error::Poisoned)?;
            if self.proof.terminal.load(Ordering::Acquire) != QUOTA_UNSETTLED {
                return Ok(());
            }
            let record = state.records.get(&self.uid).ok_or(Error::Rejected(
                crate::RejectionReason::SessionAccounting(
                    crate::SessionAccountingRejection::SessionOwnerAbsent,
                ),
            ))?;
            if !Arc::ptr_eq(&record.identity().proof, &self.proof) {
                return Err(Error::Rejected(crate::RejectionReason::SessionAccounting(
                    crate::SessionAccountingRejection::SessionLossOwnerMismatch,
                )));
            }
            SessionLedger::retain_without_handle(&mut state, self.uid, cause)
        })();
        ledger.wake.notify();
        result
    }

    pub(crate) fn native_handle_retired(&self) -> bool {
        self.proof.native_retired.load(Ordering::Acquire)
    }

    // Consuming an unpublished reservation associates its sole future entry
    // with a participant. No native handle is transferred or duplicated.
    pub(crate) fn for_client(mut self, client: crate::module::ClientId) -> Self {
        self.client = client;
        self
    }

    pub(crate) fn client_id(&self) -> crate::module::ClientId {
        self.client
    }

    pub fn uid(&self) -> u64 {
        self.uid
    }

    pub fn dispatch(&mut self) -> Result<()> {
        self.owner()?.dispatch_open(self.uid, &self.proof)?;
        self.dispatched = true;
        Ok(())
    }

    pub fn opened(&self, entry: Arc<crate::module::SessionEntry>) -> Result<()> {
        self.owner()?.publish(self.uid, entry)
    }

    pub(super) fn owner(&self) -> Result<Arc<SessionLedger>> {
        self.ledger
            .upgrade()
            .ok_or(Error::Rejected(crate::RejectionReason::SessionAccounting(
                crate::SessionAccountingRejection::SessionOwnerReleased,
            )))
    }

    pub fn closing(&self) -> Result<u64> {
        self.owner()?.begin_close(self.uid, &self.proof)
    }

    pub fn finish_close(&self, ticket: u64, success: bool) -> Result<()> {
        self.owner()?
            .complete_close(self.uid, &self.proof, ticket, success)
    }

    pub fn quarantine(&self) -> Result<()> {
        self.owner()?
            .phase(self.uid, &self.proof, Phase::Quarantined)
    }

    pub fn release(&self) -> Result<()> {
        self.owner()?.release(self.uid, &self.proof)
    }
}

impl Drop for SessionCredit {
    fn drop(&mut self) {
        if self.proof.terminal.load(Ordering::Acquire) != QUOTA_UNSETTLED {
            return;
        }
        if let Some(ledger) = self.ledger.upgrade() {
            if self.dispatched {
                let _ = ledger.phase(self.uid, &self.proof, Phase::Quarantined);
            } else {
                let _ = ledger.release(self.uid, &self.proof);
            }
        }
    }
}
