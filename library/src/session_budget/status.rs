// SPDX-License-Identifier: Apache-2.0
//! Session quota settlement, status snapshots and deferred-close selection.

use super::*;

impl SessionLedger {
    pub(crate) fn successor(previous: Arc<Self>, module: SessionLimit) -> Result<Self> {
        if !matches!(
            previous
                .state
                .lock()
                .map_err(|_| Error::Poisoned)?
                .admission,
            ReservationAdmission::Sealed
        ) {
            return Err(Error::Rejected(crate::RejectionReason::SessionAccounting(
                crate::SessionAccountingRejection::PredecessorSessionAdmissionNotSealed,
            )));
        }
        let wake = previous.wake.clone();
        let predecessor = if previous.permanently_empty()? {
            previous.retained_predecessor()?
        } else {
            Some(previous)
        };
        Ok(Self {
            wake,
            predecessor: Mutex::new(predecessor),
            state: Mutex::new(LedgerState::default()),
            module,
        })
    }

    pub(super) fn permanently_empty(&self) -> Result<bool> {
        let state = self.state.lock().map_err(|_| Error::Poisoned)?;
        Ok(matches!(state.admission, ReservationAdmission::Sealed)
            && state.records.is_empty()
            && state.total == Counts::default()
            && state
                .tokens
                .values()
                .all(|counts| *counts == Counts::default()))
    }

    pub(super) fn inherited_counts(&self, token: &TokenIdentity) -> Result<(Counts, Counts)> {
        let mut total = Counts::default();
        let mut selected = Counts::default();
        let mut ancestor = self.retained_predecessor()?;
        while let Some(ledger) = ancestor {
            let state = ledger.state.lock().map_err(|_| Error::Poisoned)?;
            if !matches!(state.admission, ReservationAdmission::Sealed) {
                return Err(Error::Rejected(crate::RejectionReason::SessionAccounting(
                    crate::SessionAccountingRejection::PredecessorSessionAdmissionReopened,
                )));
            }
            total = total.combine(state.total)?;
            selected = selected.combine(state.tokens.get(token).copied().unwrap_or_default())?;
            drop(state);
            ancestor = ledger.retained_predecessor()?;
        }
        Ok((total, selected))
    }

    pub(crate) fn notify_admission(&self) {
        self.wake.notify();
    }

    pub(crate) fn notify_admission_on_drop(&self) -> AdmissionChange<'_> {
        AdmissionChange(self)
    }

    pub(crate) fn admission_wake(&self) -> Arc<Wake> {
        self.wake.clone()
    }

    /// The caller holds exclusive module possession. Seal and empty check are
    /// one ledger transaction, excluding a late reservation before Finalize.
    pub(crate) fn seal_empty(&self) -> Result<SessionSeal<'_>> {
        let mut state = self.state.lock().map_err(|_| Error::Poisoned)?;
        if !state.records.is_empty() {
            return Err(Error::Rejected(crate::RejectionReason::SessionAccounting(
                crate::SessionAccountingRejection::SessionsActive,
            )));
        }
        let previous = state.admission;
        state.admission = ReservationAdmission::Sealed;
        drop(state);
        self.wake.notify();
        Ok(SessionSeal {
            ledger: self,
            previous,
            committed: false,
        })
    }

    pub fn is_empty(&self) -> Result<bool> {
        Ok(self
            .state
            .lock()
            .map_err(|_| Error::Poisoned)?
            .records
            .is_empty())
    }

    // Returns the removed record so its Arc destructors run outside the ledger.
    pub(super) fn remove(
        state: &mut LedgerState,
        uid: u64,
        proof: &Arc<CreditProof>,
        terminal: u8,
    ) -> Result<Record> {
        let record = state.records.get(&uid).ok_or(Error::Rejected(
            crate::RejectionReason::SessionAccounting(
                crate::SessionAccountingRejection::SessionReservationAbsent,
            ),
        ))?;
        if !Arc::ptr_eq(&record.identity().proof, proof) {
            return Err(Error::Rejected(crate::RejectionReason::SessionAccounting(
                crate::SessionAccountingRejection::SessionOwnerMismatch,
            )));
        }
        match record {
            Record::Live { .. } | Record::RetainedReturned { .. } => {
                if proof.terminal.load(Ordering::Acquire) != QUOTA_UNSETTLED {
                    return Err(Error::Rejected(crate::RejectionReason::SessionAccounting(
                        crate::SessionAccountingRejection::SessionOwnerMismatch,
                    )));
                }
                Self::settle_quota(state, uid)?;
            }
            Record::RetainedWithoutHandle { .. } => {
                if terminal != RECORD_REMOVED
                    || proof.terminal.load(Ordering::Acquire) != QUOTA_SETTLED_RETAINED
                {
                    return Err(Error::Rejected(crate::RejectionReason::SessionAccounting(
                        crate::SessionAccountingRejection::SessionOwnerMismatch,
                    )));
                }
            }
        }
        let removed = state.records.remove(&uid).expect("checked reservation");
        proof.terminal.store(terminal, Ordering::Release);
        Self::close_binding(&removed);
        Ok(removed)
    }

    // All checked arithmetic precedes mutation. This releases only native quota;
    // it does not drop an Entry or claim that any native frame is no longer used.
    pub(super) fn settle_quota(state: &mut LedgerState, uid: u64) -> Result<()> {
        let record = state.records.get(&uid).ok_or(Error::Rejected(
            crate::RejectionReason::SessionAccounting(
                crate::SessionAccountingRejection::SessionReservationAbsent,
            ),
        ))?;
        let (Record::Live { identity, .. } | Record::RetainedReturned { identity, .. }) = record
        else {
            return Err(Error::Rejected(crate::RejectionReason::SessionAccounting(
                crate::SessionAccountingRejection::SessionOwnerMismatch,
            )));
        };
        let token = identity.token.clone();
        let total = state.total.release(identity.read_write)?;
        let token_total = state
            .tokens
            .get(&token)
            .ok_or(Error::Rejected(crate::RejectionReason::SessionAccounting(
                crate::SessionAccountingRejection::SessionCountInvariant,
            )))?
            .release(identity.read_write)?;
        if token_total.total == 0 {
            state.tokens.remove(&token);
        } else {
            *state.tokens.get_mut(&token).expect("checked token count") = token_total;
        }
        state.total = total;
        Ok(())
    }

    // Native or possibly native sessions only. Reserved capacity must not stop
    // the last native close from publishing logout, or masquerade as an object
    // that C_InitToken/C_CloseAllSessions would need to close.
    pub fn has_slot(&self, slot: CK_SLOT_ID) -> Result<bool> {
        Ok(self
            .state
            .lock()
            .map_err(|_| Error::Poisoned)?
            .records
            .values()
            .any(|r| r.identity().token.slot == slot as u64 && r.native_present()))
    }

    /// Close has already returned OK for `closed_uid`, but its ledger anchor is
    /// kept until all fallible local publication has finished. Reserved capacity
    /// and this exact UID do not prevent last-session logout publication.
    pub(crate) fn has_other_slot(&self, slot: CK_SLOT_ID, closed_uid: u64) -> Result<bool> {
        Ok(self
            .state
            .lock()
            .map_err(|_| Error::Poisoned)?
            .records
            .iter()
            .any(|(&uid, record)| {
                uid != closed_uid
                    && record.identity().token.slot == slot as u64
                    && record.native_present()
            }))
    }

    /// A current local session can witness a non-last close. Retained handles,
    /// reserved credits and old token generations are not such a witness.
    /// The caller owns the token transition; native failure can still withdraw
    /// the witness, so close publication must recheck the remaining population.
    pub(crate) fn has_other_open_session(
        &self,
        closing: &crate::module::SessionEntry,
    ) -> Result<bool> {
        let state = self.state.lock().map_err(|_| Error::Poisoned)?;
        Ok(state.records.iter().any(|(&uid, record)| {
            uid != closing.credit.uid()
                && record.phase() == Some(Phase::Open)
                && record.entry().is_some_and(|entry| {
                    entry.slot == closing.slot
                        && entry.generation == closing.generation
                        && entry.snapshot.admission_available()
                        && !entry.native_handle_retired()
                        && !entry.closed.load(Ordering::Acquire)
                        && !entry.close_attempted.load(Ordering::Acquire)
                        && !entry.close_pending.load(Ordering::Acquire)
                        && !entry.poisoned.load(Ordering::Acquire)
                })
        }))
    }

    pub fn has_retention(&self, identity: &TokenIdentity) -> Result<bool> {
        Ok(self
            .state
            .lock()
            .map_err(|_| Error::Poisoned)?
            .records
            .values()
            .any(|record| {
                matches!(
                    record,
                    Record::RetainedWithoutHandle { .. } | Record::RetainedReturned { .. }
                ) && record.identity().token == *identity
            }))
    }

    // Refresh is recovery, not implicit replacement of a healthy live pool.
    // The caller holds the shared slot writer, excluding new native activity.
    pub fn refreshable_slot(&self, slot: CK_SLOT_ID) -> Result<bool> {
        let state = self.state.lock().map_err(|_| Error::Poisoned)?;
        Ok(!state
            .records
            .values()
            .filter(|r| r.identity().token.slot == slot as u64)
            .any(|r| match r.entry() {
                Some(entry) => {
                    entry.close_pending.load(Ordering::Acquire)
                        || entry.recovery.has_pending_call()
                        || entry.snapshot.domain.has_pending_token_call()
                        || (r.live_native()
                            && entry.snapshot.valid.load(Ordering::Acquire)
                            && !entry.poisoned.load(Ordering::Acquire)
                            && !entry.close_attempted.load(Ordering::Acquire)
                            && !entry.closed.load(Ordering::Acquire))
                }
                None => r.phase() == Some(Phase::Opening),
            }))
    }

    // Error path only. Clone a stable owner under the short ledger guard;
    // invalidation and all native work occur after releasing this mutex.
    pub fn for_handle(
        &self,
        handle: CK_SESSION_HANDLE,
    ) -> Result<Arc<crate::module::SessionEntry>> {
        let state = self.state.lock().map_err(|_| Error::Poisoned)?;
        let mut found = state
            .records
            .values()
            .filter(|r| r.live_native())
            .filter_map(|r| r.entry())
            .filter(|e| e.handle == handle);
        let entry = found.next().cloned().ok_or(Error::Rejected(
            crate::RejectionReason::SessionAccounting(
                crate::SessionAccountingRejection::SessionOwnerAbsent,
            ),
        ))?;
        if found.next().is_some() {
            return Err(Error::Rejected(crate::RejectionReason::SessionAccounting(
                crate::SessionAccountingRejection::AmbiguousSessionOwner,
            )));
        }
        Ok(entry)
    }

    pub fn withdraw_slot(&self, slot: CK_SLOT_ID) -> Result<()> {
        let mut state = self.state.lock().map_err(|_| Error::Poisoned)?;
        let mut changed = None;
        for r in state
            .records
            .values_mut()
            .filter(|r| r.identity().token.slot == slot as u64)
        {
            r.change_phase(Phase::Quarantined);
            if let Some(e) = r.entry() {
                e.poisoned.store(true, Ordering::Release);
                changed = Some(e.snapshot.clone());
            }
        }
        drop(state);
        // All snapshots of this module share the resource notification set.
        if let Some(snapshot) = changed {
            snapshot.notify_admission();
        }
        Ok(())
    }

    // Used only by the final sole-owner destructor; never retains the mutex
    // while invoking a native close. Allocation failure retains the mapping.
    pub(crate) fn local_poisoned(&self) -> bool {
        self.state.is_poisoned()
    }

    pub(crate) fn local_candidates(
        &self,
        domain: &Arc<crate::module::SlotDomain>,
    ) -> Result<Vec<LocalCandidate>> {
        let state = self.state.lock().map_err(|_| Error::Poisoned)?;
        let candidate = |entry: &&Arc<crate::module::SessionEntry>| {
            Arc::ptr_eq(&entry.snapshot.domain, domain)
                && entry.advanced_operation.load(Ordering::Acquire) != 0
                && entry.advanced_progress.cleanup_hint()
        };
        let count = state
            .records
            .values()
            .filter_map(Record::entry)
            .filter(candidate)
            .count();
        let mut result = Vec::new();
        result.try_reserve_exact(count).map_err(|_| {
            Error::Rejected(crate::RejectionReason::SessionAccounting(
                crate::SessionAccountingRejection::SessionSnapshotAllocation,
            ))
        })?;
        for entry in state
            .records
            .values()
            .filter_map(Record::entry)
            .filter(candidate)
        {
            // Atomic hints may change between the counting and filling passes,
            // even while the ledger table itself is stable. Never let Vec::push
            // implicitly allocate for a newly marked entry.
            result.try_reserve(1).map_err(|_| {
                Error::Rejected(crate::RejectionReason::SessionAccounting(
                    crate::SessionAccountingRejection::SessionSnapshotAllocation,
                ))
            })?;
            result.push(LocalCandidate {
                uid: entry.credit.uid(),
                entry: Arc::downgrade(entry),
                blocked: false,
            });
        }
        Ok(result)
    }

    /// The caller holds the slot reader; an advanced owner excludes local close.
    /// The cloned Entry stays alive even if that owner disappears. The callback
    /// must revalidate eligibility under session possession before acting.
    pub(crate) fn with_local_candidate<T>(
        &self,
        candidate: &LocalCandidate,
        domain: &Arc<crate::module::SlotDomain>,
        _reader: &crate::admission_wait::ReadGuard<'_, ()>,
        use_entry: impl FnOnce(&crate::module::SessionEntry) -> Result<T>,
    ) -> Result<Option<T>> {
        let entry = {
            let state = self.state.lock().map_err(|_| Error::Poisoned)?;
            let Some(entry) = state.records.get(&candidate.uid).and_then(Record::entry) else {
                return Ok(None);
            };
            if !Weak::ptr_eq(&Arc::downgrade(entry), &candidate.entry)
                || !Arc::ptr_eq(&entry.snapshot.domain, domain)
                || entry.closed.load(Ordering::Acquire)
                || entry.close_attempted.load(Ordering::Acquire)
            {
                return Ok(None);
            }
            entry.clone()
        };
        // entry is destroyed here, before the caller can release its reader.
        use_entry(&entry).map(Some)
    }

    /// Readiness only: no borrowed State, token guard or native authority.
    /// A replaced/closed candidate simply causes the caller to revalidate.
    /// Drop the gate before the temporary Arc: its last destructor may run
    /// application-owned notification cleanup after concurrent finalization.
    pub(crate) fn wait_local_candidate(
        &self,
        candidate: &LocalCandidate,
        domain: &Arc<crate::module::SlotDomain>,
        admission: &crate::ResourceAdmission,
        allow_current: bool,
        before: impl Fn() -> Result<()>,
    ) -> Result<()> {
        before()?;
        let entry = {
            let state = self.state.lock().map_err(|_| Error::Poisoned)?;
            let Some(entry) = state.records.get(&candidate.uid).and_then(Record::entry) else {
                return Ok(());
            };
            if !Weak::ptr_eq(&Arc::downgrade(entry), &candidate.entry)
                || !Arc::ptr_eq(&entry.snapshot.domain, domain)
            {
                return Ok(());
            }
            entry.clone()
        };
        let ready = entry.operation.acquire_while(admission, || {
            before()?;
            Ok(!entry.closed.load(Ordering::Acquire)
                && !entry.close_attempted.load(Ordering::Acquire)
                && !entry.close_pending.load(Ordering::Acquire)
                && !entry.poisoned.load(Ordering::Acquire)
                && !entry.advanced_progress.is_poisoned()
                && entry.advanced_operation.load(Ordering::Acquire) != 0
                && entry.advanced_progress.cleanup_hint()
                && (allow_current || !entry.snapshot.valid.load(Ordering::Acquire)))
        });
        match ready {
            Ok(ready) => drop(ready),
            Err(Error::Poisoned) => {}
            Err(error) => return Err(error),
        }
        Ok(())
    }

    pub fn deferred(
        &self,
        maximum: usize,
        context: Option<&Arc<crate::module::TokenSnapshot>>,
    ) -> Result<Vec<Arc<crate::module::SessionEntry>>> {
        self.deferred_for(maximum, context, None)
    }

    pub(crate) fn deferred_for(
        &self,
        maximum: usize,
        context: Option<&Arc<crate::module::TokenSnapshot>>,
        client: Option<crate::module::ClientId>,
    ) -> Result<Vec<Arc<crate::module::SessionEntry>>> {
        let state = self.state.lock().map_err(|_| Error::Poisoned)?;
        let mut result = Vec::new();
        result
            .try_reserve(maximum.min(state.records.len()))
            .map_err(|_| {
                Error::Rejected(crate::RejectionReason::SessionAccounting(
                    crate::SessionAccountingRejection::SessionSnapshotAllocation,
                ))
            })?;
        for r in state.records.values().filter(|r| r.live_native()) {
            if result.len() == maximum {
                break;
            }
            if let Some(e) = r.entry() {
                if context.map_or(true, |token| Arc::ptr_eq(token, &e.snapshot))
                    && client.map_or(true, |client| e.credit.client_id() == client)
                    && (e.deferred_close.load(Ordering::Acquire)
                        || e.close_pending.load(Ordering::Acquire))
                    && !e.closed.load(Ordering::Acquire)
                    && (!e.close_attempted.load(Ordering::Acquire)
                        || e.close_pending.load(Ordering::Acquire))
                {
                    result.push(e.clone());
                }
            }
        }
        Ok(result)
    }

    pub fn status(&self) -> Result<ModuleResourceStatus> {
        let mut result = self.local_status()?;
        let mut ancestor = self.retained_predecessor()?;
        while let Some(ledger) = ancestor {
            let previous = ledger.local_status()?;
            result.usage.combine(previous.usage)?;
            result
                .tokens
                .try_reserve(previous.tokens.len())
                .map_err(|_| {
                    Error::Rejected(crate::RejectionReason::SessionAccounting(
                        crate::SessionAccountingRejection::SessionSnapshotAllocation,
                    ))
                })?;
            result.tokens.extend(previous.tokens);
            ancestor = ledger.retained_predecessor()?;
        }
        result
            .tokens
            .sort_unstable_by_key(|token| (token.generation, token.identity.slot));
        Ok(result)
    }

    pub(super) fn local_status(&self) -> Result<ModuleResourceStatus> {
        let state = self.state.lock().map_err(|_| Error::Poisoned)?;
        let mut tokens: Vec<TokenResourceStatus> = Vec::new();
        tokens.try_reserve(state.tokens.len()).map_err(|_| {
            Error::Rejected(crate::RejectionReason::SessionAccounting(
                crate::SessionAccountingRejection::SessionSnapshotAllocation,
            ))
        })?;
        let mut indices: HashMap<(TokenIdentity, u64), usize> = HashMap::new();
        let mut usage = SessionUsage::default();
        for r in state
            .records
            .values()
            .filter(|r| !matches!(r, Record::RetainedWithoutHandle { .. }))
        {
            usage.add(r);
            let key = (r.identity().token.clone(), r.identity().generation);
            if let Some(i) = indices.get(&key) {
                tokens[*i].usage.add(r);
            } else {
                indices.try_reserve(1).map_err(|_| {
                    Error::Rejected(crate::RejectionReason::SessionAccounting(
                        crate::SessionAccountingRejection::SessionSnapshotAllocation,
                    ))
                })?;
                tokens.try_reserve(1).map_err(|_| {
                    Error::Rejected(crate::RejectionReason::SessionAccounting(
                        crate::SessionAccountingRejection::SessionSnapshotAllocation,
                    ))
                })?;
                indices.insert(key, tokens.len());
                let mut current = SessionUsage::default();
                current.add(r);
                tokens.push(TokenResourceStatus {
                    identity: r.identity().token.clone(),
                    generation: r.identity().generation,
                    usage: current,
                });
            }
        }
        tokens.sort_unstable_by_key(|t| (t.generation, t.identity.slot));
        Ok(ModuleResourceStatus { usage, tokens })
    }

    pub(super) fn phase(&self, uid: u64, proof: &Arc<CreditProof>, phase: Phase) -> Result<()> {
        let mut state = self.state.lock().map_err(|_| Error::Poisoned)?;
        let record = state.records.get_mut(&uid).ok_or(Error::Rejected(
            crate::RejectionReason::SessionAccounting(
                crate::SessionAccountingRejection::SessionReservationAbsent,
            ),
        ))?;
        if !Arc::ptr_eq(&record.identity().proof, proof) {
            return Err(Error::Rejected(crate::RejectionReason::SessionAccounting(
                crate::SessionAccountingRejection::SessionOwnerMismatch,
            )));
        }
        if record
            .phase()
            .is_some_and(|current| current != Phase::Recovering)
        {
            record.change_phase(phase);
        }
        Ok(())
    }
}

impl SessionUsage {
    pub(super) fn combine(&mut self, other: Self) -> Result<()> {
        for (destination, source) in [
            (&mut self.total, other.total),
            (&mut self.read_write, other.read_write),
            (&mut self.reserved, other.reserved),
            (&mut self.opening, other.opening),
            (&mut self.open, other.open),
            (&mut self.closing, other.closing),
            (&mut self.recovering, other.recovering),
            (&mut self.deferred_close, other.deferred_close),
            (&mut self.quarantined, other.quarantined),
            (&mut self.retained_returned, other.retained_returned),
        ] {
            *destination = destination.checked_add(source).ok_or(Error::Rejected(
                crate::RejectionReason::SessionAccounting(
                    crate::SessionAccountingRejection::SessionStatusOverflow,
                ),
            ))?;
        }
        Ok(())
    }

    pub(super) fn add(&mut self, r: &Record) {
        if matches!(r, Record::RetainedReturned { .. }) {
            self.total += 1;
            self.read_write += usize::from(r.identity().read_write);
            self.retained_returned += 1;
            return;
        }
        let Some(current) = r.phase() else {
            return;
        };
        // At most one addition per existing record; the vector/map length is
        // representable and bounded by the successfully reserved module total.
        self.total += 1;
        self.read_write += usize::from(r.identity().read_write);
        let phase = if current == Phase::Open
            && r.entry()
                .is_some_and(|e| e.poisoned.load(Ordering::Acquire))
        {
            Phase::Quarantined
        } else {
            current
        };
        let phase = if matches!(phase, Phase::Open | Phase::Quarantined)
            && r.entry().is_some_and(|e| {
                e.deferred_close.load(Ordering::Acquire)
                    && !e.close_attempted.load(Ordering::Acquire)
            }) {
            Phase::DeferredClose
        } else {
            phase
        };
        match phase {
            Phase::DeferredClose => self.deferred_close += 1,
            Phase::Reserved => self.reserved += 1,
            Phase::Opening => self.opening += 1,
            Phase::Open => self.open += 1,
            Phase::Closing => self.closing += 1,
            Phase::Recovering => self.recovering += 1,
            Phase::Quarantined => self.quarantined += 1,
        }
    }
}
