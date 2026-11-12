// SPDX-License-Identifier: Apache-2.0
//! Registered advanced owners and their session occupation publication.
//!
//! The ledger mutex protects identity/table mutation only. Callers release it
//! before acquiring Operation; retired owners leave the ledger before Drop.
mod storage;
use super::{lease, Operation};
use crate::{module::SessionEntry, symmetric::memory::Budget, Error, Result};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
};
pub(super) use storage::{OperationCell, PreparedOperation};

/// Proof that this session owns a quiescent operation of the attempted category.
/// Its lifetime keeps session possession alive while existing readers are lent
/// to a competing Init. It never authorizes borrowing a foreign or any writer.
pub(crate) struct InitReaderBorrow<'a> {
    uid: u64,
    _possession: std::marker::PhantomData<&'a ()>,
}

impl InitReaderBorrow<'_> {
    pub(crate) fn uid(&self) -> u64 {
        self.uid
    }
}

pub(crate) fn init_reader_borrow<'a>(
    session: &crate::Session,
    access: &'a crate::session::SessionAccess<'_>,
    category: fe11_sys::CK_FLAGS,
) -> Result<Option<InitReaderBorrow<'a>>> {
    if session.entry.advanced_operation.load(Ordering::Acquire) == 0 {
        return Ok(None);
    }
    let held = access.operations.get(session.uid)?;
    let operation = held.lock().map_err(|_| Error::Poisoned)?;
    if operation.execution_incomplete() {
        return Err(Error::Busy(crate::BusyReason::OperationOwnership(
            crate::OperationOwnershipBusy::NativeOperationCallPending,
        )));
    }
    if operation.active_categories() & category == 0 {
        return Err(Error::Busy(crate::BusyReason::OperationOwnership(
            crate::OperationOwnershipBusy::AdvancedOperation,
        )));
    }
    Ok(Some(InitReaderBorrow {
        uid: session.uid,
        _possession: std::marker::PhantomData,
    }))
}

#[derive(Clone)]
struct RegisteredOperation {
    identity: Arc<lease::Identity>,
    operation: Arc<OperationCell>,
}

/// Extracted only after native termination; destroy outside coordination guards.
pub(crate) struct ClosedOperation {
    _owner: RegisteredOperation,
}

pub(crate) struct FinalizedOperations {
    owners: HashMap<u64, RegisteredOperation>,
    image: Arc<crate::native::image::LoadedImage>,
    quarantined: bool,
}
impl Drop for FinalizedOperations {
    fn drop(&mut self) {
        if self.quarantined {
            std::mem::forget(std::mem::take(&mut self.owners));
            std::mem::forget(self.image.clone());
        }
    }
}

/// Anchors the exact leases inspected for collective recovery, without ever
/// locking their operation bodies. Keep this outside all coordination guards.
pub(crate) struct RecoveryOwners(Vec<RegisteredOperation>);
impl RecoveryOwners {
    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }
    pub(crate) fn prove(&self, ledger: &crate::session_budget::SessionLedger) -> Result<()> {
        for owner in &self.0 {
            owner.identity.prove_stranded(ledger)?;
        }
        Ok(())
    }
}

pub(crate) struct Ledger {
    slots: Mutex<HashMap<u64, RegisteredOperation>>,
    next: AtomicU64,
    budget: Arc<Budget>,
    reference_wakes: [Arc<crate::admission_wait::Wake>; 2],
}
impl Ledger {
    /// Session possession excludes installation/replacement for this UID.
    /// Check the table as well as the published operation identifier.
    pub(crate) fn has_owner(&self, entry: &SessionEntry) -> Result<bool> {
        Ok(self
            .slots
            .lock()
            .map_err(|_| Error::Poisoned)?
            .contains_key(&entry.credit.uid()))
    }

    // Publish the revision before waking resource waiters. Notifications are
    // outside the progress leaf and carry no permission to use native state.
    pub(super) fn claim_progress(&self, entry: &SessionEntry, ticket: u64) -> Result<()> {
        entry.advanced_progress.claim(ticket)?;
        self.budget.notify_progress();
        entry.snapshot.domain.activity.notify();
        entry.operation.notify();
        Ok(())
    }

    pub(crate) fn local_poisoned(&self) -> bool {
        self.slots.is_poisoned()
    }

    pub(crate) fn maintain_owned(&self, proof: &crate::session::LocalOwnership<'_>) -> Result<()> {
        self.maintain(proof, false)
    }

    pub(crate) fn maintain_marked(&self, proof: &crate::session::LocalOwnership<'_>) -> Result<()> {
        self.maintain(proof, true)
    }

    fn maintain(
        &self,
        proof: &crate::session::LocalOwnership<'_>,
        skip_target_poison: bool,
    ) -> Result<()> {
        let entry = proof.entry();
        if !entry.advanced_progress.cleanup_hint() {
            return Ok(());
        }
        proof.validate()?;
        let ticket = entry.advanced_operation.load(Ordering::Acquire);
        if skip_target_poison && entry.advanced_progress.is_poisoned() {
            return Ok(());
        }
        let effects = match entry.advanced_progress.effects(ticket) {
            Ok(effects) => effects,
            Err(Error::Poisoned) if skip_target_poison => return Ok(()),
            Err(error) => return Err(error),
        };
        let Some(effects) = effects else {
            return Ok(());
        };
        // get releases the ledger before Operation is locked. The proof's
        // session gate and token possession exclude all normal/close observers.
        let held = self.get(entry.credit.uid())?;
        let mut operation = match held.lock() {
            Ok(operation) => operation,
            Err(_) if skip_target_poison => return Ok(()),
            Err(_) => return Err(Error::Poisoned),
        };
        if operation.id != ticket {
            return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::StaleOperationTicket,
            )));
        }
        if skip_target_poison
            && (operation.body.pending()
                || operation.uncancellable_retained()
                || operation.cancel.is_submitted()
                || operation.joined.is_some()
                || operation.transfer.as_ref().is_some())
        {
            // A hint never proves native completion. The owning facade must
            // finish these controls before a third-party sweep can reclaim.
            return Ok(());
        }
        use super::progress::Effect;
        if effects.causes[0].is_some() {
            operation.cleanup_capture_resource_failure();
            entry
                .advanced_progress
                .acknowledge(&effects, Effect::RemoveStateIo)?;
        }
        if effects.causes[1].is_some() {
            // This family has no local retirement effect. It must not remove a
            // pending collector to make the terminal predicate look favorable.
            entry
                .advanced_progress
                .acknowledge(&effects, Effect::PreserveOwner)?;
        }
        // A third-party caller receives only a local cleanup failure. A prior
        // waiter's Deadline/Cancelled is never injected into this caller's API.
        Ok(())
    }

    pub(crate) fn recovery_owners(
        &self,
        domain: &Arc<crate::module::SlotDomain>,
    ) -> Result<RecoveryOwners> {
        let mut owners = Vec::new();
        {
            let slots = self.slots.lock().map_err(|_| Error::Poisoned)?;
            let count = slots
                .values()
                .filter(|r| r.identity.stranded_in(domain))
                .count();
            owners.try_reserve_exact(count).map_err(|_| {
                Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                    crate::ModuleLifecycleRejection::RecoverySnapshotAllocation,
                ))
            })?;
            for (&uid, owner) in &*slots {
                if owner.identity.stranded_in(domain) {
                    if owner.identity.uid() != uid {
                        return Err(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                            crate::ModuleLifecycleRejection::RecoveryOwnerMismatch,
                        )));
                    }
                    owners.push(owner.clone());
                }
            }
        }
        Ok(RecoveryOwners(owners))
    }

    pub(crate) fn classify_failed_close(
        &self,
        proof: &crate::session::CloseOwnership<'_>,
    ) -> Result<()> {
        let identity = self
            .slots
            .lock()
            .map_err(|_| Error::Poisoned)?
            .get(&proof.entry().credit.uid())
            .map(|record| record.identity.clone());
        if let Some(identity) = identity {
            identity.classify(proof)?;
        }
        Ok(())
    }
    pub(crate) fn new(
        budget: Arc<Budget>,
        reference_wakes: [Arc<crate::admission_wait::Wake>; 2],
    ) -> Self {
        Self {
            slots: Mutex::new(HashMap::new()),
            next: AtomicU64::new(0),
            budget,
            reference_wakes,
        }
    }

    // The caller retains the session gate. Commit the ledger and the routing
    // indicator together; a waiter must not sleep after observing the old value.
    pub(super) fn install(
        &self,
        entry: &SessionEntry,
        operation: Operation,
    ) -> Result<(u64, Arc<OperationCell>)> {
        self.install_with(entry, operation, |_| {})
    }

    // The commit closure only transfers already prepared owners. It runs after
    // every fallible registry check and before publication, with no native call,
    // allocation, wait or fallible mutation. Inputs held by the caller therefore
    // remain returnable if admission fails.
    pub(super) fn install_with(
        &self,
        entry: &SessionEntry,
        operation: Operation,
        commit: impl FnOnce(&mut Operation),
    ) -> Result<(u64, Arc<OperationCell>)> {
        self.install_with_retained(entry, &mut Some(operation), &mut None, commit)
    }

    /// The caller retains the complete operation if a registry check refuses
    /// installation. Taking it is the final commit, after all fallible checks.
    pub(super) fn install_retained(
        &self,
        entry: &SessionEntry,
        operation: &mut Option<Operation>,
        prepared: &mut Option<PreparedOperation>,
    ) -> Result<(u64, Arc<OperationCell>)> {
        // This route never falls back to allocating under possession.
        if prepared.is_none() {
            return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::PreparedOperationStorageAbsent,
            )));
        }
        self.install_with_retained(entry, operation, prepared, |_| {})
    }

    // Legacy callers without a prepared cell use the same publication policy
    // as install_with, but keep their operation if a registry check refuses.
    // Prepaid common-start callers still require install_retained's cell.
    pub(super) fn install_with_retained(
        &self,
        entry: &SessionEntry,
        operation: &mut Option<Operation>,
        prepared: &mut Option<PreparedOperation>,
        commit: impl FnOnce(&mut Operation),
    ) -> Result<(u64, Arc<OperationCell>)> {
        let candidate = operation.as_ref().ok_or(Error::Rejected(
            crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::OperationCandidateAbsent,
            ),
        ))?;
        if let Some(prepared) = prepared.as_mut() {
            prepared.check()?;
        }
        let uid = entry.credit.uid();
        if !candidate._token.identity().matches(entry) {
            return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::ForeignOperationLeaseIdentity,
            )));
        }
        let identity = candidate._token.identity().clone();
        let mut slots = self.slots.lock().map_err(|_| Error::Poisoned)?;
        if slots.contains_key(&uid) {
            return Err(Error::Busy(crate::BusyReason::OperationOwnership(
                crate::OperationOwnershipBusy::AdvancedOperation,
            )));
        }
        slots.try_reserve(1).map_err(|_| {
            Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::OperationRegistryAllocation,
            ))
        })?;
        // slots is the sole ticket allocator; use MSRV-compatible operations.
        let id = self
            .next
            .load(Ordering::Acquire)
            .checked_add(1)
            .ok_or(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::OperationTicketExhausted,
            )))?;
        self.next.store(id, Ordering::Release);
        // The session gate excludes another publisher. This fallible leaf
        // check precedes consuming any caller input in the commit closure.
        entry
            .advanced_progress
            .install(id, &entry.advanced_operation)?;
        let mut operation = operation
            .take()
            .expect("operation checked before publication");
        operation.id = id;
        commit(&mut operation);
        let operation = match prepared.take() {
            Some(prepared) => prepared.finish(operation),
            None => OperationCell::ready(operation),
        };
        slots.insert(
            uid,
            RegisteredOperation {
                identity,
                operation: operation.clone(),
            },
        );
        drop(slots);
        self.budget.notify_progress();
        for wake in &self.reference_wakes {
            wake.notify();
        }
        Ok((id, operation))
    }
    pub(super) fn reserve_ticket(&self) -> Result<u64> {
        let _slots = self.slots.lock().map_err(|_| Error::Poisoned)?;
        let id = self
            .next
            .load(Ordering::Acquire)
            .checked_add(1)
            .ok_or(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::OperationTicketExhausted,
            )))?;
        self.next.store(id, Ordering::Release);
        Ok(id)
    }
    pub(super) fn get(&self, uid: u64) -> Result<Arc<OperationCell>> {
        self.slots
            .lock()
            .map_err(|_| Error::Poisoned)?
            .get(&uid)
            .filter(|registered| registered.identity.uid() == uid)
            .map(|registered| registered.operation.clone())
            .ok_or(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::OperationAbsent,
            )))
    }

    /// Called under the token writer, which excludes native dispatch and owner
    /// replacement. An initialized sequence is allowed; a native call that has
    /// not completed is not. Never retire an owner merely to permit Logout.
    pub(crate) fn logout_ready(&self, entry: &SessionEntry) -> Result<()> {
        let id = entry.advanced_operation.load(Ordering::Acquire);
        if id == 0 {
            return Ok(());
        }
        let held = self.get(entry.credit.uid())?;
        let operation = held.try_lock().map_err(|error| match error {
            std::sync::TryLockError::WouldBlock => {
                Error::Busy(crate::BusyReason::OperationOwnership(
                    crate::OperationOwnershipBusy::OperationObservationInProgress,
                ))
            }
            std::sync::TryLockError::Poisoned(_) => Error::Poisoned,
        })?;
        if operation.id != id {
            return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::StaleOperationTicket,
            )));
        }
        if operation.execution_incomplete() {
            return Err(Error::Busy(crate::BusyReason::OperationOwnership(
                crate::OperationOwnershipBusy::NativeOperationCallPending,
            )));
        }
        Ok(())
    }
    // Only cleanup uses this observation, under the slot writer and after
    // proving that the unique public session owner has been abandoned.
    pub(crate) fn abandoned_reader_quiescent(&self, uid: u64) -> Result<bool> {
        let operation = self
            .slots
            .lock()
            .map_err(|_| Error::Poisoned)?
            .get(&uid)
            .filter(|registered| registered.identity.uid() == uid)
            .map(|registered| registered.operation.clone());
        let Some(operation) = operation else {
            return Ok(true);
        };
        let operation = match operation.try_lock() {
            Ok(value) => value,
            Err(_) => return Ok(false),
        };
        Ok(!operation.body.pending()
            && !operation.uncancellable_retained()
            && !operation.cancel.is_submitted()
            && operation.joined.is_none()
            && operation.transfer.as_ref().is_none()
            && operation.state.as_ref().is_none())
    }
    pub(crate) fn release_closed(&self, entry: &SessionEntry) -> Result<()> {
        drop(self.take_closed(entry)?);
        Ok(())
    }

    pub(crate) fn take_closed(&self, entry: &SessionEntry) -> Result<Option<ClosedOperation>> {
        let removed = {
            let mut slots = self.slots.lock().map_err(|_| Error::Poisoned)?;
            entry.advanced_progress.retire(&entry.advanced_operation)?;
            let removed = slots.remove(&entry.credit.uid());
            removed
        };
        // Neither a credit destructor nor a wake may run under the ledger.
        self.budget.notify_progress();
        entry.operation.notify();
        Ok(removed.map(|owner| ClosedOperation { _owner: owner }))
    }

    // Native replacement has succeeded. Publish before consuming the saved
    // owner; a poisoned leaf is a local post-success failure, never a retry.
    pub(super) fn publish_replacement(&self, entry: &SessionEntry, id: u64) -> Result<()> {
        entry
            .advanced_progress
            .replace(id, &entry.advanced_operation)?;
        self.budget.notify_progress();
        entry.operation.notify();
        Ok(())
    }
    pub(crate) fn is_empty(&self) -> Result<bool> {
        Ok(self.slots.lock().map_err(|_| Error::Poisoned)?.is_empty())
    }

    /// Exclusive module possession prevents an owner from dispatching while
    /// this snapshot is inspected. The caller independently proves withdrawal.
    pub(crate) fn finalization_ready(&self, entries: &[Arc<SessionEntry>]) -> Result<()> {
        let owners = {
            let slots = self.slots.lock().map_err(|_| Error::Poisoned)?;
            for entry in entries {
                let occupied = entry.advanced_operation.load(Ordering::Acquire) != 0;
                if occupied != slots.contains_key(&entry.credit.uid()) {
                    return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                        crate::OperationOwnershipRejection::FinalizationOperationPopulation,
                    )));
                }
            }
            let mut owners = Vec::new();
            owners.try_reserve_exact(slots.len()).map_err(|_| {
                Error::Rejected(crate::RejectionReason::OperationOwnership(
                    crate::OperationOwnershipRejection::FinalizationOperationSnapshot,
                ))
            })?;
            for (&uid, owner) in &*slots {
                if owner.identity.uid() != uid
                    || !entries
                        .iter()
                        .any(|e| e.credit.uid() == uid && owner.identity.matches(e))
                {
                    return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                        crate::OperationOwnershipRejection::FinalizationOperationIdentity,
                    )));
                }
                owners.push(owner.clone());
            }
            owners
        };
        // Never acquire Operation while holding the registry mutex.
        for owner in &owners {
            let operation = owner.operation.try_lock().map_err(|error| match error {
                std::sync::TryLockError::WouldBlock => {
                    Error::Busy(crate::BusyReason::OperationOwnership(
                        crate::OperationOwnershipBusy::AdvancedFinalizationActivity,
                    ))
                }
                std::sync::TryLockError::Poisoned(_) => Error::Poisoned,
            })?;
            let entry = entries
                .iter()
                .find(|e| e.credit.uid() == owner.identity.uid())
                .expect("validated operation entry");
            if operation.id == 0 || operation.id != entry.advanced_operation.load(Ordering::Acquire)
            {
                return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                    crate::OperationOwnershipRejection::FinalizationOperationTicket,
                )));
            }
            if operation.execution_incomplete() {
                return Err(Error::Busy(crate::BusyReason::OperationOwnership(
                    crate::OperationOwnershipBusy::AdvancedNativeCompletionUnproven,
                )));
            }
        }
        Ok(())
    }

    /// A slot writer excludes dispatch and lease destruction. Retire only
    /// owners of withdrawn bindings whose execution is known to have returned.
    /// The registry keeps their graphs and byte credits until separate proof.
    pub(crate) fn retire_slot_admission(&self, slot: u64) -> Result<()> {
        let owners = {
            let slots = self.slots.lock().map_err(|_| Error::Poisoned)?;
            let mut owners = Vec::new();
            owners.try_reserve_exact(slots.len()).map_err(|_| {
                Error::Rejected(crate::RejectionReason::OperationOwnership(
                    crate::OperationOwnershipRejection::RetirementOwnerSnapshot,
                ))
            })?;
            for owner in slots.values() {
                if owner.identity.slot() == slot {
                    owners.push(owner.clone());
                }
            }
            owners
        };
        for owner in &owners {
            let operation = owner.operation.try_lock().map_err(|error| match error {
                std::sync::TryLockError::WouldBlock => {
                    Error::Busy(crate::BusyReason::OperationOwnership(
                        crate::OperationOwnershipBusy::AdvancedRetirementActivity,
                    ))
                }
                std::sync::TryLockError::Poisoned(_) => Error::Poisoned,
            })?;
            if !owner.identity.retired_binding() {
                return Err(Error::Busy(crate::BusyReason::OperationOwnership(
                    crate::OperationOwnershipBusy::LiveAdvancedTokenBinding,
                )));
            }
            if operation.execution_incomplete() {
                return Err(Error::Busy(crate::BusyReason::OperationOwnership(
                    crate::OperationOwnershipBusy::AdvancedNativeCompletionUnproven,
                )));
            }
            operation._token.retire_admission()?;
        }
        Ok(())
    }

    /// Finalize OK has already been recorded. Retirement is local and may be
    /// retried after publication failure; payloads leave the writer via the result.
    pub(crate) fn take_finalized(
        &self,
        entries: &[Arc<SessionEntry>],
        image: Arc<crate::native::image::LoadedImage>,
        quarantined: bool,
    ) -> Result<FinalizedOperations> {
        let owners = {
            let mut slots = self.slots.lock().map_err(|_| Error::Poisoned)?;
            for (&uid, owner) in &*slots {
                if owner.identity.uid() != uid
                    || !entries
                        .iter()
                        .any(|e| e.credit.uid() == uid && owner.identity.matches(e))
                {
                    return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                        crate::OperationOwnershipRejection::FinalizationOperationIdentity,
                    )));
                }
            }
            for entry in entries {
                entry.advanced_progress.retire(&entry.advanced_operation)?;
            }
            std::mem::take(&mut *slots)
        };
        self.budget.notify_progress();
        for entry in entries {
            entry.operation.notify();
        }
        Ok(FinalizedOperations {
            owners,
            image,
            quarantined,
        })
    }
    // Sole-owner failure: retain buffers with the already quarantined mapping.
    // This is exceptional cleanup uncertainty, not the nominal abandonment path.
    pub(crate) fn quarantine(&mut self) {
        let slots = self.slots.get_mut().unwrap_or_else(|p| p.into_inner());
        if !slots.is_empty() {
            std::mem::forget(std::mem::take(slots));
        }
    }
}
