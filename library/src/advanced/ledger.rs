// SPDX-License-Identifier: Apache-2.0
//! Registered advanced owners and their session occupation publication.
//!
//! The ledger mutex protects identity/table mutation only. Callers release it
//! before acquiring Operation; retired owners leave the ledger before Drop.
mod group;
mod storage;
use super::{lease, Operation};
use crate::{module::SessionEntry, symmetric::memory::Budget, Error, Result};
use group::SessionOwners;
pub(in crate::advanced) use group::StagedOwners;
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
    predecessor: Arc<OperationCell>,
    siblings: [Option<Arc<OperationCell>>; 5],
    _possession: std::marker::PhantomData<&'a ()>,
}

impl InitReaderBorrow<'_> {
    pub(crate) fn allowance(
        &self,
        activity: &Arc<crate::registry::Activity>,
    ) -> Result<(u64, usize)> {
        let readers = |cell: &Arc<OperationCell>| -> Result<usize> {
            let member = cell.lock().map_err(|_| Error::Poisoned)?;
            Ok(match &member.body {
                super::OperationBody::Signature(owner) => owner.readers_on(activity, self.uid),
                super::OperationBody::Cipher(owner) => owner.readers_on(activity, self.uid),
                _ => 0,
            })
        };
        // A transferred role may share a physical permission. A peer retaining
        // it prevents attribution to the predecessor alone.
        for cell in self.siblings.iter().flatten() {
            if !Arc::ptr_eq(cell, &self.predecessor) && readers(cell)? != 0 {
                return Ok((self.uid, 0));
            }
        }
        Ok((self.uid, readers(&self.predecessor)?))
    }

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
    if category != fe11_sys::CKF_DIGEST {
        access.operations.check_key_dispatch(&session.entry, None)?;
    }
    let matching = access.operations.init_target(&session.entry, category)?;
    let Some(predecessor) = matching else {
        return Ok(None);
    };
    Ok(Some(InitReaderBorrow {
        uid: session.uid,
        predecessor,
        siblings: access.operations.live_cells(session.uid)?,
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
    _owners: SessionOwners,
}

pub(crate) struct FinalizedOperations {
    owners: HashMap<u64, SessionOwners>,
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
            owner
                .identity
                .prove_stranded(ledger, owner.operation.ticket())?;
        }
        Ok(())
    }
}

pub(crate) struct Ledger {
    slots: Mutex<HashMap<u64, SessionOwners>>,
    next: AtomicU64,
    budget: Arc<Budget>,
    reference_wakes: [Arc<crate::admission_wait::Wake>; 2],
}
impl Ledger {
    /// The caller owns the session gate. A search has a separate observation
    /// owner and borrows neither the crypto ticket nor its mechanism buffers.
    pub(crate) fn check_search_peer(&self, entry: &SessionEntry) -> Result<()> {
        self.check_search_peer_for(entry, true)
    }

    /// Final only releases the cursor. It does not inspect an object or
    /// publish a handle, but cannot overlap an outstanding native loan.
    pub(crate) fn check_search_final(&self, entry: &SessionEntry) -> Result<()> {
        self.check_search_peer_for(entry, false)
    }

    fn check_search_peer_for(&self, entry: &SessionEntry, publishes_handles: bool) -> Result<()> {
        let Some(owners) = self.session_owners(entry)? else {
            return Ok(());
        };
        for owner in owners.iter() {
            let operation = owner.operation.lock().map_err(|_| Error::Poisoned)?;
            if operation.id != owner.operation.ticket() || !owner.identity.matches(entry) {
                return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                    crate::OperationOwnershipRejection::StaleOperationTicket,
                )));
            }
            if operation.execution_incomplete() {
                return Err(Error::Busy(crate::BusyReason::OperationOwnership(
                    crate::OperationOwnershipBusy::NativeOperationCallPending,
                )));
            }
            if publishes_handles && !operation.permits_search_between_calls() {
                return Err(Error::Busy(crate::BusyReason::OperationOwnership(
                    crate::OperationOwnershipBusy::AdvancedOperation,
                )));
            }
        }
        Ok(())
    }

    /// Find the owner of this exact native category. Independent classic
    /// operations can remain parked while the caller issues the second Init.
    /// A pending call may still own native operands and excludes dispatch.
    pub(in crate::advanced) fn init_target(
        &self,
        entry: &SessionEntry,
        category: fe11_sys::CK_FLAGS,
    ) -> Result<Option<Arc<OperationCell>>> {
        let Some(owners) = self.session_owners(entry)? else {
            return Ok(None);
        };
        let mut matching = None;
        for owner in owners.iter() {
            let operation = owner.operation.lock().map_err(|_| Error::Poisoned)?;
            if operation.execution_incomplete() {
                return Err(Error::Busy(crate::BusyReason::OperationOwnership(
                    crate::OperationOwnershipBusy::NativeOperationCallPending,
                )));
            }
            if operation.classic_category() == Some(category)
                || operation.active_categories() & category != 0
            {
                matching = Some(owner.operation.clone());
            } else if !operation.permits_search_between_calls() {
                return Err(Error::Busy(crate::BusyReason::OperationOwnership(
                    crate::OperationOwnershipBusy::AdvancedOperation,
                )));
            }
        }
        Ok(matching)
    }

    fn session_owners(&self, entry: &SessionEntry) -> Result<Option<group::OwnerSnapshot>> {
        if entry.advanced_operation.load(Ordering::Acquire) == 0 {
            return Ok(None);
        }
        self.slots
            .lock()
            .map_err(|_| Error::Poisoned)?
            .get(&entry.credit.uid())
            .ok_or(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::OperationAbsent,
            )))?
            .snapshot()
            .map(Some)
    }

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
        self.check_peer_control(entry, ticket)?;
        entry.advanced_progress.claim(ticket)?;
        self.notify_claim(entry);
        Ok(())
    }

    pub(super) fn notify_claim(&self, entry: &SessionEntry) {
        self.budget.notify_progress();
        entry.snapshot.domain.activity.notify();
        entry.operation.notify();
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
        let Some(owners) = self.session_owners(entry)? else {
            return Ok(());
        };
        for owner in owners.iter() {
            self.maintain_operation(entry, &owner.operation, skip_target_poison)?;
        }
        Ok(())
    }

    fn maintain_operation(
        &self,
        entry: &SessionEntry,
        held: &Arc<OperationCell>,
        skip_target_poison: bool,
    ) -> Result<()> {
        let ticket = held.ticket();
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
                .flat_map(SessionOwners::retained)
                .filter(|r| r.identity.stranded_in(domain))
                .count();
            owners.try_reserve_exact(count).map_err(|_| {
                Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                    crate::ModuleLifecycleRejection::RecoverySnapshotAllocation,
                ))
            })?;
            for (&uid, owner) in slots
                .iter()
                .flat_map(|(uid, group)| group.retained().map(move |r| (uid, r)))
            {
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
        let owners = self
            .slots
            .lock()
            .map_err(|_| Error::Poisoned)?
            .get(&proof.entry().credit.uid())
            .map(SessionOwners::snapshot)
            .transpose()?;
        if let Some(owners) = owners {
            for owner in owners.retained() {
                owner.identity.classify(proof, owner.operation.ticket())?;
            }
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
        let occupied = entry.advanced_operation.load(Ordering::Acquire) != 0;
        if occupied {
            let category = candidate.classic_category().ok_or(Error::Busy(
                crate::BusyReason::OperationOwnership(
                    crate::OperationOwnershipBusy::AdvancedOperation,
                ),
            ))?;
            if category != fe11_sys::CKF_DIGEST {
                self.check_key_dispatch(entry, None)?;
            }
            if self.init_target(entry, category)?.is_some() {
                return Err(Error::Busy(crate::BusyReason::OperationOwnership(
                    crate::OperationOwnershipBusy::AdvancedOperation,
                )));
            }
        }
        let mut slots = self.slots.lock().map_err(|_| Error::Poisoned)?;
        if let Some(group) = slots.get_mut(&uid) {
            if !occupied {
                return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                    crate::OperationOwnershipRejection::FinalizationOperationPopulation,
                )));
            }
            group.reserve_member()?;
        } else {
            slots.try_reserve(1).map_err(|_| {
                Error::Rejected(crate::RejectionReason::OperationOwnership(
                    crate::OperationOwnershipRejection::OperationRegistryAllocation,
                ))
            })?;
        }
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
        let registered = RegisteredOperation {
            identity,
            operation: operation.clone(),
        };
        match slots.entry(uid) {
            std::collections::hash_map::Entry::Occupied(mut slot) => {
                slot.get_mut().insert_reserved(registered);
            }
            std::collections::hash_map::Entry::Vacant(slot) => {
                slot.insert(SessionOwners::single(registered));
            }
        }
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
            .and_then(SessionOwners::only)
            .filter(|registered| registered.identity.uid() == uid)
            .map(|registered| registered.operation.clone())
            .ok_or(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::OperationAbsent,
            )))
    }

    /// Route to the exact operation before taking the body lock. The caller
    /// still validates the locked body because local metadata readers can
    /// overlap replacement after the registry snapshot.
    pub(super) fn get_ticket(&self, uid: u64, ticket: u64) -> Result<Arc<OperationCell>> {
        self.get_ticket_with(
            uid,
            ticket,
            crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::StaleOperationTicket,
            ),
        )
    }

    /// Preserve the caller's typed stale-ticket diagnostic for an occupied
    /// session. A completely absent session retains its separate diagnostic.
    pub(super) fn get_ticket_with(
        &self,
        uid: u64,
        ticket: u64,
        stale: crate::RejectionReason,
    ) -> Result<Arc<OperationCell>> {
        let slots = self.slots.lock().map_err(|_| Error::Poisoned)?;
        let group =
            slots
                .get(&uid)
                .ok_or(Error::Rejected(crate::RejectionReason::OperationOwnership(
                    crate::OperationOwnershipRejection::OperationAbsent,
                )))?;
        let selected = group
            .iter()
            .find(|owner| owner.identity.uid() == uid && owner.operation.ticket() == ticket)
            .map(|owner| owner.operation.clone());
        selected.ok_or(Error::Rejected(stale))
    }

    /// Called under the token writer, which excludes native dispatch and owner
    /// replacement. An initialized sequence is allowed; a native call that has
    /// not completed is not. Login and Logout use this observation without
    /// retiring an owner or releasing any retained native buffer.
    pub(crate) fn logout_ready(&self, entry: &SessionEntry) -> Result<()> {
        let Some(owners) = self.session_owners(entry)? else {
            return Ok(());
        };
        for owner in owners.iter() {
            let operation = owner.operation.try_lock().map_err(|error| match error {
                std::sync::TryLockError::WouldBlock => {
                    Error::Busy(crate::BusyReason::OperationOwnership(
                        crate::OperationOwnershipBusy::OperationObservationInProgress,
                    ))
                }
                std::sync::TryLockError::Poisoned(_) => Error::Poisoned,
            })?;
            if operation.id != owner.operation.ticket() || !owner.identity.matches(entry) {
                return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                    crate::OperationOwnershipRejection::StaleOperationTicket,
                )));
            }
            if operation.execution_incomplete() {
                return Err(Error::Busy(crate::BusyReason::OperationOwnership(
                    crate::OperationOwnershipBusy::NativeOperationCallPending,
                )));
            }
        }
        Ok(())
    }
    // Only cleanup uses this observation, under the slot writer and after
    // proving that the unique public session owner has been abandoned.
    pub(crate) fn abandoned_reader_quiescent(&self, uid: u64) -> Result<bool> {
        let owners = self
            .slots
            .lock()
            .map_err(|_| Error::Poisoned)?
            .get(&uid)
            .map(SessionOwners::snapshot)
            .transpose()?;
        if let Some(owners) = owners {
            for owner in owners.iter() {
                if owner.identity.uid() != uid {
                    return Ok(false);
                }
                let operation = match owner.operation.try_lock() {
                    Ok(operation) => operation,
                    Err(_) => return Ok(false),
                };
                if operation.body.pending()
                    || operation.uncancellable_retained()
                    || operation.cancel.is_submitted()
                    || operation.joined.is_some()
                    || operation.transfer.as_ref().is_some()
                    || operation.state.as_ref().is_some()
                {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }
    pub(crate) fn release_closed(&self, entry: &SessionEntry) -> Result<()> {
        drop(self.take_closed(entry)?);
        Ok(())
    }

    pub(crate) fn take_closed(&self, entry: &SessionEntry) -> Result<Option<ClosedOperation>> {
        self.remove_owner(entry, None)
    }

    /// Ordinary completion retires the operation whose native loan ended.
    /// A session close holds separate authority over every operation in it.
    pub(super) fn take_operation(
        &self,
        entry: &SessionEntry,
        lease: &Arc<lease::Identity>,
    ) -> Result<Option<ClosedOperation>> {
        self.remove_owner(entry, Some(lease))
    }

    pub(super) fn release_operation(
        &self,
        entry: &SessionEntry,
        lease: &Arc<lease::Identity>,
    ) -> Result<()> {
        drop(self.take_operation(entry, lease)?);
        Ok(())
    }

    fn remove_owner(
        &self,
        entry: &SessionEntry,
        expected: Option<&Arc<lease::Identity>>,
    ) -> Result<Option<ClosedOperation>> {
        let removed = {
            let mut slots = self.slots.lock().map_err(|_| Error::Poisoned)?;
            let uid = entry.credit.uid();
            if let Some(identity) = expected {
                let Some(group) = slots.get_mut(&uid) else {
                    return Ok(None);
                };
                let (index, id) = group
                    .iter()
                    .enumerate()
                    .find(|(_, owner)| Arc::ptr_eq(identity, &owner.identity))
                    .map(|(index, owner)| (index, owner.operation.ticket()))
                    .ok_or(Error::Rejected(crate::RejectionReason::OperationOwnership(
                        crate::OperationOwnershipRejection::StaleOperationTicket,
                    )))?;
                entry
                    .advanced_progress
                    .retire_one(id, &entry.advanced_operation)?;
                if group.only().is_some() {
                    slots.remove(&uid)
                } else {
                    Some(SessionOwners::single(group.extract(index)))
                }
            } else {
                entry.advanced_progress.retire(&entry.advanced_operation)?;
                slots.remove(&uid)
            }
        };
        // Neither a credit destructor nor a wake may run under the ledger.
        self.budget.notify_progress();
        entry.operation.notify();
        Ok(removed.map(|owner| ClosedOperation { _owners: owner }))
    }

    // Native replacement has succeeded. Publish before consuming the saved
    // owner; a poisoned leaf is a local post-success failure, never a retry.
    pub(super) fn publish_replacement(
        &self,
        entry: &SessionEntry,
        cell: &OperationCell,
        id: u64,
    ) -> Result<()> {
        self.replace_identity(entry, cell, id)?;
        self.notify_claim(entry);
        Ok(())
    }

    fn replace_identity(&self, entry: &SessionEntry, cell: &OperationCell, id: u64) -> Result<()> {
        // An idle destination already has the fresh restore identity. A
        // replacement invalidates the previous operation and its context login.
        if cell.ticket() != id {
            entry
                .advanced_progress
                .replace(cell.ticket(), id, &entry.advanced_operation)?;
        } else {
            entry.advanced_progress.claim(id)?;
        }
        cell.publish_ticket(id);
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
            owners
                .try_reserve_exact(slots.values().flat_map(SessionOwners::retained).count())
                .map_err(|_| {
                    Error::Rejected(crate::RejectionReason::OperationOwnership(
                        crate::OperationOwnershipRejection::FinalizationOperationSnapshot,
                    ))
                })?;
            for (&uid, owner) in slots
                .iter()
                .flat_map(|(uid, group)| group.retained().map(move |r| (uid, r)))
            {
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
            if operation.id == 0 || operation.id != owner.operation.ticket() {
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
            owners
                .try_reserve_exact(slots.values().flat_map(SessionOwners::retained).count())
                .map_err(|_| {
                    Error::Rejected(crate::RejectionReason::OperationOwnership(
                        crate::OperationOwnershipRejection::RetirementOwnerSnapshot,
                    ))
                })?;
            for owner in slots.values().flat_map(SessionOwners::retained) {
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
            for (&uid, owner) in slots
                .iter()
                .flat_map(|(uid, group)| group.retained().map(move |r| (uid, r)))
            {
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
