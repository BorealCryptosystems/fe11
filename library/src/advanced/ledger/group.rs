// SPDX-License-Identifier: Apache-2.0
//! Owners installed on one native session. A single operation stays inline.
//! Snapshot membership under the registry mutex, then inspect each operation
//! under session possession after releasing the registry mutex.
use super::RegisteredOperation;
use crate::{Error, OperationOwnershipRejection, RejectionReason, Result};

pub(super) struct SessionOwners {
    first: RegisteredOperation,
    companions: Vec<RegisteredOperation>,
    // Counted leases prepared for C_SetOperationState. Recovery sees these
    // leases immediately; ordinary callers cannot route to them before OK.
    replacements: Vec<RegisteredOperation>,
}

impl SessionOwners {
    pub(super) fn single(first: RegisteredOperation) -> Self {
        Self {
            first,
            companions: Vec::new(),
            replacements: Vec::new(),
        }
    }

    pub(super) fn iter(&self) -> impl Iterator<Item = &RegisteredOperation> {
        std::iter::once(&self.first).chain(&self.companions)
    }

    pub(super) fn retained(&self) -> impl Iterator<Item = &RegisteredOperation> {
        self.iter().chain(&self.replacements)
    }

    pub(super) fn reserve_member(&mut self) -> Result<()> {
        self.companions.try_reserve_exact(1).map_err(|_| {
            Error::Rejected(RejectionReason::OperationOwnership(
                OperationOwnershipRejection::OperationRegistryAllocation,
            ))
        })
    }

    pub(super) fn insert_reserved(&mut self, owner: RegisteredOperation) {
        self.companions.push(owner);
    }

    pub(super) fn only(&self) -> Option<&RegisteredOperation> {
        self.companions.is_empty().then_some(&self.first)
    }

    /// Remove one known member without allocating or changing any survivor's ticket.
    pub(super) fn extract(&mut self, index: usize) -> RegisteredOperation {
        if index == 0 {
            let next = self
                .companions
                .pop()
                .expect("another group member was established");
            std::mem::replace(&mut self.first, next)
        } else {
            self.companions.swap_remove(index - 1)
        }
    }

    pub(super) fn snapshot(&self) -> Result<OwnerSnapshot> {
        let mut live: [Option<RegisteredOperation>; 5] = Default::default();
        let mut staged: [Option<RegisteredOperation>; 4] = Default::default();
        for (index, member) in self.iter().enumerate() {
            *live.get_mut(index).ok_or_else(registry_error)? = Some(member.clone());
        }
        for (index, member) in self.replacements.iter().enumerate() {
            *staged.get_mut(index).ok_or_else(registry_error)? = Some(member.clone());
        }
        Ok(OwnerSnapshot { live, staged })
    }
}

pub(super) struct OwnerSnapshot {
    live: [Option<RegisteredOperation>; 5],
    staged: [Option<RegisteredOperation>; 4],
}
impl OwnerSnapshot {
    pub(super) fn iter(&self) -> impl Iterator<Item = &RegisteredOperation> {
        self.live.iter().flatten()
    }
    pub(super) fn retained(&self) -> impl Iterator<Item = &RegisteredOperation> {
        self.iter().chain(self.staged.iter().flatten())
    }
}

impl super::Ledger {
    /// A state transfer or an unreturned native loan owns the session. Called
    /// under possession before advancing another operation. Never inspect the
    /// caller's own body here: the caller may already hold its mutex.
    pub(in crate::advanced) fn check_peer_control(
        &self,
        entry: &crate::module::SessionEntry,
        ticket: u64,
    ) -> Result<()> {
        let Some(owners) = self.session_owners(entry)? else {
            return Ok(());
        };
        for owner in owners.iter().filter(|r| r.operation.ticket() != ticket) {
            let peer = owner.operation.lock().map_err(|_| Error::Poisoned)?;
            if peer.execution_incomplete()
                || peer.state.is_some()
                || peer.transfer.is_some()
                || peer.cancel.is_submitted()
            {
                return Err(Error::Busy(crate::BusyReason::OperationOwnership(
                    crate::OperationOwnershipBusy::OperationStateControl,
                )));
            }
        }
        Ok(())
    }

    /// The PKCS#11 login has no key or operation argument. Validate every
    /// sibling under the session gate before attributing a PIN to one ticket.
    /// A digest can have consumed a key even though its mechanism is keyless.
    pub(in crate::advanced) fn check_context_siblings(
        &self,
        entry: &crate::module::SessionEntry,
        ticket: u64,
    ) -> Result<()> {
        let Some(owners) = self.session_owners(entry)? else {
            return Ok(());
        };
        for owner in owners.iter().filter(|r| r.operation.ticket() != ticket) {
            let body = owner.operation.lock().map_err(|_| Error::Poisoned)?;
            let keyless = matches!(&body.body, crate::advanced::OperationBody::Digest(digest)
                if digest.input.progress.key_inputs == 0 && !digest.input.retained_submission);
            if !keyless || body.execution_incomplete() || !body.permits_search_between_calls() {
                return Err(ambiguous_key());
            }
        }
        Ok(())
    }

    /// A new key-bearing operation or DigestKey could consume another
    /// operation's context login. The caller holds session possession.
    pub(in crate::advanced) fn check_key_dispatch(
        &self,
        entry: &crate::module::SessionEntry,
        ticket: Option<u64>,
    ) -> Result<()> {
        let Some(owners) = self.session_owners(entry)? else {
            return Ok(());
        };
        if owners
            .iter()
            .any(|r| Some(r.operation.ticket()) != ticket && r.operation.context_key.is_bound())
        {
            return Err(ambiguous_key());
        }
        Ok(())
    }
}

fn ambiguous_key() -> Error {
    Error::Rejected(RejectionReason::Authentication(
        crate::AuthenticationRejection::AmbiguousContextKey,
    ))
}

fn registry_error() -> Error {
    Error::Rejected(RejectionReason::OperationOwnership(
        OperationOwnershipRejection::OperationRegistryAllocation,
    ))
}

#[derive(Default)]
pub(in crate::advanced) struct StagedOwners(Vec<RegisteredOperation>);

impl StagedOwners {
    pub(in crate::advanced) fn member_bytes() -> usize {
        std::mem::size_of::<RegisteredOperation>()
    }

    pub(in crate::advanced) fn reserve(&mut self, count: usize) -> Result<()> {
        self.0
            .try_reserve_exact(count)
            .map_err(|_| registry_error())
    }

    pub(in crate::advanced) fn add(
        &mut self,
        operation: super::Operation,
        cell: super::PreparedOperation,
    ) -> std::sync::Arc<super::OperationCell> {
        let identity = operation._token.identity().clone();
        let cell = cell.finish(operation);
        self.0.push(RegisteredOperation {
            identity,
            operation: cell.clone(),
        });
        cell
    }
}

impl super::Ledger {
    pub(in crate::advanced) fn stage_replacement(
        &self,
        entry: &crate::module::SessionEntry,
        prepared: &mut StagedOwners,
    ) -> Result<()> {
        let mut slots = self.slots.lock().map_err(|_| Error::Poisoned)?;
        let group = slots
            .get_mut(&entry.credit.uid())
            .ok_or_else(registry_error)?;
        if !group.replacements.is_empty() {
            return Err(registry_error());
        }
        std::mem::swap(&mut group.replacements, &mut prepared.0);
        Ok(())
    }

    pub(in crate::advanced) fn discard_staged(
        &self,
        entry: &crate::module::SessionEntry,
    ) -> Result<StagedOwners> {
        let mut slots = self.slots.lock().map_err(|_| Error::Poisoned)?;
        let group = slots
            .get_mut(&entry.credit.uid())
            .ok_or_else(registry_error)?;
        Ok(StagedOwners(std::mem::take(&mut group.replacements)))
    }

    /// Session possession excludes all dispatch. The caller keeps the old
    /// owners until it has released both the operation and session guards.
    pub(in crate::advanced) fn commit_state_group(
        &self,
        entry: &crate::module::SessionEntry,
        primary: &super::OperationCell,
        id: u64,
    ) -> Result<super::ClosedOperation> {
        let mut slots = self.slots.lock().map_err(|_| Error::Poisoned)?;
        let current = slots
            .get_mut(&entry.credit.uid())
            .ok_or_else(registry_error)?;
        let first = current
            .iter()
            .find(|owner| std::ptr::eq(owner.operation.as_ref(), primary))
            .cloned()
            .ok_or_else(registry_error)?;
        for owner in current
            .iter()
            .filter(|owner| !std::sync::Arc::ptr_eq(&owner.operation, &first.operation))
        {
            entry
                .advanced_progress
                .retire_one(owner.operation.ticket(), &entry.advanced_operation)?;
        }
        for owner in &current.replacements {
            entry
                .advanced_progress
                .install(owner.operation.ticket(), &entry.advanced_operation)?;
        }
        self.replace_identity(entry, primary, id)?;
        let mut next = SessionOwners::single(first);
        next.companions = std::mem::take(&mut current.replacements);
        let previous = std::mem::replace(current, next);
        drop(slots);
        self.notify_claim(entry);
        Ok(super::ClosedOperation { _owners: previous })
    }
}

impl super::Ledger {
    /// Copy the live cell anchors without locking their bodies or allocating.
    pub(in crate::advanced) fn live_cells(
        &self,
        uid: u64,
    ) -> Result<[Option<std::sync::Arc<super::OperationCell>>; 5]> {
        let slots = self.slots.lock().map_err(|_| Error::Poisoned)?;
        let mut cells = Default::default();
        let output: &mut [Option<std::sync::Arc<super::OperationCell>>; 5] = &mut cells;
        if let Some(group) = slots.get(&uid) {
            for (index, member) in group.iter().enumerate() {
                *output.get_mut(index).ok_or_else(registry_error)? = Some(member.operation.clone());
            }
        }
        Ok(cells)
    }
}

impl super::Ledger {
    /// Preserve each family's detailed single-owner diagnostic. With several
    /// owners, transfer only a uniquely matching parked observer.
    pub(in crate::advanced) fn parked_cell(
        &self,
        uid: u64,
        matches: impl Fn(&super::Operation) -> bool,
    ) -> Result<std::sync::Arc<super::OperationCell>> {
        let cells = self.live_cells(uid)?;
        let mut live = cells.iter().flatten();
        let absent = || {
            Error::Rejected(RejectionReason::OperationOwnership(
                OperationOwnershipRejection::OperationAbsent,
            ))
        };
        let first = live.next().ok_or_else(absent)?;
        if live.next().is_none() {
            return Ok(first.clone());
        }
        let mut selected = None;
        for cell in cells.iter().flatten() {
            let operation = cell.lock().map_err(|_| Error::Poisoned)?;
            if matches(&operation) && selected.replace(cell.clone()).is_some() {
                return Err(Error::Busy(crate::BusyReason::OperationOwnership(
                    crate::OperationOwnershipBusy::AdvancedOperation,
                )));
            }
        }
        selected.ok_or_else(absent)
    }
}
