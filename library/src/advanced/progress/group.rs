// SPDX-License-Identifier: Apache-2.0
//! Session possession serializes installation and retirement. Each concurrent
//! operation has its own revision, waiters and cleanup effects. Stable cells
//! let a resource waiter observe its ticket without taking the session gate or
//! a second mutex while holding a resource wake lock.
use super::{Effect, Effects, Leaf, Lifecycle, ResourceCause, Stamp};
use crate::{Error, OperationOwnershipRejection, RejectionReason, Result};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    OnceLock,
};

#[derive(Default)]
pub(crate) struct Progress {
    leaf: Leaf,
    next: OnceLock<Box<Progress>>,
    // Only dynamically added leaves own a storage credit.
    _storage: Option<crate::symmetric::memory::Credit>,
}

impl Progress {
    fn leaves(&self) -> impl Iterator<Item = &Leaf> {
        std::iter::successors(Some(self), |node| node.next.get().map(Box::as_ref))
            .map(|node| &node.leaf)
    }

    fn find(&self, ticket: u64) -> Option<&Leaf> {
        self.leaves()
            .find(|leaf| ticket != 0 && leaf.ticket.load(Ordering::Acquire) == ticket)
    }

    fn required(&self, ticket: u64) -> Result<&Leaf> {
        self.find(ticket)
            .ok_or(Error::Rejected(RejectionReason::OperationOwnership(
                OperationOwnershipRejection::StaleOperationTicket,
            )))
    }

    pub(crate) fn contains(&self, ticket: u64) -> bool {
        self.find(ticket)
            .is_some_and(|leaf| leaf.lifecycle.load(Ordering::Acquire) == Lifecycle::Live as u8)
    }

    /// Copy ticket identities and revisions under session possession. The
    /// named classic categories cap simultaneous independent operations at
    /// five; a combined driver occupies one slot in this observation.
    pub(in crate::advanced) fn snapshot(&self) -> Result<[Option<Stamp>; 5]> {
        let mut snapshot = [None; 5];
        for (index, leaf) in self
            .leaves()
            .filter(|leaf| leaf.lifecycle.load(Ordering::Acquire) == Lifecycle::Live as u8)
            .enumerate()
        {
            let slot = snapshot.get_mut(index).ok_or(Error::Rejected(
                RejectionReason::OperationOwnership(
                    OperationOwnershipRejection::FinalizationOperationPopulation,
                ),
            ))?;
            *slot = Some(leaf.observe_revision(leaf.ticket.load(Ordering::Acquire))?);
        }
        Ok(snapshot)
    }

    /// Called under a resource wake lock. Only atomics are read here.
    pub(in crate::advanced) fn population_changed(&self, observed: &[Option<Stamp>; 5]) -> bool {
        let live = self
            .leaves()
            .filter(|leaf| leaf.lifecycle.load(Ordering::Acquire) == Lifecycle::Live as u8);
        live.count() != observed.iter().flatten().count()
            || observed.iter().flatten().any(|s| self.changed(*s))
    }

    pub(in crate::advanced) fn has_vacancy(&self) -> bool {
        self.leaves()
            .any(|leaf| leaf.lifecycle.load(Ordering::Acquire) != Lifecycle::Live as u8)
    }

    /// Allocate persistent waiter storage outside session and registry guards.
    /// A competing preparer can win publication; only its charged node survives.
    pub(in crate::advanced) fn prepare_population(
        &self,
        count: usize,
        session: &crate::Session,
        progress: &crate::session::AdmissionProgress,
    ) -> Result<()> {
        let mut node = self;
        for _ in 1..count {
            if node.next.get().is_none() {
                let credit = super::super::preparation::reserve_new_while(
                    session,
                    std::mem::size_of::<Self>(),
                    progress,
                    || Ok(node.next.get().is_none()),
                )?;
                if let Some(credit) = credit {
                    let next = Box::new(Self {
                        _storage: Some(credit),
                        ..Self::default()
                    });
                    let _ = node.next.set(next);
                }
            }
            node = node
                .next
                .get()
                .expect("a competing preparer or this call published the leaf");
        }
        Ok(())
    }

    pub(in crate::advanced) fn prepare_init_slot(
        &self,
        session: &crate::Session,
        progress: &crate::session::AdmissionProgress,
        category: fe11_sys::CK_FLAGS,
    ) -> Result<()> {
        if self.has_vacancy() {
            return Ok(());
        }
        let count = {
            let access = session.advanced_access_progress_at_epoch(
                progress,
                session.snapshot.authentication_stamp(),
            )?;
            if self.has_vacancy()
                || access
                    .operations
                    .init_target(&session.entry, category)?
                    .is_some()
            {
                return Ok(());
            }
            self.leaves().count() + 1
        };
        self.prepare_population(count, session, progress)
    }

    pub(in crate::advanced) fn install(&self, ticket: u64, occupation: &AtomicU64) -> Result<()> {
        let mut current = self;
        while current.leaf.lifecycle.load(Ordering::Acquire) == Lifecycle::Live as u8 {
            current =
                current
                    .next
                    .get()
                    .ok_or(Error::Rejected(RejectionReason::OperationOwnership(
                        OperationOwnershipRejection::OperationPublicationStorageSize,
                    )))?;
        }
        current.leaf.install(ticket)?;
        if occupation.load(Ordering::Acquire) == 0 {
            occupation.store(ticket, Ordering::Release);
        }
        Ok(())
    }

    pub(in crate::advanced) fn replace(
        &self,
        old: u64,
        new: u64,
        occupation: &AtomicU64,
    ) -> Result<()> {
        self.required(old)?.replace(new)?;
        if occupation.load(Ordering::Acquire) == old {
            occupation.store(new, Ordering::Release);
        }
        Ok(())
    }

    pub(in crate::advanced) fn retire_one(
        &self,
        ticket: u64,
        occupation: &AtomicU64,
    ) -> Result<()> {
        self.required(ticket)?.retire()?;
        if occupation.load(Ordering::Acquire) == ticket {
            let next = self
                .leaves()
                .find(|leaf| leaf.lifecycle.load(Ordering::Acquire) == Lifecycle::Live as u8);
            occupation.store(
                next.map_or(0, |leaf| leaf.ticket.load(Ordering::Acquire)),
                Ordering::Release,
            );
        }
        Ok(())
    }

    pub(in crate::advanced) fn retire(&self, occupation: &AtomicU64) -> Result<()> {
        for leaf in self.leaves() {
            leaf.retire()?;
        }
        occupation.store(0, Ordering::Release);
        Ok(())
    }

    pub(in crate::advanced) fn replacement_ready(&self, ticket: u64) -> Result<bool> {
        self.required(ticket)?.replacement_ready(ticket)
    }

    pub(in crate::advanced) fn claim(&self, ticket: u64) -> Result<Stamp> {
        self.required(ticket)?.claim(ticket)
    }

    pub(in crate::advanced) fn register(&self, ticket: u64) -> Result<Stamp> {
        self.required(ticket)?.register(ticket)
    }

    pub(in crate::advanced) fn unregister(
        &self,
        stamp: Stamp,
        failure: Option<(Effect, ResourceCause)>,
    ) -> Result<bool> {
        match self.find(stamp.ticket) {
            Some(leaf) => leaf.unregister(stamp, failure),
            None => Ok(false),
        }
    }

    pub(in crate::advanced) fn effects(&self, ticket: u64) -> Result<Option<Effects>> {
        self.required(ticket)?.effects(ticket)
    }

    pub(in crate::advanced) fn acknowledge(&self, effects: &Effects, effect: Effect) -> Result<()> {
        self.required(effects.stamp.ticket)?
            .acknowledge(effects, effect)
    }

    pub(in crate::advanced) fn retired(&self, ticket: u64) -> Result<bool> {
        match self.find(ticket) {
            Some(leaf) => leaf.retired(ticket),
            None => Ok(false),
        }
    }

    pub(crate) fn changed(&self, stamp: Stamp) -> bool {
        self.find(stamp.ticket)
            .map_or(true, |leaf| leaf.changed(stamp))
    }

    pub(crate) fn is_poisoned(&self) -> bool {
        self.leaves().any(Leaf::is_poisoned)
    }

    pub(crate) fn cleanup_hint(&self) -> bool {
        self.leaves().any(Leaf::cleanup_hint)
    }
}
