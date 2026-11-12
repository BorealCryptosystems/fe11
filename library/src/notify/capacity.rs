// SPDX-License-Identifier: Apache-2.0
//! Revision-only observation of notification capacity, outside native guards.
use crate::{
    admission_wait::{Attempt, Wake},
    symmetric::memory::{Budget, ResidentCredit},
    Error, ResourceAdmission, Result,
};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

/// Independent of the native registry mutex and of application handlers.
/// Contexts share only this control block, never Native/Inner or the registry.
/// A retained callback keeps its charge alive even after registry withdrawal.
pub(super) struct Progress {
    revision: AtomicU64,
    wake: Arc<Wake>,
    // Last: the module holds this control allocation throughout its lifetime.
    _credit: ResidentCredit,
}

impl Progress {
    pub(super) fn prepare(budget: &Arc<Budget>) -> Result<Arc<Self>> {
        let bytes = std::mem::size_of::<Self>() + 2 * std::mem::size_of::<usize>();
        let credit = budget.reserve(bytes)?.into_module_resident()?;
        Ok(Arc::new(Self {
            revision: AtomicU64::new(0),
            wake: budget.admission_wake(),
            _credit: credit,
        }))
    }

    pub(super) fn revision(&self) -> Result<u64> {
        match self.revision.load(Ordering::Acquire) {
            u64::MAX => Err(Error::Rejected(crate::RejectionReason::Callbacks(
                crate::CallbacksRejection::NotificationRegistryWithdrawn,
            ))),
            revision => Ok(revision),
        }
    }

    /// Publish while mutating the observed state; notify after releasing its
    /// mutex. Saturation withdraws observation rather than allowing an ABA wrap.
    pub(super) fn invalidate(&self) -> bool {
        let mut revision = self.revision.load(Ordering::Acquire);
        loop {
            let Some(next) = revision.checked_add(1) else {
                return false;
            };
            match self.revision.compare_exchange_weak(
                revision,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(observed) => revision = observed,
            }
        }
    }

    pub(super) fn notify(&self) {
        self.wake.notify();
    }

    pub(super) fn withdraw(&self) {
        self.revision.store(u64::MAX, Ordering::Release);
        self.notify();
    }

    pub(super) fn snapshot(self: &Arc<Self>) -> Result<Revision> {
        Ok(Revision {
            progress: self.clone(),
            revision: self.revision()?,
        })
    }

    pub(super) fn plan(self: &Arc<Self>, revision: u64, count: usize, old_bytes: usize) -> Plan {
        Plan {
            progress: self.clone(),
            revision,
            count,
            old_bytes,
        }
    }
}

/// An immutable recipe; it grants no right to modify or read native state.
pub(crate) struct Plan {
    progress: Arc<Progress>,
    revision: u64,
    pub(super) count: usize,
    pub(super) old_bytes: usize,
}

impl Plan {
    pub(super) fn current(&self) -> Result<bool> {
        Ok(self.progress.revision()? == self.revision)
    }

    pub(super) fn can_reuse_peer_slot(&self) -> bool {
        // count includes this new registration. Existing contexts can close
        // independently, making a growth request unnecessary.
        self.count > 1
    }

    pub(super) fn wait_changed(
        &self,
        admission: &ResourceAdmission,
        mut before: impl FnMut() -> Result<()>,
    ) -> Result<()> {
        self.progress.wake.acquire(admission, || {
            before()?;
            Ok(if self.current()? {
                Attempt::Occupied(crate::BusyReason::Callbacks(
                    crate::CallbacksBusy::NotificationRegistryCapacity,
                ))
            } else {
                Attempt::Acquired(())
            })
        })
    }
}

/// Observe changes while preparing the fixed OpenSession owners as one graph.
pub(crate) struct Revision {
    progress: Arc<Progress>,
    revision: u64,
}
impl Revision {
    pub(crate) fn current(&self) -> Result<bool> {
        Ok(self.progress.revision()? == self.revision)
    }
}
