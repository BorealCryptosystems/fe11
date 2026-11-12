// SPDX-License-Identifier: Apache-2.0
//! Returned call storage, detached from coordination guards without allocation.
use super::*;
pub(crate) mod observations;
use std::sync::{atomic::AtomicBool, Mutex};

/// Native execution and memory lifetime are independent. A returned boundary
/// anomaly permits explicit native cleanup but never release of its graph.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Lifetime {
    UntilClose,
    Quarantined,
    Pending,
}
impl Lifetime {
    fn release_after_close(self, objects: &RetainedObjects) -> bool {
        self == Self::UntilClose && !objects.is_quarantined()
    }
}

struct Retention {
    objects: Arc<RetainedObjects>,
    _image: Arc<crate::native::image::LoadedImage>,
    lifetime: Lifetime,
}

/// Metadata is inline in the same allocation as the native data. Converting
/// its Box to a trait object changes neither its address nor its allocation.
/// The optional next link belongs to the ledger only after a recorded return.
pub(crate) struct Stored<T> {
    value: T,
    retention: Option<Retention>,
    next: Option<Box<dyn RetainedCall>>,
}
impl<T> Stored<T> {
    pub(crate) fn new(value: T) -> Self {
        Self {
            value,
            retention: None,
            next: None,
        }
    }
    pub(crate) const fn overhead() -> usize {
        // Includes the actual Rust padding of the complete allocation.
        std::mem::size_of::<Self>() - std::mem::size_of::<T>()
    }
    pub(crate) fn value(&self) -> &T {
        &self.value
    }
    pub(crate) fn value_mut(&mut self) -> &mut T {
        &mut self.value
    }
    pub(crate) fn into_inner(self) -> T {
        assert!(self.retention.is_none() && self.next.is_none());
        self.value
    }
}

trait RetainedCall: Send {
    fn retention(&self) -> &Retention;
    fn next(&self) -> Option<&dyn RetainedCall>;
    fn take_next(&mut self) -> Option<Box<dyn RetainedCall>>;
}
impl<T: Send> RetainedCall for [Stored<T>; 1] {
    fn retention(&self) -> &Retention {
        self[0].retention.as_ref().expect("retained call metadata")
    }
    fn next(&self) -> Option<&dyn RetainedCall> {
        self[0].next.as_deref()
    }
    fn take_next(&mut self) -> Option<Box<dyn RetainedCall>> {
        self[0].next.take()
    }
}

#[derive(Default)]
struct Chain {
    head: Option<Box<dyn RetainedCall>>,
}
impl Chain {
    fn pop(&mut self) -> Option<Box<dyn RetainedCall>> {
        let mut head = self.head.take()?;
        self.head = head.take_next();
        Some(head)
    }
}
impl Drop for Chain {
    fn drop(&mut self) {
        // Losing the Rust ledger is not proof of native termination. Detach
        // iteratively to avoid recursive drop, and retain every native owner.
        while let Some(record) = self.pop() {
            std::mem::forget(record);
        }
    }
}

#[derive(Default)]
pub(crate) struct Ledger {
    calls: Mutex<Chain>,
    // Resident frames and handle-only calls need an execution receipt even
    // when no borrowed call storage is appended to the retained chain.
    pending_execution: AtomicBool,
    pub(crate) observations: observations::Registry,
}
pub(crate) struct ClosedFrames {
    calls: Chain,
    _observations: observations::ClosedObservations,
}
impl Drop for ClosedFrames {
    fn drop(&mut self) {
        // Every link is detached before a destructor; a quarantined child
        // cannot accidentally retain or recursively destroy a sibling chain.
        while let Some(record) = self.calls.pop() {
            let retention = record.retention();
            if !retention.lifetime.release_after_close(&retention.objects) {
                std::mem::forget(record);
            }
        }
    }
}
impl Ledger {
    /// Called with this session possessed. Empty coordination cells do not lend
    /// native memory; any retained frame or observation owner does.
    pub(crate) fn is_empty_for_close(&self) -> Result<bool> {
        if self.pending_execution.load(Ordering::Acquire)
            || self
                .calls
                .lock()
                .map_err(|_| Error::Poisoned)?
                .head
                .is_some()
        {
            return Ok(false);
        }
        self.observations.is_empty_for_close()
    }

    /// No synchronous recovery path can prove completion of these unexpected
    /// pending returns. Withdrawal alone must not authorize native cleanup.
    pub(crate) fn mark_pending_call(&self) {
        self.pending_execution.store(true, Ordering::Release);
    }

    pub(crate) fn has_pending_call(&self) -> bool {
        if self.pending_execution.load(Ordering::Acquire) {
            return true;
        }
        let calls = self.calls.lock().unwrap_or_else(|e| e.into_inner());
        let mut current = calls.head.as_deref();
        while let Some(record) = current {
            if record.retention().lifetime == Lifetime::Pending {
                return true;
            }
            current = record.next();
        }
        false
    }
    pub(crate) fn release_closed(&self) {
        drop(self.take_closed());
    }
    /// Detach under possession, destroy only after the coordination guards.
    pub(crate) fn take_closed(&self) -> ClosedFrames {
        ClosedFrames {
            calls: std::mem::take(&mut *self.calls.lock().unwrap_or_else(|e| e.into_inner())),
            _observations: self.observations.take_closed(),
        }
    }
}

/// Exact Entry identity only; no per-ticket allocation or ledger capacity.
pub(crate) struct Ticket {
    entry: Arc<SessionEntry>,
}
impl Ticket {
    pub(super) fn reserve(entry: Arc<SessionEntry>) -> Result<Self> {
        // Preserve the pre-dispatch poison check without allocating a slot.
        drop(entry.recovery.calls.lock().map_err(|_| Error::Poisoned)?);
        Ok(Self { entry })
    }
    pub(crate) fn retain<T: Send + 'static, G>(
        self,
        mut data: Box<[Stored<T>; 1]>,
        access: &SessionAccess<'_, G>,
        lifetime: Lifetime,
    ) {
        self.entry.poisoned.store(true, Ordering::Release);
        access
            .guards
            .recovery_required
            .store(true, Ordering::Release);
        let objects = access.retained_protections();
        if lifetime != Lifetime::UntilClose {
            objects.quarantine();
        }
        if data[0].retention.is_some() || data[0].next.is_some() {
            // An impossible duplicate transfer must never replace live native data.
            std::mem::forget(data);
            access.native.mark_uncertain();
        } else {
            data[0].retention = Some(Retention {
                objects,
                _image: access.native.image.clone(),
                lifetime,
            });
            let mut calls = self
                .entry
                .recovery
                .calls
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            data[0].next = calls.head.take();
            calls.head = Some(data);
        }
        // No recovery leaf or admission Wake is held during notification.
        self.entry.snapshot.notify_admission();
    }
}
