// SPDX-License-Identifier: Apache-2.0
//! OpenSession notification storage, prepared before lifecycle/slot guards.
use super::{Binding, Contexts, Diagnostics, NotifyContext, NotifyHandler, NotifyRegistry};
use crate::{
    symmetric::memory::{Budget, ControlledReservation, Credit, RetainedBytes, RetainedStorage},
    Error, ResourceAdmission, Result,
};
use std::{
    mem::size_of,
    sync::{
        atomic::{AtomicBool, AtomicUsize},
        Arc, Mutex,
    },
};

pub(crate) struct PreparedNotification {
    // Session storage remains live through notification admission and opening.
    retained_bytes: usize,
    context: Option<Credit>,
    diagnostics: Option<Credit>,
    candidate: Option<Contexts>,
}
pub(crate) enum Registration {
    Ready {
        context: Arc<NotifyContext>,
        retired: Option<RetiredContexts>,
    },
    NeedCapacity(super::capacity::Plan),
    // The caller releases all native/registry guards before dropping captures.
    Retired(Arc<NotifyContext>),
}
/// Empty old vector and its capacity credit, returned outside all guards.
pub(crate) struct RetiredContexts {
    _contexts: Contexts,
}

impl PreparedNotification {
    pub(crate) fn allocation_bytes() -> Result<usize> {
        (size_of::<NotifyContext>() + 2 * size_of::<usize>())
            .checked_add(size_of::<Diagnostics>() + 2 * size_of::<usize>())
            .ok_or(Error::Rejected(crate::RejectionReason::Callbacks(
                crate::CallbacksRejection::NotificationRegistryStorageOverflow,
            )))
    }

    pub(crate) fn from_prepaid(prepaid: &mut Credit, retained_bytes: usize) -> Result<Self> {
        let context_bytes = size_of::<NotifyContext>() + 2 * size_of::<usize>();
        let mut credit = prepaid.split(Self::allocation_bytes()?)?;
        Ok(Self {
            retained_bytes,
            context: Some(credit.split(context_bytes)?),
            diagnostics: Some(credit),
            candidate: None,
        })
    }
    pub(crate) fn prepare_capacity(
        &mut self,
        plan: super::capacity::Plan,
        budget: &Arc<Budget>,
        admission: &ResourceAdmission,
        mut before: impl FnMut() -> Result<()>,
    ) -> Result<()> {
        // A stale candidate is never retained while reserving its replacement.
        drop(self.candidate.take());
        // These two owners cannot disappear while this preparation waits. They
        // must fit together with the replacement vector, even when unrelated
        // sessions can release other credits. Measuring does not reserve twice.
        let retained = RetainedBytes::measure(budget, |retained| {
            self.context.retain_credits(retained)?;
            self.diagnostics.retain_credits(retained)
        })?;
        let count = plan.count;
        let mut bytes =
            count
                .checked_mul(size_of::<Arc<NotifyContext>>())
                .ok_or(Error::Rejected(crate::RejectionReason::Callbacks(
                    crate::CallbacksRejection::NotificationRegistryStorageOverflow,
                )))?;
        enum Route {
            Replan,
            WaitForSlot,
        }
        loop {
            before()?;
            if !plan.current()? {
                return Ok(());
            }
            let reserved = budget.reserve_controlled_retaining(
                bytes,
                self.retained_bytes,
                admission,
                || {
                    before()?;
                    if !plan.current()? {
                        return Ok(Some(Route::Replan));
                    }
                    let additional = bytes
                        .checked_add(self.retained_bytes)
                        .and_then(|bytes| bytes.checked_add(plan.old_bytes))
                        .ok_or(Error::Rejected(crate::RejectionReason::Callbacks(
                            crate::CallbacksRejection::NotificationRetainedStorageOverflow,
                        )))?;
                    match retained.check(budget, additional) {
                        Err(Error::ResourceLimitExceeded { .. }) if plan.can_reuse_peer_slot() => {
                            Ok(Some(Route::WaitForSlot))
                        }
                        result => result.map(|()| None),
                    }
                },
                || Ok(None),
            );
            let mut credit = match reserved {
                Ok(ControlledReservation::Acquired(credit)) => credit,
                Ok(ControlledReservation::Redirect(Route::Replan)) => return Ok(()),
                Ok(ControlledReservation::Redirect(Route::WaitForSlot)) => {
                    plan.wait_changed(admission, &mut before)?;
                    return Ok(());
                }
                Err(error) => {
                    before()?;
                    if !plan.current()? {
                        return Ok(());
                    }
                    if matches!(error, Error::ResourceLimitExceeded { .. })
                        && plan.can_reuse_peer_slot()
                    {
                        plan.wait_changed(admission, &mut before)?;
                        return Ok(());
                    }
                    return Err(error);
                }
            };
            let mut entries = Vec::new();
            entries.try_reserve_exact(count).map_err(|_| {
                Error::Rejected(crate::RejectionReason::Callbacks(
                    crate::CallbacksRejection::NotificationRegistryAllocation,
                ))
            })?;
            let actual = entries
                .capacity()
                .checked_mul(size_of::<Arc<NotifyContext>>())
                .ok_or(Error::Rejected(crate::RejectionReason::Callbacks(
                    crate::CallbacksRejection::NotificationRegistryStorageOverflow,
                )))?;
            if actual > bytes {
                drop(entries);
                drop(credit);
                bytes = actual;
                continue;
            }
            credit.release(bytes - actual);
            self.candidate = Some(Contexts {
                entries,
                _credit: Some(credit),
            });
            return Ok(());
        }
    }
}

impl NotifyRegistry {
    /// The caller must drop the returned handler owner outside module/slot and
    /// opening-transition guards. Extracting it never invokes application code.
    pub(crate) fn take_retired(&self) -> Result<Option<Arc<NotifyContext>>> {
        let mut contexts = self.contexts.lock().map_err(|_| Error::Poisoned)?;
        let retired = contexts
            .entries
            .iter()
            .position(|context| context.closed_and_idle())
            .map(|index| contexts.entries.swap_remove(index));
        if retired.is_some() {
            self.progress.invalidate();
        }
        drop(contexts);
        if retired.is_some() {
            self.progress.notify();
        }
        Ok(retired)
    }

    /// A raced capacity request consumes neither the handler nor its credits.
    /// No byte admission, old-vector destruction or handler Drop occurs here.
    pub(crate) fn register_prepared(
        &self,
        handler: &mut Option<NotifyHandler>,
        image: &Arc<crate::native::image::LoadedImage>,
        dispatch: Option<Arc<crate::native::dispatch::Dispatch>>,
        prepared: &mut PreparedNotification,
    ) -> Result<Registration> {
        let mut contexts = self.contexts.lock().map_err(|_| Error::Poisoned)?;
        // Capture before inspecting bindings. A concurrent close/last callback
        // either becomes reclaimable here or invalidates the resulting ticket.
        let revision = self.progress.revision()?;
        if let Some(index) = contexts
            .entries
            .iter()
            .position(|context| context.closed_and_idle())
        {
            let retired = contexts.entries.swap_remove(index);
            self.progress.invalidate();
            drop(contexts);
            self.progress.notify();
            return Ok(Registration::Retired(retired));
        }
        let count = contexts
            .entries
            .len()
            .checked_add(1)
            .ok_or(Error::Rejected(crate::RejectionReason::Callbacks(
                crate::CallbacksRejection::NotificationRegistryCountOverflow,
            )))?;
        if contexts.entries.capacity() < count
            && prepared
                .candidate
                .as_ref()
                .map_or(true, |c| c.entries.capacity() < count)
        {
            let old_bytes = contexts
                .entries
                .capacity()
                .checked_mul(size_of::<Arc<NotifyContext>>())
                .ok_or(Error::Rejected(crate::RejectionReason::Callbacks(
                    crate::CallbacksRejection::NotificationRegistryStorageOverflow,
                )))?;
            return Ok(Registration::NeedCapacity(
                self.progress.plan(revision, count, old_bytes),
            ));
        }
        if handler.is_none() || prepared.context.is_none() || prepared.diagnostics.is_none() {
            return Err(Error::Rejected(crate::RejectionReason::Callbacks(
                crate::CallbacksRejection::NotificationPreparationConsumed,
            )));
        }
        // Check every fallible condition before moving application ownership.
        let retired = if contexts.entries.capacity() < count {
            let mut replacement = prepared.candidate.take().expect("capacity checked");
            replacement.entries.append(&mut contexts.entries);
            Some(RetiredContexts {
                _contexts: std::mem::replace(&mut *contexts, replacement),
            })
        } else {
            None
        };
        let context = Arc::new(NotifyContext {
            dispatch,
            handler: handler.take().expect("handler checked"),
            binding: Mutex::new(Binding::Opening(None)),
            retirement_hint: AtomicBool::new(false),
            diagnostics: Arc::new(Diagnostics {
                panicked: AtomicBool::new(false),
                mismatch: AtomicBool::new(false),
                exhausted: AtomicBool::new(false),
                _credit: prepared.diagnostics.take().expect("credit checked"),
            }),
            active: AtomicUsize::new(0),
            total_active: self.active.clone(),
            capacity_progress: self.progress.clone(),
            _image: image.clone(),
            _credit: prepared.context.take().expect("credit checked"),
        });
        contexts.entries.push(context.clone());
        self.progress.invalidate();
        drop(contexts);
        self.progress.notify();
        Ok(Registration::Ready { context, retired })
    }
}
