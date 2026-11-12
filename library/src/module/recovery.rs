// SPDX-License-Identifier: Apache-2.0
//! Retain uncertainty and slot-closing participation through recovery guards.
//! Dropping an armed recovery sequence cannot silently establish native completion.

use super::*;

impl SlotDomain {
    /// Retained close participation, distinct from the borrowed activity lock.
    pub(crate) fn has_retained_close(&self) -> bool {
        self.closing_active.load(Ordering::Acquire) != 0
    }
}

impl RecoverySequence<'_> {
    /// Borrow the whole unwind guard before evaluating native-call arguments.
    /// Until return is observed, Drop must retain unscoped execution evidence.
    pub(super) fn entering_native_call(&mut self) {
        self.native_inflight = true;
    }

    /// End only the call-in-flight marker. Native success, returned memory and
    /// recovery completion are classified separately by the caller.
    pub(super) fn native_call_returned(&mut self) {
        self.native_inflight = false;
    }
}

impl Drop for RecoverySequence<'_> {
    fn drop(&mut self) {
        if self.armed {
            if self.native_inflight {
                self.native.mark_unscoped_pending();
            } else {
                self.native.mark_uncertain();
            }
        }
    }
}

impl SlotClose {
    pub(crate) fn new(domain: &Arc<SlotDomain>) -> Result<Self> {
        domain
            .closing_active
            .update_checked(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_add(1))
            .map_err(|_| {
                Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                    crate::ModuleLifecycleRejection::SlotCloseCount,
                ))
            })?;
        Ok(Self(domain.clone()))
    }
}

impl Drop for SlotClose {
    fn drop(&mut self) {
        self.0.closing_active.fetch_sub(1, Ordering::AcqRel);
        self.0.activity.notify();
    }
}
