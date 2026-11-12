// SPDX-License-Identifier: Apache-2.0
//! One maintenance opportunity; borrowed input graphs remain outside stored owners.
use super::{LocalOwnership, Session};
use crate::Result;
use std::sync::atomic::{AtomicBool, Ordering};

/// Stored preparation owners keep only this Send/Sync bookkeeping. A captured
/// native frame need not be Sync: its borrowed accounting view stays on the
/// preparing thread, outside those owners and outside native possession.
#[derive(Default)]
pub(crate) struct AdmissionProgress {
    maintenance_attempted: AtomicBool,
    retained_source: Option<crate::symmetric::memory::RetainedBytes>,
}

impl AdmissionProgress {
    /// The caller keeps this exact immutable source alive through all phases.
    /// Carry its footprint explicitly, without a thread-local budget override.
    pub(crate) fn retaining(
        mut self,
        source: crate::symmetric::memory::RetainedBytes,
    ) -> Result<Self> {
        if self.retained_source.is_some() {
            return Err(crate::Error::Rejected(
                crate::RejectionReason::SessionLifecycle(
                    crate::SessionLifecycleRejection::RetainedSourceAlreadyAttached,
                ),
            ));
        }
        self.retained_source = Some(source);
        Ok(self)
    }

    /// Add an exclusive owner kept through the rest of this public call. This
    /// does not reset the maintenance opportunity or reserve the same bytes
    /// twice. The caller must add each owner once, before subsequent admission.
    /// Additional credits must be global-account credits. Child accounts require
    /// a fresh complete footprint to deduplicate their shared headers correctly.
    pub(crate) fn retain_additional(
        &mut self,
        storage: &impl crate::symmetric::memory::RetainedStorage,
    ) -> Result<()> {
        let source = self.retained_source.as_mut().ok_or(crate::Error::Rejected(
            crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::RetainedSourceAbsent,
            ),
        ))?;
        storage.retain_credits(source)
    }

    pub(crate) fn check_retained(&self, session: &Session, additional: usize) -> Result<()> {
        let additional = super::lifecycle_diagnostics::Store::including(additional)?;
        if let Some(source) = &self.retained_source {
            source.check(&session.inner.symmetric_budget, additional)
        } else {
            session.inner.symmetric_budget.check_request(additional)
        }
    }

    pub(crate) fn retained_source(&self) -> Option<&crate::symmetric::memory::RetainedBytes> {
        self.retained_source.as_ref()
    }

    pub(crate) fn can_maintain(&self) -> bool {
        !self.maintenance_attempted.load(Ordering::Relaxed)
    }

    pub(crate) fn maintain_local(&self, session: &Session) -> Result<()> {
        if !self.maintenance_attempted.swap(true, Ordering::Relaxed) {
            // Count even an unavailable gate as the call's one attempt. A
            // subsequent acquisition must not turn Immediate into polling.
            session.maintain_local()?;
        }
        Ok(())
    }

    pub(super) fn maintain_owned(&self, proof: &LocalOwnership<'_>) -> Result<()> {
        if (proof.entry().advanced_progress.cleanup_hint()
            || proof.entry().recovery.observations.cleanup_hint())
            && !self.maintenance_attempted.swap(true, Ordering::Relaxed)
        {
            proof.maintain()?;
        }
        Ok(())
    }
}
