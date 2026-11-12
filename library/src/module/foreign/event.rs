// SPDX-License-Identifier: Apache-2.0
//! The foreign event source uses the same single-waiter/finalization protocol.

use super::*;
use crate::native::events::{EventLease, EventMode};

/// One C_WaitForSlotEvent invocation by the selected foreign source. The graph
/// owns pSlot and every native referent; a blocking waiter retains the image but
/// releases ordinary admission, allowing the standard's Finalize exception.
pub struct ForeignEvent<'a> {
    participant: &'a ForeignParticipant,
    admission: Option<crate::admission_wait::ReadGuard<'a, super::super::State>>,
    // begin_event installs the lease; only Drop takes it, after all methods
    // have ended. The Option controls destruction order, not event validity.
    // returned consumes self, so no caller can observe it after retirement.
    lease: Option<EventLease>,
    context: crate::random::EventContext,
    scope: Option<super::call_scope::CallScope>,
    graph: Option<Box<dyn Send + Sync>>,
    mode: EventMode,
    phase: Phase,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Prepared,
    Issued,
    Returned,
}

impl RuntimeOwner {
    /// Select this participant as the sole native event source. An existing
    /// waiter must return before changing source. No native function is called.
    pub fn use_foreign_events(&self, participant: &ForeignParticipant) -> Result<()> {
        if !Arc::ptr_eq(&self.module().inner, &participant.inner) {
            return Err(Error::Rejected(crate::RejectionReason::ExternalExecution(
                crate::ExternalExecutionRejection::ForeignEventRuntimeMismatch,
            )));
        }
        self.module().inner.check_lifecycle_reentry()?;
        let _state = self.module().inner.read()?;
        self.module()
            .inner
            .slot_events
            .select_source(Some(participant.participant.id))
    }

    /// Restore Fe11 as the single event source after the current waiter returns.
    pub fn use_fe11_events(&self) -> Result<()> {
        self.module().inner.check_lifecycle_reentry()?;
        let _state = self.module().inner.read()?;
        self.module().inner.slot_events.select_source(None)
    }
}

impl ForeignParticipant {
    /// Prepare the selected source's one event call. `blocking` selects flags
    /// zero; false selects CKF_DONT_BLOCK. No event is consumed by this method.
    ///
    /// # Safety
    /// The adapter must call exactly C_WaitForSlotEvent with the selected flags,
    /// null pReserved, and a stable pSlot retained by owner. No callback may use
    /// that output graph. No other event call may bypass the runtime protocol.
    pub unsafe fn begin_event<T: Send + Sync + 'static>(
        &self,
        blocking: bool,
        owner: T,
    ) -> Result<ForeignEvent<'_>> {
        let graph: Box<dyn Send + Sync> = Box::new(owner);
        self.inner.check_lifecycle_reentry()?;
        let prepared_scope;
        let policy = crate::admission_wait::current();
        let admission = loop {
            let candidate = super::call_scope::PreparedScope::new(
                self.inner.foreign.image_id(),
                &self.inner.symmetric_budget,
                || {
                    self.inner.state.check_admission(false)?;
                    self.inner.availability.check_available()
                },
            )?;
            match policy.try_once(|| {
                crate::with_resource_admission(crate::ResourceAdmission::Immediate, || {
                    self.inner.read()
                })
            }) {
                Ok(admission) => {
                    prepared_scope = candidate;
                    break admission;
                }
                Err(Error::Busy(_)) => {
                    drop(candidate);
                    drop(self.inner.read()?);
                }
                Err(error) => return Err(error),
            }
        };
        let mode = if blocking {
            EventMode::Blocking
        } else {
            EventMode::Poll
        };
        let context = crate::random::EventContext::new(&admission);
        let lease = self.inner.slot_events.reserve_for(
            self.inner.clone(),
            mode,
            self.inner.availability.clone(),
            Some(self.participant.id),
        )?;
        let scope = prepared_scope.enter();
        Ok(ForeignEvent {
            participant: self,
            admission: Some(admission),
            lease: Some(lease),
            context,
            scope: Some(scope),
            graph: Some(graph),
            mode,
            phase: Phase::Prepared,
        })
    }
}

impl ForeignEvent<'_> {
    /// Mark the one dispatch immediately before entering C. A blocking call
    /// releases module admission here; its independent event lease remains.
    pub fn dispatched(&mut self) -> Result<()> {
        if self.phase != Phase::Prepared {
            return Err(Error::Rejected(crate::RejectionReason::ExternalExecution(
                crate::ExternalExecutionRejection::ForeignEventAlreadyIssued,
            )));
        }
        self.lease.as_mut().expect("event lease").dispatch();
        self.phase = Phase::Issued;
        if self.mode == EventMode::Blocking {
            drop(self.admission.take());
        }
        Ok(())
    }

    /// Publish the real return and pSlot output in the original runtime. The
    /// receipt preserves the native code even if local invalidation fails.
    ///
    /// # Safety
    /// This exact invocation must have returned with code, and slot must be its
    /// actual pSlot output on CKR_OK. Never infer return from a timeout/Finalize.
    pub unsafe fn returned(mut self, code: u64, slot: u64) -> ForeignReceipt {
        let publication = (|| {
            let rv = fe11_sys::CK_RV::try_from(code).map_err(|_| {
                Error::Rejected(crate::RejectionReason::ExternalExecution(
                    crate::ExternalExecutionRejection::ForeignEventCodeConversion,
                ))
            })?;
            if self.phase != Phase::Issued {
                // A claimed actual return without a dispatch marker cannot
                // justify freeing its arguments. Retain the uncertain lease.
                self.lease.as_mut().expect("event lease").dispatch();
                self.phase = Phase::Issued;
                return Err(Error::Rejected(crate::RejectionReason::ExternalExecution(
                    crate::ExternalExecutionRejection::ForeignEventNotDispatched,
                )));
            }
            if rv == fe11_sys::CKR_PENDING {
                return Err(Error::Rejected(crate::RejectionReason::ExternalExecution(
                    crate::ExternalExecutionRejection::ForeignEventCompletionUnproven,
                )));
            }
            let lease = self.lease.as_mut().expect("event lease");
            lease.native_returned();
            self.phase = Phase::Returned;
            // Always retire a returned waiter, even if local slot publication
            // fails. Neither result substitutes for the real Finalize receipt.
            let observation = if rv == fe11_sys::CKR_OK {
                fe11_sys::CK_SLOT_ID::try_from(slot)
                    .map_err(|_| {
                        Error::Rejected(crate::RejectionReason::ExternalExecution(
                            crate::ExternalExecutionRejection::ForeignEventSlotConversion,
                        ))
                    })
                    .and_then(|slot| self.context.invalidate(slot))
            } else {
                Ok(())
            };
            let retirement = lease.finish(rv);
            observation?;
            retirement.map(|_| ())
        })();
        if publication.is_err() {
            // A retained Issued lease must reject Logout before this mark or
            // the admission guard's release wakes another caller.
            self.lease.as_ref().expect("event lease").retain_unproven();
            self.participant.inner.availability.mark();
        }
        drop(self.admission.take());
        drop(self.scope.take());
        ForeignReceipt { code, publication }
    }
}

impl Drop for ForeignEvent<'_> {
    fn drop(&mut self) {
        if let Some(lease) = &self.lease {
            lease.retain_unproven();
        }
        drop(self.admission.take());
        drop(self.scope.take());
        if self.phase == Phase::Issued {
            self.participant.inner.availability.mark();
            if let Some(graph) = self.graph.take() {
                std::mem::forget(graph);
            }
            std::mem::forget(self.participant.participant.image.clone());
        }
        // EventLease handles pre-dispatch cancellation versus unresolved native
        // dispatch. Opaque data is dropped only after its admission and scope.
        drop(self.lease.take());
        drop(self.graph.take());
    }
}
