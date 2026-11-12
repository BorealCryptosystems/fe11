// SPDX-License-Identifier: Apache-2.0
//! Protected restoration shares destination and publication custody with creation.
pub(crate) use super::private::observation::{Evidence as KeyEvidence, Plan};
use super::*;
use crate::crypto::integer_key::PublicDer;

pub(crate) struct InitialRestoration {
    initial: Initial,
    evidence: private::observation::Initial,
}
impl InitialRestoration {
    pub(crate) fn fixed_bytes() -> Result<usize> {
        Initial::fixed_bytes()
    }
    pub(crate) fn requested(
        class: ManagedClass,
        admission: &crate::ObjectAdmission,
        id: &[u8],
        label: &[u8],
        evidence: Plan<'_>,
    ) -> Result<usize> {
        let identity = DestinationIdentity::KeyOrCertificate { class, id, label };
        Initial::requested(class, admission, &admission.destination, &identity, false)?
            .checked_add(evidence.requested()?)
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
                crate::ObjectCreationRejection::RestorationObservationStorageSize,
            )))
    }
    pub(crate) fn allocate(
        class: ManagedClass,
        admission: &crate::ObjectAdmission,
        id: &[u8],
        label: &[u8],
        evidence: Plan<'_>,
    ) -> Result<Self> {
        let identity = DestinationIdentity::KeyOrCertificate { class, id, label };
        let evidence = evidence.allocate()?;
        Ok(Self {
            initial: Initial::allocate(class, admission, &admission.destination, &identity, false)?,
            evidence,
        })
    }
    pub(crate) fn allocated_bytes(&self) -> Result<usize> {
        self.initial
            .allocated_bytes()?
            .checked_add(self.evidence.allocated_bytes()?)
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
                crate::ObjectCreationRejection::RestorationObservationStorageSize,
            )))
    }
    pub(crate) fn publish<'a>(
        mut self,
        session: &'a Session,
        access: SessionAccess<'a>,
        call: crate::transport::UnwrapCall,
        reservation: &Reservation,
        class: ManagedClass,
        admission: crate::ObjectAdmission,
        public: PublicDer,

        permit: crate::registry::Reservation<crate::managed::NativeIdentity>,
        epoch: u64,
        registry: Prepared,
        prepaid: Credit,
    ) -> Result<Restoration<'a>> {
        self.initial.post = PostCreation::Private {
            read: self.evidence,
            public,
        };
        let plan = admission.destination.clone();
        let (coordination, access, cleanup) = self.initial.publish_native(
            session,
            access,
            PreparedCall::Unwrap(call),
            reservation,
            class,
            admission,
            crate::ContentObservation::NotRequested,
            plan,
            permit,
            epoch,
            registry,
            prepaid,
        )?;
        Ok(Restoration {
            cleanup,
            access,
            waiter: Waiting::new(session, coordination, Some(epoch), epoch),
            epoch,
            class,
        })
    }
}
pub(crate) struct Restoration<'a> {
    // Abandoning the intact candidate must release possession before cleanup
    // credit return can notify admission waiters.
    access: SessionAccess<'a>,
    waiter: Waiting<'a>,
    cleanup: crate::error::PreparedCleanupStorage,
    epoch: u64,
    class: ManagedClass,
}
impl<'a> Restoration<'a> {
    pub(crate) fn finish<T>(
        self,
        session: &'a Session,
        admission: &crate::ObjectAdmission,
        progress: &crate::session::AdmissionProgress,
        contextual: bool,
        diagnostics: &mut crate::error::ObjectCreationDiagnostics,
        completion: crate::error::PreparedCompletion,

        unwrap: impl FnMut(
            &SessionAccess<'_>,
            UnwrapDispatch,
            &mut crate::error::CleanupStorage,
            &mut Option<crate::error::CompletionDiagnostic>,
        ) -> Result<CreatedObject>,
        finish: impl FnOnce(&SessionAccess<'_>, ManagedObjectRef, KeyEvidence, PublicDer) -> Result<T>,
    ) -> Result<crate::CreatedObjects<T>> {
        let Self {
            cleanup,
            access,
            waiter,
            epoch,
            class,
        } = self;
        // Public custody outlives every internal result and its native guards.
        let (completion, cleanup) = diagnostics.insert((completion, cleanup));
        runner::run_with_native(
            session,
            admission,
            class,
            None,
            progress,
            epoch,
            waiter.coordination.clone(),
            access,
            completion,
            cleanup,
            contextual,
            unwrap,
            |_, _, _, _| {
                Err(Error::Rejected(crate::RejectionReason::ObjectCreation(
                    crate::ObjectCreationRejection::UnexpectedRestorationKem,
                )))
            },
            |access, reference, evidence, _| {
                let Evidence::Private { key, public } = evidence else {
                    return Err(Error::Rejected(crate::RejectionReason::ObjectCreation(
                        crate::ObjectCreationRejection::RestorationEvidenceAbsent,
                    )));
                };
                finish(access, reference, key, public)
            },
        )
    }
}
