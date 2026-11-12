// SPDX-License-Identifier: Apache-2.0
//! ML-KEM ciphertext and created-key observation share one resident lifetime.
use super::*;
use crate::crypto::derivation::output_observation;

pub(crate) struct InitialKem(Initial);
impl InitialKem {
    pub(crate) fn fixed_bytes() -> Result<usize> {
        Initial::fixed_bytes()
    }
    pub(crate) fn requested(
        admission: &crate::ObjectAdmission,
        id: &[u8],
        label: &[u8],
        evidence: output_observation::Spec<'_>,
    ) -> Result<usize> {
        let class = ManagedClass::SecretKey;
        let identity = DestinationIdentity::KeyOrCertificate { class, id, label };
        Initial::requested(class, admission, &admission.destination, &identity, false)?
            .checked_add(output_observation::Initial::requested(evidence)?)
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
                crate::ObjectCreationRejection::KemObservationStorageSize,
            )))
    }
    pub(crate) fn allocate(
        admission: &crate::ObjectAdmission,
        id: &[u8],
        label: &[u8],
        evidence: output_observation::Spec<'_>,
    ) -> Result<Self> {
        let class = ManagedClass::SecretKey;
        let identity = DestinationIdentity::KeyOrCertificate { class, id, label };
        let mut initial =
            Initial::allocate(class, admission, &admission.destination, &identity, false)?;
        initial.post = PostCreation::Derived(output_observation::Initial::allocate(evidence)?);
        Ok(Self(initial))
    }
    pub(crate) fn allocated_bytes(&self) -> Result<usize> {
        self.0.allocated_bytes()
    }
    pub(crate) fn publish<'a>(
        self,
        session: &'a Session,
        access: SessionAccess<'a>,
        call: crate::crypto::kem::KemCall,
        reservation: &Reservation,
        admission: crate::ObjectAdmission,
        permit: crate::registry::Reservation<crate::managed::NativeIdentity>,
        epoch: u64,
        registry: Prepared,
        prepaid: Credit,
    ) -> Result<KemContinuation<'a>> {
        let plan = admission.destination.clone();
        let (coordination, access, cleanup) = self.0.publish_native(
            session,
            access,
            PreparedCall::Kem(call),
            reservation,
            ManagedClass::SecretKey,
            admission,
            crate::ContentObservation::NotRequested,
            plan,
            permit,
            epoch,
            registry,
            prepaid,
        )?;
        Ok(KemContinuation {
            cleanup,
            access,
            waiter: Waiting::new(session, coordination, Some(epoch), epoch),
            epoch,
        })
    }
}
pub(crate) struct KemContinuation<'a> {
    // Whole-candidate abandonment releases possession before diagnostics can
    // return their credits and notify admission waiters.
    access: SessionAccess<'a>,
    waiter: Waiting<'a>,
    cleanup: crate::error::PreparedCleanupStorage,
    epoch: u64,
}
impl<'a> KemContinuation<'a> {
    pub(crate) fn finish<T>(
        self,
        session: &'a Session,
        admission: &crate::ObjectAdmission,
        progress: &crate::session::AdmissionProgress,
        diagnostics: &mut crate::error::ObjectCreationDiagnostics,
        completion: crate::error::PreparedCompletion,
        native: impl FnMut(
            &SessionAccess<'_>,
            KemDispatch,
            &mut crate::error::CleanupStorage,
            &mut Option<crate::error::CompletionDiagnostic>,
        ) -> Result<crate::crypto::kem::CompletedKem>,
        finish: impl FnOnce(
            &SessionAccess<'_>,
            ManagedObjectRef,
            output_observation::Evidence,
            &mut Option<crate::symmetric::memory::Buffer>,
        ) -> Result<T>,
    ) -> Result<crate::CreatedObjects<T>> {
        let Self {
            cleanup,
            access,
            waiter,
            epoch,
        } = self;
        // The public invocation retains the charge even after an error leaf
        // leaves this continuation and crosses the result projection helpers.
        let (completion, cleanup) = diagnostics.insert((completion, cleanup));
        runner::run_with_native(
            session,
            admission,
            ManagedClass::SecretKey,
            None,
            progress,
            epoch,
            waiter.coordination.clone(),
            access,
            completion,
            cleanup,
            false,
            |_, _, _, _| {
                Err(Error::Rejected(crate::RejectionReason::ObjectCreation(
                    crate::ObjectCreationRejection::UnexpectedKemUnwrap,
                )))
            },
            native,
            |access, reference, evidence, auxiliary| {
                let Evidence::Derived { key } = evidence else {
                    return Err(Error::Rejected(crate::RejectionReason::ObjectCreation(
                        crate::ObjectCreationRejection::KemOutputEvidenceAbsent,
                    )));
                };
                finish(access, reference, key, auxiliary)
            },
        )
    }
}
