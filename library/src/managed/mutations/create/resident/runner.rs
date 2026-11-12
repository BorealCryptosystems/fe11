// SPDX-License-Identifier: Apache-2.0
//! Creation waits retain only scalar needs and a completed-call diagnostic.
use super::*;

pub(in crate::managed::mutations) fn run<'a>(
    session: &'a Session,
    admission: &crate::ObjectAdmission,
    class: ManagedClass,
    after: Option<crate::ContentReadPlan>,
    progress: &crate::session::AdmissionProgress,
    epoch: u64,
    coordination: Arc<crate::session::recovery::observations::Coordination>,
    first_access: SessionAccess<'a>,
    diagnostic: &mut crate::error::PreparedCompletion,
    cleanup: &mut crate::error::PreparedCleanupStorage,
) -> Result<crate::CreatedObjects<ManagedObjectRef>> {
    run_with(
        session,
        admission,
        class,
        after,
        progress,
        epoch,
        coordination,
        first_access,
        diagnostic,
        cleanup,
        |reference, _| Ok(reference),
    )
}

pub(super) fn run_with<'a, T>(
    session: &'a Session,
    admission: &crate::ObjectAdmission,
    class: ManagedClass,
    after: Option<crate::ContentReadPlan>,
    progress: &crate::session::AdmissionProgress,
    epoch: u64,
    coordination: Arc<crate::session::recovery::observations::Coordination>,
    first_access: SessionAccess<'a>,
    diagnostic: &mut crate::error::PreparedCompletion,
    cleanup: &mut crate::error::PreparedCleanupStorage,
    finish: impl FnOnce(ManagedObjectRef, Evidence) -> Result<T>,
) -> Result<crate::CreatedObjects<T>> {
    run_with_effect(
        session,
        admission,
        class,
        after,
        progress,
        epoch,
        coordination,
        first_access,
        diagnostic,
        cleanup,
        false,
        finish,
    )
}

pub(super) fn run_with_effect<'a, T>(
    session: &'a Session,
    admission: &crate::ObjectAdmission,
    class: ManagedClass,
    after: Option<crate::ContentReadPlan>,
    progress: &crate::session::AdmissionProgress,
    epoch: u64,
    coordination: Arc<crate::session::recovery::observations::Coordination>,
    first_access: SessionAccess<'a>,
    diagnostic: &mut crate::error::PreparedCompletion,
    cleanup: &mut crate::error::PreparedCleanupStorage,
    contextual: bool,

    finish: impl FnOnce(ManagedObjectRef, Evidence) -> Result<T>,
) -> Result<crate::CreatedObjects<T>> {
    run_with_native(
        session,
        admission,
        class,
        after,
        progress,
        epoch,
        coordination,
        first_access,
        diagnostic,
        cleanup,
        contextual,
        |_, _, _, _| {
            Err(Error::Rejected(crate::RejectionReason::ObjectCreation(
                crate::ObjectCreationRejection::UnexpectedNativeUnwrap,
            )))
        },
        |_, _, _, _| {
            Err(Error::Rejected(crate::RejectionReason::ObjectCreation(
                crate::ObjectCreationRejection::UnexpectedNativeKem,
            )))
        },
        |_, reference, evidence, _| finish(reference, evidence),
    )
}

pub(super) fn run_with_native<'a, T>(
    session: &'a Session,
    admission: &crate::ObjectAdmission,
    class: ManagedClass,
    after: Option<crate::ContentReadPlan>,
    progress: &crate::session::AdmissionProgress,
    epoch: u64,
    coordination: Arc<crate::session::recovery::observations::Coordination>,
    first_access: SessionAccess<'a>,
    diagnostic: &mut crate::error::PreparedCompletion,
    cleanup: &mut crate::error::PreparedCleanupStorage,
    contextual: bool,

    mut unwrap: impl FnMut(
        &SessionAccess<'_>,
        UnwrapDispatch,
        &mut crate::error::CleanupStorage,
        &mut Option<crate::error::CompletionDiagnostic>,
    ) -> Result<CreatedObject>,
    mut kem: impl FnMut(
        &SessionAccess<'_>,
        KemDispatch,
        &mut crate::error::CleanupStorage,
        &mut Option<crate::error::CompletionDiagnostic>,
    ) -> Result<crate::crypto::kem::CompletedKem>,
    finish: impl FnOnce(
        &SessionAccess<'_>,
        ManagedObjectRef,
        Evidence,
        &mut Option<crate::symmetric::memory::Buffer>,
    ) -> Result<T>,
) -> Result<crate::CreatedObjects<T>> {
    let mut finish = Some(finish);
    let policy = crate::admission_wait::current();
    let waiter = Waiting::new(session, coordination, Some(epoch), epoch);
    let search_open = std::cell::Cell::new(false);
    let _withdrawal = SearchWithdrawal::new(session, &search_open);
    let mut receipt = None;
    // Each route carries its real native function, including KEM and
    // unwrap. A later loss of the resident owner cannot erase that success.
    let mut native_created = false;
    let mut published = false;
    let mut access = Some(first_access);
    let result = (|| loop {
        waiter.check()?;
        let held =
            access
                .as_ref()
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
                    crate::ObjectCreationRejection::CreationPossessionAbsent,
                )))?;
        let slot = session
            .entry
            .recovery
            .observations
            .get(&waiter.coordination)?;
        let mut payload = slot.owner.lock().map_err(|_| Error::Poisoned)?;
        let owner = payload
            .as_mut()
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
                crate::ObjectCreationRejection::CreationOwnerAbsent,
            )))?
            .creation_mut()?;
        search_open.set(owner.search_claimed());
        // The marker covers one of three exclusive outcomes: dispatch refusal,
        // a context failure with a published object, or unpublished cleanup.
        // Published objects bypass destructive cleanup even on observation failure.
        // Keep the prepaid owner through final result publication.
        let advanced = owner.advance(
            session,
            held,
            Some(&mut *diagnostic),
            &mut receipt,
            cleanup.storage(),
        );
        native_created |= owner.created().is_ok();
        published |= owner.publication.identity().is_some();
        search_open.set(owner.search_claimed() && owner.pending());
        if let Err(error) = advanced {
            return Err(error);
        }
        if owner.complete() {
            let result = owner
                .result(session, held)
                .and_then(|(reference, mechanisms)| {
                    finish.take().expect("single creation result")(
                        held,
                        reference,
                        mechanisms,
                        &mut owner.ciphertext,
                    )
                });
            return result;
        }
        let need = owner
            .need()?
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
                crate::ObjectCreationRejection::CreationResourceNeedAbsent,
            )))?;
        if need == Need::Kem {
            let dispatch = owner.take_kem(held)?;
            drop(payload);
            // Retain the exact resident slot until the returned owner is installed.
            let mut completed = Some(diagnostic.take()?);
            let result = kem(held, dispatch, cleanup.storage(), &mut completed);
            if result.is_ok() {
                receipt = completed;
                native_created = true;
            }
            let mut payload = slot.owner.lock().map_err(|_| Error::Poisoned)?;
            let owner = payload
                .as_mut()
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
                    crate::ObjectCreationRejection::CreationOwnerAbsent,
                )))?
                .creation_mut()?;
            let returned = owner.kem_returned(result, session, held, cleanup.storage());
            published |= owner.publication.identity().is_some();
            returned?;
            continue;
        }
        if need == Need::Unwrap {
            let dispatch = owner.take_unwrap(held)?;
            drop(payload);
            // Retain the exact resident slot until the returned owner is installed.
            let mut completed = Some(diagnostic.take()?);
            let result = unwrap(held, dispatch, cleanup.storage(), &mut completed);
            if result.is_ok() {
                receipt = completed;
                native_created = true;
            }
            let mut payload = slot.owner.lock().map_err(|_| Error::Poisoned)?;
            let owner = payload
                .as_mut()
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
                    crate::ObjectCreationRejection::CreationOwnerAbsent,
                )))?
                .creation_mut()?;
            let returned = owner.unwrap_returned(result, session, held, cleanup.storage());
            published |= owner.publication.identity().is_some();
            returned?;
            continue;
        }

        drop(payload);
        drop(slot);
        drop(access.take());
        loop {
            let candidate = prepare(need, admission, class, after, session, &policy, &waiter)?;
            // Attach empty storage using only the resident-owner lock. No
            // native dispatch or session access is needed for this transition.
            // Thus every fallible attach (including nested helpers consuming
            // the candidate) releases refused storage outside session guards.
            waiter.check()?;
            let slot = session
                .entry
                .recovery
                .observations
                .get(&waiter.coordination)?;
            let mut payload = slot.owner.lock().map_err(|_| Error::Poisoned)?;
            let owner = payload
                .as_mut()
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
                    crate::ObjectCreationRejection::CreationOwnerAbsent,
                )))?
                .creation_mut()?;
            context(session, Some(epoch), epoch)?;
            attach(owner, need, candidate)?;
            drop(payload);
            drop(slot);
            // Authentication and session state are checked again on resumption.
            // Context-specific authentication retains its exclusive access mode.
            access = Some(if contextual {
                session.context_operation_access_progress(progress)?
            } else {
                session.access_progress_at_epoch(progress, epoch)?
            });
            waiter.check()?;
            break;
        }
    })();
    if published {
        // Native success survives loss of the resident publication owner.
        // Extract under one fallible boundary, then route *every* outcome
        // through the receipt reserved before the native side effect.
        let extracted = (|| {
            let slot = session
                .entry
                .recovery
                .observations
                .get(&waiter.coordination)?;
            let mut payload = slot.owner.lock().map_err(|_| Error::Poisoned)?;
            let owner = payload
                .as_mut()
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
                    crate::ObjectCreationRejection::CreationOwnerAbsent,
                )))?
                .creation_mut()?;
            let object = owner.publication.reference(session)?;
            // A context or metadata failure may precede begin_post. Keep the
            // ciphertext returned by the native call in that case as well.
            if matches!(owner.native, NativeCreation::CreatedKem(_)) {
                let NativeCreation::CreatedKem(completed) =
                    std::mem::replace(&mut owner.native, NativeCreation::Stopped)
                else {
                    unreachable!()
                };
                owner.native = NativeCreation::Created(completed.created);
                // Only a complete native ciphertext is a valid auxiliary
                // result. Keep ownership and the receipt for a short result,
                // but never expose the unproduced suffix of its capacity.
                if completed.length == completed.expected_length {
                    owner.ciphertext = Some(completed.bytes);
                }
            }
            let remainder = owner
                .ciphertext
                .take()
                .map(crate::CreationRemainder::ciphertext_buffer);
            if !owner.pending() {
                *payload = None;
            }
            Ok((crate::CreatedObjectSet::one(object), remainder))
        })();
        return match extracted {
            Ok((objects, remainder)) => Ok(crate::CreatedObjects {
                objects,
                observation: match receipt {
                    Some(receipt) => receipt.finish(result),
                    None => result,
                },
                remainder,
            }),
            Err(publication) => {
                // Preserve the first failure if observation already failed.
                // An absent/retired owner cannot provide a usable object ref.
                let failure = Err(result.err().unwrap_or(publication));
                match receipt {
                    Some(receipt) => receipt.finish(failure),
                    None => failure,
                }
            }
        };
    }
    let result = crate::managed::mutations::recovery::cleanup_failed_mutation(
        session,
        &waiter.coordination,
        native_created,
        result,
        cleanup.storage(),
        access.take(),
        || session.try_advanced_access_progress(progress),
        |owner, held, cause| {
            let owner = owner.creation_mut()?;
            let initialization_lost = held.native.uncertainty_flag().initialization_lost();
            if owner.cleanup_is_unneeded(cause, native_created, initialization_lost) {
                return Ok(());
            }
            // A retained search is not itself an outstanding C call. Its
            // finish method checks the call phase before dispatching Final.
            if owner.pending() && !owner.search_claimed() {
                return Err(Error::Busy(crate::BusyReason::ObjectPublication(
                    crate::ObjectPublicationBusy::MutationCleanupAwaitsNativeCompletion,
                )));
            }
            // Retirement is a context fact, not a claim that another native
            // loan has completed or that admission is valid again.
            if initialization_lost {
                return Err(Error::Rejected(crate::RejectionReason::NativeExecution(
                    crate::NativeExecutionRejection::NativeInitializationRetired,
                )));
            }
            if held.native.is_uncertain() {
                return Err(Error::Busy(crate::BusyReason::ObjectPublication(
                    crate::ObjectPublicationBusy::MutationCleanupAwaitsNativeCompletion,
                )));
            }
            let result = owner.finish_search(session, held);
            search_open.set(owner.search_claimed() && owner.pending());
            result
        },
        |owner, held, cause, storage| {
            // Preparation checked the family under this same exclusive lock.
            owner
                .creation_mut()
                .expect("prepared creation cleanup owner")
                .cleanup(session, held, cause, storage)
        },
    );
    drop(access);
    match receipt {
        Some(completed) => completed.finish(result),
        None => result,
    }
    .map(|value| crate::CreatedObjects::without_objects(Ok(value)))
}

enum Candidate {
    Search(SearchCandidate),
    Metadata(crate::attributes::owned::resident::ValueCandidate),
    Admission(discovery::preparation::Candidate),
}
fn prepare(
    need: Need,
    admission: &crate::ObjectAdmission,
    class: ManagedClass,
    content: Option<crate::ContentReadPlan>,
    session: &Session,
    policy: &crate::ResourceAdmission,
    waiter: &Waiting<'_>,
) -> Result<Candidate> {
    match need {
        Need::Unwrap | Need::Kem => {
            Err(Error::Rejected(crate::RejectionReason::ObjectPublication(
                crate::ObjectPublicationRejection::NativeEffectIsNotAResourceRequest,
            )))
        }
        Need::Search(need) => {
            match SearchCandidate::prepare(need, waiter.budget(), policy, || {
                waiter.check()?;
                Ok(None::<()>)
            })? {
                SearchPreparation::Ready(candidate) => Ok(Candidate::Search(candidate)),
                SearchPreparation::Redirect(()) => unreachable!("no redirect requested"),
            }
        }
        Need::Metadata(need) => {
            crate::attributes::owned::resident::prepare_value(need, waiter.budget(), policy, || {
                waiter.check()
            })
            .map(Candidate::Metadata)
        }
        Need::Admission(need) => discovery::preparation::prepare(
            need, class, admission, content, session, policy, waiter,
        )
        .map(Candidate::Admission),
    }
}
fn attach(owner: &mut CreationOwner, need: Need, candidate: Candidate) -> Result<()> {
    if owner.need()? != Some(need) {
        return Err(Error::Rejected(crate::RejectionReason::ObjectCreation(
            crate::ObjectCreationRejection::CreationContinuationChanged,
        )));
    }
    match (need, candidate) {
        (Need::Search(_), Candidate::Search(candidate)) => match &mut owner.phase {
            Phase::Destination(read) => read.attach(candidate),
            _ => Err(Error::Rejected(crate::RejectionReason::ObjectCreation(
                crate::ObjectCreationRejection::CreationDestinationPhase,
            ))),
        },
        (Need::Metadata(need), Candidate::Metadata(value)) => match &mut owner.phase {
            Phase::Class { read, .. } => read.attach(need, value),
            Phase::Public { read, .. } => read.attach(need, value),
            Phase::Private { read, .. } => read.attach(need, value),
            Phase::Derived { read, .. } => read.attach(need, value),
            _ => Err(Error::Rejected(crate::RejectionReason::ObjectCreation(
                crate::ObjectCreationRejection::CreationMetadataPhase,
            ))),
        },
        (Need::Admission(need), Candidate::Admission(candidate)) => match &mut owner.phase {
            Phase::Admission { read, .. } => read.attach(need, candidate),
            _ => Err(Error::Rejected(crate::RejectionReason::ObjectCreation(
                crate::ObjectCreationRejection::CreationAdmissionPhase,
            ))),
        },
        _ => Err(Error::Rejected(crate::RejectionReason::ObjectCreation(
            crate::ObjectCreationRejection::CreationCandidateKind,
        ))),
    }
}

impl CreationOwner {
    /// A direct refusal can leave no search or returned object to clean up.
    /// This says nothing about unknown effects or frames retained elsewhere;
    /// their reservations and native completion obligations remain unchanged.
    fn cleanup_is_unneeded(
        &self,
        cause: &Error,
        created: bool,
        initialization_lost: bool,
    ) -> bool {
        !created
            && initialization_lost
            && matches!(self.phase, Phase::Stopped)
            && matches!(self.native, NativeCreation::Stopped)
            && matches!(self.publication, crate::managed::SinglePublication::Prepared(_))
            && self.ciphertext.is_none()
            && !self.pending()
            && !self.search_claimed()
            && matches!(
                cause,
                Error::Native {
                    function: "C_CreateObject"
                        | "C_UnwrapKey"
                        | "C_UnwrapKeyAuthenticated"
                        | "C_EncapsulateKey"
                        | "C_DecapsulateKey",
                    code,
                    ..
                } if *code == fe11_sys::CKR_CRYPTOKI_NOT_INITIALIZED as u64
            )
    }
}
