// SPDX-License-Identifier: Apache-2.0
//! Copy waits retain only scalar needs and a completed-call diagnostic.
use super::*;

pub(super) fn run<'a>(
    session: &'a Session,
    object: &ManagedObjectRef,
    selection: &crate::ObjectMutationPlan,
    admission: &crate::ObjectAdmission,
    class: ManagedClass,
    before: Option<crate::ContentReadPlan>,
    after: Option<crate::ContentReadPlan>,
    progress: &crate::session::AdmissionProgress,
    epoch: u64,
    coordination: Arc<crate::session::recovery::observations::Coordination>,
    first_access: SessionAccess<'a>,
    diagnostics: &mut PreparedCopyDiagnostics,
    cleanup: &mut crate::error::PreparedCleanupStorage,
) -> Result<crate::CreatedObjects<ManagedObjectRef>> {
    let policy = crate::admission_wait::current();
    let waiter = Waiting::new(session, coordination, Some(epoch), epoch);
    let search_open = std::cell::Cell::new(false);
    let _withdrawal = SearchWithdrawal::new(session, &search_open);
    let mut receipt = None;
    let mut published = false;
    let mut access = Some(first_access);
    let result = (|| loop {
        waiter.check()?;
        let held = access
            .as_ref()
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectCopy(
                crate::ObjectCopyRejection::CopyPossessionAbsent,
            )))?;
        let slot = session
            .entry
            .recovery
            .observations
            .get(&waiter.coordination)?;
        let mut payload = slot.owner.lock().map_err(|_| Error::Poisoned)?;
        let owner = payload
            .as_mut()
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectCopy(
                crate::ObjectCopyRejection::CopyOwnerAbsent,
            )))?
            .copy_mut()?;
        search_open.set(owner.search_claimed());
        let advanced = owner.advance(
            session,
            held,
            object,
            diagnostics,
            &mut receipt,
            cleanup.storage(),
        );
        published |= owner.publication.identity().is_some();
        search_open.set(owner.search_claimed() && owner.pending());
        if let Err(error) = advanced {
            return Err(error);
        }
        if owner.complete() {
            let result = owner.result(session, held, object);
            return result;
        }
        let need = owner
            .need()?
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectCopy(
                crate::ObjectCopyRejection::CopyResourceNeedAbsent,
            )))?;
        let search_start = matches!(need, Need::StartDestination)
            && owner
                .future
                .destination
                .as_ref()
                .is_some_and(DestinationInitial::has_search);
        drop(payload);
        drop(slot);
        if matches!(need, Need::StartDestination) {
            // Starting a prepared child needs no new credit or possession.
            // Check the one-search rule outside the payload mutex, then attach
            // under this same possession; do not manufacture a Busy boundary.
            if search_start {
                session
                    .entry
                    .recovery
                    .observations
                    .check_search_available_except(Some(&waiter.coordination))?;
            }
            let slot = session
                .entry
                .recovery
                .observations
                .get(&waiter.coordination)?;
            let mut payload = slot.owner.lock().map_err(|_| Error::Poisoned)?;
            let owner = payload
                .as_mut()
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectCopy(
                    crate::ObjectCopyRejection::CopyOwnerAbsent,
                )))?
                .copy_mut()?;
            attach(
                owner,
                need,
                Candidate::StartDestination,
                session,
                held,
                object,
            )?;
            continue;
        }
        drop(access.take());
        loop {
            let candidate = prepare(
                need, selection, admission, class, before, after, session, &policy, &waiter,
            )?;
            let resumed = match session.try_operation_access_progress(false, progress) {
                Ok(access) => access,
                Err(Error::Busy(_)) => {
                    drop(candidate);
                    drop(session.access_progress(progress)?);
                    continue;
                }
                Err(error) => return Err(error),
            };
            access = Some(resumed);
            let held = access.as_ref().expect("copy possession installed");
            waiter.check()?;
            if search_start {
                session
                    .entry
                    .recovery
                    .observations
                    .check_search_available_except(Some(&waiter.coordination))?;
            }
            let slot = session
                .entry
                .recovery
                .observations
                .get(&waiter.coordination)?;
            let mut payload = slot.owner.lock().map_err(|_| Error::Poisoned)?;
            let owner = payload
                .as_mut()
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectCopy(
                    crate::ObjectCopyRejection::CopyOwnerAbsent,
                )))?
                .copy_mut()?;
            owner.check(session, held, object)?;
            attach(owner, need, candidate, session, held, object)?;
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
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectCopy(
                    crate::ObjectCopyRejection::CopyOwnerAbsent,
                )))?
                .copy_mut()?;
            let object = owner.publication.reference(session)?;
            if !owner.pending() {
                *payload = None;
            }
            Ok((crate::CreatedObjectSet::one(object), None))
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
    let native_created = receipt.is_some();
    let result = crate::managed::mutations::recovery::cleanup_failed_mutation(
        session,
        &waiter.coordination,
        native_created,
        result,
        cleanup.storage(),
        access.take(),
        || session.try_advanced_access_progress(progress),
        |owner, held, cause| {
            let owner = owner.copy_mut()?;
            let initialization_lost = held.native.uncertainty_flag().initialization_lost();
            if owner.cleanup_is_unneeded(cause, native_created, initialization_lost) {
                return Ok(());
            }
            // The phase contains one owner: defer an active search to its own
            // checked Final, but retain every other unfinished native loan.
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
                .copy_mut()
                .expect("prepared copy cleanup owner")
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
    Reference(reference::preparation::Candidate),
    StartDestination,
    Search(SearchCandidate),
    Metadata(crate::attributes::owned::resident::ValueCandidate),
    Admission(discovery::preparation::Candidate),
}
fn prepare(
    need: Need,
    selection: &crate::ObjectMutationPlan,
    admission: &crate::ObjectAdmission,
    class: ManagedClass,
    before: Option<crate::ContentReadPlan>,
    after: Option<crate::ContentReadPlan>,
    session: &Session,
    policy: &crate::ResourceAdmission,
    waiter: &Waiting<'_>,
) -> Result<Candidate> {
    match need {
        Need::Reference(need) => reference::preparation::prepare(
            need,
            &selection.source,
            before,
            session,
            policy,
            waiter,
        )
        .map(Candidate::Reference),
        Need::StartDestination => Ok(Candidate::StartDestination),
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
        Need::Admission(need) => {
            discovery::preparation::prepare(need, class, admission, after, session, policy, waiter)
                .map(Candidate::Admission)
        }
    }
}
fn attach(
    owner: &mut CopyOwner,
    need: Need,
    candidate: Candidate,
    session: &Session,
    access: &SessionAccess<'_>,
    object: &ManagedObjectRef,
) -> Result<()> {
    if owner.need()? != Some(need) {
        return Err(Error::Rejected(crate::RejectionReason::ObjectCopy(
            crate::ObjectCopyRejection::CopyContinuationChanged,
        )));
    }
    match (need, candidate) {
        (Need::Reference(need), Candidate::Reference(candidate)) => match &mut owner.phase {
            Phase::Reference(read) => read.attach(need, candidate),
            _ => Err(Error::Rejected(crate::RejectionReason::ObjectCopy(
                crate::ObjectCopyRejection::CopyReferencePhase,
            ))),
        },
        (Need::StartDestination, Candidate::StartDestination) => {
            let initial = owner.future.destination.as_mut().ok_or(Error::Rejected(
                crate::RejectionReason::ObjectCopy(
                    crate::ObjectCopyRejection::CopyDestinationPreparationAbsent,
                ),
            ))?;
            // The parent retains the initial graph and the original mutation
            // protection if activation refuses before the phase transition.
            let mut protection = Some(ObservationProtection::mutation(&owner.protection));
            let read = initial.bind_retained(
                session,
                access,
                &owner.selection.destination,
                Some(object.handle),
                owner.epoch,
                &mut protection,
                &mut owner.future.prepaid,
            )?;
            drop(owner.future.destination.take());
            let Phase::NeedDestination(reference) =
                std::mem::replace(&mut owner.phase, Phase::Stopped)
            else {
                unreachable!("need checked")
            };
            owner.phase = Phase::Destination {
                reference,
                read: Box::new(read),
            };
            Ok(())
        }
        (Need::Search(_), Candidate::Search(candidate)) => match &mut owner.phase {
            Phase::Destination { read, .. } => read.attach(candidate),
            _ => Err(Error::Rejected(crate::RejectionReason::ObjectCopy(
                crate::ObjectCopyRejection::CopyDestinationPhase,
            ))),
        },
        (Need::Metadata(need), Candidate::Metadata(value)) => match &mut owner.phase {
            Phase::Before { read, .. } | Phase::Class { read, .. } | Phase::After { read, .. } => {
                read.attach(need, value)
            }
            _ => Err(Error::Rejected(crate::RejectionReason::ObjectCopy(
                crate::ObjectCopyRejection::CopyMetadataPhase,
            ))),
        },
        (Need::Admission(need), Candidate::Admission(candidate)) => match &mut owner.phase {
            Phase::Admission { read, .. } => read.attach(need, candidate),
            _ => Err(Error::Rejected(crate::RejectionReason::ObjectCopy(
                crate::ObjectCopyRejection::CopyAdmissionPhase,
            ))),
        },
        _ => Err(Error::Rejected(crate::RejectionReason::ObjectCopy(
            crate::ObjectCopyRejection::CopyCandidateKind,
        ))),
    }
}

impl CopyOwner {
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
            && matches!(self.native, NativeCopy::Stopped)
            && matches!(self.publication, crate::managed::SinglePublication::Prepared(_))
            && !self.pending()
            && !self.search_claimed()
            && matches!(
                cause,
                Error::Native {
                    function: "C_CopyObject",
                    code,
                    ..
                } if *code == fe11_sys::CKR_CRYPTOKI_NOT_INITIALIZED as u64
            )
    }
}
