// SPDX-License-Identifier: Apache-2.0
//! Waiters carry immutable selections, scalar needs and a completion receipt.
use super::*;

pub(in crate::managed::mutations) fn run<'a, T>(
    session: &'a Session,
    progress: &crate::session::AdmissionProgress,
    epoch: u64,
    coordination: Arc<crate::session::recovery::observations::Coordination>,
    first: SessionAccess<'a>,
    diagnostic: &mut crate::error::PreparedCompletionStorage,
    cleanup: &mut crate::error::PreparedCleanupStorage,
    finish: impl FnOnce(
        &SessionAccess<'_>,
        &mut OutputsOwner,
        &mut crate::error::CleanupStorage,
    ) -> Result<T>,
) -> Result<crate::CreatedObjects<T>> {
    let waiter = Waiting::new(session, coordination, Some(epoch), epoch);
    let policy = crate::admission_wait::current();
    let search_open = std::cell::Cell::new(false);
    let _withdrawal = search::SearchWithdrawal::new(session, &search_open);
    let mut access = Some(first);
    let mut finish = Some(finish);
    let mut receipt = None;
    let mut created = false;
    let mut registered = false;
    let result = (|| loop {
        waiter.check()?;
        let held =
            access
                .as_ref()
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectPublication(
                    crate::ObjectPublicationRejection::NativeOutputPossessionAbsent,
                )))?;
        let slot = session
            .entry
            .recovery
            .observations
            .get(&waiter.coordination)?;
        let mut payload = slot.owner.lock().map_err(|_| Error::Poisoned)?;
        let owner = payload
            .as_mut()
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectPublication(
                crate::ObjectPublicationRejection::NativeOutputOwnerAbsent,
            )))?
            .outputs_mut()?;
        search_open.set(owner.search_claimed());
        let advanced = owner.advance(session, held);
        search_open.set(owner.search_claimed() && owner.pending());
        advanced?;
        if owner.complete() {
            let result = finish.take().expect("single native output publication")(
                held,
                owner,
                cleanup.storage(),
            );
            return result;
        }
        let need =
            owner
                .need()?
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectPublication(
                    crate::ObjectPublicationRejection::NativeOutputNeedAbsent,
                )))?;
        if let Need::Destination(index) = need {
            let searching = matches!(&owner.slots[index].state, SlotState::Prepared { destination, .. } if destination.has_search());
            drop(payload);
            drop(slot);
            if searching {
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
            payload
                .as_mut()
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectPublication(
                    crate::ObjectPublicationRejection::NativeOutputOwnerAbsent,
                )))?
                .outputs_mut()?
                .activate_destination(session, held, index)?;
            continue;
        }
        if need == Need::Native {
            // Check all original destination contexts together immediately before C.
            for item in &owner.slots {
                if let SlotState::Ready { report, .. } = &item.state {
                    report.check_context(session)?;
                }
            }
            let (call, creation) = owner.dispatch(held)?;
            drop(payload);
            // Keep this exact slot across C. A concurrent context retirement
            // must not discard a historical success before it is recorded.
            // An invalid returned alias consumes one uncertainty marker and
            // stops dispatch before any output is registered. That path never
            // enters per-object cleanup, so it shares the existing marker pool.
            let result = call.execute(
                session,
                held,
                diagnostic.take()?,
                creation,
                cleanup.storage(),
            );
            // Capture the receipt before any fallible lock/publication step.
            // Context validity is checked by returned() after storing outputs.
            let result = result.map(|success| {
                created = true;
                receipt = Some(success.receipt);
                (success.output, success.creation)
            });
            let mut payload = slot.owner.lock().map_err(|_| Error::Poisoned)?;
            let owner = payload
                .as_mut()
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectPublication(
                    crate::ObjectPublicationRejection::NativeOutputOwnerAbsent,
                )))?
                .outputs_mut()?;
            match result {
                Ok((output, creation)) => {
                    let returned =
                        owner.returned(output, creation, session, held, cleanup.storage());
                    registered = owner.registered();
                    returned?;
                }
                Err(error) => {
                    owner.failed_dispatch();
                    return Err(error);
                }
            }
            continue;
        }
        // These are only copies of original caller choices; no observed bytes,
        // identity, native frame or object permit crosses into the waiter.
        let selection = match need {
            Need::Admission(index, _) => {
                let item = &owner.slots[index];
                Some((
                    item.class,
                    item.admission.clone().ok_or(Error::Rejected(
                        crate::RejectionReason::ObjectPublication(
                            crate::ObjectPublicationRejection::RequestedObservationSelectionAbsent,
                        ),
                    ))?,
                    item.content_plan,
                ))
            }
            _ => None,
        };
        drop(payload);
        drop(slot);
        drop(access.take());
        loop {
            let candidate = match need {
                Need::Search(need) => {
                    match search::SearchCandidate::prepare(need, waiter.budget(), &policy, || {
                        waiter.check()?;
                        Ok(None::<()>)
                    })? {
                        search::SearchPreparation::Ready(value) => Candidate::Search(value),
                        search::SearchPreparation::Redirect(()) => {
                            unreachable!("no redirect requested")
                        }
                    }
                }
                Need::Admission(_, need) => {
                    let (class, admission, content) =
                        selection.as_ref().expect("original admission selection");
                    Candidate::Admission(discovery::preparation::prepare(
                        need, *class, admission, *content, session, &policy, &waiter,
                    )?)
                }
                _ => {
                    return Err(Error::Rejected(crate::RejectionReason::ObjectPublication(
                        crate::ObjectPublicationRejection::NativeEffectIsNotAResourceRequest,
                    )))
                }
            };
            // Attach empty storage using only the resident-owner lock. No
            // native dispatch or session access is needed for this transition.
            // Thus every fallible attach (including nested helpers consuming
            // the candidate) releases refused storage outside session guards.
            waiter.check()?;
            context(session, Some(epoch), epoch)?;
            let slot = session
                .entry
                .recovery
                .observations
                .get(&waiter.coordination)?;
            let mut payload = slot.owner.lock().map_err(|_| Error::Poisoned)?;
            let owner = payload
                .as_mut()
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectPublication(
                    crate::ObjectPublicationRejection::NativeOutputOwnerAbsent,
                )))?
                .outputs_mut()?;
            if owner.need()? != Some(need) {
                return Err(Error::Rejected(crate::RejectionReason::ObjectPublication(
                    crate::ObjectPublicationRejection::NativeOutputContinuationChanged,
                )));
            }
            match (need, candidate) {
                (Need::Search(_), Candidate::Search(value)) => {
                    let Phase::Destination(index) = owner.phase else {
                        return Err(Error::Rejected(crate::RejectionReason::ObjectPublication(
                            crate::ObjectPublicationRejection::NativeOutputSearchPhase,
                        )));
                    };
                    let SlotState::Destination { read, .. } = &mut owner.slots[index].state else {
                        return Err(Error::Rejected(crate::RejectionReason::ObjectPublication(
                            crate::ObjectPublicationRejection::NativeOutputSearchOwner,
                        )));
                    };
                    read.attach(value)?;
                }
                (Need::Admission(index, need), Candidate::Admission(value)) => {
                    let SlotState::Admission { read, .. } = &mut owner.slots[index].state else {
                        return Err(Error::Rejected(crate::RejectionReason::ObjectPublication(
                            crate::ObjectPublicationRejection::NativeOutputAdmissionOwner,
                        )));
                    };
                    read.attach(need, value)?;
                }
                _ => {
                    return Err(Error::Rejected(crate::RejectionReason::ObjectPublication(
                        crate::ObjectPublicationRejection::NativeOutputCandidateKind,
                    )))
                }
            }
            drop(payload);
            drop(slot);
            // The candidate is now resident before access can wait again.
            access = Some(session.access_progress_at_epoch(progress, epoch)?);
            break;
        }
    })();
    if registered {
        // Native success survives loss of the resident publication owner.
        // Extract under one fallible boundary, then route *every* outcome
        // through the receipt reserved before the native side effect.
        let extracted = (|| {
            // Observation failure is not a creation failure. Keep all native
            // objects and auxiliary output; never invoke destruction for this path.
            let slot = session
                .entry
                .recovery
                .observations
                .get(&waiter.coordination)?;
            let mut payload = slot.owner.lock().map_err(|_| Error::Poisoned)?;
            let owner = payload
                .as_mut()
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectPublication(
                    crate::ObjectPublicationRejection::NativeOutputOwnerAbsent,
                )))?
                .outputs_mut()?;
            let objects = owner.take_native_objects(session)?;
            let remainder = if result.is_err() && matches!(owner.native, Native::Created { .. }) {
                Some(crate::CreationRemainder::native(owner.take_output()?))
            } else {
                None
            };
            let credit = owner.publication_credit.take();
            // A pending attribute call still owns its native-addressable buffers.
            // Returning object references does not release that continuation.
            if !owner.pending() {
                *payload = None;
            }
            Ok((crate::CreatedObjectSet::many(objects, credit), remainder))
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
        created,
        result,
        cleanup.storage(),
        access.take(),
        || session.try_advanced_access_progress(progress),
        |owner, held, cause| {
            let owner = owner.outputs_mut()?;
            let initialization_lost = held.native.uncertainty_flag().initialization_lost();
            if owner.cleanup_is_unneeded(cause, created, initialization_lost) {
                return Ok(());
            }
            if owner.non_search_pending() {
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
                .outputs_mut()
                .expect("prepared outputs cleanup owner")
                .cleanup(session, held, cause, storage)
        },
    );
    drop(access);
    match receipt {
        Some(receipt) => receipt
            .finish(result)
            .map(|value| crate::CreatedObjects::without_objects(Ok(value))),
        None => result.map(|value| crate::CreatedObjects::without_objects(Ok(value))),
    }
}
enum Candidate {
    Search(search::SearchCandidate),
    Admission(discovery::preparation::Candidate),
}

impl OutputsOwner {
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
            && matches!(self.native, Native::Stopped)
            && matches!(self.publication, Publication::Prepared(_))
            && self.slots.iter().all(|slot| {
                matches!(slot.state, SlotState::Ready { .. }) && slot.handle == CK_INVALID_HANDLE
            })
            && !self.pending()
            && !self.search_claimed()
            && matches!(
                cause,
                Error::Native {
                    function: "C_GenerateKey"
                        | "C_GenerateKeyPair"
                        | "C_DeriveKey"
                        | "C_UnwrapKey"
                        | "C_EncapsulateKey"
                        | "C_DecapsulateKey",
                    code,
                    ..
                } if *code == fe11_sys::CKR_CRYPTOKI_NOT_INITIALIZED as u64
            )
    }
}
