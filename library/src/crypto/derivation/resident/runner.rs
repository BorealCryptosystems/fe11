// SPDX-License-Identifier: Apache-2.0
//! A derivation waiter carries coordination and scalar needs, never evidence.
use super::*;

pub(in crate::crypto::derivation) fn run<'a, T>(
    session: &'a Session,
    admission: &crate::ObjectAdmission,
    progress: &crate::session::AdmissionProgress,
    epoch: u64,
    coordination: Arc<crate::session::recovery::observations::Coordination>,
    first_access: SessionAccess<'a>,
    diagnostic: &mut crate::error::PreparedCompletion,
    cleanup: &mut crate::error::PreparedCleanupStorage,
    mut native: impl FnMut(
        &SessionAccess<'_>,
        Dispatch,
        &mut crate::error::CleanupStorage,
        &mut Option<crate::error::CompletionDiagnostic>,
    ) -> Result<CreatedObject>,
    finish: impl FnOnce(&SessionAccess<'_>, ManagedObjectRef, Evidence) -> Result<T>,
) -> Result<crate::CreatedObjects<T>> {
    let waiter = Waiting::new(session, coordination, Some(epoch), epoch);
    let search_open = std::cell::Cell::new(false);
    let _withdrawal = search::SearchWithdrawal::new(session, &search_open);
    let mut access = Some(first_access);
    let mut finish = Some(finish);
    let mut native_created = false;
    let mut receipt = None;
    let mut published = false;
    let policy = crate::admission_wait::current();
    let result = (|| loop {
        waiter.check()?;
        let held =
            access
                .as_ref()
                .ok_or(Error::Rejected(crate::RejectionReason::KeyDerivation(
                    crate::KeyDerivationRejection::DerivationPossessionAbsent,
                )))?;
        let slot = session
            .entry
            .recovery
            .observations
            .get(&waiter.coordination)?;
        let mut payload = slot.owner.lock().map_err(|_| Error::Poisoned)?;
        let owner = payload
            .as_mut()
            .ok_or(Error::Rejected(crate::RejectionReason::KeyDerivation(
                crate::KeyDerivationRejection::DerivationOwnerAbsent,
            )))?
            .derivation_mut()?;
        search_open.set(owner.search_claimed());
        let advanced = owner.advance(session, held);
        native_created |= owner.created().is_ok();
        search_open.set(owner.search_claimed() && owner.pending());
        advanced?;
        if owner.complete() {
            let result = owner
                .result(session, held)
                .and_then(|(reference, evidence)| {
                    finish.take().expect("single derivation result")(held, reference, evidence)
                });
            return result;
        }
        let need = owner
            .need()?
            .ok_or(Error::Rejected(crate::RejectionReason::KeyDerivation(
                crate::KeyDerivationRejection::DerivationResourceNeedAbsent,
            )))?;
        if need == Need::Destination {
            let search = owner
                .destination
                .as_ref()
                .is_some_and(DestinationInitial::has_search);
            drop(payload);
            drop(slot);
            // Registry inspection must not recursively lock this owner's payload.
            if search {
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
                .ok_or(Error::Rejected(crate::RejectionReason::KeyDerivation(
                    crate::KeyDerivationRejection::DerivationOwnerAbsent,
                )))?
                .derivation_mut()?
                .activate_destination(session, held)?;
            continue;
        }
        if need == Need::Native {
            let dispatch = owner.take_dispatch(held)?;
            drop(payload);
            drop(slot);
            let mut completed = Some(diagnostic.take()?);
            let result = native(held, dispatch, cleanup.storage(), &mut completed);
            if result.is_ok() {
                receipt = completed;
                native_created = true;
            }
            if held.native.is_uncertain() {
                return Err(result.err().unwrap_or(Error::Rejected(
                    crate::RejectionReason::KeyDerivation(
                        crate::KeyDerivationRejection::DerivationCompletionUnknown,
                    ),
                )));
            }
            let slot = session
                .entry
                .recovery
                .observations
                .get(&waiter.coordination)?;
            let mut payload = slot.owner.lock().map_err(|_| Error::Poisoned)?;
            let owner = payload
                .as_mut()
                .ok_or(Error::Rejected(crate::RejectionReason::KeyDerivation(
                    crate::KeyDerivationRejection::DerivationOwnerAbsent,
                )))?
                .derivation_mut()?;
            let returned = owner.returned(result, session, held, cleanup.storage());
            published |= owner.publication.identity().is_some();
            returned?;
            continue;
        }
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
                Need::Metadata(need) => {
                    Candidate::Metadata(crate::attributes::owned::resident::prepare_value(
                        need,
                        waiter.budget(),
                        &policy,
                        || waiter.check(),
                    )?)
                }
                Need::Admission(need) => Candidate::Admission(discovery::preparation::prepare(
                    need,
                    ManagedClass::SecretKey,
                    admission,
                    None,
                    session,
                    &policy,
                    &waiter,
                )?),
                Need::Native | Need::Destination => {
                    return Err(Error::Rejected(crate::RejectionReason::KeyDerivation(
                        crate::KeyDerivationRejection::DerivationIsNotAResourceRequest,
                    )))
                }
            };
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
            let held = access.as_ref().expect("derivation possession installed");
            waiter.check()?;
            context(session, Some(epoch), epoch)?;
            session.entry(held)?;
            let slot = session
                .entry
                .recovery
                .observations
                .get(&waiter.coordination)?;
            let mut payload = slot.owner.lock().map_err(|_| Error::Poisoned)?;
            let owner = payload
                .as_mut()
                .ok_or(Error::Rejected(crate::RejectionReason::KeyDerivation(
                    crate::KeyDerivationRejection::DerivationOwnerAbsent,
                )))?
                .derivation_mut()?;
            if owner.need()? != Some(need) {
                return Err(Error::Rejected(crate::RejectionReason::KeyDerivation(
                    crate::KeyDerivationRejection::DerivationContinuationChanged,
                )));
            }
            match (&mut owner.phase, need, candidate) {
                (Phase::Destination { read, .. }, Need::Search(_), Candidate::Search(value)) => {
                    read.attach(value)?
                }
                (Phase::Parent(read), Need::Metadata(need), Candidate::Metadata(value)) => {
                    read.attach(need, value)?
                }
                (
                    Phase::Child {
                        read: Some(read), ..
                    },
                    Need::Metadata(need),
                    Candidate::Metadata(value),
                ) => read.attach(need, value)?,
                (Phase::Output { read, .. }, Need::Metadata(need), Candidate::Metadata(value)) => {
                    read.attach(need, value)?
                }
                (
                    Phase::Admission { read, .. },
                    Need::Admission(need),
                    Candidate::Admission(value),
                ) => read.attach(need, value)?,
                _ => {
                    return Err(Error::Rejected(crate::RejectionReason::KeyDerivation(
                        crate::KeyDerivationRejection::DerivationCandidateKind,
                    )))
                }
            }
            break;
        }
    })();
    if published {
        // Recovery may retire the resident owner while observation waits.
        // Preserve native success on both extraction and observation errors.
        let extracted = (|| {
            let slot = session
                .entry
                .recovery
                .observations
                .get(&waiter.coordination)?;
            let mut payload = slot.owner.lock().map_err(|_| Error::Poisoned)?;
            let owner = payload
                .as_mut()
                .ok_or(Error::Rejected(crate::RejectionReason::KeyDerivation(
                    crate::KeyDerivationRejection::DerivationOwnerAbsent,
                )))?
                .derivation_mut()?;
            let object = owner.publication.reference(session)?;
            if !owner.pending() {
                *payload = None;
            }
            Ok(crate::CreatedObjectSet::one(object))
        })();
        return match extracted {
            Ok(objects) => Ok(crate::CreatedObjects {
                objects,
                observation: match receipt {
                    Some(receipt) => receipt.finish(result),
                    None => result,
                },
                remainder: None,
            }),
            Err(publication) => {
                let failure = Err(result.err().unwrap_or(publication));
                match receipt {
                    Some(receipt) => receipt.finish(failure),
                    None => failure,
                }
            }
        };
    }
    let result = match result {
        Ok(value) => Ok(value),
        Err(cause) => {
            if access.is_none() {
                access = session.try_advanced_access_progress(progress).ok();
            }
            let mut cause = Some(cause);
            let considered = access.as_ref().is_some_and(|held| {
                if held.native.is_uncertain() {
                    return false;
                }
                let Ok(slot) = session
                    .entry
                    .recovery
                    .observations
                    .get(&waiter.coordination)
                else {
                    return false;
                };
                let Ok(mut payload) = slot.owner.lock() else {
                    return false;
                };
                let Some(owner) = payload.as_mut() else {
                    return false;
                };
                let Ok(owner) = owner.derivation_mut() else {
                    return false;
                };
                if owner.pending() {
                    return false;
                }
                let search = owner.finish_search(session, held);
                search_open.set(owner.search_claimed() && owner.pending());
                let primary = cause.take().expect("derivation cause");
                cause = Some(match search {
                    Ok(()) => owner.cleanup(session, held, primary, cleanup.storage()),
                    Err(failure) if native_created => {
                        cleanup.storage().object_failure(primary, failure)
                    }
                    Err(failure) => cleanup.storage().sequence_failure(primary, failure),
                });
                true
            });
            let cause = cause.expect("unhandled derivation cause");
            Err(if native_created && !considered {
                cleanup.storage().mark_remaining(cause)
            } else {
                cause
            })
        }
    };
    drop(access);
    match receipt {
        Some(receipt) => receipt.finish(result),
        None => result,
    }
    .map(|value| crate::CreatedObjects::without_objects(Ok(value)))
}
enum Candidate {
    Search(search::SearchCandidate),
    Metadata(crate::attributes::owned::resident::ValueCandidate),
    Admission(discovery::preparation::Candidate),
}
