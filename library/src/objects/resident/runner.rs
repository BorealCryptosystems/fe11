// SPDX-License-Identifier: Apache-2.0
//! RSA waiters retain coordination and completed-effect diagnostics only.
use super::*;
use crate::crypto::integer_key::{PublicDerCandidate, PublicDerPreparation};

pub(in crate::objects) fn generate(
    session: &Session,
    spec: KeySpec,
    diagnostics: &mut GenerationDiagnostics,
) -> Result<crate::CreatedObjects<KeyPair>> {
    validate_id(&spec.id)?;
    crate::bounds::ck_length(spec.label.len())?;
    Ok(
        run(session, Request::Generate(spec), diagnostics)?.try_map(|result| match result {
            ResultValue::Pair(pair) => Ok(pair),
            _ => Err(Error::Rejected(crate::RejectionReason::ObjectObservation(
                crate::ObjectObservationRejection::RsaGenerationResultKind,
            ))),
        }),
    )
}
pub(in crate::objects) fn find(session: &Session, selector: ObjectSelector) -> Result<ObjectRef> {
    validate_id(&selector.id)?;
    let mut diagnostics = None;
    match run(session, Request::Find { selector }, &mut diagnostics)?.observation? {
        ResultValue::Reference(reference) => Ok(reference),
        _ => Err(Error::Rejected(crate::RejectionReason::ObjectObservation(
            crate::ObjectObservationRejection::RsaSelectionResultKind,
        ))),
    }
}
fn run(
    session: &Session,
    request: Request,
    diagnostics: &mut GenerationDiagnostics,
) -> Result<crate::CreatedObjects<ResultValue>> {
    let generating = matches!(request, Request::Generate(_));
    let epoch = session.snapshot.authentication_stamp();
    let admission = session.reference_admission_at_epoch(
        crate::session::ReferenceMode::Synchronous,
        epoch,
        |state| {
            if generating {
                state.native.table.C_GenerateKeyPair.ok_or(Error::Rejected(
                    crate::RejectionReason::NativeExecution(
                        crate::NativeExecutionRejection::CGenerateKeyPairUnavailable,
                    ),
                ))?;
                Ok(())
            } else {
                Session::reference_search_functions(state)
            }
        },
    )?;
    let selection_bytes = if generating {
        0
    } else {
        crate::managed::ManagedSelectionStorage::requested_key_bytes(request.id())?
    };
    let diagnostic_bytes = if generating {
        crate::error::PreparedCompletionStorage::allocation_bytes()
            .checked_mul(2)
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectObservation(
                crate::ObjectObservationRejection::RsaDiagnosticAccounting,
            )))?
    } else {
        0
    };
    let mut required = preparation::Initial::requested(&request)?
        .checked_add(diagnostic_bytes)
        .ok_or(Error::Rejected(crate::RejectionReason::ObjectObservation(
            crate::ObjectObservationRejection::RsaDiagnosticAccounting,
        )))?
        .checked_add(selection_bytes)
        .ok_or(Error::Rejected(crate::RejectionReason::ObjectObservation(
            crate::ObjectObservationRejection::RsaObjectGraphSize,
        )))?;
    // The quota belongs to the unpublished candidate, so a possession retry
    // releases it with the payload. Find results are retained only after publish.
    let mut prepare = |overhead: usize, current: &dyn Fn() -> Result<bool>| loop {
        context(session, Some(epoch), epoch)?;
        let admitted = required.checked_add(overhead).ok_or(Error::Rejected(
            crate::RejectionReason::ObjectObservation(
                crate::ObjectObservationRejection::RsaObjectAggregateAccounting,
            ),
        ))?;
        let group =
            admission.objects_with_storage(if generating { 2 } else { 1 }, admitted, || {
                context(session, Some(epoch), epoch)?;
                if !current()? {
                    return Err(Error::Busy(crate::BusyReason::ObjectObservation(
                        crate::ObjectObservationBusy::RsaObjectCreationPlanChanged,
                    )));
                }
                Ok(())
            });
        let (permit, mut prepaid) = match group {
            Ok(group) => group,
            Err(Error::Busy(crate::BusyReason::ObjectObservation(
                crate::ObjectObservationBusy::RsaObjectCreationPlanChanged,
            ))) => return Ok(None),
            Err(error) => return Err(error),
        };
        let initial = preparation::Initial::allocate(&request)?;
        let selection = if generating {
            None
        } else {
            Some(crate::managed::ManagedSelectionStorage::allocate_key(
                crate::ManagedClass::PublicKey,
                request.id(),
            )?)
        };
        let actual = initial
            .allocated_bytes(&request)?
            .checked_add(
                selection
                    .as_ref()
                    .map_or(0, |value| value.allocated_bytes()),
            )
            .and_then(|bytes| bytes.checked_add(diagnostic_bytes))
            .and_then(|bytes| bytes.checked_add(overhead))
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectObservation(
                crate::ObjectObservationRejection::RsaObjectGraphSize,
            )))?;
        if actual > admitted {
            drop(selection);
            drop(initial);
            drop((prepaid, permit));
            required = actual.checked_sub(overhead).ok_or(Error::Rejected(
                crate::RejectionReason::ObjectObservation(
                    crate::ObjectObservationRejection::RsaObjectAggregateAccounting,
                ),
            ))?;
            continue;
        }
        prepaid.release(admitted - actual);
        let registry = Prepared::allocate(&session.inner.symmetric_budget, &mut prepaid)?;
        let diagnostic = if generating {
            Some((
                crate::error::PreparedCompletionStorage::prepare(&mut prepaid)?,
                crate::error::PreparedCompletionStorage::prepare(&mut prepaid)?,
            ))
        } else {
            None
        };
        let selection = selection
            .map(|selection| selection.bind(session, &mut prepaid)?.for_key_pair())
            .transpose()?;
        let coordination = prepaid.split(overhead)?;
        return Ok(Some((
            (diagnostic, initial, registry, permit, prepaid, selection),
            coordination,
        )));
    };
    let (((diagnostic, initial, registry, permit, prepaid, selection), reservation), first) =
        if generating {
            let recipes = [
                crate::managed::DestinationRecipe::new(
                    session,
                    crate::ManagedClass::PublicKey,
                    &[request.id()],
                )?,
                crate::managed::DestinationRecipe::new(
                    session,
                    crate::ManagedClass::PrivateKey,
                    &[request.id()],
                )?,
            ];
            crate::managed::Reservation::prepare_generation_prepaid(
                session,
                &recipes,
                epoch,
                admission.progress(),
                prepare,
                |access| admission.check(access),
            )
            .map(|((candidate, reservation), access)| ((candidate, Some(reservation)), access))?
        } else {
            // Selection storage is private until initial.publish. No destination or
            // creation ticket is required before the first native Find operation.
            session
                .prepare_with_native_roles_prepaid_at_epoch(
                    [],
                    false,
                    epoch,
                    admission.progress(),
                    |overhead| {
                        prepare(overhead, &|| Ok(true))?.ok_or(Error::Rejected(
                            crate::RejectionReason::ObjectObservation(
                                crate::ObjectObservationRejection::RsaSelectionPreparationAbsent,
                            ),
                        ))
                    },
                )
                .map(|(candidate, access)| ((candidate, None), access))?
        };
    admission.check(&first)?;
    session.entry(&first)?;
    let (coordination, first) = initial.publish(
        request,
        session,
        first,
        reservation.as_deref(),
        permit,
        epoch,
        registry,
        prepaid,
        selection,
    )?;
    *diagnostics = diagnostic;
    drop(reservation);
    let waiter = Waiting::new(session, coordination, Some(epoch), epoch);
    let policy = crate::admission_wait::current();
    let search_open = std::cell::Cell::new(false);
    let _withdrawal = search::SearchWithdrawal::new(session, &search_open);
    let mut access = Some(first);
    let mut receipt = None;
    let mut generated = false;
    let mut native_objects = None;
    let result = (|| loop {
        waiter.check()?;
        let held =
            access
                .as_ref()
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectObservation(
                    crate::ObjectObservationRejection::RsaObjectPossessionAbsent,
                )))?;
        let slot = session
            .entry
            .recovery
            .observations
            .get(&waiter.coordination)?;
        let mut payload = slot.owner.lock().map_err(|_| Error::Poisoned)?;
        let owner = payload
            .as_mut()
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectObservation(
                crate::ObjectObservationRejection::RsaObjectOwnerAbsent,
            )))?
            .rsa_objects_mut()?;
        search_open.set(owner.search_claimed());
        let advanced = owner.advance(session, held);
        search_open.set(owner.search_claimed() && owner.pending());
        advanced?;
        if matches!(owner.phase, Phase::Complete { .. }) {
            let result = owner.result(session);
            if result.is_ok() {
                *payload = None;
            }
            return result;
        }
        let need =
            owner
                .need()?
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectObservation(
                    crate::ObjectObservationRejection::RsaObjectNeedAbsent,
                )))?;
        if need == Need::Activate {
            let searching = owner.activation_search();
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
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectObservation(
                    crate::ObjectObservationRejection::RsaObjectOwnerAbsent,
                )))?
                .rsa_objects_mut()?
                .activate(session, held)?;
            continue;
        }
        if need == Need::Native {
            admission.check(held)?;
            let generation = owner.dispatch(session, held)?;
            drop(payload);
            drop(slot);
            let result = generation.call.execute_resident(
                session,
                held,
                diagnostics
                    .as_mut()
                    .ok_or(Error::Rejected(crate::RejectionReason::ObjectObservation(
                        crate::ObjectObservationRejection::RsaGenerationDiagnosticAbsent,
                    )))?
                    .0
                    .take()?,
                generation.creation,
                || {

                },
                |cause| mark_remaining(diagnostics, cause),
            );
            if held.native.is_uncertain() {
                return Err(result.err().unwrap_or(Error::Rejected(
                    crate::RejectionReason::ObjectObservation(
                        crate::ObjectObservationRejection::RsaGenerationCompletionUnknown,
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
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectObservation(
                    crate::ObjectObservationRejection::RsaObjectOwnerAbsent,
                )))?
                .rsa_objects_mut()?;
            match result {
                Ok(completed) => {
                    let (handles, creation, diagnostic) = completed.into_parts();
                    generated = true;
                    receipt = Some(diagnostic);
                    let returned = owner.returned(handles, creation, session, held, |cause| {
                        mark_remaining(diagnostics, cause)
                    });
                    native_objects = owner.created_objects(session);
                    returned?;
                }
                Err(error) => {
                    owner.phase = Phase::Stopped;
                    return Err(error);
                }
            }
            continue;
        }
        drop(payload);
        drop(slot);
        drop(access.take());
        loop {
            let candidate = prepare_candidate(need, &policy, &waiter)?;
            let resumed = match session.try_operation_access_progress(false, admission.progress()) {
                Ok(access) => access,
                Err(Error::Busy(_)) => {
                    drop(candidate);
                    drop(session.access_progress(admission.progress())?);
                    continue;
                }
                Err(error) => return Err(error),
            };
            access = Some(resumed);
            let held = access.as_ref().expect("RSA object possession installed");
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
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectObservation(
                    crate::ObjectObservationRejection::RsaObjectOwnerAbsent,
                )))?
                .rsa_objects_mut()?;
            if owner.need()? != Some(need) {
                return Err(Error::Rejected(crate::RejectionReason::ObjectObservation(
                    crate::ObjectObservationRejection::RsaObjectContinuationChanged,
                )));
            }
            match (&mut owner.phase, need, candidate) {
                (
                    Phase::PublicDestination { read, .. } | Phase::PrivateDestination { read, .. },
                    Need::Search(_),
                    Candidate::Search(value),
                ) => read.attach(value)?,
                (
                    Phase::PublicSearch { read, .. } | Phase::PrivateSearch { read, .. },
                    Need::Search(_),
                    Candidate::Search(value),
                ) => read.attach(value)?,
                (Phase::Pair { read, .. }, Need::Pair(need), Candidate::Pair(value)) => {
                    read.attach(need, value)?
                }
                (
                    Phase::Properties { read, .. },
                    Need::Properties(need),
                    Candidate::Properties(value),
                ) => read.attach(need, value)?,
                _ => {
                    return Err(Error::Rejected(crate::RejectionReason::ObjectObservation(
                        crate::ObjectObservationRejection::RsaObjectCandidateKind,
                    )))
                }
            }
            break;
        }
    })();
    if result.is_err() {
        if access.is_none() {
            access = session
                .try_advanced_access_progress(admission.progress())
                .ok();
        }
        if let Some(held) = access.as_ref().filter(|held| !held.native.is_uncertain()) {
            if let Ok(slot) = session
                .entry
                .recovery
                .observations
                .get(&waiter.coordination)
            {
                if let Ok(mut payload) = slot.owner.lock() {
                    if let Some(owner) = payload.as_mut() {
                        if let Ok(owner) = owner.rsa_objects_mut() {
                            let _ = owner.finish_search(session, held);
                            search_open.set(owner.search_claimed() && owner.pending());
                        }
                    }
                }
            }
        }
    }
    drop(access);
    if let Some(objects) = native_objects {
        let observation = match receipt {
            Some(receipt) => receipt.finish(result),
            None => result,
        };
        return Ok(crate::CreatedObjects {
            objects,
            observation,
            remainder: None,
        });
    }
    // Only an intrinsic failure before complete ownership can leave objects
    // without publishable references. Preserve that diagnostic explicitly.
    let result = result.map_err(|cause| {
        if generated {
            mark_remaining(diagnostics, cause)
        } else {
            cause
        }
    });
    let result = match receipt {
        Some(receipt) => receipt.finish(result),
        None => result,
    }?;
    Ok(crate::CreatedObjects::without_objects(Ok(result)))
}
// Registration failure prevents `generated`; a context failure occurs only
// after Published identities exist. The final unpublished-effect branch is
// therefore disjoint from both: a single marker covers these three outcomes.
fn mark_remaining(diagnostics: &mut GenerationDiagnostics, cause: Error) -> Error {
    diagnostics
        .as_mut()
        .expect("generation owns diagnostics")
        .1
        .take()
        .expect("one generation marker on exclusive failure branches")
        .mark_remaining(cause)
}

enum Candidate {
    Search(search::SearchCandidate),
    Pair(super::super::pair_observation::Candidate),
    Properties(crate::attributes::owned::resident::ValueCandidate),
}
fn prepare_candidate(
    need: Need,
    policy: &crate::ResourceAdmission,
    waiter: &Waiting<'_>,
) -> Result<Candidate> {
    use super::super::pair_observation::{Candidate as PairCandidate, Need as PairNeed};
    match need {
        Need::Search(need) => {
            match search::SearchCandidate::prepare(need, waiter.budget(), policy, || {
                waiter.check()?;
                Ok(None::<()>)
            })? {
                search::SearchPreparation::Ready(value) => Ok(Candidate::Search(value)),
                search::SearchPreparation::Redirect(()) => unreachable!("no redirect requested"),
            }
        }
        Need::Properties(need) => {
            crate::attributes::owned::resident::prepare_value(need, waiter.budget(), policy, || {
                waiter.check()
            })
            .map(Candidate::Properties)
        }
        Need::Pair(PairNeed::Value(need)) => {
            crate::attributes::owned::resident::prepare_value(need, waiter.budget(), policy, || {
                waiter.check()
            })
            .map(|value| Candidate::Pair(PairCandidate::Value(value)))
        }
        Need::Pair(PairNeed::Encoding(need)) => {
            match PublicDerCandidate::prepare(need, waiter.budget(), policy, || {
                waiter.check()?;
                Ok(None::<()>)
            })? {
                PublicDerPreparation::Ready(value) => {
                    Ok(Candidate::Pair(PairCandidate::Encoding(value)))
                }
                PublicDerPreparation::Redirect(()) => unreachable!("no redirect requested"),
            }
        }
        _ => Err(Error::Rejected(crate::RejectionReason::ObjectObservation(
            crate::ObjectObservationRejection::RsaNativeEffectIsNotAStorageRequest,
        ))),
    }
}
