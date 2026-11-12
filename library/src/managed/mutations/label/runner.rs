// SPDX-License-Identifier: Apache-2.0
//! Whole label candidate and metadata-only waits between its native phases.
use super::*;

fn add(values: impl IntoIterator<Item = usize>) -> Result<usize> {
    values.into_iter().try_fold(0usize, |sum, value| {
        sum.checked_add(value)
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::LabelMutationStorageSize,
            )))
    })
}
fn snapshot_bytes(plan: &crate::MutationObservationPlan) -> Result<usize> {
    if plan.attributes.is_empty() {
        Ok(0)
    } else {
        ReadStorage::requested(Recipe::Mutation(plan))
    }
}
fn snapshot_storage(plan: &crate::MutationObservationPlan) -> Result<Option<ReadStorage>> {
    if plan.attributes.is_empty() {
        Ok(None)
    } else {
        ReadStorage::allocate(Recipe::Mutation(plan)).map(Some)
    }
}
fn actual(storage: &Option<ReadStorage>) -> Result<usize> {
    storage
        .as_ref()
        .map(ReadStorage::allocated_bytes)
        .transpose()
        .map(|bytes| bytes.unwrap_or(0))
}
fn identity<T>(
    destination: &DestinationRecipe<'_>,
    label: &str,
    visit: impl FnOnce(crate::destination_controls::DestinationIdentity<'_>) -> Result<T>,
) -> Result<T> {
    destination.with_identity(label, visit)
}

pub(crate) fn set(
    session: &Session,
    object: &ManagedObjectRef,
    label: &str,
    admission: crate::ObjectAdmission,
    selection: crate::ObjectMutationPlan,
    content: crate::ContentMutationPlan,
) -> Result<ManagedObjectRef> {
    label_valid(label)?;
    let epoch = session.snapshot.authentication_stamp();
    let reference_admission = session.reference_admission_at_epoch(
        crate::session::ReferenceMode::Synchronous,
        epoch,
        |state| {
            state
                .native
                .table
                .C_SetAttributeValue
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectMutation(
                    crate::ObjectMutationRejection::CSetAttributeValueUnavailable,
                )))?;
            Ok(())
        },
    )?;
    let progress = reference_admission.progress();
    let policy = crate::admission_wait::current();
    let input = [crate::AttributeInput {
        attribute: crate::StandardAttribute::LABEL.into(),
        value: crate::AttributeInputValue::Bytes(label.as_bytes()),
    }];
    let template_plan = InputTemplate::plan_scoped(
        &input,
        crate::AttributeTemplateLimits {
            maximum_depth: 0,
            maximum_attributes: 1,
            maximum_value_bytes: label.len(),
        },
        &session.inner,
    )?;
    let previous = identity_recipe(session, &object.identity)?;
    let mut destination = previous;
    if object.identity.class == ManagedClass::Data {
        destination.parts[2] = Some(label.as_bytes());
    }
    let keys = [previous, destination];
    let keys = if previous == destination {
        &keys[1..]
    } else {
        &keys[..]
    };
    let class_bytes =
        attributes::ClassReadStorage::allocation_bytes(admission.metadata.maximum_bytes)?;
    let class = object.identity.class;
    let before_content = reference::content_plan(&content.before);
    let after_content = reference::content_plan(&content.after);
    let frame_bytes = crate::native::frame::SessionFrame::<'_, InputTemplate>::allocation_bytes();
    let fixed = add([
        frame_bytes,
        Prepared::allocation_bytes(),
        std::mem::size_of::<LabelOwner>(),
        MutationProtection::allocation_bytes(),
        crate::error::PreparedCompletion::allocation_bytes(),
        crate::error::PreparedCleanupDiagnostic::allocation_bytes(),
        class_bytes,
    ])?;
    let mut required = add([
        fixed,
        template_plan.prepared_allocation_bytes()?,
        ReferenceInitial::requested(&selection.source, object)?,
        identity(&destination, label, |identity| {
            DestinationInitial::requested(&selection.destination, &identity)
        })?,
        snapshot_bytes(&selection.before)?,
        snapshot_bytes(&selection.after)?,
        SelectedInitial::requested(class, &admission)?,
    ])?;
    let (
        (
            mut search_cleanup,
            mut completion_owner,
            class_storage,
            template,
            source,
            destination_initial,
            before,
            after,
            selected,
            registry,
            permit,
            mut credit,
            targets,
        ),
        reservation,
        first_access,
    ) = loop {
        let retirement = super::super::DestinationRetirement::new(session);
        retirement.retire();
        let (
            (
                (
                    search_cleanup,
                    completion_owner,
                    class_storage,
                    template,
                    source,
                    destination_initial,
                    before,
                    after,
                    selected,
                    registry,
                    permit,
                    credit,
                    mut revocation,
                ),
                reservation,
            ),
            first_access,
        ) = Reservation::prepare_mutation_prepaid(
            session,
            keys,
            0,
            None,
            [(Some(&**object), crate::session::activity::AccessMode::Write)],
            false,
            epoch,
            progress,
            |overhead, current| loop {
                context(session, Some(epoch), epoch)?;
                let shape = crate::managed::RevocationShape::discover(
                    session,
                    object.identity.resource(),
                    epoch,
                )?;
                let revocation_bytes = shape.allocation_bytes()?;
                let admitted = required
                    .checked_add(overhead)
                    .and_then(|n| n.checked_add(revocation_bytes))
                    .ok_or(Error::Rejected(crate::RejectionReason::ObjectReferences(
                        crate::ObjectReferencesRejection::DestinationAggregateAccounting,
                    )))?;
                let group =
                    reference_admission.managed_with_observation_storage(1, admitted, || {
                        context(session, Some(epoch), epoch)?;
                        if !current()? {
                            return Err(Error::Busy(crate::BusyReason::ObjectMutation(
                                crate::ObjectMutationBusy::LabelMutationPlanChanged,
                            )));
                        }
                        Ok(())
                    });
                let (permit, mut credit) = match group {
                    Ok(group) => group,
                    Err(Error::Busy(crate::BusyReason::ObjectMutation(
                        crate::ObjectMutationBusy::LabelMutationPlanChanged,
                    ))) => return Ok(None),
                    Err(error) => return Err(error),
                };
                let revocation = shape.allocate()?;
                let revocation_actual = revocation.allocated_bytes()?;
                let template = template_plan.allocate()?;
                let source = ReferenceInitial::allocate(&selection.source, object)?;
                let destination_initial = identity(&destination, label, |identity| {
                    DestinationInitial::allocate(&selection.destination, &identity)
                })?;
                let before = snapshot_storage(&selection.before)?;
                let after = snapshot_storage(&selection.after)?;
                let selected = SelectedInitial::allocate(class, &admission)?;
                let actual = add([
                    revocation_actual,
                    fixed,
                    template.allocated_bytes()?,
                    source.allocated_bytes()?,
                    destination_initial.allocated_bytes()?,
                    actual(&before)?,
                    actual(&after)?,
                    selected.allocated_bytes()?,
                ])?;
                let actual = actual.checked_add(overhead).ok_or(Error::Rejected(
                    crate::RejectionReason::ObjectReferences(
                        crate::ObjectReferencesRejection::DestinationAggregateAccounting,
                    ),
                ))?;
                if actual > admitted {
                    drop(revocation);
                    drop((
                        template,
                        source,
                        destination_initial,
                        before,
                        after,
                        selected,
                    ));
                    drop((credit, permit));
                    required = actual
                        .checked_sub(overhead)
                        .and_then(|n| n.checked_sub(revocation_bytes))
                        .ok_or(Error::Rejected(crate::RejectionReason::ObjectReferences(
                            crate::ObjectReferencesRejection::DestinationAggregateAccounting,
                        )))?;
                    continue;
                }
                credit.release(admitted - actual);
                credit.observation_budget()?;
                let search_cleanup = crate::error::PreparedCleanupDiagnostic::prepare(&mut credit)?;
                let completion_owner =
                    crate::error::PreparedCompletion::prepare("C_SetAttributeValue", &mut credit)?;
                let revocation = revocation.bind(&mut credit)?;
                let mut template = template.bind(&mut credit)?;
                template.retain_frame_credit(credit.split(frame_bytes)?)?;
                let registry = Prepared::allocate(&session.inner.symmetric_budget, &mut credit)?;
                let class_storage = attributes::ClassReadStorage::prepaid(&mut credit)?;
                let coordination = credit.split(overhead)?;
                return Ok(Some((
                    (
                        search_cleanup,
                        completion_owner,
                        class_storage,
                        template,
                        source,
                        destination_initial,
                        before,
                        after,
                        selected,
                        registry,
                        permit,
                        credit,
                        revocation,
                    ),
                    coordination,
                )));
            },
            |access| {
                reference_admission.check(access)?;
                context(session, Some(epoch), epoch)?;
                session.managed_handle(access, object).map(|_| ())
            },
        )?;
        let targets = match revocation.bind(&first_access) {
            Ok(Some(targets)) => targets,
            Ok(None) => {
                // Return possession first, then destroy the still-unbound
                // storage before releasing the credit that covers it.
                drop(first_access);
                drop((
                    template,
                    source,
                    destination_initial,
                    before,
                    after,
                    selected,
                    registry,
                    class_storage,
                ));
                drop((permit, reservation, credit));
                continue;
            }
            Err(error) => {
                drop(first_access);
                drop((
                    template,
                    source,
                    destination_initial,
                    before,
                    after,
                    selected,
                    registry,
                    class_storage,
                ));
                drop((permit, reservation, credit));
                return Err(error);
            }
        };
        break (
            (
                search_cleanup,
                completion_owner,
                class_storage,
                template,
                source,
                destination_initial,
                before,
                after,
                selected,
                registry,
                permit,
                credit,
                targets,
            ),
            reservation,
            first_access,
        );
    };
    // Retain every privately owned result until the later-declared access
    // leaves on refusal. The revocation snapshot is still unarmed here.
    let destination_key;
    let protection;
    let mut reference_protection;
    let mut expected_content;
    let bound_source;
    let owner_credit;
    let mut source = source;
    let mut registry = Some(registry);
    let first_access = first_access;
    destination_key = reservation.destination(&destination)?;
    reference_admission.check(&first_access)?;
    protection = MutationProtection::take(session, &first_access, &mut credit)?;
    reference_protection = Some(ObservationProtection::mutation(&protection));
    expected_content = Some(content.before);
    bound_source = source.bind_retained(
        session,
        &first_access,
        object,
        &selection.source,
        &mut expected_content,
        epoch,
        &mut reference_protection,
        &mut credit,
    )?;
    owner_credit = credit.split(std::mem::size_of::<LabelOwner>())?;
    let owner = LabelOwner {
        phase: Phase::Reference(Box::new(bound_source)),
        effect: Effect::BeforeDispatch,

        selection: selection.clone(),
        admission: admission.clone(),
        content: content.after,
        permit: Some(permit),
        future: FutureStorage {
            template: Some(generic::PreparedSetInput { template, targets }),
            class: Some(class_storage),
            destination: Some(destination_initial),
            before,
            after,
            admission: Some(selected),
            prepaid: credit,
        },
        destination: destination_key,
        protection,
        epoch,
        _credit: owner_credit,
    };
    registry = Some(
        registry
            .take()
            .expect("mutation registry preparation")
            .bind_label(owner),
    );
    let coordination = session
        .entry
        .recovery
        .observations
        .publish_retained(&mut registry)?;
    drop(reservation);
    let waiter = Waiting::new(session, coordination, Some(epoch), epoch);
    let search_open = std::cell::Cell::new(false);
    let _withdrawal = SearchWithdrawal::new(session, &search_open);
    let completion = completion_owner.take()?;
    let mut effect = Effect::BeforeDispatch;
    let mut access = Some(first_access);
    let result = (|| loop {
        waiter.check()?;
        let held = access
            .take()
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::LabelPossessionAbsent,
            )))?;
        let slot = session
            .entry
            .recovery
            .observations
            .get(&waiter.coordination)?;
        let mut payload = slot.owner.lock().map_err(|_| Error::Poisoned)?;
        let owner = payload
            .as_mut()
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::LabelOwnerAbsent,
            )))?
            .label_mut()?;
        search_open.set(owner.search_claimed());
        let advanced = owner.advance(session, &held, object);
        effect = owner.effect;
        search_open.set(owner.search_claimed() && owner.pending());
        advanced?;
        if owner.complete() {
            return payload
                .take()
                .expect("completed label")
                .into_label()?
                .result(session, &held, object);
        }
        let need = owner
            .need()?
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::LabelResourceNeedAbsent,
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
            // This prepared transition needs no new resource. Check native
            // search exclusion outside the payload lock under the same access.
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
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectMutation(
                    crate::ObjectMutationRejection::MutationOwnerAbsent,
                )))?
                .label_mut()?;
            attach(
                owner,
                need,
                Candidate::StartDestination,
                session,
                &held,
                object,
            )?;
            drop(payload);
            drop(slot);
            access = Some(held);
            continue;
        }
        drop(held);
        loop {
            let candidate = prepare(
                need,
                &selection,
                &admission,
                class,
                before_content,
                after_content,
                session,
                &policy,
                &waiter,
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
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectMutation(
                    crate::ObjectMutationRejection::LabelOwnerAbsent,
                )))?
                .label_mut()?;
            owner.check(session, &resumed, object)?;
            attach(owner, need, candidate, session, &resumed, object)?;
            drop(payload);
            drop(slot);
            access = Some(resumed);
            break;
        }
    })();
    drop(access);
    let result = crate::managed::search::finish_failed_search(
        session,
        &waiter.coordination,
        &search_open,
        result,
        &mut search_cleanup,
        None,
        || session.try_advanced_access_progress(progress),
        |owner, access| {
            let owner = owner.label_mut()?;
            let cleanup = owner.finish_search(session, access);
            search_open.set(owner.search_claimed() && owner.pending());
            cleanup
        },
    );
    match effect {
        Effect::Returned {
            code,
            storage_returned: false,
            local_failure: true,
        } => result.map_err(|cause| completion.boundary_failure(code, cause)),
        Effect::Returned {
            code,
            local_failure: true,
            ..
        } => completion.finish_native(code, result),
        Effect::Returned { code: CKR_OK, .. } => completion.finish(result),
        _ => result,
    }
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
    owner: &mut LabelOwner,
    need: Need,
    candidate: Candidate,
    session: &Session,
    access: &SessionAccess<'_>,
    object: &ManagedObjectRef,
) -> Result<()> {
    if owner.need()? != Some(need) {
        return Err(Error::Rejected(crate::RejectionReason::ObjectMutation(
            crate::ObjectMutationRejection::LabelContinuationChanged,
        )));
    }
    match (need, candidate) {
        (Need::Reference(need), Candidate::Reference(candidate)) => match &mut owner.phase {
            Phase::Reference(read) => read.attach(need, candidate),
            _ => Err(Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::LabelReferencePhase,
            ))),
        },
        (Need::StartDestination, Candidate::StartDestination) => {
            let initial = owner.future.destination.as_mut().ok_or(Error::Rejected(
                crate::RejectionReason::ObjectMutation(
                    crate::ObjectMutationRejection::LabelDestinationPreparationAbsent,
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
            _ => Err(Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::LabelDestinationPhase,
            ))),
        },
        (Need::Metadata(need), Candidate::Metadata(value)) => match &mut owner.phase {
            Phase::Before { read, .. } | Phase::After { read, .. } => read.attach(need, value),
            _ => Err(Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::LabelMetadataPhase,
            ))),
        },
        (Need::Admission(need), Candidate::Admission(candidate)) => match &mut owner.phase {
            Phase::Admission { read, .. } => read.attach(need, candidate),
            _ => Err(Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::LabelAdmissionPhase,
            ))),
        },
        _ => Err(Error::Rejected(crate::RejectionReason::ObjectMutation(
            crate::ObjectMutationRejection::LabelCandidateKind,
        ))),
    }
}
