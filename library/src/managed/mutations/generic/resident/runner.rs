// SPDX-License-Identifier: Apache-2.0
//! Candidate allocation, possession and scalar completion receipt for a setter.
use super::*;

fn add(values: impl IntoIterator<Item = usize>) -> Result<usize> {
    values.into_iter().try_fold(0usize, |sum, value| {
        sum.checked_add(value)
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::AttributeMutationStorageSize,
            )))
    })
}
fn metadata_bytes(plan: &crate::MutationObservationPlan) -> Result<usize> {
    if plan.attributes.is_empty() {
        Ok(0)
    } else {
        ReadStorage::requested(Recipe::Mutation(plan))
    }
}
fn metadata(plan: &crate::MutationObservationPlan) -> Result<Option<ReadStorage>> {
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
fn content_bytes(plan: Option<ContentReadPlan>) -> Result<usize> {
    match plan {
        None => Ok(0),
        Some(ContentReadPlan::Value { .. }) => Ok(ContentOwner::fixed_bytes()),
        Some(ContentReadPlan::PublicFingerprintV1 { read }) => add([
            ReadStorage::requested(fingerprint_recipe(read))?,
            std::mem::size_of::<fingerprint::FingerprintOwner>(),
        ]),
    }
}
fn content_storage(plan: Option<ContentReadPlan>) -> Result<ContentStorage> {
    Ok(match plan {
        None => ContentStorage::None,
        Some(ContentReadPlan::Value { maximum_bytes }) => ContentStorage::Value(maximum_bytes),
        Some(ContentReadPlan::PublicFingerprintV1 { read }) => ContentStorage::Fingerprint {
            read,
            header: ReadStorage::allocate(fingerprint_recipe(read))?,
        },
    })
}
fn content_actual(storage: &ContentStorage) -> Result<usize> {
    match storage {
        ContentStorage::None => Ok(0),
        ContentStorage::Value(_) => Ok(ContentOwner::fixed_bytes()),
        ContentStorage::Fingerprint { header, .. } => add([
            header.allocated_bytes()?,
            std::mem::size_of::<fingerprint::FingerprintOwner>(),
        ]),
    }
}

pub(crate) fn set<'a>(
    session: &Session,
    object: &ManagedObjectRef,
    input: &'a [crate::AttributeInput<'a>],
    template_plan: crate::attribute_values::InputTemplatePlan<'a>,
    selection: crate::ObjectMutationPlan,
    content: crate::ContentMutationPlan,
) -> Result<AttributeMutationReport> {
    let identity_changes = changes_identity(object.identity.class, input);
    let visibility_changes = input
        .iter()
        .any(|value| value.attribute == crate::StandardAttribute::PRIVATE);
    let destination = if identity_changes {
        DestinationRecipe::class_scope(session, object.identity.class)?
    } else {
        identity_recipe(session, &object.identity)?
    };
    let progress = crate::session::AdmissionProgress::default();
    let epoch = session.snapshot.authentication_stamp();
    let policy = crate::admission_wait::current();
    let identity = InputIdentity::new(object.identity.class, input, Some(&object.identity));
    let before_content = reference::content_plan(&content.before);
    let after_content = reference::content_plan(&content.after);
    let frame_bytes = crate::native::frame::SessionFrame::<'_, InputTemplate>::allocation_bytes();
    let fixed = add([
        frame_bytes,
        Prepared::allocation_bytes(),
        std::mem::size_of::<SetAttributesOwner>(),
        MutationProtection::allocation_bytes(),
        crate::error::PreparedCompletion::allocation_bytes(),
        crate::error::PreparedFailurePair::allocation_bytes(),
        crate::error::PreparedCleanupDiagnostic::allocation_bytes(),
    ])?;
    let mut required = add([
        fixed,
        template_plan.prepared_allocation_bytes()?,
        DestinationInitial::requested(&selection.destination, &identity.identity())?,
        ReferenceInitial::requested(&selection.source, object)?,
        metadata_bytes(&selection.before)?,
        metadata_bytes(&selection.after)?,
        content_bytes(after_content)?,
    ])?;
    let (
        (
            mut search_cleanup,
            mut completion_owner,
            failures,
            template,
            destination_initial,
            reference_initial,
            before,
            after,
            content_storage,
            registry,
            mut credit,
            targets,
        ),
        reservation,
        first_access,
    ) = loop {
        let retirement =
            crate::managed::mutations::reservation_preparation::DestinationRetirement::new(session);
        retirement.retire();
        let (
            (
                (
                    search_cleanup,
                    completion_owner,
                    failures,
                    template,
                    destination_initial,
                    reference_initial,
                    before,
                    after,
                    content_storage,
                    registry,
                    credit,
                    mut revocation,
                ),
                reservation,
            ),
            first_access,
        ) = Reservation::prepare_mutation_prepaid(
            session,
            &[destination],
            0,
            None,
            [(Some(&**object), crate::session::activity::AccessMode::Write)],
            false,
            epoch,
            &progress,
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
                let Some(mut credit) = crate::advanced::reserve_preparation_while(
                    session,
                    admitted,
                    &progress,
                    || {
                        context(session, Some(epoch), epoch)?;
                        current()
                    },
                )?
                else {
                    return Ok(None);
                };
                let revocation = shape.allocate()?;
                let revocation_actual = revocation.allocated_bytes()?;
                let template = template_plan.allocate()?;
                let destination =
                    DestinationInitial::allocate(&selection.destination, &identity.identity())?;
                let reference = ReferenceInitial::allocate(&selection.source, object)?;
                let before = metadata(&selection.before)?;
                let after = metadata(&selection.after)?;
                let content = content_storage(after_content)?;
                let actual = add([
                    revocation_actual,
                    fixed,
                    template.allocated_bytes()?,
                    destination.allocated_bytes()?,
                    reference.allocated_bytes()?,
                    actual(&before)?,
                    actual(&after)?,
                    content_actual(&content)?,
                ])?;
                let actual = actual.checked_add(overhead).ok_or(Error::Rejected(
                    crate::RejectionReason::ObjectReferences(
                        crate::ObjectReferencesRejection::DestinationAggregateAccounting,
                    ),
                ))?;
                if actual > admitted {
                    drop(revocation);
                    drop((template, destination, reference, before, after, content));
                    drop(credit);
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
                let failures = crate::error::PreparedFailurePair::prepare(&mut credit)?;
                let revocation = revocation.bind(&mut credit)?;
                let mut template = template.bind(&mut credit)?;
                template.retain_frame_credit(credit.split(frame_bytes)?)?;
                let registry = Prepared::allocate(&session.inner.symmetric_budget, &mut credit)?;
                let coordination = credit.split(overhead)?;
                return Ok(Some((
                    (
                        search_cleanup,
                        completion_owner,
                        failures,
                        template,
                        destination,
                        reference,
                        before,
                        after,
                        content,
                        registry,
                        credit,
                        revocation,
                    ),
                    coordination,
                )));
            },
            |access| {
                context(session, Some(epoch), epoch)?;
                session.managed_handle(access, object)?;
                access
                    .native
                    .table
                    .C_SetAttributeValue
                    .ok_or(Error::Rejected(crate::RejectionReason::ObjectMutation(
                        crate::ObjectMutationRejection::CSetAttributeValueUnavailable,
                    )))?;
                Ok(())
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
                    destination_initial,
                    reference_initial,
                    before,
                    after,
                    content_storage,
                    registry,
                ));
                drop((reservation, credit));
                continue;
            }
            Err(error) => {
                drop(first_access);
                drop((
                    template,
                    destination_initial,
                    reference_initial,
                    before,
                    after,
                    content_storage,
                    registry,
                ));
                drop((reservation, credit));
                return Err(error);
            }
        };
        break (
            (
                search_cleanup,
                completion_owner,
                failures,
                template,
                destination_initial,
                reference_initial,
                before,
                after,
                content_storage,
                registry,
                credit,
                targets,
            ),
            reservation,
            first_access,
        );
    };
    // The prepared graph and unarmed revocation snapshot precede this local
    // access. A failed destination activation keeps both in their owners.
    let destination_key;
    let protection;
    let mut destination_protection;
    let destination_read;
    let owner_credit;
    let mut destination_initial = destination_initial;
    let mut registry = Some(registry);
    let first_access = first_access;
    destination_key = reservation.destination(&destination)?;
    if destination_initial.has_search() {
        session
            .entry
            .recovery
            .observations
            .check_search_available()?;
    }
    protection = MutationProtection::take(session, &first_access, &mut credit)?;
    destination_protection = Some(ObservationProtection::mutation(&protection));
    destination_read = destination_initial.bind_retained(
        session,
        &first_access,
        &selection.destination,
        Some(object.handle),
        epoch,
        &mut destination_protection,
        &mut credit,
    )?;
    owner_credit = credit.split(std::mem::size_of::<SetAttributesOwner>())?;
    let owner = SetAttributesOwner {
        phase: Phase::Destination(Box::new(destination_read)),
        effect: Effect::BeforeDispatch,
        failures,
        // This is allocator-owned report storage, with the same original
        // before-observation order. It is not another resource-budget frontier.
        selection: selection.clone(),
        before_content: Some(content.before),
        after_content: content.after,
        future: FutureStorage {
            input: Some(PreparedSetInput { template, targets }),
            reference: Some(reference_initial),
            before,
            after,
            content: content_storage,
            prepaid: credit,
        },
        destination: destination_key,
        identity_changes,
        visibility_changes,
        protection,
        epoch,
        _credit: owner_credit,
    };
    registry = Some(
        registry
            .take()
            .expect("mutation registry preparation")
            .bind_set_attributes(owner),
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
    // Error-report metadata only: it contains neither a native output nor a
    // source permit. Its scalar receipt survives removal of the session owner.
    let completion = completion_owner.take()?;
    let mut effect = Effect::BeforeDispatch;
    let mut access = Some(first_access);
    let result = (|| loop {
        waiter.check()?;
        let held = access
            .take()
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::AttributeMutationPossessionAbsent,
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
                crate::ObjectMutationRejection::AttributeMutationOwnerAbsent,
            )))?
            .set_attributes_mut()?;
        search_open.set(owner.search_claimed());
        let advanced = owner.advance(session, &held, object);
        effect = owner.effect;
        search_open.set(owner.search_claimed() && owner.pending());
        advanced?;
        if matches!(owner.phase, Phase::Complete(_)) {
            return payload
                .take()
                .expect("completed setter")
                .into_set_attributes()?
                .result(session, &held);
        }
        let need = owner
            .need()?
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::AttributeMutationResourceNeedAbsent,
            )))?;
        let search_start = matches!(need, Need::StartReference)
            && owner
                .future
                .reference
                .as_ref()
                .is_some_and(ReferenceInitial::has_search);
        drop(payload);
        drop(slot);
        if matches!(need, Need::StartReference) {
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
                .set_attributes_mut()?;
            attach(
                owner,
                need,
                Candidate::StartReference,
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
                before_content,
                after_content,
                session,
                &policy,
                &waiter,
            )?;
            let resumed = match session.try_operation_access_progress(false, &progress) {
                Ok(access) => access,
                Err(Error::Busy(_)) => {
                    drop(candidate);
                    drop(session.access_progress(&progress)?);
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
                    crate::ObjectMutationRejection::AttributeMutationOwnerAbsent,
                )))?
                .set_attributes_mut()?;
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
        || session.try_advanced_access_progress(&progress),
        |owner, access| {
            let owner = owner.set_attributes_mut()?;
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
        Effect::Returned {
            code: fe11_sys::CKR_OK,
            ..
        } => completion.finish(result),
        _ => result,
    }
}

enum Candidate {
    Search(SearchCandidate),
    StartReference,
    Reference(reference::preparation::Candidate),
    Metadata(crate::attributes::owned::resident::ValueCandidate),
    Value(crate::SecretBytes),
    Fingerprint(fingerprint::Candidate),
}
fn prepare(
    need: Need,
    selection: &crate::ObjectMutationPlan,
    before_content: Option<ContentReadPlan>,
    after_content: Option<ContentReadPlan>,
    session: &Session,
    policy: &crate::ResourceAdmission,
    waiter: &Waiting<'_>,
) -> Result<Candidate> {
    match need {
        Need::Search(need) => {
            match SearchCandidate::prepare(need, waiter.budget(), policy, || {
                waiter.check()?;
                Ok(None::<()>)
            })? {
                SearchPreparation::Ready(candidate) => Ok(Candidate::Search(candidate)),
                SearchPreparation::Redirect(()) => unreachable!("no redirect requested"),
            }
        }
        Need::StartReference => Ok(Candidate::StartReference),
        Need::Reference(need) => reference::preparation::prepare(
            need,
            &selection.source,
            before_content,
            session,
            policy,
            waiter,
        )
        .map(Candidate::Reference),
        Need::Metadata(need) => {
            crate::attributes::owned::resident::prepare_value(need, waiter.budget(), policy, || {
                waiter.check()
            })
            .map(Candidate::Metadata)
        }
        Need::Value(length) => crate::content_controls::owned::resident::prepare_value(
            length,
            waiter.budget(),
            policy,
            || waiter.check(),
        )
        .map(Candidate::Value),
        Need::Fingerprint(need) => {
            let Some(ContentReadPlan::PublicFingerprintV1 { read }) = after_content else {
                return Err(Error::Rejected(crate::RejectionReason::ObjectMutation(
                    crate::ObjectMutationRejection::MutationFingerprintSelection,
                )));
            };
            fingerprint::prepare_candidate(need, read, waiter.budget(), policy, || waiter.check())
                .map(Candidate::Fingerprint)
        }
    }
}
fn attach(
    owner: &mut SetAttributesOwner,
    need: Need,
    candidate: Candidate,
    session: &Session,
    access: &SessionAccess<'_>,
    object: &ManagedObjectRef,
) -> Result<()> {
    if owner.need()? != Some(need) {
        return Err(Error::Rejected(crate::RejectionReason::ObjectMutation(
            crate::ObjectMutationRejection::AttributeMutationContinuationChanged,
        )));
    }
    match (need, candidate) {
        (Need::Search(_), Candidate::Search(candidate)) => match &mut owner.phase {
            Phase::Destination(read) => read.attach(candidate),
            _ => Err(Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::MutationDestinationPhase,
            ))),
        },
        (Need::StartReference, Candidate::StartReference) => {
            let initial = owner.future.reference.as_mut().ok_or(Error::Rejected(
                crate::RejectionReason::ObjectMutation(
                    crate::ObjectMutationRejection::MutationSourcePreparationAbsent,
                ),
            ))?;
            let mut protection = Some(ObservationProtection::mutation(&owner.protection));
            // Search availability was checked outside this owner mutex while
            // holding the same possession. Binding must not re-lock the registry.
            let read = initial.bind_prechecked_retained(
                session,
                access,
                object,
                &owner.selection.source,
                &mut owner.before_content,
                owner.epoch,
                &mut protection,
                &mut owner.future.prepaid,
            )?;
            drop(owner.future.reference.take());
            let Phase::NeedReference(destination) =
                std::mem::replace(&mut owner.phase, Phase::Stopped)
            else {
                unreachable!("need checked")
            };
            owner.phase = Phase::Reference {
                destination,
                read: Box::new(read),
            };
            Ok(())
        }
        (Need::Reference(need), Candidate::Reference(candidate)) => match &mut owner.phase {
            Phase::Reference { read, .. } => read.attach(need, candidate),
            _ => Err(Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::MutationReferencePhase,
            ))),
        },
        (Need::Metadata(need), Candidate::Metadata(value)) => match &mut owner.phase {
            Phase::Before { read, .. } | Phase::After { read, .. } => read.attach(need, value),
            _ => Err(Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::MutationMetadataPhase,
            ))),
        },
        (Need::Value(length), Candidate::Value(value)) => match &mut owner.phase {
            Phase::Value { read, .. } => read.attach(length, value),
            _ => Err(Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::MutationContentPhase,
            ))),
        },
        (Need::Fingerprint(need), Candidate::Fingerprint(candidate)) => match &mut owner.phase {
            Phase::Fingerprint { read, .. } => read.attach(need, candidate),
            _ => Err(Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::MutationFingerprintPhase,
            ))),
        },
        _ => Err(Error::Rejected(crate::RejectionReason::ObjectMutation(
            crate::ObjectMutationRejection::AttributeMutationCandidateKind,
        ))),
    }
}
