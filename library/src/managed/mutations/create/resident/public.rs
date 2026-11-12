// SPDX-License-Identifier: Apache-2.0
//! Public import preparation shares creation custody, not algorithm policy.
use super::*;
use crate::crypto::public_import::observation;

pub(crate) fn create_public<T>(
    session: &Session,
    id: crate::attributes::ByteParts<'_>,
    label: &[u8],
    admission: &crate::ObjectAdmission,
    evidence: observation::Spec<'_>,
    planned_template: usize,
    template: impl FnMut() -> Result<crate::attributes::Template>,
    references: &crate::session::ReferenceAdmission<'_>,
    epoch: u64,
    invocation: &mut crate::error::ObjectCreationDiagnostics,
    check: impl Fn(&SessionAccess<'_>) -> Result<()>,
    finish: impl FnOnce(ManagedObjectRef, crate::MechanismObservationReport) -> Result<T>,
) -> Result<crate::CreatedObjects<T>> {
    create_public_with_publication(
        session,
        id,
        label,
        admission,
        evidence,
        None,
        planned_template,
        template,
        references,
        epoch,
        invocation,
        check,
        |reference, mechanisms, _| finish(reference, mechanisms),
    )
}

pub(crate) fn create_public_with_publication<T>(
    session: &Session,
    id: crate::attributes::ByteParts<'_>,
    label: &[u8],
    admission: &crate::ObjectAdmission,
    evidence: observation::Spec<'_>,
    publication: Option<&[u8]>,
    planned_template: usize,
    template: impl FnMut() -> Result<crate::attributes::Template>,
    references: &crate::session::ReferenceAdmission<'_>,
    epoch: u64,
    invocation: &mut crate::error::ObjectCreationDiagnostics,
    check: impl Fn(&SessionAccess<'_>) -> Result<()>,
    finish: impl FnOnce(
        ManagedObjectRef,
        crate::MechanismObservationReport,
        Option<crate::crypto::integer_key::PublicDer>,
    ) -> Result<T>,
) -> Result<crate::CreatedObjects<T>> {
    create_public_prepared(
        session,
        id,
        label,
        admission,
        evidence,
        publication.map(crate::crypto::public_import::publication::Plan::Der),
        planned_template,
        template,
        references,
        epoch,
        invocation,
        check,
        |reference, mechanisms, publication| {
            let publication = match publication {
                Some(crate::crypto::public_import::publication::Prepared::Der(value)) => {
                    Some(value)
                }
                None => None,
                _ => {
                    return Err(Error::Rejected(crate::RejectionReason::ObjectCreation(
                        crate::ObjectCreationRejection::PublicDerPublicationPairing,
                    )))
                }
            };
            finish(reference, mechanisms, publication)
        },
    )
}

pub(crate) fn create_public_prepared<T>(
    session: &Session,
    id: crate::attributes::ByteParts<'_>,
    label: &[u8],
    admission: &crate::ObjectAdmission,
    evidence: observation::Spec<'_>,
    publication: Option<crate::crypto::public_import::publication::Plan<'_>>,
    planned_template: usize,
    mut template: impl FnMut() -> Result<crate::attributes::Template>,
    references: &crate::session::ReferenceAdmission<'_>,
    epoch: u64,
    invocation: &mut crate::error::ObjectCreationDiagnostics,
    check: impl Fn(&SessionAccess<'_>) -> Result<()>,
    finish: impl FnOnce(
        ManagedObjectRef,
        crate::MechanismObservationReport,
        Option<crate::crypto::public_import::publication::Prepared>,
    ) -> Result<T>,
) -> Result<crate::CreatedObjects<T>> {
    let class = ManagedClass::PublicKey;
    let progress = references.progress();
    let identity = DestinationIdentity::PublicImport { id, label };
    let recipes = [
        crate::managed::mutations::reservation_preparation::PublicImportDestination::new(
            session, id,
        )?,
    ];
    let fixed = Initial::fixed_bytes()?
        .checked_add(ObjectCreation::public_frame_bytes())
        .and_then(|bytes| bytes.checked_add(crate::error::PreparedCompletion::allocation_bytes()))
        .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
            crate::ObjectCreationRejection::PublicCreationStorageSize,
        )))?;
    let observations =
        Initial::requested(class, admission, &admission.destination, &identity, false)?;
    let evidence_bytes = observation::Initial::requested(evidence)?;
    let publication_bytes = publication
        .as_ref()
        .map(|plan| plan.requested_bytes())
        .transpose()?
        .unwrap_or(0);
    let mut required = fixed
        .checked_add(planned_template)
        .and_then(|bytes| bytes.checked_add(observations))
        .and_then(|bytes| bytes.checked_add(evidence_bytes))
        .and_then(|bytes| bytes.checked_add(publication_bytes))
        .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
            crate::ObjectCreationRejection::PublicCreationStorageSize,
        )))?;
    let (((diagnostic, call, observations, registry, permit, prepaid), reservation), access) =
        Reservation::prepare_generation_prepaid(
            session,
            &recipes,
            epoch,
            progress,
            |overhead, current| loop {
                context(session, Some(epoch), epoch)?;
                let admitted = required.checked_add(overhead).ok_or(Error::Rejected(
                    crate::RejectionReason::ObjectReferences(
                        crate::ObjectReferencesRejection::DestinationAggregateAccounting,
                    ),
                ))?;
                let group = references.managed_with_observation_storage(1, admitted, || {
                    context(session, Some(epoch), epoch)?;
                    if !current()? {
                        return Err(Error::Busy(crate::BusyReason::ObjectCreation(
                            crate::ObjectCreationBusy::PublicImportCreationPlanChanged,
                        )));
                    }
                    Ok(())
                });
                let (permit, mut prepaid) = match group {
                    Ok(group) => group,
                    Err(Error::Busy(crate::BusyReason::ObjectCreation(
                        crate::ObjectCreationBusy::PublicImportCreationPlanChanged,
                    ))) => return Ok(None),
                    Err(error) => return Err(error),
                };
                let template = crate::attributes::OwnedTemplateStorage::allocate(template()?)?;
                let mut observations =
                    Initial::allocate(class, admission, &admission.destination, &identity, false)?;
                observations.post = PostCreation::Public {
                    read: observation::Initial::allocate(evidence)?,
                    publication: None,
                };
                let public = publication
                    .as_ref()
                    .map(|plan| plan.allocate())
                    .transpose()?;
                let public_bytes = public
                    .as_ref()
                    .map(|storage| storage.allocated_bytes())
                    .transpose()?
                    .unwrap_or(0);
                let observation_bytes = observations.allocated_bytes()?;
                let actual = fixed
                    .checked_add(template.allocated_bytes()?)
                    .and_then(|bytes| bytes.checked_add(observation_bytes))
                    .and_then(|bytes| bytes.checked_add(public_bytes))
                    .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
                        crate::ObjectCreationRejection::PublicCreationStorageSize,
                    )))?;
                let actual = actual.checked_add(overhead).ok_or(Error::Rejected(
                    crate::RejectionReason::ObjectReferences(
                        crate::ObjectReferencesRejection::DestinationAggregateAccounting,
                    ),
                ))?;
                if actual > admitted {
                    drop((template, observations, public));
                    drop((prepaid, permit));
                    required = actual.checked_sub(overhead).ok_or(Error::Rejected(
                        crate::RejectionReason::ObjectReferences(
                            crate::ObjectReferencesRejection::DestinationAggregateAccounting,
                        ),
                    ))?;
                    continue;
                }
                prepaid.release(admitted - actual);
                prepaid.observation_budget()?;
                let diagnostic =
                    crate::error::PreparedCompletion::prepare("C_CreateObject", &mut prepaid)?;
                if let PostCreation::Public {
                    publication: target,
                    ..
                } = &mut observations.post
                {
                    *target =
                        match (public, publication.as_ref()) {
                            (Some(storage), Some(plan)) => Some(plan.bind(storage, &mut prepaid)?),
                            (None, None) => None,
                            _ => return Err(Error::Rejected(crate::RejectionReason::KeyEncoding(
                                crate::KeyEncodingRejection::PublicPublicationPreparationPairing,
                            ))),
                        };
                }
                let call =
                    ObjectCreation::public_prepaid(template.bind(&mut prepaid)?, &mut prepaid)?;
                let registry = Prepared::allocate(&session.inner.symmetric_budget, &mut prepaid)?;
                let coordination = prepaid.split(overhead)?;
                return Ok(Some((
                    (diagnostic, call, observations, registry, permit, prepaid),
                    coordination,
                )));
            },
            |access| check(access),
        )?;
    check(&access)?;
    let (coordination, access, cleanup) = observations.publish(
        session,
        access,
        call,
        &reservation,
        class,
        admission.clone(),
        crate::ContentObservation::NotRequested,
        admission.destination.clone(),
        permit,
        epoch,
        registry,
        prepaid,
    )?;
    drop(reservation);
    let (diagnostic, cleanup) = invocation.insert((diagnostic, cleanup));
    // Any fallible final construction still runs while the exact created output
    // and its cleanup ticket are resident. No successful output escapes early.
    runner::run_with(
        session,
        admission,
        class,
        None,
        progress,
        epoch,
        coordination,
        access,
        diagnostic,
        cleanup,
        |reference, evidence| {
            let Evidence::Public {
                mechanisms,
                publication,
            } = evidence
            else {
                return Err(Error::Rejected(crate::RejectionReason::ObjectCreation(
                    crate::ObjectCreationRejection::PublicImportMechanismReportAbsent,
                )));
            };
            finish(reference, mechanisms, publication)
        },
    )
}
