// SPDX-License-Identifier: Apache-2.0
//! Exact caller template and the complete known observation graph.
use super::*;
use crate::attribute_values::InputTemplate;

pub(crate) fn create<'a>(
    session: &Session,
    input: &'a [crate::AttributeInput<'a>],
    limits: crate::AttributeTemplateLimits,
    admission: crate::ObjectAdmission,
    content: crate::ContentObservation,
    destination_plan: crate::DestinationPlan,
    invocation: &mut crate::error::ObjectCreationDiagnostics,
) -> Result<crate::CreatedObjects<ManagedObjectRef>> {
    let class = super::super::object_class(input)?;
    let plan = InputTemplate::plan_scoped(input, limits, &session.inner)?;
    let epoch = session.snapshot.authentication_stamp();
    let reference = session.reference_admission_at_epoch(
        crate::session::ReferenceMode::Synchronous,
        epoch,
        |state| {
            state.native.table.C_CreateObject.ok_or(Error::Rejected(
                crate::RejectionReason::PublicVerification(
                    crate::PublicVerificationRejection::CCreateObjectUnavailable,
                ),
            ))?;
            Ok(())
        },
    )?;
    let progress = reference.progress();
    let identity = input_identity::InputIdentity::new(class, input, None);
    let recipes = [identity.destination(session)?];
    let fixed = Initial::fixed_bytes()?
        .checked_add(ObjectCreation::typed_frame_bytes())
        .and_then(|bytes| bytes.checked_add(crate::error::PreparedCompletion::allocation_bytes()))
        .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
            crate::ObjectCreationRejection::CreationStorageSize,
        )))?;
    let observation_bytes = Initial::requested(
        class,
        &admission,
        &destination_plan,
        &identity.identity(),
        false,
    )?;
    let mut required = fixed
        .checked_add(plan.prepared_allocation_bytes()?)
        .and_then(|bytes| bytes.checked_add(observation_bytes))
        .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
            crate::ObjectCreationRejection::CreationStorageSize,
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
                let group = reference.managed_with_observation_storage(1, admitted, || {
                    context(session, Some(epoch), epoch)?;
                    if !current()? {
                        return Err(Error::Busy(crate::BusyReason::ObjectCreation(
                            crate::ObjectCreationBusy::TypedObjectCreationPlanChanged,
                        )));
                    }
                    Ok(())
                });
                let (permit, mut prepaid) = match group {
                    Ok(group) => group,
                    Err(Error::Busy(crate::BusyReason::ObjectCreation(
                        crate::ObjectCreationBusy::TypedObjectCreationPlanChanged,
                    ))) => return Ok(None),
                    Err(error) => return Err(error),
                };
                let template = plan.allocate()?;
                let observations = Initial::allocate(
                    class,
                    &admission,
                    &destination_plan,
                    &identity.identity(),
                    false,
                )?;
                let template_bytes = template.allocated_bytes()?;
                let observation_bytes = observations.allocated_bytes()?;
                let actual = fixed
                    .checked_add(template_bytes)
                    .and_then(|bytes| bytes.checked_add(observation_bytes))
                    .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
                        crate::ObjectCreationRejection::CreationStorageSize,
                    )))?;
                let actual = actual.checked_add(overhead).ok_or(Error::Rejected(
                    crate::RejectionReason::ObjectReferences(
                        crate::ObjectReferencesRejection::DestinationAggregateAccounting,
                    ),
                ))?;
                if actual > admitted {
                    drop((template, observations));
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
                let template = template.bind(&mut prepaid)?;
                template.check_extensions(&session.inner)?;
                let call = ObjectCreation::typed_prepaid(template, &mut prepaid)?;
                let registry = Prepared::allocate(&session.inner.symmetric_budget, &mut prepaid)?;
                let coordination = prepaid.split(overhead)?;
                return Ok(Some((
                    (diagnostic, call, observations, registry, permit, prepaid),
                    coordination,
                )));
            },
            |access| reference.check(access),
        )?;
    reference.check(&access)?;
    let content_plan = match &content {
        crate::ContentObservation::NotRequested => None,
        crate::ContentObservation::Observe(read) => Some(*read),
    };
    let (coordination, access, cleanup) = observations.publish(
        session,
        access,
        call,
        &reservation,
        class,
        admission.clone(),
        content,
        destination_plan,
        permit,
        epoch,
        registry,
        prepaid,
    )?;
    drop(reservation);
    let (diagnostic, cleanup) = invocation.insert((diagnostic, cleanup));
    runner::run(
        session,
        &admission,
        class,
        content_plan,
        progress,
        epoch,
        coordination,
        access,
        diagnostic,
        cleanup,
    )
}
