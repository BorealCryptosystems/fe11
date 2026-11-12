// SPDX-License-Identifier: Apache-2.0
//! Direct setters prepare their complete private storage before observations.
use super::{DestinationRecipe, Reservation};
use crate::{
    attribute_values::{InputTemplate, InputTemplatePlan},
    managed::{RevocationShape, RevocationTargets},
    native::frame::SessionFrame,
    session::{activity::AccessMode, AdmissionProgress, SessionAccess},
    Error, NativeObjectRef, Result, Session,
};
use std::sync::Arc;

pub(super) fn prepare<'s>(
    session: &'s Session,
    recipes: &[DestinationRecipe<'_>],
    object: &NativeObjectRef,
    plan: &InputTemplatePlan<'_>,
    progress: &AdmissionProgress,
    authentication: u64,
) -> Result<(
    crate::error::PreparedCompletion,
    crate::error::PreparedFailurePair,
    InputTemplate,
    Arc<Reservation>,
    SessionAccess<'s>,
    RevocationTargets,
)> {
    let frame_bytes = SessionFrame::<'_, InputTemplate>::allocation_bytes();
    let mut required = plan
        .prepared_allocation_bytes()?
        .checked_add(frame_bytes)
        .and_then(|n| n.checked_add(crate::error::PreparedCompletion::allocation_bytes()))
        .and_then(|n| n.checked_add(crate::error::PreparedFailurePair::allocation_bytes()))
        .ok_or(Error::Rejected(crate::RejectionReason::ObjectMutation(
            crate::ObjectMutationRejection::AttributeMutationPreparationAccounting,
        )))?;
    loop {
        // Binding can discover concurrent alias growth after the driver returns.
        // Retire the discarded destination before entering another source wait.
        let retirement =
            crate::managed::mutations::reservation_preparation::DestinationRetirement::new(session);
        retirement.retire();
        let (((completion, failures, template, mut revocation), reservation), access) =
            Reservation::prepare_mutation_prepaid(
                session,
                recipes,
                0,
                None,
                [(Some(object), AccessMode::Write)],
                false,
                authentication,
                progress,
                |overhead, current| loop {
                    session
                        .snapshot
                        .check_authentication_unchanged(authentication)?;
                    let shape = RevocationShape::discover(
                        session,
                        object.identity.resource(),
                        authentication,
                    )?;
                    let revocation_bytes = shape.allocation_bytes()?;
                    let admitted = required
                        .checked_add(revocation_bytes)
                        .and_then(|bytes| bytes.checked_add(overhead))
                        .ok_or(Error::Rejected(crate::RejectionReason::ObjectMutation(
                            crate::ObjectMutationRejection::AttributeMutationPreparationAccounting,
                        )))?;
                    let Some(mut credit) = crate::advanced::reserve_preparation_while(
                        session,
                        admitted,
                        progress,
                        || {
                            crate::session::recovery::observations::context(
                                session,
                                Some(authentication),
                                authentication,
                            )?;
                            current()
                        },
                    )?
                    else {
                        return Ok(None);
                    };
                    let storage = plan.allocate()?;
                    let revocation = shape.allocate()?;
                    let revocation_actual = revocation.allocated_bytes()?;
                    let actual = storage
                        .allocated_bytes()?
                        .checked_add(frame_bytes)
                        .and_then(|n| {
                            n.checked_add(crate::error::PreparedCompletion::allocation_bytes())
                        })
                        .and_then(|n| {
                            n.checked_add(crate::error::PreparedFailurePair::allocation_bytes())
                        })
                        .and_then(|bytes| bytes.checked_add(revocation_actual))
                        .and_then(|bytes| bytes.checked_add(overhead))
                        .ok_or(Error::Rejected(crate::RejectionReason::ObjectMutation(
                            crate::ObjectMutationRejection::AttributeMutationPreparationAccounting,
                        )))?;
                    if actual > admitted {
                        drop(revocation);
                        drop(storage);
                        drop(credit);
                        required = actual
                            .checked_sub(revocation_bytes)
                            .and_then(|bytes| bytes.checked_sub(overhead))
                            .ok_or(Error::Rejected(crate::RejectionReason::ObjectMutation(crate::ObjectMutationRejection::AttributeMutationPreparationAccounting)))?;
                        continue;
                    }
                    credit.release(admitted - actual);
                    let completion = crate::error::PreparedCompletion::prepare(
                        "C_SetAttributeValue",
                        &mut credit,
                    )?;
                    let failures = crate::error::PreparedFailurePair::prepare(&mut credit)?;
                    let mut template = storage.bind(&mut credit)?;
                    template.retain_frame_credit(credit.split(frame_bytes)?)?;
                    let revocation = revocation.bind(&mut credit)?;
                    // Return the complete candidate and only its coordination credit.
                    // No native call or optional observation belongs in this factory.
                    return Ok(Some(((completion, failures, template, revocation), credit)));
                },
                |_| Ok(()),
            )?;
        match revocation.bind(&access)? {
            Some(targets) => {
                return Ok((completion, failures, template, reservation, access, targets))
            }
            None => {
                // Registry growth raced preparation. No observation or mutation
                // has occurred, so release the whole candidate before re-admission.
                drop(access);
                drop(template);
                drop(reservation);
            }
        }
    }
}
