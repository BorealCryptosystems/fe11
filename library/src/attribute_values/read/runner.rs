// SPDX-License-Identifier: Apache-2.0
//! Guard-free resource waits between two completed attribute passes.
use super::owner::{self, FlatOwner};
use crate::{
    attribute_values::{AttributeBatchCalls, FlatAttributeBatch, FlatAttributeRequest},
    session::{
        recovery::observations::{Coordination, Prepared as RegistryPreparation, Waiting},
        AdmissionProgress, SessionAccess,
    },
    Error, NativeObjectRef, Result, Session,
};
use std::sync::Arc;

fn prepare<'a>(
    session: &'a Session,
    object: &NativeObjectRef,
    requests: &[FlatAttributeRequest],
    maximum: usize,
    progress: &AdmissionProgress,
    epoch: u64,
) -> Result<(Arc<Coordination>, SessionAccess<'a>)> {
    let budget = &session.inner.symmetric_budget;
    let policy = crate::admission_wait::current();
    let session_policy = session.admission();
    let context = || {
        crate::session::activity::context(session)?;
        // Both passes belong to this request, not the old visibility report.
        session.snapshot.observe_authentication_unchanged(epoch)
    };
    let reader =
        object
            .identity
            .activity()?
            .prepare_reader_checked(session.uid, &policy, context)?;
    let registry_bytes = RegistryPreparation::allocation_bytes();
    let mut required = owner::Plan::new(session, requests, maximum)?
        .requested_bytes()?
        .checked_add(registry_bytes)
        .ok_or(Error::Rejected(crate::RejectionReason::AttributeValues(
            crate::AttributeValuesRejection::AttributeOwnerAccounting,
        )))?;
    loop {
        context()?;
        policy.check_available()?;
        session_policy.check_available()?;
        let mut credit =
            crate::advanced::reserve_preparation_with_progress(session, required, progress)?;
        let plan = owner::Plan::new(session, requests, maximum)?;
        let storage = plan.allocate()?;
        let actual = storage
            .allocated_bytes()?
            .checked_add(registry_bytes)
            .ok_or(Error::Rejected(crate::RejectionReason::AttributeValues(
                crate::AttributeValuesRejection::AttributeOwnerAccounting,
            )))?;
        if actual > required {
            drop(storage);
            drop(credit);
            required = actual;
            continue;
        }
        credit.release(required - actual);
        let registry = RegistryPreparation::allocate(budget, &mut credit)?;
        let prepared = plan.bind(storage, &mut credit)?;
        let acquired = (|| {
            // This slot predates access: refusal releases the guards first.
            let mut permit = None;
            let access = session.try_advanced_access_progress(progress)?;
            context()?;
            reader.acquire_into(&policy, &mut permit)?;
            session.native_object_handle(&access, object)?;
            Ok((access, permit.take().expect("reader acquired")))
        })();
        match acquired {
            Ok((access, permit)) => {
                let owner = FlatOwner::bind(prepared, object, permit, epoch);
                let coordination = session
                    .entry
                    .recovery
                    .observations
                    .publish(registry.bind(owner))?;
                return Ok((coordination, access));
            }
            Err(Error::Busy(_)) => {
                // No copied input, empty graph or partial permission crosses a
                // possession wait. The reader's attribution slot is metadata.
                drop(prepared);
                drop(registry);
                drop(credit);
                drop(session.advanced_access_progress(
                    crate::session::CleanupAdmission::Ordinary,
                    progress,
                )?);
                reader.wait_available_checked(&policy, context)?;
            }
            Err(error) => return Err(error),
        }
    }
}

pub(super) fn observe_batch(
    session: &Session,
    object: &NativeObjectRef,
    requests: &[FlatAttributeRequest],
    maximum: usize,
) -> Result<FlatAttributeBatch> {
    super::validate_requests(session, requests, maximum)?;
    if requests.is_empty() {
        return FlatAttributeBatch::prepare(&session.inner.symmetric_budget, 0)?
            .finish(AttributeBatchCalls::None);
    }
    // Attribute reads do not advance a parked cryptographic operation. Keep
    // its owner intact while serializing both passes with actual session use.
    // This synchronous entry point still cannot dispatch asynchronous calls.
    session.check_synchronous_dispatch()?;
    let progress = AdmissionProgress::default();
    let policy = crate::admission_wait::current();
    let epoch = session.snapshot.authentication_stamp();
    let (coordination, access) = prepare(session, object, requests, maximum, &progress, epoch)?;
    // Declare the waiter before the optional access so unwinding releases all
    // possession before its nonwaiting reclamation attempt.
    let waiter = Waiting::new(session, coordination, Some(epoch), epoch);
    let mut access = Some(access);
    let mut calls = AttributeBatchCalls::None;
    let run =
        (|| {
            loop {
                waiter.check()?;
                let owned_access = access.take().ok_or(Error::Rejected(
                    crate::RejectionReason::AttributeValues(
                        crate::AttributeValuesRejection::AttributePossessionAbsent,
                    ),
                ))?;
                let slot = session
                    .entry
                    .recovery
                    .observations
                    .get(&waiter.coordination)?;
                let mut payload = slot.owner.lock().map_err(|_| Error::Poisoned)?;
                let owner = payload
                    .as_mut()
                    .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
                        crate::KeyAdmissionRejection::AttributeOwnerAbsent,
                    )))?
                    .flat_mut()?;
                let advance = owner.advance(session, &owned_access);
                calls = owner.calls();
                advance?;
                if owner.complete() {
                    let owner = payload.take().expect("completed owner").into_flat()?;
                    let result = owner.result(session, &owned_access);
                    drop(payload);
                    drop(slot);
                    drop(owned_access);
                    return result;
                }
                let need = owner.need().ok_or(Error::Rejected(
                    crate::RejectionReason::AttributeValues(
                        crate::AttributeValuesRejection::AttributeValueNeedAbsent,
                    ),
                ))?;
                drop(payload);
                drop(slot);
                drop(owned_access);

                loop {
                    // Neither a Slot Arc nor native output is retained here. Close
                    // can extract and destroy the observation while credit waits.
                    let value = match owner::prepare_value(need, waiter.budget(), &policy, || {
                        waiter.check()?;
                        Ok(None::<()>)
                    }) {
                        Ok(owner::ValuePreparation::Ready(value)) => Ok(value),
                        Ok(owner::ValuePreparation::Redirect(())) => {
                            unreachable!("no redirect requested")
                        }
                        Err(error) => Err(error),
                    };
                    waiter.check()?;
                    let resumed = match session.try_advanced_access_progress(&progress) {
                        Ok(access) => access,
                        Err(Error::Busy(_)) => {
                            drop(value);
                            drop(session.advanced_access_progress(
                                crate::session::CleanupAdmission::Ordinary,
                                &progress,
                            )?);
                            continue;
                        }
                        Err(error) => return Err(error),
                    };
                    waiter.check()?;
                    let slot = session
                        .entry
                        .recovery
                        .observations
                        .get(&waiter.coordination)?;
                    let mut payload = slot.owner.lock().map_err(|_| Error::Poisoned)?;
                    let owner = payload
                        .as_mut()
                        .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
                            crate::KeyAdmissionRejection::AttributeOwnerAbsent,
                        )))?
                        .flat_mut()?;
                    // Only this private synchronous call advances this observation.
                    // Identity and exact need still exclude attachment after close.
                    owner.attach(need, value)?;
                    drop(payload);
                    drop(slot);
                    access = Some(resumed);
                    break;
                }
            }
        })();
    drop(access);
    run.map_err(|error| FlatOwner::interrupted(error, calls))
}
