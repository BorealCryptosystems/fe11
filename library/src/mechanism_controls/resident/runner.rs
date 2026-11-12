// SPDX-License-Identifier: Apache-2.0
//! Run requested mechanism observations with resident result storage.
//! The observation owner retains its buffers through native result publication.
use super::*;
use crate::session::{
    recovery::observations::{context, Prepared, Waiting},
    AdmissionProgress,
};

/// `check` validates the existing reference and native table without dispatch;
/// `finish` constructs its alias without another resource wait or native call.
pub(crate) fn observe<T>(
    session: &Session,
    object: &crate::ManagedObjectRef,
    properties: &ObjectAdmission,
    mechanisms: &MechanismObservationPlan,
    check: impl Fn(&SessionAccess<'_>) -> Result<()>,
    finish: impl FnOnce(
        &SessionAccess<'_>,
        ObjectObservationReport,
        MechanismObservationReport,
    ) -> Result<T>,
) -> Result<T> {
    let epoch = session.snapshot.authentication_stamp();
    // This request observes the existing handle anew; old visibility is history.
    let authentication = Some(epoch);
    let policy = crate::admission_wait::current();
    let progress = AdmissionProgress::default();
    {
        let access = session.access_progress(&progress)?;
        session.managed_handle(&access, object)?;
        check(&access)?;
    }
    let activity = object.identity.activity.clone();
    let reader = activity.prepare_reader_checked(session.uid, &policy, || {
        context(session, authentication, epoch)
    })?;
    let registry_bytes = Prepared::allocation_bytes();
    let mut required = add(Initial::requested(properties, mechanisms)?, registry_bytes)?;
    let (coordination, first_access) = loop {
        context(session, authentication, epoch)?;
        let mut credit =
            crate::advanced::reserve_preparation_with_progress(session, required, &progress)?;
        let storage = Initial::allocate(properties, mechanisms)?;
        let actual = add(storage.allocated_bytes()?, registry_bytes)?;
        if actual > required {
            drop(storage);
            drop(credit);
            required = actual;
            continue;
        }
        credit.release(required - actual);
        let registry = Prepared::allocate(&session.inner.symmetric_budget, &mut credit)?;
        let acquired = (|| {
            // This slot predates access: refusal releases the guards first.
            let mut permit = None;
            let access = session.try_operation_access_progress(false, &progress)?;
            reader.acquire_into(&policy, &mut permit)?;
            let handle = session.managed_handle(&access, object)?;
            check(&access)?;
            Ok((access, permit.take().expect("reader acquired"), handle))
        })();
        match acquired {
            Ok((access, permit, handle)) => {
                let owner = storage.bind(
                    properties.clone(),
                    mechanisms.clone(),
                    handle,
                    authentication,
                    ObservationProtection::object(permit),
                    &mut credit,
                )?;
                let coordination = session
                    .entry
                    .recovery
                    .observations
                    .publish(registry.bind_policy(owner))?;
                break (coordination, access);
            }
            Err(Error::Busy(_)) => {
                drop(storage);
                drop(registry);
                drop(credit);
                drop(session.access_progress(&progress)?);
                reader
                    .wait_available_checked(&policy, || context(session, authentication, epoch))?;
            }
            Err(error) => return Err(error),
        }
    };
    let waiter = Waiting::new(session, coordination, authentication, epoch);
    let mut access = Some(first_access);
    let mut finish = Some(finish);
    loop {
        waiter.check()?;
        let held = access
            .take()
            .ok_or(Error::Rejected(crate::RejectionReason::Mechanisms(
                crate::MechanismsRejection::PolicyObservationPossessionAbsent,
            )))?;
        let handle = session.managed_handle(&held, object)?;
        check(&held)?;
        let slot = session
            .entry
            .recovery
            .observations
            .get(&waiter.coordination)?;
        let mut payload = slot.owner.lock().map_err(|_| Error::Poisoned)?;
        let owner = payload
            .as_mut()
            .ok_or(Error::Rejected(crate::RejectionReason::Mechanisms(
                crate::MechanismsRejection::PolicyObservationOwnerAbsent,
            )))?
            .policy_mut()?;
        owner.advance(session, &held, handle)?;
        if owner.complete() {
            let owner = payload
                .take()
                .expect("completed policy observation")
                .into_policy()?;
            // These callbacks perform local checks/alias construction only.
            return owner.result(session, &held, |properties, mechanisms| {
                finish.take().expect("single policy result")(&held, properties, mechanisms)
            });
        }
        let need = owner
            .need()
            .ok_or(Error::Rejected(crate::RejectionReason::Mechanisms(
                crate::MechanismsRejection::PolicyObservationNeedAbsent,
            )))?;
        drop(payload);
        drop(slot);
        drop(held);
        loop {
            let value = crate::attributes::owned::resident::prepare_value(
                need,
                waiter.budget(),
                &policy,
                || waiter.check(),
            )?;
            let resumed = match session.try_operation_access_progress(false, &progress) {
                Ok(access) => access,
                Err(Error::Busy(_)) => {
                    drop(value);
                    drop(session.access_progress(&progress)?);
                    continue;
                }
                Err(error) => return Err(error),
            };
            waiter.check()?;
            session.managed_handle(&resumed, object)?;
            check(&resumed)?;
            let slot = session
                .entry
                .recovery
                .observations
                .get(&waiter.coordination)?;
            let mut payload = slot.owner.lock().map_err(|_| Error::Poisoned)?;
            payload
                .as_mut()
                .ok_or(Error::Rejected(crate::RejectionReason::Mechanisms(
                    crate::MechanismsRejection::PolicyObservationOwnerAbsent,
                )))?
                .policy_mut()?
                .attach(need, value)?;
            drop(payload);
            drop(slot);
            access = Some(resumed);
            break;
        }
    }
}
