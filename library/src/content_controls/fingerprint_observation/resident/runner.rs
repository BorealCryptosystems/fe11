// SPDX-License-Identifier: Apache-2.0
//! Root possession loop for the complete historical fingerprint protocol.
use super::*;
use crate::{
    attributes::owned::resident::ReadStorage,
    session::{
        recovery::observations::{context, Prepared, Waiting},
        AdmissionProgress,
    },
    ManagedObjectRef,
};

pub(crate) fn observe<T>(
    session: &Session,
    object: &ManagedObjectRef,
    read: AttributeReadPlan,
    finish: impl FnOnce(ProtectedContent) -> Result<T>,
) -> Result<T> {
    let epoch = session.snapshot.authentication_stamp();
    // This request observes the existing handle anew; old visibility is history.
    let authentication = Some(epoch);
    let progress = AdmissionProgress::default();
    let policy = crate::admission_wait::current();
    let session_policy = session.admission();
    let reader = object
        .identity
        .activity
        .prepare_reader_checked(session.uid, &policy, || {
            context(session, authentication, epoch)
        })?;
    let recipe = Recipe::Fingerprint {
        fields: &FINGERPRINT_HEADER,
        plan: read,
    };
    let fixed = std::mem::size_of::<FingerprintOwner>()
        .checked_add(Prepared::allocation_bytes())
        .ok_or(Error::Rejected(crate::RejectionReason::ObjectContent(
            crate::ObjectContentRejection::FingerprintOwnerStorageSize,
        )))?;
    let mut required =
        ReadStorage::requested(recipe)?
            .checked_add(fixed)
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectContent(
                crate::ObjectContentRejection::FingerprintOwnerStorageSize,
            )))?;
    let (coordination, access) = loop {
        context(session, authentication, epoch)?;
        policy.check_available()?;
        session_policy.check_available()?;
        let mut credit =
            crate::advanced::reserve_preparation_with_progress(session, required, &progress)?;
        let storage = ReadStorage::allocate(recipe)?;
        let actual = storage
            .allocated_bytes()?
            .checked_add(fixed)
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectContent(
                crate::ObjectContentRejection::FingerprintOwnerStorageSize,
            )))?;
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
            Ok((access, handle, permit.take().expect("reader acquired")))
        })();
        match acquired {
            Ok((access, handle, permit)) => {
                let header = storage.bind(
                    &mut credit,
                    recipe,
                    handle,
                    authentication,
                    permit.duplicate()?,
                )?;
                let owner = FingerprintOwner::bind(
                    header,
                    read,
                    handle,
                    authentication,
                    permit,
                    &mut credit,
                )?;
                let coordination = session
                    .entry
                    .recovery
                    .observations
                    .publish(registry.bind_fingerprint(owner))?;
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
    let mut access = Some(access);
    let result = (|| loop {
        waiter.check()?;
        let owned_access =
            access
                .take()
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectContent(
                    crate::ObjectContentRejection::FingerprintPossessionAbsent,
                )))?;
        let handle = session.managed_handle(&owned_access, object)?;
        let slot = session
            .entry
            .recovery
            .observations
            .get(&waiter.coordination)?;
        let mut payload = slot.owner.lock().map_err(|_| Error::Poisoned)?;
        let owner = payload
            .as_mut()
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectContent(
                crate::ObjectContentRejection::FingerprintOwnerAbsent,
            )))?
            .fingerprint_mut()?;
        owner.advance(session, &owned_access, handle)?;
        if owner.complete() {
            let owner = payload
                .take()
                .expect("completed fingerprint")
                .into_fingerprint()?;
            let result = owner.result(session, &owned_access, finish);
            drop(payload);
            drop(slot);
            drop(owned_access);
            return result;
        }
        let need = owner
            .need()
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectContent(
                crate::ObjectContentRejection::FingerprintPreparationNeedAbsent,
            )))?;
        drop(payload);
        drop(slot);
        drop(owned_access);
        loop {
            let candidate =
                preparation::prepare(need, read, waiter.budget(), &policy, || waiter.check())?;
            waiter.check()?;
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
            session.managed_handle(&resumed, object)?;
            let slot = session
                .entry
                .recovery
                .observations
                .get(&waiter.coordination)?;
            let mut payload = slot.owner.lock().map_err(|_| Error::Poisoned)?;
            payload
                .as_mut()
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectContent(
                    crate::ObjectContentRejection::FingerprintOwnerAbsent,
                )))?
                .fingerprint_mut()?
                .attach(need, candidate)?;
            drop(payload);
            drop(slot);
            access = Some(resumed);
            break;
        }
    })();
    drop(access);
    result
}
