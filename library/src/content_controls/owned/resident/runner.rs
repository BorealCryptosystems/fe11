// SPDX-License-Identifier: Apache-2.0
//! Protected-content root: drop possession before every credit wait.
use super::*;
use crate::{
    session::{
        recovery::observations::{context, Prepared, Waiting},
        AdmissionProgress,
    },
    ManagedObjectRef,
};

pub(crate) fn value(
    session: &Session,
    object: &ManagedObjectRef,
    maximum: usize,
) -> Result<ProtectedContent> {
    value_with(session, object, maximum, Ok)
}
pub(crate) fn value_with<T>(
    session: &Session,
    object: &ManagedObjectRef,
    maximum: usize,
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
    let frame_bytes =
        std::mem::size_of::<ValueCall>() + SessionFrame::<'static, ValueCall>::allocation_bytes();
    let required = frame_bytes
        .checked_add(Prepared::allocation_bytes())
        .ok_or(Error::Rejected(crate::RejectionReason::ObjectContent(
            crate::ObjectContentRejection::ContentObservationStorageSize,
        )))?;
    let (coordination, access) = loop {
        context(session, authentication, epoch)?;
        policy.check_available()?;
        session_policy.check_available()?;
        let mut credit =
            crate::advanced::reserve_preparation_with_progress(session, required, &progress)?;
        let registry = Prepared::allocate(&session.inner.symmetric_budget, &mut credit)?;
        let call = ValueCall {
            descriptor: CK_ATTRIBUTE {
                r#type: CKA_VALUE,
                pValue: std::ptr::null_mut(),
                ulValueLen: 0,
            },
            phase: Phase::Sizing,
            _credit: credit.split(frame_bytes)?,
        };
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
                let owner = ContentOwner::bind(call, handle, maximum, authentication, permit);
                let coordination = session
                    .entry
                    .recovery
                    .observations
                    .publish(registry.bind_content(owner))?;
                break (coordination, access);
            }
            Err(Error::Busy(_)) => {
                drop(call);
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
                    crate::ObjectContentRejection::ContentPossessionAbsent,
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
                crate::ObjectContentRejection::ContentOwnerAbsent,
            )))?
            .content_mut()?;
        owner.advance(session, &owned_access, handle)?;
        if owner.complete() {
            let owner = payload.take().expect("completed content").into_content()?;
            let result = owner.result(session, &owned_access, finish);
            drop(payload);
            drop(slot);
            drop(owned_access);
            return result;
        }
        let length = owner
            .need()
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectContent(
                crate::ObjectContentRejection::ContentValueNeedAbsent,
            )))?;
        drop(payload);
        drop(slot);
        drop(owned_access);
        loop {
            let output = prepare_value(length, waiter.budget(), &policy, || waiter.check())?;
            waiter.check()?;
            let resumed = match session.try_operation_access_progress(false, &progress) {
                Ok(access) => access,
                Err(Error::Busy(_)) => {
                    drop(output);
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
                    crate::ObjectContentRejection::ContentOwnerAbsent,
                )))?
                .content_mut()?
                .attach(length, output)?;
            drop(payload);
            drop(slot);
            access = Some(resumed);
            break;
        }
    })();
    drop(access);
    result
}
