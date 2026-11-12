// SPDX-License-Identifier: Apache-2.0
//! Possession boundaries for one reference observation, never native retries.
use super::*;
use crate::managed::search::SearchWithdrawal;

pub(crate) fn observe(
    session: &Session,
    object: &ManagedObjectRef,
    selection: ObjectReferencePlan,
    content: ContentObservation,
) -> Result<ObjectReferenceReport> {
    let selected_content = content_plan(&content);
    let epoch = session.snapshot.authentication_stamp();
    // This request observes the existing handle anew; old visibility is history.
    let authentication = Some(epoch);
    let progress = AdmissionProgress::default();
    let policy = crate::admission_wait::current();
    // Counting and materialization visit the same immutable caller-bound fields.
    if !preparation::Initial::requires_preparation(&selection, object, selected_content)? {
        // No native observation and no byte-owned graph: retain the original
        // reference validation without introducing a synthetic memory admission.
        let (access, mut readers) = session.managed_read_access([Some(object)], false)?;
        access.retain_prepared_reader(readers[0].take().expect("prepared object reader"))?;
        let result =
            ObjectReferenceReport::observe_local(selection, &access, session, object, content);
        return object.identity.access.result(session, &access, result);
    }
    context(session, authentication, epoch)?;
    // Bind before preparing or waiting: drain and Activity release must
    // notify the same domain, including references with a fresh Activity.
    let wake = session
        .inner
        .reservations
        .lock()
        .map_err(|_| Error::Poisoned)?
        .scan_wake();
    object.identity.activity.bind_context_wake(&wake)?;
    let reader = object
        .identity
        .activity
        .prepare_reader_checked(session.uid, &policy, || {
            context(session, authentication, epoch)
        })?;
    let fixed = Prepared::allocation_bytes()
        .checked_add(crate::error::PreparedCleanupDiagnostic::allocation_bytes())
        .ok_or(Error::Rejected(crate::RejectionReason::ObjectReferences(
            crate::ObjectReferencesRejection::ReferenceDiagnosticStorageSize,
        )))?;
    let mut required = preparation::Initial::requested(&selection, object)?
        .checked_add(fixed)
        .ok_or(Error::Rejected(crate::RejectionReason::ObjectReferences(
            crate::ObjectReferencesRejection::ReferenceStorageSize,
        )))?;
    let mut content = Some(content);
    let (mut search_cleanup, coordination, first_access) = loop {
        context(session, authentication, epoch)?;
        policy.check_available()?;
        session.admission().check_available()?;
        let mut credit =
            crate::advanced::reserve_preparation_while(session, required, &progress, || {
                // Keep the current observation coherent across resource waits;
                // the reference does not confer a current login state.
                context(session, authentication, epoch)?;
                Ok(true)
            })?
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectReferences(
                crate::ObjectReferencesRejection::ReferencePreparationInvalidated,
            )))?;
        // Search buffers and bound metadata are one credited preparation.
        // Partial copies can fail here without any session possession.
        let mut initial = preparation::Initial::allocate(&selection, object)?;
        let actual = initial
            .allocated_bytes()?
            .checked_add(fixed)
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectReferences(
                crate::ObjectReferencesRejection::ReferenceStorageSize,
            )))?;
        if actual > required {
            drop(initial);
            drop(credit);
            required = actual;
            continue;
        }
        credit.release(required - actual);
        credit.observation_budget()?;
        let search_cleanup = crate::error::PreparedCleanupDiagnostic::prepare(&mut credit)?;
        let mut registry = Some(Prepared::allocate(
            &session.inner.symmetric_budget,
            &mut credit,
        )?);
        // Keep preparation, protection and registry outside access through
        // every fallible binding step and publication.
        let mut permit = None;
        let mut protection;
        let acquired = (|| {
            let access = session.try_operation_access_progress(false, &progress)?;
            reader.acquire_into(&policy, &mut permit)?;
            session.managed_handle(&access, object)?;
            context(session, authentication, epoch)?;
            Ok(access)
        })();
        let access = match acquired {
            Ok(value) => value,
            Err(Error::Busy(_)) => {
                drop(search_cleanup);
                drop(permit.take());
                drop(initial);
                drop(registry);
                drop(credit);
                drop(session.access_progress_at_epoch(&progress, epoch)?);
                reader.wait_available_in_context(&policy, || {
                    context(session, authentication, epoch)
                })?;
                continue;
            }
            Err(error) => return Err(error),
        };
        protection = Some(ObservationProtection::object(
            permit.take().expect("reader acquired"),
        ));
        let owner = initial.bind_retained(
            session,
            &access,
            object,
            &selection,
            &mut content,
            epoch,
            &mut protection,
            &mut credit,
        )?;
        registry = Some(
            registry
                .take()
                .expect("prepared registry")
                .bind_reference(owner),
        );
        let coordination = session
            .entry
            .recovery
            .observations
            .publish_retained(&mut registry)?;
        break (search_cleanup, coordination, access);
    };
    let waiter = Waiting::new(session, coordination, authentication, epoch);
    let search_open = std::cell::Cell::new(false);
    let _withdrawal = SearchWithdrawal::new(session, &search_open);
    let mut access = Some(first_access);
    let result = (|| loop {
        waiter.check()?;
        let owned_access =
            access
                .take()
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectReferences(
                    crate::ObjectReferencesRejection::ReferencePossessionAbsent,
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
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectReferences(
                crate::ObjectReferencesRejection::ReferenceOwnerAbsent,
            )))?
            .reference_mut()?;
        search_open.set(owner.search_claimed());
        let advanced = owner.advance(session, &owned_access, handle);
        search_open.set(owner.search_claimed() && owner.pending());
        advanced?;
        if owner.complete() {
            let owner = payload
                .take()
                .expect("complete reference")
                .into_reference()?;
            return object.identity.access.result(
                session,
                &owned_access,
                owner.result(session, &owned_access),
            );
        }
        let need =
            owner
                .need()?
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectReferences(
                    crate::ObjectReferencesRejection::ReferenceResourceNeedAbsent,
                )))?;
        drop(payload);
        drop(slot);
        drop(owned_access);
        loop {
            let candidate = prepare(
                need,
                &selection,
                selected_content,
                session,
                &policy,
                &waiter,
            )?;
            // As in the other resident observation runners, attaching
            // empty storage is local. No candidate is consumed under access.
            waiter.check()?;
            let slot = session
                .entry
                .recovery
                .observations
                .get(&waiter.coordination)?;
            let mut payload = slot.owner.lock().map_err(|_| Error::Poisoned)?;
            payload
                .as_mut()
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectReferences(
                    crate::ObjectReferencesRejection::ReferenceOwnerAbsent,
                )))?
                .reference_mut()?
                .attach(need, candidate)?;
            drop(payload);
            drop(slot);
            access = Some(session.access_progress_at_epoch(&progress, epoch)?);
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
            let owner = owner.reference_mut()?;
            let cleanup = owner.finish_search(session, access);
            search_open.set(owner.search_claimed() && owner.pending());
            cleanup
        },
    );
    result
}
