// SPDX-License-Identifier: Apache-2.0
//! A complete bounded batch is published before releasing its catalogue guard.
use super::*;

pub(super) fn fetch(session: &Session, cursor: &Cursor<'_>) -> Result<Option<NativeObjectMatches>> {
    let reference =
        session.reference_admission(crate::session::ReferenceMode::Synchronous, |_| Ok(()))?;
    let policy = crate::admission_wait::current();
    let count = loop {
        cursor.waiter.check()?;
        let mut credit = crate::advanced::reserve_preparation_while_in(
            session,
            cursor.waiter.budget(),
            mutations::PreparedInventory::allocation_bytes()?,
            reference.progress(),
            || {
                cursor.waiter.check()?;
                Ok(true)
            },
        )?
        .ok_or(Error::Rejected(crate::RejectionReason::ObjectSearch(
            crate::ObjectSearchRejection::SearchPreparationUnexpectedlyInvalidated,
        )))?;
        // Retained publication keeps this allocation alive on refusal. These
        // locals precede possession, so every exit releases possession first.
        let mut inventory = mutations::PreparedInventory::from_prepaid(session, &mut credit)?;
        let access = match session.try_operation_access_progress(false, reference.progress()) {
            Ok(access) => access,
            Err(Error::Busy(_)) => {
                drop((inventory, credit));
                drop(session.access_progress(reference.progress())?);
                continue;
            }
            Err(error) => return Err(error),
        };
        reference.check(&access)?;
        cursor.waiter.check()?;
        let slot = session
            .entry
            .recovery
            .observations
            .get(&cursor.waiter.coordination)?;
        let mut payload = slot.owner.lock().map_err(|_| Error::Poisoned)?;
        let owner = payload
            .as_mut()
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectSearch(
                crate::ObjectSearchRejection::NativeSearchStreamOwnerAbsent,
            )))?
            .native_search_stream_mut()?;
        if !matches!(owner.batch, Batch::Idle) {
            return Err(Error::Rejected(crate::RejectionReason::ObjectSearch(
                crate::ObjectSearchRejection::SearchStreamBatchAlreadyOwned,
            )));
        }
        let protection = match inventory.publish_retained(session) {
            Ok(protection) => protection,
            Err(Error::Busy(_)) => {
                drop(payload);
                drop(slot);
                drop(access);
                drop((inventory, credit));
                mutations::PreparedInventory::wait_available(session, cursor.epoch)?;
                continue;
            }
            Err(error) => return Err(error),
        };
        owner.batch = Batch::Reading(protection);
        let fetched = owner.search.stream_batch(session, &access);
        cursor.pending.set(owner.pending());
        let count = fetched?;
        if count == 0 {
            let finished = owner.search.finish(session, &access);
            cursor.pending.set(owner.pending());
            finished?;
            // Waiting retires the complete owner after these guards leave.
            return Ok(None);
        }
        break count;
    };

    // The native batch is already resident. Admission retries below prepare
    // only its identities and cannot invoke Find again or retain a prefix quota.
    loop {
        let matches = AllMatches::prepare(session, cursor.epoch, count, &cursor.waiter, |bytes| {
            reference.objects_with_storage_observing(count, bytes, cursor.waiter.budget(), || {
                cursor.waiter.check()
            })
        })?;
        let access = match session.try_operation_access_progress(false, reference.progress()) {
            Ok(access) => access,
            Err(Error::Busy(_)) => {
                drop(matches);
                drop(session.access_progress(reference.progress())?);
                continue;
            }
            Err(error) => return Err(error),
        };
        reference.check(&access)?;
        cursor.waiter.check()?;
        let slot = session
            .entry
            .recovery
            .observations
            .get(&cursor.waiter.coordination)?;
        let mut payload = slot.owner.lock().map_err(|_| Error::Poisoned)?;
        let owner = payload
            .as_mut()
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectSearch(
                crate::ObjectSearchRejection::NativeSearchStreamOwnerAbsent,
            )))?
            .native_search_stream_mut()?;
        if !matches!(owner.batch, Batch::Reading(_)) || owner.search.stream_batch_len()? != count {
            return Err(Error::Rejected(crate::RejectionReason::ObjectSearch(
                crate::ObjectSearchRejection::SearchStreamPublicationChanged,
            )));
        }
        let Batch::Reading(inventory) = std::mem::replace(&mut owner.batch, Batch::Idle) else {
            unreachable!("checked resident reading state")
        };
        owner.batch = Batch::Publishing { inventory, matches };
        break;
    }
    publish(session, cursor, reference.progress(), &policy, count).map(Some)
}

impl NativeSearchStreamOwner {
    fn publication_activity(
        &mut self,
        session: &Session,
    ) -> Result<Arc<crate::registry::Activity>> {
        let Batch::Publishing { matches, .. } = &mut self.batch else {
            return Err(Error::Rejected(crate::RejectionReason::ObjectSearch(
                crate::ObjectSearchRejection::SearchStreamPublicationAbsent,
            )));
        };
        let identity = matches
            .identities
            .get(matches.published)
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectSearch(
                crate::ObjectSearchRejection::SearchStreamPublicationIndexAbsent,
            )))?;
        let handle = self.search.stream_handle(matches.published)?;
        let activity = mutations::object_activity_at(
            &session.inner,
            ResourceIdentity {
                handle,
                ..identity.resource()
            },
            crate::Observation::NotRequested,
            &mut matches.permit,
        )?;
        let wake = session
            .inner
            .reservations
            .lock()
            .map_err(|_| Error::Poisoned)?
            .scan_wake();
        activity.bind_context_wake(&wake)?;
        Ok(activity)
    }
}

fn publish(
    session: &Session,
    cursor: &Cursor<'_>,
    progress: &crate::session::AdmissionProgress,
    policy: &crate::ResourceAdmission,
    count: usize,
) -> Result<NativeObjectMatches> {
    loop {
        let activity = {
            let access = session.access_progress(progress)?;
            session.entry(&access)?;
            cursor.waiter.check()?;
            let slot = session
                .entry
                .recovery
                .observations
                .get(&cursor.waiter.coordination)?;
            let mut payload = slot.owner.lock().map_err(|_| Error::Poisoned)?;
            payload
                .as_mut()
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectSearch(
                    crate::ObjectSearchRejection::NativeSearchStreamOwnerAbsent,
                )))?
                .native_search_stream_mut()?
                .publication_activity(session)?
        };
        let reader =
            activity.prepare_reader_checked(session.uid, policy, || cursor.waiter.check())?;
        loop {
            let mut permits = [None];
            let access = session.access_progress(progress)?;
            session.entry(&access)?;
            cursor.waiter.check()?;
            let slot = session
                .entry
                .recovery
                .observations
                .get(&cursor.waiter.coordination)?;
            let mut payload = slot.owner.lock().map_err(|_| Error::Poisoned)?;
            match reader.acquire_into(policy, &mut permits[0]) {
                Ok(()) => (),
                Err(Error::Busy(_)) => {
                    drop(payload);
                    drop(slot);
                    drop(access);
                    reader.wait_available_in_context(policy, || cursor.waiter.check())?;
                    continue;
                }
                Err(error) => return Err(error),
            };
            let owner = payload
                .as_mut()
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectSearch(
                    crate::ObjectSearchRejection::NativeSearchStreamOwnerAbsent,
                )))?
                .native_search_stream_mut()?;
            let Batch::Publishing { matches, .. } = &mut owner.batch else {
                return Err(Error::Rejected(crate::RejectionReason::ObjectSearch(
                    crate::ObjectSearchRejection::SearchStreamPublicationAbsent,
                )));
            };
            let handle = owner.search.stream_handle(matches.published)?;
            let identity = matches
                .identities
                .get_mut(matches.published)
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectSearch(
                    crate::ObjectSearchRejection::SearchStreamPublicationIndexAbsent,
                )))?;
            NativeIdentity::publish_discovered(
                identity,
                session,
                &access,
                handle,
                &mut matches.permit,
                &mut permits,
            )?;
            matches.published += 1;
            if matches.published != count {
                // The next canonical reader is prepared outside possession.
                break;
            }
            owner.search.acknowledge_stream_batch()?;
            let batch = std::mem::replace(&mut owner.batch, Batch::Idle);
            drop(payload);
            drop(slot);
            drop(access);
            let Batch::Publishing { inventory, matches } = batch else {
                unreachable!("checked resident publication state")
            };
            // Public references contain Inner; assemble them only after the
            // publication leaves recovery. The iterator never holds catalogue
            // exclusion while its caller consumes this ready batch.
            drop(inventory);
            return matches.result(session, count);
        }
    }
}
