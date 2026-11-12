// SPDX-License-Identifier: Apache-2.0
//! One cleanup attempt for a failed resident mutation, preserving both errors.
use crate::{
    session::{
        recovery::observations::{Coordination, Owner},
        SessionAccess,
    },
    Error, Result, Session,
};
use std::sync::Arc;

/// Only the resident family can prove that its returned handles are eligible
/// for destruction. Registry or possession failure never grants that authority.
/// `prepare` borrows the original failure to distinguish an empty cleanup from
/// work blocked by an unfinished loan or a retired native context. It finishes
/// eligible searches before `cleanup` receives that same, unmodified cause.
/// The family checks and cleanup run under one exclusive resident-owner lock.
pub(super) fn cleanup_failed_mutation<'a, T>(
    session: &'a Session,
    coordination: &Arc<Coordination>,
    created: bool,
    result: Result<T>,
    storage: &mut crate::error::CleanupStorage,
    access: Option<SessionAccess<'a>>,
    acquire: impl FnOnce() -> Result<SessionAccess<'a>>,
    prepare: impl FnOnce(&mut Owner, &SessionAccess<'a>, &Error) -> Result<()>,
    cleanup: impl FnOnce(
        &mut Owner,
        &SessionAccess<'a>,
        Error,
        &mut crate::error::CleanupStorage,
    ) -> Error,
) -> Result<T> {
    let cause = match result {
        Ok(value) => return Ok(value),
        Err(cause) => cause,
    };
    // The root prepared every leaf before native effects. Keep the earlier
    // chain intact while reacquiring; successful preparation reuses those same
    // leaves for destruction instead of allocating another error envelope.
    let mut cause = Some(cause);
    let attempt = (|| {
        let access = match access {
            Some(access) => access,
            None => acquire()?,
        };
        let slot = session.entry.recovery.observations.get(coordination)?;
        let mut payload = slot.owner.lock().map_err(|_| Error::Poisoned)?;
        let owner =
            payload
                .as_mut()
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectCleanup(
                    crate::ObjectCleanupRejection::MutationCleanupOwnerAbsent,
                )))?;
        prepare(
            owner,
            &access,
            cause.as_ref().expect("mutation cleanup cause not consumed"),
        )?;
        let cause = cause.take().expect("mutation cleanup cause not consumed");
        Ok(cleanup(owner, &access, cause, storage))
    })();
    Err(match attempt {
        Ok(cause) => cause,
        Err(failure) => {
            let cause = cause.expect("mutation cleanup preparation failed");
            preparation_failure(created, cause, failure, storage)
        }
    })
}

fn preparation_failure(
    created: bool,
    cause: Error,
    failure: Error,
    storage: &mut crate::error::CleanupStorage,
) -> Error {
    if created {
        storage.object_failure(cause, failure)
    } else {
        storage.sequence_failure(cause, failure)
    }
}
