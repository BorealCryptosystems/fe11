// SPDX-License-Identifier: Apache-2.0
//! One nonwaiting cleanup attempt that preserves the original operation error.
use crate::{
    session::{
        recovery::observations::{Coordination, Owner},
        SessionAccess,
    },
    Error, Result, Session,
};
use std::{cell::Cell, sync::Arc};

/// The caller supplies its original admission and family-specific search owner.
/// No failed admission becomes permission to dispatch, and no error is replaced
/// by a registry/lock failure encountered while trying to finish the search.
pub(crate) fn finish_failed_search<'a, T>(
    session: &'a Session,
    coordination: &Arc<Coordination>,
    open: &Cell<bool>,
    result: Result<T>,
    prepared: &mut crate::error::PreparedCleanupDiagnostic,
    access: Option<SessionAccess<'a>>,
    acquire: impl FnOnce() -> Result<SessionAccess<'a>>,
    finish: impl FnOnce(&mut Owner, &SessionAccess<'a>) -> Result<()>,
) -> Result<T> {
    let error = match result {
        Ok(value) => return Ok(value),
        Err(error) if !open.get() => return Err(error),
        Err(error) => error,
    };
    // The enclosing root supplies the error shape and retains its credit through
    // publication. Preserve any earlier compound failure as the primary cause.
    let diagnostic = prepared.take(error);
    let mut metadata_unproven = false;
    let cleanup = (|| {
        let access = match access {
            Some(access) => access,
            None => acquire()?,
        };
        let slot = session.entry.recovery.observations.get(coordination)?;
        let mut payload = match slot.owner.lock() {
            Ok(payload) => payload,
            Err(error) => {
                // Recover mutex ownership only, never native-call authority.
                // The original owner stays in its registry with all referents.
                let retained = error.into_inner();
                drop(retained);
                metadata_unproven = true;
                return Err(Error::Poisoned);
            }
        };
        let owner =
            payload
                .as_mut()
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectSearch(
                    crate::ObjectSearchRejection::SearchCleanupOwnerAbsent,
                )))?;
        finish(owner, &access)
    })();
    Err(if metadata_unproven {
        diagnostic.finish(cleanup.err())
    } else {
        diagnostic.finish_sequence(cleanup.err())
    })
}
