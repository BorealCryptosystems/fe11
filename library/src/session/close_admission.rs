// SPDX-License-Identifier: Apache-2.0
//! Possession for a single session close, selected before installing its receipt.
//! A non-creator with no retained owners needs no exclusion of peer readers.

use super::{CleanupAdmission, SessionEntry, State};
use crate::admission_wait::{ReadGuard, ResourceGuard, WriteGuard};
use crate::{Error, Result};
use std::sync::{atomic::Ordering, TryLockError};

enum TokenGuard<'a> {
    Local { _guard: ReadGuard<'a, ()> },
    Protected(WriteGuard<'a, ()>),
}

pub(super) struct CloseGuards<'a> {
    // Fields drop in declaration order: possession before transition/token.
    pub(super) session: ResourceGuard<'a>,
    _transition: ResourceGuard<'a>,
    token: TokenGuard<'a>,
}

fn busy_token() -> Error {
    Error::Busy(crate::BusyReason::ModuleLifecycle(
        crate::ModuleLifecycleBusy::TokenActivityDuringSessionClose,
    ))
}

fn transition(entry: &SessionEntry) -> Result<ResourceGuard<'_>> {
    entry
        .snapshot
        .domain
        .transition
        .try_lock()
        .map_err(|error| match error {
            TryLockError::WouldBlock => Error::Busy(crate::BusyReason::SessionLifecycle(
                crate::SessionLifecycleBusy::SessionTransition,
            )),
            TryLockError::Poisoned(_) => Error::Poisoned,
        })
}

/// A negative answer selects existing cleanup; a positive answer is rechecked
/// under all guards and supplemented with the ledgers, never used as authority.
fn candidate(entry: &SessionEntry) -> bool {
    entry.mode == crate::AdvancedSessionMode::Synchronous
        && entry.generation == entry.snapshot.generation
        && entry.slot as u64 == entry.snapshot.capabilities.identity.slot
        && entry.snapshot.admission_available()
        && !entry.creation_attempted.load(Ordering::Acquire)
        && entry.advanced_operation.load(Ordering::Acquire) == 0
        && !entry.native_handle_retired()
        && !entry.closed.load(Ordering::Acquire)
        && !entry.close_attempted.load(Ordering::Acquire)
        && !entry.close_pending.load(Ordering::Acquire)
        && !entry.poisoned.load(Ordering::Acquire)
        && !entry.snapshot.domain.has_retained_close()
}

impl<'a> CloseGuards<'a> {
    pub(super) fn acquire(
        state: &State,
        entry: &'a SessionEntry,
        admission: CleanupAdmission,
    ) -> Result<Self> {
        if matches!(admission, CleanupAdmission::Ordinary) && candidate(entry) {
            if let Some(guards) = Self::local(state, entry)? {
                return Ok(guards);
            }
        }
        // The local probe has dropped every guard; never upgrade a reader.
        let token = entry.snapshot.close_activity(match admission {
            CleanupAdmission::Ordinary => Some(false),
            CleanupAdmission::Token => Some(true),
            CleanupAdmission::Module => None,
        })?;
        let transition = transition(entry)?;
        let session = match entry.operation.try_lock() {
            Ok(guard) => guard,
            Err(TryLockError::WouldBlock) => {
                return Err(Error::Busy(crate::BusyReason::ModuleLifecycle(
                    crate::ModuleLifecycleBusy::SessionActivity,
                )))
            }
            // Cleanup after an unwind does not resume its uncertain operation.
            Err(TryLockError::Poisoned(poison)) => poison.into_inner(),
        };
        Ok(Self {
            session,
            _transition: transition,
            token: TokenGuard::Protected(token),
        })
    }

    fn local(state: &State, entry: &'a SessionEntry) -> Result<Option<Self>> {
        entry.snapshot.check_drain(false)?;
        let token = entry
            .snapshot
            .domain
            .activity
            .try_read()
            .map_err(|error| match error {
                TryLockError::WouldBlock => busy_token(),
                TryLockError::Poisoned(_) => Error::Poisoned,
            })?;
        entry.snapshot.check_drain(false)?;
        let transition = transition(entry)?;
        let session = match entry.operation.try_lock() {
            Ok(guard) => guard,
            Err(TryLockError::WouldBlock) => return Err(busy_token()),
            // A poisoned session cannot justify the local proof. Release the
            // recovered gate and let the ordinary protected cleanup inspect it.
            Err(TryLockError::Poisoned(poison)) => {
                drop(poison.into_inner());
                return Ok(None);
            }
        };
        // Poison cannot prove the local scope, but must not remove the existing
        // protected cleanup path's ability to inspect and retain damaged state.
        match Self::local_eligible(state, entry) {
            Ok(true) => {}
            Ok(false) | Err(Error::Poisoned) => return Ok(None),
            Err(error) => return Err(error),
        }
        Ok(Some(Self {
            session,
            _transition: transition,
            token: TokenGuard::Local { _guard: token },
        }))
    }

    fn local_eligible(state: &State, entry: &SessionEntry) -> Result<bool> {
        if !candidate(entry) || state.native.is_uncertain() {
            return Ok(false);
        }
        let has_receipt = {
            let control = entry.close_control.lock().map_err(|_| Error::Poisoned)?;
            control.is_some()
        };
        if has_receipt || state.operations.has_owner(entry)? {
            return Ok(false);
        }
        if !entry.recovery.is_empty_for_close()? {
            return Ok(false);
        }
        state.session_ledger.has_other_open_session(entry)
    }

    pub(super) fn writer(&self) -> Option<&WriteGuard<'a, ()>> {
        match &self.token {
            TokenGuard::Protected(guard) => Some(guard),
            TokenGuard::Local { .. } => None,
        }
    }

    pub(super) fn is_local(&self) -> bool {
        matches!(self.token, TokenGuard::Local { .. })
    }
}
