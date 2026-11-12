// SPDX-License-Identifier: Apache-2.0
//! Reader storage before possession, followed by all-or-none permission binding.
use crate::{
    registry::{PreparedReader, ReadPermit},
    session::SessionAccess,
    Error, ResourceAdmission, Result, Session,
};
use std::sync::Arc;
pub(super) mod dynamic;
pub(crate) use dynamic::{DynamicReadPlan, DynamicReadStorage};
mod prepaid;
mod preparation;
pub(super) mod roles;
pub(crate) use preparation::PossessionAttempt;
pub(crate) use roles::{
    AccessMode, Permission, PermissionStorage, Permissions, PreparedRoles, RetiredRolePlan,
    RolePlan,
};

pub(crate) struct Readers<const N: usize> {
    readers: [Option<PreparedReader>; N],
    admission: ResourceAdmission,
    authentication: u64,
}
impl<const N: usize> Readers<N> {
    /// Probe every prepared role without retaining partial permissions or
    /// waiting. The caller owns any transient candidate and drops it on Busy.
    pub(crate) fn try_acquire<'a>(
        &self,
        session: &'a Session,
        acquire: impl FnOnce() -> Result<SessionAccess<'a>>,
    ) -> Result<(SessionAccess<'a>, [Option<ReadPermit>; N])> {
        self.admission.check_available()?;
        // Declare retained permits before access so every error releases the
        // session guards first, including the post-acquisition deadline check.
        let mut permits = std::array::from_fn(|_| None);
        let access = acquire()?;
        session
            .snapshot
            .check_authentication_unchanged(self.authentication)?;
        for (index, reader) in self.readers.iter().enumerate() {
            if let Some(reader) = reader {
                reader.acquire_into(&self.admission, &mut permits[index])?;
            }
        }
        self.admission.check_available()?;
        Ok((access, permits))
    }

    pub(crate) fn prepare(
        session: &Session,
        activities: [Option<&Arc<crate::registry::Activity>>; N],
    ) -> Result<Self> {
        Self::prepare_with_epoch(
            session,
            activities,
            session.snapshot.authentication_stamp(),
            None,
        )
    }

    /// Bind the same catalogue notification domain as native role plans. Token
    /// withdrawal and writer release must both wake a cipher's reader wait.
    pub(crate) fn prepare_at_epoch(
        session: &Session,
        activities: [Option<&Arc<crate::registry::Activity>>; N],
        authentication: u64,
    ) -> Result<Self> {
        Self::prepare_retaining_at_epoch(session, activities, authentication, None)
    }

    pub(crate) fn prepare_retaining_at_epoch(
        session: &Session,
        activities: [Option<&Arc<crate::registry::Activity>>; N],
        authentication: u64,
        retained: Option<&crate::symmetric::memory::RetainedBytes>,
    ) -> Result<Self> {
        crate::session::recovery::observations::context(
            session,
            Some(authentication),
            authentication,
        )?;
        if activities.iter().any(Option::is_some) {
            let wake = session
                .inner
                .reservations
                .lock()
                .map_err(|_| Error::Poisoned)?
                .scan_wake();
            for activity in activities.iter().flatten() {
                activity.bind_context_wake(&wake)?;
            }
        }
        Self::prepare_with_epoch(session, activities, authentication, retained)
    }

    fn prepare_with_epoch(
        session: &Session,
        activities: [Option<&Arc<crate::registry::Activity>>; N],
        authentication: u64,
        retained: Option<&crate::symmetric::memory::RetainedBytes>,
    ) -> Result<Self> {
        let admission = crate::admission_wait::current();
        let mut readers = std::array::from_fn(|_| None);
        for (index, activity) in activities.into_iter().enumerate() {
            let Some(activity) = activity else { continue };
            readers[index] = Some(activity.prepare_reader_retaining(
                session.uid,
                &admission,
                retained,
                || {
                    context(session)?;
                    session
                        .snapshot
                        .observe_authentication_unchanged(authentication)
                },
            )?);
        }
        Ok(Self {
            readers,
            admission,
            authentication,
        })
    }

    /// Returns ordinary possession and a temporary read anchor for each role.
    /// Callers transfer these permissions into their native owner or duplicate
    /// their pinned UID slots before releasing the anchors. No acquisition
    /// closure may dispatch native work: it grants ordinary access only.
    pub(crate) fn acquire<'a>(
        &self,
        session: &'a Session,
        acquire: impl FnMut() -> Result<SessionAccess<'a>>,
    ) -> Result<(SessionAccess<'a>, [Option<ReadPermit>; N])> {
        self.acquire_on(session, false, acquire)
    }

    /// Requires readers prepared with prepare_at_epoch and its bound notifier.
    pub(crate) fn acquire_in_context<'a>(
        &self,
        session: &'a Session,
        acquire: impl FnMut() -> Result<SessionAccess<'a>>,
    ) -> Result<(SessionAccess<'a>, [Option<ReadPermit>; N])> {
        self.acquire_on(session, true, acquire)
    }

    fn acquire_on<'a>(
        &self,
        session: &'a Session,
        contextual: bool,
        mut acquire: impl FnMut() -> Result<SessionAccess<'a>>,
    ) -> Result<(SessionAccess<'a>, [Option<ReadPermit>; N])> {
        let mut permits = std::array::from_fn(|_| None);
        loop {
            let access = acquire()?;
            session
                .snapshot
                .check_authentication_unchanged(self.authentication)?;
            let mut blocked = None;
            for (index, reader) in self.readers.iter().enumerate() {
                let Some(reader) = reader else { continue };
                match reader.acquire_into(&self.admission, &mut permits[index]) {
                    Ok(()) => (),
                    Err(Error::Busy(_)) => {
                        blocked = Some(index);
                        break;
                    }
                    Err(error) => return Err(error),
                }
            }
            let Some(index) = blocked else {
                return Ok((access, permits));
            };
            drop(access);
            for permit in &mut permits {
                drop(permit.take());
            }
            let reader = self.readers[index].as_ref().expect("contended key role");
            let before = || {
                context(session)?;
                session
                    .snapshot
                    .observe_authentication_unchanged(self.authentication)
            };
            if contextual {
                reader.wait_available_in_context(&self.admission, before)?;
            } else {
                reader.wait_available_checked(&self.admission, before)?;
            }
        }
    }
}

impl Session {
    /// Prepare the exact managed-key roles before ordinary session possession.
    /// Returned anchors keep their UID slots and read authority alive while the
    /// caller transfers protection into its native frame. A contextual writer
    /// is acquired only for final possession and is never released after Init.
    pub(crate) fn managed_read_access<const N: usize>(
        &self,
        keys: [Option<&crate::NativeObjectRef>; N],
        contextual: bool,
    ) -> Result<(SessionAccess<'_>, [Option<ReadPermit>; N])> {
        let progress = super::AdmissionProgress::default();
        let acquire = || {
            let access = if contextual {
                self.context_operation_access_progress(&progress)?
            } else {
                self.access_progress(&progress)?
            };
            for key in keys.iter().flatten() {
                self.managed_handle(&access, key)?;
            }
            Ok(access)
        };
        // Identity failure precedes attribution allocation. Native dispatch is
        // forbidden in this preparatory access and in the reacquisition closure.
        drop(acquire()?);
        let mut activities = [None; N];
        for (slot, key) in activities.iter_mut().zip(keys) {
            *slot = key.map(|key| key.identity.activity()).transpose()?;
        }
        let readers = Readers::prepare(self, activities)?;
        readers.acquire(self, acquire)
    }
}

// Atomic/pure observations only; safe inside an admission Wake predicate.
pub(crate) fn context(session: &Session) -> Result<()> {
    context_admitted(session, super::CleanupAdmission::Ordinary)
}

/// Pure routing checks for an existing operation's resource preparation.
/// A drain permit is revalidated by ordinary possession before any native call.
pub(crate) fn context_admitted(
    session: &Session,
    admission: super::CleanupAdmission,
) -> Result<()> {
    session
        .inner
        .state
        .check_admission(matches!(admission, super::CleanupAdmission::Module))?;
    session.inner.availability.check_available()?;
    session.snapshot.check()?;
    // Module cleanup takes the token activity guard without requiring a token
    // drain of its own. Token cleanup, in contrast, requires that exact drain.
    if !matches!(admission, super::CleanupAdmission::Module) {
        session
            .snapshot
            .check_drain(matches!(admission, super::CleanupAdmission::Token))?;
    }
    let entry = &session.entry;
    if let Some(notification) = &entry.notification {
        notification.check()?;
    }
    if entry.closed.load(std::sync::atomic::Ordering::Acquire) {
        return Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
            crate::SessionLifecycleRejection::SessionClosed,
        )));
    }
    if entry
        .close_attempted
        .load(std::sync::atomic::Ordering::Acquire)
    {
        return Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
            crate::SessionLifecycleRejection::SessionClosingOrCloseFailed,
        )));
    }
    if entry.generation != session.snapshot.generation
        || entry.slot as u64 != session.snapshot.capabilities.identity.slot
    {
        return Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
            crate::SessionLifecycleRejection::SessionGenerationMismatch,
        )));
    }
    if entry.poisoned.load(std::sync::atomic::Ordering::Acquire) {
        return Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
            crate::SessionLifecycleRejection::SessionStateUncertain,
        )));
    }
    Ok(())
}
