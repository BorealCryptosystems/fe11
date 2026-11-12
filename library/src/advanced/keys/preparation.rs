// SPDX-License-Identifier: Apache-2.0
//! Validate advanced key identity before preparing shared reader attribution.
use crate::{
    registry::ReadPermit,
    session::{activity::Readers, SessionAccess},
    Error, NativeObjectRef, Result, Session,
};
use std::sync::Arc;

// Prepare resident Activity attribution before retaining a new transient frame.
// A preparation pins a UID slot but grants no object read permission. Candidate
// vector growth and its retry occur outside all native/session/operation guards;
// the Activity owns the published capacity independently of the future operation.
pub(in crate::advanced) struct KeyReaders<const N: usize>(Readers<N>);
impl<const N: usize> KeyReaders<N> {
    /// Materialize a whole unpublished candidate, then probe possession once.
    /// Availability waits retain only the prepared UID slots. In particular,
    /// no input copy, cancellation shell or partial reader survives the wait.
    pub(in crate::advanced) fn prepare_with<'a, T>(
        &self,
        session: &'a Session,
        progress: &crate::session::AdmissionProgress,
        prepare: impl FnMut() -> Result<T>,
    ) -> Result<(T, SessionAccess<'a>, [Option<ReadPermit>; N])> {
        self.prepare_with_epoch(session, progress, None, prepare)
    }

    pub(in crate::advanced) fn prepare_with_at_epoch<'a, T>(
        &self,
        session: &'a Session,
        progress: &crate::session::AdmissionProgress,
        epoch: u64,
        prepare: impl FnMut() -> Result<T>,
    ) -> Result<(T, SessionAccess<'a>, [Option<ReadPermit>; N])> {
        self.prepare_with_epoch(session, progress, Some(epoch), prepare)
    }

    fn prepare_with_epoch<'a, T>(
        &self,
        session: &'a Session,
        progress: &crate::session::AdmissionProgress,
        epoch: Option<u64>,
        mut prepare: impl FnMut() -> Result<T>,
    ) -> Result<(T, SessionAccess<'a>, [Option<ReadPermit>; N])> {
        let resources = crate::admission_wait::current();
        let session_policy = session.admission();
        loop {
            resources.check_available()?;
            session_policy.check_available()?;
            let candidate = prepare()?;
            match self.0.try_acquire(session, || match epoch {
                Some(epoch) => session.try_advanced_access_progress_at_epoch(progress, epoch),
                None => session.try_advanced_access_progress(progress),
            }) {
                Ok((access, readers)) => return Ok((candidate, access, readers)),
                Err(error @ Error::Busy(_)) => {
                    drop(candidate);
                    if matches!(resources, crate::ResourceAdmission::Immediate)
                        && matches!(session_policy, crate::ResourceAdmission::Immediate)
                    {
                        return Err(error);
                    }
                }
                Err(error) => return Err(error),
            }
            // Availability is not ownership. Drop all returned guards and
            // permits before rebuilding; a competing publisher may win again.
            match epoch {
                Some(epoch) => drop(self.0.acquire_in_context(session, || {
                    session.advanced_access_progress_at_epoch(progress, epoch)
                })?),
                None => drop(self.access_with_progress(session, progress)?),
            }
        }
    }

    pub(in crate::advanced) fn try_access_with_progress<'a>(
        &self,
        session: &'a Session,
        progress: &crate::session::AdmissionProgress,
    ) -> Result<(SessionAccess<'a>, [Option<ReadPermit>; N])> {
        self.0
            .try_acquire(session, || session.try_advanced_access_progress(progress))
    }

    /// Call only after disposing every unpublished candidate and partial guard.
    /// Returning grants availability only; it transfers no permission to C.
    pub(in crate::advanced) fn wait_after_contention(
        &self,
        session: &Session,
        progress: &crate::session::AdmissionProgress,
        authentication: u64,
        cause: Error,
    ) -> Result<()> {
        if !matches!(cause, Error::Busy(_))
            || (matches!(
                crate::admission_wait::current(),
                crate::ResourceAdmission::Immediate
            ) && matches!(session.admission(), crate::ResourceAdmission::Immediate))
        {
            return Err(cause);
        }
        drop(self.0.acquire_in_context(session, || {
            session.advanced_access_progress_at_epoch(progress, authentication)
        })?);
        Ok(())
    }

    pub(in crate::advanced) fn prepare(
        session: &Session,
        keys: [Option<&NativeObjectRef>; N],
    ) -> Result<Self> {
        Self::prepare_in_context(session, keys, None, None)
    }

    pub(in crate::advanced) fn prepare_at_epoch(
        session: &Session,
        keys: [Option<&NativeObjectRef>; N],
        epoch: u64,
    ) -> Result<Self> {
        Self::prepare_in_context(session, keys, Some(epoch), None)
    }

    pub(in crate::advanced) fn prepare_retaining_at_epoch(
        session: &Session,
        keys: [Option<&NativeObjectRef>; N],
        epoch: u64,
        progress: &crate::session::AdmissionProgress,
    ) -> Result<Self> {
        Self::prepare_in_context(session, keys, Some(epoch), progress.retained_source())
    }

    fn prepare_in_context(
        session: &Session,
        keys: [Option<&NativeObjectRef>; N],
        epoch: Option<u64>,
        retained: Option<&crate::symmetric::memory::RetainedBytes>,
    ) -> Result<Self> {
        for key in keys.iter().flatten() {
            let identity = &key.identity;
            if !Arc::ptr_eq(&session.inner, &key.inner)
                || session.uid != identity.session
                || session.entry.slot != identity.slot
                || session.snapshot.generation != identity.generation
            {
                return Err(Error::Rejected(crate::RejectionReason::OperationKeys(
                    crate::OperationKeysRejection::ForeignOrStaleMessageKey,
                )));
            }
        }
        let mut activities = [None; N];
        for (index, key) in keys.iter().enumerate() {
            if let Some(key) = key {
                activities[index] = Some(key.identity.activity()?);
            }
        }
        let readers = match epoch {
            Some(epoch) => match retained {
                Some(source) => {
                    Readers::prepare_retaining_at_epoch(session, activities, epoch, Some(source))?
                }
                None => Readers::prepare_at_epoch(session, activities, epoch)?,
            },
            None => Readers::prepare(session, activities)?,
        };
        Ok(Self(readers))
    }
    pub(in crate::advanced) fn access_with_progress<'a>(
        &self,
        session: &'a Session,
        progress: &crate::session::AdmissionProgress,
    ) -> Result<(SessionAccess<'a>, [Option<ReadPermit>; N])> {
        self.0.acquire(session, || {
            session.advanced_access_progress(crate::session::CleanupAdmission::Ordinary, progress)
        })
    }
}
