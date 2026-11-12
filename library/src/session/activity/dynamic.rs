// SPDX-License-Identifier: Apache-2.0
//! Shared reader attribution precedes aggregate admission of private vectors.
use super::context;
use crate::{
    registry::{PreparedReader, ReadPermit},
    session::{AdmissionProgress, SessionAccess},
    symmetric::memory::Credit,
    Error, NativeObjectRef, ResourceAdmission, Result, Session,
};
use std::sync::Arc;

pub(crate) struct DynamicReaders {
    // Release permissions before attribution pins, and storage before credit.
    permits: Vec<Option<ReadPermit>>,
    readers: Vec<Option<PreparedReader>>,
    _credit: Credit,
}

/// Empty private vectors, bound from the complete measured aggregate before
/// installing any attribution or permission.
pub(crate) struct DynamicReadStorage {
    permits: Vec<Option<ReadPermit>>,
    readers: Vec<Option<PreparedReader>>,
}

fn bytes(readers: usize, permits: usize) -> Result<usize> {
    readers
        .checked_mul(std::mem::size_of::<Option<PreparedReader>>())
        .and_then(|n| {
            permits
                .checked_mul(std::mem::size_of::<Option<ReadPermit>>())
                .and_then(|p| n.checked_add(p))
        })
        .ok_or(Error::Rejected(crate::RejectionReason::SessionLifecycle(
            crate::SessionLifecycleRejection::ObjectActivityStorageAccounting,
        )))
}

impl DynamicReadStorage {
    pub(crate) fn requested(count: usize) -> Result<usize> {
        bytes(count, count)
    }

    pub(crate) fn allocate(count: usize) -> Result<Self> {
        let mut readers = Vec::new();
        readers.try_reserve_exact(count).map_err(|_| {
            Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::ObjectActivityOwnersAllocation,
            ))
        })?;
        let mut permits = Vec::new();
        permits.try_reserve_exact(count).map_err(|_| {
            Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::ObjectActivityOwnersAllocation,
            ))
        })?;
        readers.resize_with(count, || None);
        permits.resize_with(count, || None);
        Ok(Self { permits, readers })
    }

    pub(crate) fn allocated_bytes(&self) -> Result<usize> {
        bytes(self.readers.capacity(), self.permits.capacity())
    }

    pub(crate) fn bind(self, credit: &mut Credit) -> Result<DynamicReaders> {
        let own_credit = credit.split(self.allocated_bytes()?)?;
        Ok(DynamicReaders {
            permits: self.permits,
            readers: self.readers,
            _credit: own_credit,
        })
    }
}

/// Borrowed identities and original authentication. No private allocation is
/// retained while shared attribution capacity is being prepared.
pub(crate) struct DynamicReadPlan<I> {
    keys: I,
    authentication: u64,
    count: usize,
}

impl<'k, I: Iterator<Item = &'k NativeObjectRef> + Clone> DynamicReadPlan<I> {
    /// The internal immutable iterator must identify the same keys each time.
    pub(crate) fn prepare_at_epoch(
        session: &Session,
        keys: I,
        progress: &AdmissionProgress,
        authentication: u64,
    ) -> Result<Self> {
        crate::session::recovery::observations::context(
            session,
            Some(authentication),
            authentication,
        )?;
        {
            let access = session.access_progress_at_epoch(progress, authentication)?;
            session
                .snapshot
                .check_authentication_unchanged(authentication)?;
            for key in keys.clone() {
                session.native_object_handle(&access, key)?;
            }
        }
        let plan = Self {
            count: keys.clone().count(),
            keys,
            authentication,
        };
        plan.prime(session, &crate::admission_wait::current())?;
        Ok(plan)
    }

    pub(crate) fn count(&self) -> usize {
        self.count
    }

    pub(crate) fn check(&self, session: &Session) -> Result<()> {
        context(session)?;
        session
            .snapshot
            .observe_authentication_unchanged(self.authentication)
    }

    fn duplicate(&self, index: usize, key: &NativeObjectRef) -> Result<bool> {
        let activity = key.identity.activity()?;
        for previous in self.keys.clone().take(index) {
            if Arc::ptr_eq(previous.identity.activity()?, activity) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn prime(&self, session: &Session, policy: &ResourceAdmission) -> Result<()> {
        for (index, key) in self.keys.clone().enumerate() {
            if self.duplicate(index, key)? {
                continue;
            }
            // Dropping this temporary pin leaves shared capacity available, but
            // reserves no slot. Concurrent growth is handled by the final probe.
            drop(
                key.identity
                    .activity()?
                    .prepare_reader_checked(session.uid, policy, || self.check(session))?,
            );
        }
        Ok(())
    }

    /// Pin without waiting while private credit is held. On Busy the caller
    /// drops the entire private candidate before entering an availability wait.
    pub(crate) fn pin(&self, session: &Session, prepared: &mut DynamicReaders) -> Result<()> {
        if prepared.readers.len() != self.count || prepared.permits.len() != self.count {
            return Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::ObjectActivityStorageShapeChanged,
            )));
        }
        self.check(session)?;
        for (index, key) in self.keys.clone().enumerate() {
            if self.duplicate(index, key)? {
                continue;
            }
            prepared.readers[index] = Some(key.identity.activity()?.prepare_reader_checked(
                session.uid,
                &ResourceAdmission::Immediate,
                || self.check(session),
            )?);
        }
        Ok(())
    }

    /// Consume one destination/session grant in a nonwaiting probe. A refusal
    /// drops that grant and all partially acquired reader permits.
    pub(crate) fn try_access<'a>(
        &self,
        session: &'a Session,
        access: SessionAccess<'a>,
        mut prepared: DynamicReaders,
    ) -> Result<SessionAccess<'a>> {
        let attempt = (|| {
            self.check(session)?;
            for key in self.keys.clone() {
                session.native_object_handle(&access, key)?;
            }
            for (index, reader) in prepared.readers.iter().enumerate() {
                let Some(reader) = reader else { continue };
                prepared.permits[index] = Some(reader.acquire_once(&ResourceAdmission::Immediate)?);
            }
            Ok(())
        })();
        if let Err(error) = attempt {
            // Release possession before waking resource/byte waiters through
            // partial permission and storage disposal.
            drop(access);
            drop(prepared);
            return Err(error);
        }
        access.retain_dynamic_readers(prepared)?;
        Ok(access)
    }

    /// Observe one resource at a time with no private vectors, no partial read
    /// set and no session guard retained over an object wait.
    pub(crate) fn wait_available(
        &self,
        session: &Session,
        policy: &ResourceAdmission,
        progress: &AdmissionProgress,
    ) -> Result<()> {
        {
            let access = session.access_progress_at_epoch(progress, self.authentication)?;
            self.check(session)?;
            for key in self.keys.clone() {
                session.native_object_handle(&access, key)?;
            }
        }
        let wake = session
            .inner
            .reservations
            .lock()
            .map_err(|_| Error::Poisoned)?
            .scan_wake();
        for (index, key) in self.keys.clone().enumerate() {
            if self.duplicate(index, key)? {
                continue;
            }
            // Activity already uses the catalogue domain after publication;
            // bind before checking availability so context changes cannot be lost.
            key.identity.activity()?.bind_context_wake(&wake)?;
            let reader =
                key.identity
                    .activity()?
                    .prepare_reader_checked(session.uid, policy, || self.check(session))?;
            reader.wait_available_in_context(policy, || self.check(session))?;
        }
        Ok(())
    }
}
