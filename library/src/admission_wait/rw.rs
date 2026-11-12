// SPDX-License-Identifier: Apache-2.0
use super::{AdmissionWake, Attempt, ResourceAdmission, Wake};
use crate::{Error, Result};
use std::sync::{
    Arc, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard, TryLockError, TryLockResult,
};

/// Private escape from a writer wait, carrying no native-call authority.
pub(crate) enum WriterAdmission<'a, T> {
    Acquired(WriteGuard<'a, T>),
    MaintenanceRequired,
}

pub(crate) enum WriterReadiness {
    Ready,
    MaintenanceRequired,
}

/// Ordinary resource possession with notification on the actual unlock.
/// Scheduling inherits std::sync::RwLock and the OS: no reader/writer priority
/// or fairness guarantee is added. Notifications trigger predicate revalidation,
/// not a transferable reservation or permission to use a native resource.
pub(crate) struct ResourceRwLock<T> {
    value: RwLock<T>,
    wake: AdmissionWake,
}

// Constructors install the underlying lock guard. Only consuming Drop takes
// it, so live Deref borrows always retain Some, including during poison unwind.
pub(crate) struct ReadGuard<'a, T> {
    value: Option<RwLockReadGuard<'a, T>>,
    wake: &'a AdmissionWake,
    pub(crate) dispatch: Option<crate::native::dispatch::Guard>,
}

// As with ReadGuard, Option exists only to unlock before notifying waiters.
pub(crate) struct WriteGuard<'a, T> {
    value: Option<RwLockWriteGuard<'a, T>>,
    wake: &'a AdmissionWake,
    pub(crate) dispatch: Option<crate::native::dispatch::Guard>,
}

impl<T> std::ops::Deref for ReadGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.value.as_ref().expect("live read guard")
    }
}

impl<T> std::ops::Deref for WriteGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.value.as_ref().expect("live write guard")
    }
}

impl<T> std::ops::DerefMut for WriteGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        self.value.as_mut().expect("live write guard")
    }
}

impl<T> Drop for ReadGuard<'_, T> {
    fn drop(&mut self) {
        drop(self.value.take());
        drop(self.dispatch.take());
        self.wake.notify();
    }
}

impl<T> Drop for WriteGuard<'_, T> {
    fn drop(&mut self) {
        drop(self.value.take());
        drop(self.dispatch.take());
        self.wake.notify();
    }
}

impl<T> ResourceRwLock<T> {
    pub(crate) fn new(value: T) -> Self {
        Self {
            value: RwLock::new(value),
            wake: AdmissionWake::default(),
        }
    }

    pub(crate) fn admission_wake(&self) -> Arc<Wake> {
        self.wake.private().clone()
    }

    pub(crate) fn bind_context(&self, context: &Arc<Wake>) -> Result<()> {
        self.wake.bind_context(context)
    }

    pub(crate) fn notify(&self) {
        self.wake.notify();
    }

    fn reader<'a>(&'a self, value: RwLockReadGuard<'a, T>) -> ReadGuard<'a, T> {
        ReadGuard {
            value: Some(value),
            wake: &self.wake,
            dispatch: None,
        }
    }

    fn writer<'a>(&'a self, value: RwLockWriteGuard<'a, T>) -> WriteGuard<'a, T> {
        WriteGuard {
            value: Some(value),
            wake: &self.wake,
            dispatch: None,
        }
    }

    pub(crate) fn try_read(&self) -> TryLockResult<ReadGuard<'_, T>> {
        match self.value.try_read() {
            Ok(value) => Ok(self.reader(value)),
            Err(TryLockError::WouldBlock) => Err(TryLockError::WouldBlock),
            Err(TryLockError::Poisoned(error)) => Err(TryLockError::Poisoned(PoisonError::new(
                self.reader(error.into_inner()),
            ))),
        }
    }

    pub(crate) fn try_write(&self) -> TryLockResult<WriteGuard<'_, T>> {
        match self.value.try_write() {
            Ok(value) => Ok(self.writer(value)),
            Err(TryLockError::WouldBlock) => Err(TryLockError::WouldBlock),
            Err(TryLockError::Poisoned(error)) => Err(TryLockError::Poisoned(PoisonError::new(
                self.writer(error.into_inner()),
            ))),
        }
    }

    /// Wait without retaining possession or writer intent. The caller must
    /// reacquire in its normal lock order and revalidate; this is only a hint.
    pub(crate) fn wait_write_ready(
        &self,
        admission: &ResourceAdmission,
        busy: crate::BusyReason,
        validate: impl Fn() -> Result<Option<crate::BusyReason>>,
        maintenance: impl Fn() -> bool,
    ) -> Result<WriterReadiness> {
        self.wake.acquire(admission, || {
            if let Some(reason) = validate()? {
                if maintenance() {
                    return Ok(Attempt::Acquired(WriterReadiness::MaintenanceRequired));
                }
                return Ok(Attempt::Occupied(reason));
            }
            match self.value.try_write() {
                Ok(raw) => {
                    // No wrapped guard here: notifying while Wake is held
                    // would recurse into its mutex. No state was changed.
                    drop(raw);
                    Ok(Attempt::Acquired(WriterReadiness::Ready))
                }
                Err(TryLockError::WouldBlock) => Ok(Attempt::Occupied(busy)),
                Err(TryLockError::Poisoned(_)) => Err(Error::Poisoned),
            }
        })
    }

    pub(crate) fn read_in_context(
        &self,
        context: &Arc<Wake>,
        admission: &ResourceAdmission,
        busy: crate::BusyReason,
        validate: impl Fn() -> Result<Option<crate::BusyReason>>,
    ) -> Result<ReadGuard<'_, T>> {
        self.bind_context(context)?;
        self.read_on(context, admission, busy, validate)
    }

    pub(crate) fn read(
        &self,
        admission: &ResourceAdmission,
        busy: crate::BusyReason,
        validate: impl Fn() -> Result<Option<crate::BusyReason>>,
    ) -> Result<ReadGuard<'_, T>> {
        self.read_on(self.wake.private(), admission, busy, validate)
    }

    fn read_on(
        &self,
        wake: &Arc<Wake>,
        admission: &ResourceAdmission,
        busy: crate::BusyReason,
        validate: impl Fn() -> Result<Option<crate::BusyReason>>,
    ) -> Result<ReadGuard<'_, T>> {
        wake.acquire(admission, || {
            if let Some(reason) = validate()? {
                return Ok(Attempt::Occupied(reason));
            }
            match self.value.try_read() {
                Ok(value) => Ok(Attempt::Acquired(self.reader(value))),
                Err(TryLockError::WouldBlock) => Ok(Attempt::Occupied(busy)),
                Err(TryLockError::Poisoned(_)) => Err(Error::Poisoned),
            }
        })
    }

    pub(crate) fn write_with_maintenance(
        &self,
        admission: &ResourceAdmission,
        busy: crate::BusyReason,
        validate: impl Fn() -> Result<Option<crate::BusyReason>>,
        maintenance: impl Fn() -> bool,
    ) -> Result<WriterAdmission<'_, T>> {
        self.wake.acquire(admission, || {
            // Preconditions precede the hint. Neither callback inspects a ledger.
            if let Some(reason) = validate()? {
                if maintenance() {
                    return Ok(Attempt::Acquired(WriterAdmission::MaintenanceRequired));
                }
                return Ok(Attempt::Occupied(reason));
            }
            match self.value.try_write() {
                Ok(value) => Ok(Attempt::Acquired(WriterAdmission::Acquired(
                    self.writer(value),
                ))),
                Err(TryLockError::WouldBlock) => Ok(Attempt::Occupied(busy)),
                Err(TryLockError::Poisoned(_)) => Err(Error::Poisoned),
            }
        })
    }

    /// Couple exclusive possession to the existing fixed context domain.
    /// Binding precedes the first predicate check; writer/read guard releases
    /// already notify this domain after releasing the underlying lock.
    pub(crate) fn write_in_context(
        &self,
        context: &Arc<Wake>,
        admission: &ResourceAdmission,
        busy: crate::BusyReason,
        validate: impl Fn() -> Result<Option<crate::BusyReason>>,
    ) -> Result<WriteGuard<'_, T>> {
        self.bind_context(context)?;
        self.write_on(context, admission, busy, validate)
    }

    pub(crate) fn write(
        &self,
        admission: &ResourceAdmission,
        busy: crate::BusyReason,
        validate: impl Fn() -> Result<Option<crate::BusyReason>>,
    ) -> Result<WriteGuard<'_, T>> {
        self.write_on(self.wake.private(), admission, busy, validate)
    }

    fn write_on(
        &self,
        wake: &Arc<Wake>,
        admission: &ResourceAdmission,
        busy: crate::BusyReason,
        validate: impl Fn() -> Result<Option<crate::BusyReason>>,
    ) -> Result<WriteGuard<'_, T>> {
        wake.acquire(admission, || {
            if let Some(reason) = validate()? {
                return Ok(Attempt::Occupied(reason));
            }
            match self.value.try_write() {
                Ok(value) => Ok(Attempt::Acquired(self.writer(value))),
                Err(TryLockError::WouldBlock) => Ok(Attempt::Occupied(busy)),
                Err(TryLockError::Poisoned(_)) => Err(Error::Poisoned),
            }
        })
    }
}
