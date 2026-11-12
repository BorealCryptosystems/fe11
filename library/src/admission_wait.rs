// SPDX-License-Identifier: Apache-2.0
//! Admission before native dispatch, without polling or native-call retries.

use crate::{Error, Result};
mod context;

pub(crate) use context::{AdmissionWake, ContextWakes};
use std::{
    cell::RefCell,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Condvar, Mutex, MutexGuard, PoisonError, TryLockError, TryLockResult, Weak,
    },
    time::Instant,
};

/// Caller-selected local admission before possession of a resource.
///
/// The deadline applies only before possession. It is neither an execution
/// deadline nor permission to cancel or repeat a native call after dispatch.
/// The library adds no default execution timeout. Supervision deadlines belong
/// to the application and do not establish native completion.
/// A byte request exceeding its configured ceiling returns
/// [`Error::ResourceLimitExceeded`] without waiting, in either mode. `Busy`
/// describes contention for an amount that can fit; it is not a capacity error.
/// Admission provides no FIFO or starvation-freedom guarantee. Coordination
/// uses standard mutexes/read-write locks and notification-based rechecking;
/// another contender may acquire a newly available resource first. WaitUntil
/// keeps the original cancellation signal and deadline across those races.
///
/// Inside a native Notify callback, acquisition still checks the selected
/// cancellation/deadline and may take an available resource. Contention returns
/// Busy immediately: waiting could require the native call to leave this same
/// callback. The callback does not silently receive an extended deadline.
#[derive(Clone)]
pub enum ResourceAdmission {
    /// Return immediately when the requested local resource cannot be acquired.
    Immediate,
    /// Wait for local possession until acquisition, cancellation or the deadline.
    WaitUntil {
        /// Absolute monotonic deadline, never renewed by the library.
        deadline: Instant,
        /// Shared cancellation signal affecting only admission before dispatch.
        cancellation: AdmissionCancellation,
    },
}

impl ResourceAdmission {
    /// Preserve the caller's prerequisites around a single nonwaiting attempt.
    /// This never changes the scoped policy and must never wrap a native call.
    pub(crate) fn try_once<T>(&self, acquire: impl FnOnce() -> Result<T>) -> Result<T> {
        self.check_available()?;
        let value = acquire()?;
        self.check_available()?;
        Ok(value)
    }
    pub(crate) fn check_available(&self) -> Result<()> {
        if let Self::WaitUntil {
            deadline,
            cancellation,
        } = self
        {
            if cancellation.is_cancelled() {
                return Err(Error::AdmissionCancelled);
            }
            if Instant::now() >= *deadline {
                return Err(Error::AdmissionDeadline);
            }
        }
        Ok(())
    }
}

/// Session-local spelling retained for callers configuring that owner.
pub type SessionAdmission = ResourceAdmission;

thread_local! {
    static SCOPED_ADMISSION: RefCell<Option<ResourceAdmission>> = const { RefCell::new(None) };
}

struct AdmissionScope(Option<ResourceAdmission>);

impl Drop for AdmissionScope {
    fn drop(&mut self) {
        SCOPED_ADMISSION.with(|slot| *slot.borrow_mut() = self.0.take());
    }
}

/// Choose admission for calls made on the current thread within this closure.
/// The closure runs exactly once. No error, native refusal or completed effect
/// causes it to be repeated. Nested scopes restore the previous choice on exit
/// or unwind; spawned threads must choose their own admission explicitly.
/// A session's explicit override takes precedence for possession of that session;
/// shared resources (including byte and reference credits) use this scope.
pub fn with_resource_admission<T>(
    admission: ResourceAdmission,
    operation: impl FnOnce() -> T,
) -> T {
    let previous = SCOPED_ADMISSION.with(|slot| slot.replace(Some(admission)));
    let _scope = AdmissionScope(previous);
    operation()
}

pub(crate) fn current() -> ResourceAdmission {
    SCOPED_ADMISSION.with(|slot| {
        slot.borrow()
            .clone()
            .unwrap_or(ResourceAdmission::Immediate)
    })
}

mod rw;
pub(crate) use rw::{ReadGuard, ResourceRwLock, WriteGuard, WriterAdmission, WriterReadiness};

/// One-way cancellation of local admission waits. Clones share the same signal.
/// Create a new instance for an independent subsequent admission.
#[derive(Clone)]
pub struct AdmissionCancellation(Arc<Cancellation>);

struct Cancellation {
    cancelled: AtomicBool,
    waiters: Mutex<Vec<Weak<Wake>>>,
}

impl AdmissionCancellation {
    /// Create a new, initially uncancelled signal shared by its clones.
    pub fn new() -> Self {
        Self(Arc::new(Cancellation {
            cancelled: AtomicBool::new(false),
            waiters: Mutex::new(Vec::new()),
        }))
    }

    /// Whether cancellation was requested; this does not query a native module.
    pub fn is_cancelled(&self) -> bool {
        self.0.cancelled.load(Ordering::Acquire)
    }

    /// Wake registered local waiters. This never invokes a native cancellation.
    pub fn cancel(&self) {
        self.0.cancelled.store(true, Ordering::Release);
        let mut waiters = self.0.waiters.lock().unwrap_or_else(|e| e.into_inner());
        waiters.retain(|waiter| {
            if let Some(wake) = waiter.upgrade() {
                wake.notify();
                true
            } else {
                false
            }
        });
    }

    fn subscribe(&self, wake: &Arc<Wake>) -> Result<Subscription> {
        let mut waiters = self.0.waiters.lock().unwrap_or_else(|e| e.into_inner());
        if self.is_cancelled() {
            return Err(Error::AdmissionCancelled);
        }
        waiters.retain(|waiter| waiter.strong_count() != 0);
        waiters.try_reserve(1).map_err(|_| {
            Error::Rejected(crate::RejectionReason::LocalAdmission(
                crate::LocalAdmissionRejection::AdmissionWaiterAllocation,
            ))
        })?;
        waiters.push(Arc::downgrade(wake));
        Ok(Subscription {
            cancellation: self.clone(),
            wake: Arc::downgrade(wake),
        })
    }
}

impl Default for AdmissionCancellation {
    fn default() -> Self {
        Self::new()
    }
}

struct Subscription {
    cancellation: AdmissionCancellation,
    wake: Weak<Wake>,
}

impl Drop for Subscription {
    fn drop(&mut self) {
        let mut waiters = self
            .cancellation
            .0
            .waiters
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(index) = waiters.iter().position(|wake| wake.ptr_eq(&self.wake)) {
            waiters.swap_remove(index);
        }
    }
}

pub(crate) enum Attempt<T> {
    Acquired(T),
    Occupied(crate::BusyReason),
}

#[derive(Default)]
pub(crate) struct Wake {
    mutex: Mutex<()>,
    condition: Condvar,
}

impl Wake {
    pub(crate) fn notify(&self) {
        // A waiter checks the resource under this mutex. Every owner releases
        // its resource before notifying: no missed wakeup or inverted order.
        let _guard = self.mutex.lock().unwrap_or_else(|e| e.into_inner());
        self.condition.notify_all();
    }

    /// Retry only a local, reversible reservation, never a native/API call.
    /// Occupied is retryable. Errors, including drain closure, are terminal for
    /// this request. The predicate must drop internal resource locks on return.
    pub(crate) fn acquire<T>(
        self: &Arc<Self>,
        admission: &ResourceAdmission,
        mut reserve: impl FnMut() -> Result<Attempt<T>>,
    ) -> Result<T> {
        let ResourceAdmission::WaitUntil {
            deadline,
            cancellation,
        } = admission
        else {
            return match reserve()? {
                Attempt::Acquired(value) => Ok(value),
                Attempt::Occupied(reason) => Err(Error::Busy(reason)),
            };
        };
        let available = || -> Result<()> {
            if cancellation.is_cancelled() {
                return Err(Error::AdmissionCancelled);
            }
            if Instant::now() >= *deadline {
                return Err(Error::AdmissionDeadline);
            }
            Ok(())
        };
        available()?;
        if crate::notify::in_callback() {
            let value = match reserve()? {
                Attempt::Acquired(value) => value,
                Attempt::Occupied(reason) => return Err(Error::Busy(reason)),
            };
            available()?;
            return Ok(value);
        }
        let _subscription = cancellation.subscribe(self)?;
        let mut wake = self.mutex.lock().map_err(|_| Error::Poisoned)?;
        loop {
            available()?;
            match reserve() {
                Ok(Attempt::Acquired(value)) => {
                    let admitted = available();
                    // A rejected reservation's destructor may notify this same
                    // condition. Release Wake before dropping its owner.
                    drop(wake);
                    admitted?;
                    return Ok(value);
                }
                Ok(Attempt::Occupied(_)) => {}
                Err(error) => {
                    // A predicate may have acquired then released a raw guard
                    // while checking invariants. Let other waiters observe it.
                    self.condition.notify_all();
                    return Err(error);
                }
            }
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .filter(|remaining| !remaining.is_zero())
                .ok_or(Error::AdmissionDeadline)?;
            wake = self
                .condition
                .wait_timeout(wake, remaining)
                .map_err(|_| Error::Poisoned)?
                .0;
        }
    }
}

pub(crate) struct ResourceGate {
    busy: crate::BusyReason,
    value: Mutex<()>,
    wake: AdmissionWake,
}

/// Revalidation leaves no gate owner behind when a marked target changes.
pub(crate) enum GateAdmission<'a> {
    Acquired(ResourceGuard<'a>),
    Revalidate,
}

pub(crate) struct ResourceGuard<'a> {
    value: Option<MutexGuard<'a, ()>>,
    wake: &'a AdmissionWake,
}

impl std::fmt::Debug for ResourceGuard<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ResourceGuard")
    }
}

impl Drop for ResourceGuard<'_> {
    fn drop(&mut self) {
        drop(self.value.take());
        self.wake.notify();
    }
}

impl ResourceGate {
    pub(crate) fn new(busy: crate::BusyReason) -> Self {
        Self {
            busy,
            value: Mutex::new(()),
            wake: AdmissionWake::default(),
        }
    }

    fn guard<'a>(&'a self, value: MutexGuard<'a, ()>) -> ResourceGuard<'a> {
        ResourceGuard {
            value: Some(value),
            wake: &self.wake,
        }
    }

    pub(crate) fn try_lock(&self) -> TryLockResult<ResourceGuard<'_>> {
        match self.value.try_lock() {
            Ok(value) => Ok(self.guard(value)),
            Err(TryLockError::WouldBlock) => Err(TryLockError::WouldBlock),
            Err(TryLockError::Poisoned(error)) => Err(TryLockError::Poisoned(PoisonError::new(
                self.guard(error.into_inner()),
            ))),
        }
    }

    pub(crate) fn notify(&self) {
        self.wake.notify();
    }

    pub(crate) fn acquire_while(
        &self,
        admission: &ResourceAdmission,
        applicable: impl Fn() -> Result<bool>,
    ) -> Result<GateAdmission<'_>> {
        self.wake.acquire(admission, || {
            if !applicable()? {
                return Ok(Attempt::Acquired(GateAdmission::Revalidate));
            }
            match self.value.try_lock() {
                Ok(value) => Ok(Attempt::Acquired(GateAdmission::Acquired(
                    self.guard(value),
                ))),
                Err(TryLockError::WouldBlock) => Ok(Attempt::Occupied(self.busy)),
                Err(TryLockError::Poisoned(_)) => Err(Error::Poisoned),
            }
        })
    }

    pub(crate) fn acquire(&self, admission: &ResourceAdmission) -> Result<ResourceGuard<'_>> {
        self.acquire_checked(admission, || Ok(()))
    }

    pub(crate) fn bind_context(&self, context: &Arc<Wake>) -> Result<()> {
        self.wake.bind_context(context)
    }

    pub(crate) fn acquire_in_context(
        &self,
        context: &Arc<Wake>,
        admission: &ResourceAdmission,
        validate: impl Fn() -> Result<()>,
    ) -> Result<ResourceGuard<'_>> {
        self.bind_context(context)?;
        self.acquire_checked_on(context, admission, validate)
    }

    pub(crate) fn acquire_checked(
        &self,
        admission: &ResourceAdmission,
        validate: impl Fn() -> Result<()>,
    ) -> Result<ResourceGuard<'_>> {
        self.acquire_checked_on(self.wake.private(), admission, validate)
    }

    fn acquire_checked_on(
        &self,
        wake: &Arc<Wake>,
        admission: &ResourceAdmission,
        validate: impl Fn() -> Result<()>,
    ) -> Result<ResourceGuard<'_>> {
        wake.acquire(admission, || {
            validate()?;
            match self.value.try_lock() {
                Ok(value) => Ok(Attempt::Acquired(self.guard(value))),
                Err(TryLockError::WouldBlock) => Ok(Attempt::Occupied(self.busy)),
                Err(TryLockError::Poisoned(_)) => Err(Error::Poisoned),
            }
        })
    }
}
