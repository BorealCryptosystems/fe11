// SPDX-License-Identifier: Apache-2.0
use crate::{
    admission_wait::{ReadGuard, ResourceRwLock, WriteGuard},
    Error, Result,
};
use std::sync::atomic::{AtomicBool, Ordering};

// Waiting is explicit and event-driven; no native call is retried.
// Draining closes admission, not the resources of already admitted operations.
pub(crate) struct StateLock<T> {
    value: ResourceRwLock<T>,
    draining: AtomicBool,
    dispatch: Option<std::sync::Arc<crate::native::dispatch::Dispatch>>,
}
impl<T> StateLock<T> {
    pub(crate) fn with_dispatch(
        value: T,
        dispatch: Option<std::sync::Arc<crate::native::dispatch::Dispatch>>,
    ) -> Result<Self> {
        let value = ResourceRwLock::new(value);
        if let Some(dispatch) = &dispatch {
            dispatch.bind_context(&value.admission_wake())?;
        }
        Ok(Self {
            value,
            draining: AtomicBool::new(false),
            dispatch,
        })
    }
    pub(crate) fn reserve_close(&self) -> Result<Option<crate::native::dispatch::Closing>> {
        self.dispatch
            .as_ref()
            .map(|dispatch| dispatch.reserve_close())
            .transpose()
    }
    fn enter_dispatch(
        &self,
        close: Option<&crate::native::dispatch::Closing>,
    ) -> Result<Option<crate::native::dispatch::Guard>> {
        self.dispatch
            .as_ref()
            .map(|dispatch| dispatch.enter(&crate::admission_wait::current(), close))
            .transpose()
    }
    pub(crate) fn check_admission(&self, permit: bool) -> Result<()> {
        if self.draining.load(Ordering::Acquire) != permit {
            return Err(Error::Busy(crate::BusyReason::LocalAdmission(
                crate::LocalAdmissionBusy::ModuleDraining,
            )));
        }
        Ok(())
    }
    pub fn begin_drain(&self) -> Result<()> {
        self.draining
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| {
                Error::Busy(crate::BusyReason::LocalAdmission(
                    crate::LocalAdmissionBusy::ModuleDraining,
                ))
            })?;
        self.value.notify();
        Ok(())
    }
    pub fn end_drain(&self) {
        self.draining.store(false, Ordering::Release);
        self.value.notify();
    }

    pub(crate) fn write_closing(
        &self,
        permit: bool,
        close: Option<&crate::native::dispatch::Closing>,
    ) -> Result<WriteGuard<'_, T>> {
        self.check_admission(permit)?;
        let dispatch = self.enter_dispatch(close)?;
        let mut guard = self.value.write(
            &crate::admission_wait::current(),
            crate::BusyReason::LocalAdmission(crate::LocalAdmissionBusy::ModuleActivity),
            || {
                self.check_admission(permit)?;
                Ok(None)
            },
        )?;
        self.check_admission(permit)?;
        guard.dispatch = dispatch;
        Ok(guard)
    }
    pub fn read(&self) -> Result<ReadGuard<'_, T>> {
        self.read_admitted(false)
    }
    pub fn read_admitted(&self, permit: bool) -> Result<ReadGuard<'_, T>> {
        self.read_with_validation(permit, None)
    }

    pub(crate) fn admission_wake(&self) -> std::sync::Arc<crate::admission_wait::Wake> {
        self.value.admission_wake()
    }

    pub(crate) fn read_checked(
        &self,
        validate: &dyn Fn() -> Result<()>,
    ) -> Result<ReadGuard<'_, T>> {
        self.read_with_validation(false, Some(validate))
    }

    fn read_with_validation(
        &self,
        permit: bool,
        validate: Option<&dyn Fn() -> Result<()>>,
    ) -> Result<ReadGuard<'_, T>> {
        self.check_admission(permit)?;
        let before = || {
            if let Some(validate) = validate {
                validate()?;
            }
            Ok(())
        };
        before()?;
        let context = self.admission_wake();
        let policy = crate::admission_wait::current();
        let dispatch = if validate.is_some() {
            let check_dispatch = || {
                before()?;
                self.check_admission(permit)
            };
            self.dispatch
                .as_ref()
                .map(|dispatch| dispatch.enter_checked(&context, &policy, &check_dispatch))
                .transpose()?
        } else {
            self.enter_dispatch(None)?
        };
        let check = || {
            before()?;
            self.check_admission(permit)?;
            Ok(None)
        };
        let mut guard = if validate.is_some() {
            self.value.read_in_context(
                &context,
                &policy,
                crate::BusyReason::LocalAdmission(crate::LocalAdmissionBusy::ModuleActivity),
                check,
            )?
        } else {
            self.value.read(
                &policy,
                crate::BusyReason::LocalAdmission(crate::LocalAdmissionBusy::ModuleActivity),
                check,
            )?
        };
        self.check_admission(permit)?;
        before()?;
        guard.dispatch = dispatch;
        Ok(guard)
    }

    // Local observation and retained-owner handoffs only, never permission for
    // native dispatch. The read guard excludes finalization while accessing the
    // counters or ledger; each handoff still verifies its exact registered owner.
    pub fn observe(&self) -> Result<ReadGuard<'_, T>> {
        self.value.try_read().map_err(|e| match e {
            std::sync::TryLockError::WouldBlock => Error::Busy(crate::BusyReason::LocalAdmission(
                crate::LocalAdmissionBusy::ModuleActivity,
            )),
            _ => Error::Poisoned,
        })
    }
}
