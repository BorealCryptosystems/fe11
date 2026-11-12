// SPDX-License-Identifier: Apache-2.0
//! Instance-wide admission for modules initialized without OS_LOCKING_OK.
//!
//! Possession accompanies the existing module guard. Internal nested reads on
//! the same thread may borrow that possession; application callbacks may not.
//! A blocking event releases the thread's guard but retains its distinct native
//! reservation. Closing reserves against that waiter before seeking a writer.
use crate::admission_wait::{AdmissionWake, Attempt, Wake};
use crate::{Error, ResourceAdmission, Result};
use std::sync::{Arc, Mutex};
use std::thread::ThreadId;

#[derive(Default)]
struct State {
    holder: Option<(ThreadId, usize)>,
    blocking_event: bool,
    closing: bool,
    callbacks: usize,
}

pub(crate) struct Dispatch {
    image: usize,
    state: Mutex<State>,
    wake: AdmissionWake,
}

impl Dispatch {
    pub(crate) fn new(image: &Arc<super::image::LoadedImage>) -> Arc<Self> {
        Arc::new(Self {
            image: Arc::as_ptr(image) as usize,
            state: Mutex::new(State::default()),
            wake: AdmissionWake::default(),
        })
    }

    fn check_callback(&self) -> Result<()> {
        if crate::notify::in_callback_for(self.image) {
            return Err(Error::Rejected(crate::RejectionReason::NativeExecution(
                crate::NativeExecutionRejection::SerializedModuleCallbackReentry,
            )));
        }
        Ok(())
    }

    pub(crate) fn bind_context(&self, context: &Arc<Wake>) -> Result<()> {
        self.wake.bind_context(context)
    }

    pub(crate) fn enter_checked(
        self: &Arc<Self>,
        context: &Arc<Wake>,
        admission: &ResourceAdmission,
        validate: &dyn Fn() -> Result<()>,
    ) -> Result<Guard> {
        self.bind_context(context)?;
        self.enter_on(context, admission, None, validate)
    }

    pub(crate) fn enter(
        self: &Arc<Self>,
        admission: &ResourceAdmission,
        close: Option<&Closing>,
    ) -> Result<Guard> {
        self.enter_on(self.wake.private(), admission, close, &|| Ok(()))
    }

    /// Initial discovery and loader aliases share dispatch and withdrawal
    /// notifications. Recheck the owner on every wake before granting entry.
    pub(crate) fn enter_loading(
        self: &Arc<Self>,
        admission: &ResourceAdmission,
        validate: &dyn Fn() -> Result<()>,
    ) -> Result<Guard> {
        self.enter_on(&self.wake.context_or_private(), admission, None, validate)
    }

    fn enter_on(
        self: &Arc<Self>,
        wake: &Arc<Wake>,
        admission: &ResourceAdmission,
        close: Option<&Closing>,
        validate: &dyn Fn() -> Result<()>,
    ) -> Result<Guard> {
        self.check_callback()?;
        validate()?;
        let owns_close = close.is_some_and(|close| Arc::ptr_eq(self, &close.0));
        let thread = std::thread::current().id();
        wake.acquire(admission, || {
            validate()?;
            let mut state = self.state.lock().map_err(|_| Error::Poisoned)?;
            let nested = state
                .holder
                .as_ref()
                .is_some_and(|(owner, _)| *owner == thread);
            if state.blocking_event
                || state.callbacks != 0
                || state.closing && !owns_close && !nested
            {
                return Ok(Attempt::Occupied(crate::BusyReason::NativeExecution(
                    crate::NativeExecutionBusy::SerializedModuleDispatch,
                )));
            }
            match state.holder.as_mut() {
                Some((owner, count)) if *owner == thread => {
                    *count = count.checked_add(1).ok_or(Error::Rejected(
                        crate::RejectionReason::NativeExecution(
                            crate::NativeExecutionRejection::SerializedDispatchDepth,
                        ),
                    ))?;
                }
                Some(_) => {
                    return Ok(Attempt::Occupied(crate::BusyReason::NativeExecution(
                        crate::NativeExecutionBusy::SerializedModuleDispatch,
                    )))
                }
                None => state.holder = Some((thread, 1)),
            }
            Ok(Attempt::Acquired(Guard(
                self.clone(),
                std::marker::PhantomData,
            )))
        })
    }

    pub(crate) fn reserve_blocking(self: &Arc<Self>) -> Result<BlockingEvent> {
        let mut state = self.state.lock().map_err(|_| Error::Poisoned)?;
        if state.closing || state.blocking_event {
            return Err(Error::Busy(crate::BusyReason::NativeExecution(
                crate::NativeExecutionBusy::SerializedModuleEventAdmission,
            )));
        }
        if !state
            .holder
            .as_ref()
            .is_some_and(|(owner, _)| *owner == std::thread::current().id())
        {
            return Err(Error::Rejected(crate::RejectionReason::NativeExecution(
                crate::NativeExecutionRejection::BlockingEventWithoutModulePossession,
            )));
        }
        state.blocking_event = true;
        Ok(BlockingEvent(self.clone()))
    }

    pub(crate) fn reserve_close(self: &Arc<Self>) -> Result<Closing> {
        self.check_callback()?;
        let mut state = self.state.lock().map_err(|_| Error::Poisoned)?;
        // Do not wait or change lifecycle when a blocking call is admitted.
        if state.blocking_event {
            return Err(Error::Busy(crate::BusyReason::NativeExecution(
                crate::NativeExecutionBusy::SerializedBlockingSlotEvent,
            )));
        }
        if state.closing {
            return Err(Error::Busy(crate::BusyReason::NativeExecution(
                crate::NativeExecutionBusy::SerializedModuleClosing,
            )));
        }
        state.closing = true;
        Ok(Closing(self.clone()))
    }

    /// Lifecycle entry must not wait behind a serialized blocking event. This
    /// metadata-only check precedes callback waits and resource acquisition.
    pub(crate) fn check_lifecycle(&self) -> Result<()> {
        self.check_callback()?;
        let state = self.state.lock().map_err(|_| Error::Poisoned)?;
        if state.blocking_event {
            return Err(Error::Busy(crate::BusyReason::NativeExecution(
                crate::NativeExecutionBusy::SerializedBlockingSlotEvent,
            )));
        }
        Ok(())
    }

    /// A callback can run on the native call's thread or a module-owned thread.
    /// It extends exclusion without waiting for its parent C call to return.
    pub(crate) fn callback(self: &Arc<Self>) -> Result<Callback> {
        let mut state = self.state.lock().map_err(|_| Error::Poisoned)?;
        state.callbacks = state.callbacks.checked_add(1).ok_or(Error::Rejected(
            crate::RejectionReason::NativeExecution(
                crate::NativeExecutionRejection::SerializedCallbackDepth,
            ),
        ))?;
        Ok(Callback(self.clone()))
    }

    /// An admitted sequence may contain several C calls. A callback retained by
    /// the preceding call must leave before its next dispatch. Callback reentry
    /// into this instance is rejected before module/key possession, so this wait
    /// does not require the callback to acquire any guard retained here.
    pub(crate) fn wait_callbacks(&self) -> Result<()> {
        self.wait_callbacks_on(self.wake.private(), &|| Ok(()))
    }

    pub(crate) fn wait_callbacks_checked(
        &self,
        context: &Arc<Wake>,
        validate: &dyn Fn() -> Result<()>,
    ) -> Result<()> {
        self.bind_context(context)?;
        self.wait_callbacks_on(context, validate)
    }

    fn wait_callbacks_on(&self, wake: &Arc<Wake>, validate: &dyn Fn() -> Result<()>) -> Result<()> {
        self.check_callback()?;
        wake.acquire(&crate::admission_wait::current(), || {
            validate()?;
            let state = self.state.lock().map_err(|_| Error::Poisoned)?;
            if state.callbacks == 0 {
                Ok(Attempt::Acquired(()))
            } else {
                Ok(Attempt::Occupied(crate::BusyReason::NativeExecution(
                    crate::NativeExecutionBusy::SerializedNativeCallback,
                )))
            }
        })
    }
}

pub(crate) struct Callback(Arc<Dispatch>);
impl Drop for Callback {
    fn drop(&mut self) {
        {
            let mut state = self.0.state.lock().unwrap_or_else(|e| e.into_inner());
            state.callbacks -= 1;
        }
        self.0.wake.notify();
    }
}

// Like the module read/write guard, this reservation cannot migrate threads.
pub(crate) struct Guard(Arc<Dispatch>, std::marker::PhantomData<std::rc::Rc<()>>);
impl Drop for Guard {
    fn drop(&mut self) {
        {
            let mut state = self.0.state.lock().unwrap_or_else(|e| e.into_inner());
            if let Some((_, count)) = &mut state.holder {
                *count -= 1;
                if *count == 0 {
                    state.holder = None;
                }
            }
        }
        self.0.wake.notify();
    }
}

/// Retained after the module guard is released; a certain return retires it.
pub(crate) struct BlockingEvent(Arc<Dispatch>);
impl Drop for BlockingEvent {
    fn drop(&mut self) {
        self.0
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .blocking_event = false;
        self.0.wake.notify();
    }
}

/// Rollback of local close admission is harmless before any native dispatch.
pub(crate) struct Closing(Arc<Dispatch>);
impl Drop for Closing {
    fn drop(&mut self) {
        self.0
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .closing = false;
        self.0.wake.notify();
    }
}
