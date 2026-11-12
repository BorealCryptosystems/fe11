// SPDX-License-Identifier: Apache-2.0
//! Owned PKCS#11 session notifications. No native handle is exposed.

use crate::atomic_update::AtomicUpdate;
use crate::{symmetric::memory::Credit, Error, Result};
use fe11_sys::*;
mod capacity;
mod preparation;
pub(crate) use preparation::{PreparedNotification, Registration};
use std::{
    panic::{catch_unwind, AssertUnwindSafe},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
};

/// An application decision for a standard surrender callback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotifyDecision {
    /// Return CKR_OK to permit the module's operation to continue.
    Continue,
    /// Return CKR_CANCEL in response to CKN_SURRENDER.
    Cancel,
}

/// Notification delivered by the module, without a raw session handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Notification {
    /// CKN_SURRENDER: the module asks whether its operation should continue.
    Surrender,
    /// No vendor semantics are inferred. Its native result is always CKR_OK.
    Other(u64),
}

/// Local diagnostics, independent of whether the enclosing native call succeeds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NotifyDiagnostics {
    /// A callback panicked and its unwind was contained at the native boundary.
    pub callback_panicked: bool,
    /// A callback used a session identity inconsistent with its registration.
    pub binding_mismatch: bool,
    /// The callback activity counter could not admit another invocation.
    pub activity_exhausted: bool,
}

struct Diagnostics {
    panicked: AtomicBool,
    mismatch: AtomicBool,
    exhausted: AtomicBool,
    _credit: Credit,
}

type Callback = dyn Fn(Notification) -> NotifyDecision + Send + Sync + 'static;

struct Handler {
    callback: Option<Box<Callback>>,
}

impl Drop for Handler {
    fn drop(&mut self) {
        // Captured application values may themselves panic on drop. Never let
        // their destructor unwind across a native callback or module cleanup.
        if let Some(callback) = self.callback.take() {
            if let Err(payload) = catch_unwind(AssertUnwindSafe(|| drop(callback))) {
                std::mem::forget(payload);
            }
        }
    }
}

/// Owned, thread-safe application callback. Captures must outlive registration.
///
/// The provider may never call it. A caught panic requests Cancel for Surrender
/// and records a diagnostic; unknown events still return CKR_OK. Abort and
/// arbitrary blocking application code cannot be intercepted or interrupted.
/// User-owned captured secrets and copies have the caller's erasure policy.
#[derive(Clone)]
pub struct NotifyHandler {
    handler: Arc<Handler>,
}

impl NotifyHandler {
    /// Own a callback for later session registration; this does not call the module.
    /// This autonomous allocation and application captures are outside a module's
    /// byte budget. Registration separately accounts for its native context storage.
    /// The callback can be invoked concurrently and must not block indefinitely.
    pub fn new(callback: impl Fn(Notification) -> NotifyDecision + Send + Sync + 'static) -> Self {
        Self {
            handler: Arc::new(Handler {
                callback: Some(Box::new(callback)),
            }),
        }
    }
}

enum Binding {
    Opening(Option<CK_SESSION_HANDLE>),
    Bound(CK_SESSION_HANDLE),
    Closed,
}

pub(crate) struct NotifyContext {
    dispatch: Option<Arc<crate::native::dispatch::Dispatch>>,
    handler: NotifyHandler,
    binding: Mutex<Binding>,
    // A cleanup hint only: Binding is authoritative. Nominal callback completion
    // need not lock it when no close has requested retirement.
    retirement_hint: AtomicBool,
    diagnostics: Arc<Diagnostics>,
    active: AtomicUsize,
    total_active: Arc<AtomicUsize>,
    capacity_progress: Arc<capacity::Progress>,
    // No Arc<Inner>: the session ledger owns this context. Holding Inner here
    // would form a cycle and prevent last-owner cleanup.
    _image: Arc<crate::native::image::LoadedImage>,
    _credit: Credit,
}

impl NotifyContext {
    pub(crate) fn arguments(self: &Arc<Self>) -> (CK_VOID_PTR, CK_NOTIFY) {
        (Arc::as_ptr(self).cast_mut().cast(), Some(trampoline))
    }

    pub(crate) fn bind(&self, handle: CK_SESSION_HANDLE) -> Result<()> {
        let mut binding = self.binding.lock().map_err(|_| Error::Poisoned)?;
        let valid = match *binding {
            Binding::Opening(None) => true,
            Binding::Opening(Some(observed)) => observed == handle,
            Binding::Bound(_) | Binding::Closed => false,
        };
        if !valid {
            self.diagnostics.mismatch.store(true, Ordering::Release);
            return Err(Error::Rejected(crate::RejectionReason::Callbacks(
                crate::CallbacksRejection::NotificationSessionBinding,
            )));
        }
        *binding = Binding::Bound(handle);
        self.check()
    }

    pub(crate) fn close(&self) {
        // Only local state is changed under the ledger's mutex. Dropping the
        // callback (and therefore arbitrary captured values) is deferred.
        let mut binding = self.binding.lock().unwrap_or_else(|e| e.into_inner());
        *binding = Binding::Closed;
        self.retirement_hint.store(true, Ordering::Release);
        let changed = self.capacity_progress.invalidate();
        drop(binding);
        if changed {
            self.capacity_progress.notify();
        }
    }

    fn notify_idle_capacity(&self) {
        if self.retirement_hint.load(Ordering::Acquire)
            && self.closed_and_idle()
            && self.capacity_progress.invalidate()
        {
            self.capacity_progress.notify();
        }
    }

    pub(crate) fn check(&self) -> Result<()> {
        if self.diagnostics.mismatch.load(Ordering::Acquire) {
            return Err(Error::Rejected(crate::RejectionReason::Callbacks(
                crate::CallbacksRejection::NotificationSessionBinding,
            )));
        }
        Ok(())
    }

    pub(crate) fn diagnostics(&self) -> NotifyDiagnostics {
        NotifyDiagnostics {
            callback_panicked: self.diagnostics.panicked.load(Ordering::Acquire),
            binding_mismatch: self.diagnostics.mismatch.load(Ordering::Acquire),
            activity_exhausted: self.diagnostics.exhausted.load(Ordering::Acquire),
        }
    }

    fn closed_and_idle(&self) -> bool {
        matches!(
            *self.binding.lock().unwrap_or_else(|e| e.into_inner()),
            Binding::Closed
        ) && self.active.load(Ordering::Acquire) == 0
    }

    fn observe(&self, handle: CK_SESSION_HANDLE) -> bool {
        let mut binding = self.binding.lock().unwrap_or_else(|e| e.into_inner());
        let valid = match &mut *binding {
            Binding::Opening(observed) => match observed {
                Some(previous) => *previous == handle,
                None => {
                    *observed = Some(handle);
                    handle != CK_INVALID_HANDLE as CK_SESSION_HANDLE
                }
            },
            Binding::Bound(expected) => *expected == handle,
            Binding::Closed => false,
        };
        if !valid {
            self.diagnostics.mismatch.store(true, Ordering::Release);
        }
        valid
    }
}

/// Keeps pApplication valid even when opening/closing has uncertain effects.
pub(crate) struct NotifyRegistry {
    contexts: Mutex<Contexts>,
    active: Arc<AtomicUsize>,
    progress: Arc<capacity::Progress>,
    finalized: bool,
}

// The backing vector has its own credit: closing a context does not free its
// capacity. A failed growth leaves all prior registrations and credits intact.
#[derive(Default)]
struct Contexts {
    entries: Vec<Arc<NotifyContext>>,
    // Own the backing-vector charge until its allocation is destroyed.
    _credit: Option<Credit>,
}

/// Registrations extracted during finalization, with their backing-store credit.
///
/// The caller declares this owner before acquiring module/ledger guards so its
/// destruction, including arbitrary application captures, occurs after them on
/// every return path. Extraction does not allocate or destroy a registration.
#[derive(Default)]
pub(crate) struct RetiredNotifications {
    contexts: Option<Contexts>,
    quarantined: bool,
}

impl RetiredNotifications {
    pub(crate) fn is_empty(&self) -> bool {
        self.contexts.is_none()
    }

    pub(crate) fn quarantine(&mut self) {
        self.quarantined = true;
    }
}

impl Drop for RetiredNotifications {
    fn drop(&mut self) {
        if self.quarantined {
            // A successful Finalize does not discharge a prior uncertain native
            // borrow. Retain pApplication, captures, image leases and all credits,
            // including the vector's storage; no module guard is retained here.
            if let Some(contexts) = self.contexts.take() {
                std::mem::forget(contexts);
            }
        }
    }
}

impl NotifyRegistry {
    pub(crate) fn prepare(budget: &Arc<crate::symmetric::memory::Budget>) -> Result<Self> {
        let progress = capacity::Progress::prepare(budget)?;
        Ok(Self {
            contexts: Mutex::new(Contexts {
                entries: Vec::new(),
                _credit: None,
            }),
            active: Arc::new(AtomicUsize::new(0)),
            progress,
            finalized: false,
        })
    }

    pub(crate) fn opening_revision(&self) -> Result<capacity::Revision> {
        self.progress.snapshot()
    }

    pub(crate) fn quiescent(&self) -> bool {
        self.active.load(Ordering::Acquire) == 0
    }

    pub(crate) fn finalized(&mut self, retired: &mut RetiredNotifications, quarantined: bool) {
        self.finalized = true;
        self.progress.withdraw();
        let contexts = self.contexts.get_mut().unwrap_or_else(|e| e.into_inner());
        for context in contexts.entries.iter() {
            context.close();
        }
        // Native validates the empty destination before dispatch. Move the
        // already-credited vector without running handler Drop under the writer.
        // A later publication failure can still quarantine the extracted lot.
        retired.quarantined |= quarantined;
        retired.contexts = Some(std::mem::take(contexts));
    }
}

impl Drop for NotifyRegistry {
    fn drop(&mut self) {
        self.progress.withdraw();
        if !self.finalized {
            // A failed/PENDING close or finalization does not prove that native
            // code has relinquished pApplication. Retain each registration and
            // its image; releasing a Rust session alone is insufficient.
            let contexts = self.contexts.get_mut().unwrap_or_else(|e| e.into_inner());
            for context in contexts.entries.drain(..) {
                std::mem::forget(context);
            }
        }
    }
}

mod callback_scope;
pub(crate) use callback_scope::{in_callback, in_callback_for, CallbackScope};

struct Activity<'a> {
    counter: &'a AtomicUsize,
    context: Option<&'a NotifyContext>,
}

impl<'a> Activity<'a> {
    fn enter(counter: &'a AtomicUsize) -> Option<Self> {
        counter
            .update_checked(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_add(1)
            })
            .ok()
            .map(|_| Self {
                counter,
                context: None,
            })
    }

    fn enter_context(context: &'a NotifyContext) -> Option<Self> {
        Self::enter(&context.active).map(|mut activity| {
            activity.context = Some(context);
            activity
        })
    }
}

impl Drop for Activity<'_> {
    fn drop(&mut self) {
        if self.counter.fetch_sub(1, Ordering::AcqRel) == 1 {
            if let Some(context) = self.context {
                context.notify_idle_capacity();
            }
        }
    }
}

unsafe extern "C" fn trampoline(
    session: CK_SESSION_HANDLE,
    event: CK_NOTIFICATION,
    application: CK_VOID_PTR,
) -> CK_RV {
    let refusal = if event == CKN_SURRENDER as CK_NOTIFICATION {
        CKR_CANCEL
    } else {
        CKR_OK
    };
    if application.is_null() {
        return refusal;
    }
    // SAFETY: pApplication points to the stable Arc registered before Open.
    // The registry retains it through uncertain outcomes and confirmed close.
    // The trusted provider calls it only within that registration's lifetime.
    let context = application.cast::<NotifyContext>();
    unsafe { Arc::increment_strong_count(context) };
    let context = unsafe { Arc::from_raw(context) };
    let _dispatch_activity = match context
        .dispatch
        .as_ref()
        .map(|dispatch| dispatch.callback())
        .transpose()
    {
        Ok(activity) => activity,
        Err(_) => {
            context.diagnostics.exhausted.store(true, Ordering::Release);
            return refusal;
        }
    };
    let diagnostics = context.diagnostics.clone();
    // Activity is established before reading the opening/published binding.
    // The enclosing native call's image lease covers the return into provider
    // code after this trampoline's last local Arc has been released.
    let result = catch_unwind(AssertUnwindSafe(|| {
        let context = context;
        let Some(_total) = Activity::enter(&context.total_active) else {
            diagnostics.exhausted.store(true, Ordering::Release);
            return refusal;
        };
        let Some(_active) = Activity::enter_context(&context) else {
            diagnostics.exhausted.store(true, Ordering::Release);
            return refusal;
        };
        if !context.observe(session) {
            return refusal;
        }
        // Concurrent modules retain the existing allocation-free scope. Only
        // serialized instances need image-specific reentry exclusion; an outer
        // serialized callback remains on the stack across a concurrent one.
        let image = context
            .dispatch
            .as_ref()
            .map(|_| Arc::as_ptr(&context._image) as usize);
        let Some(_scope) = CallbackScope::enter(image, context._credit.budget()) else {
            diagnostics.exhausted.store(true, Ordering::Release);
            return refusal;
        };
        let notification = if event == CKN_SURRENDER as CK_NOTIFICATION {
            Notification::Surrender
        } else {
            Notification::Other(event as u64)
        };
        let decision = (context
            .handler
            .handler
            .callback
            .as_ref()
            .expect("live callback"))(notification);
        match (notification, decision) {
            (Notification::Surrender, NotifyDecision::Cancel) => CKR_CANCEL,
            _ => CKR_OK,
        }
    }));
    match result {
        Ok(rv) => rv,
        Err(payload) => {
            diagnostics.panicked.store(true, Ordering::Release);
            // The application may panic with an arbitrary destructor-bearing
            // payload. Dropping it here could panic a second time across C.
            std::mem::forget(payload);
            refusal
        }
    }
}
