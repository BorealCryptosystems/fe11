Cause contracts for `NativeExecutionBusy`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.



## Causes and local owners


<a id="cause-NotificationCallback"></a>

### `NotificationCallback`

Finalization admission found a notification callback still active. The callback registration and native image remain owned. Let the callback return through its original protocol before another lifecycle admission; do not unload its code or finalize recursively from it.


Local detection/handling phase and implementation owner:

- `Native::finalize_admitted` — `src/native.rs`. Enclosing true branch: `!self.notifications.quiescent()`.


<a id="cause-RuntimeNativeCompletionUnproven"></a>

### `RuntimeNativeCompletionUnproven`

Successor admission cannot prove completion of an outstanding native owner.
Possible causes are an incomplete finalization, an unscoped pending call,
an active notification callback, or an asynchronous parent's execution whose
completion is unproven. The old runtime and its owners remain retained.
Complete the original protocol where available; initializing a successor or
repeating Finalize does not substitute for native completion. An ordinary
returned error of a direct synchronous call is not, alone, this condition.

Local detection/handling owner: `Native::successor_ready` in `src/native.rs`.
It checks finalization, unscoped calls and callbacks, then retained asynchronous
execution when finalization has not succeeded.

<a id="cause-RuntimeWaiterOrFinalizationUnresolved"></a>

### `RuntimeWaiterOrFinalizationUnresolved`

Successor reservation found a non-idle slot-event waiter or a Finalize that was issued or remains pending. The event registry retains the old image reservation. Resolve the existing request through its owner; a second successor/Finalize cannot replace the missing native completion proof.


Local detection/handling phase and implementation owner:

- `EventRegistry::reserve_successor` — `src/native/events.rs`. The waiter is non-idle, or finalization is issued or pending. A failed local publication is reconciled separately; an absent identity reservation returns a rejection, not this waiting condition.


<a id="cause-SerializedBlockingSlotEvent"></a>

### `SerializedBlockingSlotEvent`

Lifecycle admission found an admitted blocking slot-event call in serialized mode. The event lease still owns dispatch exclusion. This check deliberately does not wait while changing lifecycle. Finish the existing event request before retrying local lifecycle admission; no synthetic event or native cancellation is issued by this refusal.


Local detection/handling phase and implementation owner:

- `Dispatch::reserve_close` — `src/native/dispatch.rs`. Enclosing true branch: `state.blocking_event`.
- `Dispatch::check_lifecycle` — `src/native/dispatch.rs`. Enclosing true branch: `state.blocking_event`.


<a id="cause-SerializedModuleClosing"></a>

### `SerializedModuleClosing`

A second close reservation found the dispatch state already closing. The first Closing guard retains that reservation. Allow that lifecycle request to finish before requesting local admission again; this cause is not a reason to issue another native Close or Finalize.


Local detection/handling phase and implementation owner:

- `Dispatch::reserve_close` — `src/native/dispatch.rs`. Enclosing true branch: `state.closing`.


<a id="cause-SerializedModuleDispatch"></a>

### `SerializedModuleDispatch`

Acquiring serialized dispatch found a blocking event, callbacks, a conflicting close, or another thread holding dispatch. Existing holders retain their guards. The caller-selected local admission policy may wait and revalidate this same acquisition. Admission success alone does not validate a retired token or session.


Local detection/handling phase and implementation owner:

- `Dispatch::enter_on` — `src/native/dispatch.rs`. Enclosing true branch: `state.blocking_event || state.callbacks != 0 || state.closing && !owns_close && !nested`.
- `Dispatch::enter_on` — `src/native/dispatch.rs`. Enclosing match alternative: `Some(_)`.


<a id="cause-SerializedModuleEventAdmission"></a>

### `SerializedModuleEventAdmission`

Reserving a blocking event found a close or another blocking event already reserved. No new event lease is granted. Keep the existing owner; another event request requires its reservation to end and the lifecycle to remain open.


Local detection/handling phase and implementation owner:

- `Dispatch::reserve_blocking` — `src/native/dispatch.rs`. Enclosing true branch: `state.closing || state.blocking_event`.


<a id="cause-SerializedNativeCallback"></a>

### `SerializedNativeCallback`

Before the next native dispatch, callback accounting is nonzero. Existing callbacks retain dispatch exclusion. Local WaitUntil may wait for those callbacks with the original deadline; callback return, not timeout or cancellation, establishes quiescence. Do not call back into the same serialized instance to force progress.


Local detection/handling phase and implementation owner:

- `Dispatch::wait_callbacks_on` — `src/native/dispatch.rs`. Enclosing false branch: `state.callbacks == 0`.


<a id="cause-SlotEventCompletionUnproven"></a>

### `SlotEventCompletionUnproven`

Logout admission found an unproven slot-event completion. The existing event lease/image and arguments are retained. Logout cannot serve as completion or cleanup of that waiter. Preserve the waiter owner and report the refusal; only its documented completion path can establish that native execution ended.


Local detection/handling phase and implementation owner:

- `EventRegistry::check_logout_admission` — `src/native/events.rs`. Enclosing true branch: `self.completion_unproven.load(Ordering::Acquire)`.


<a id="cause-SlotEventLifecycleUnresolved"></a>

### `SlotEventLifecycleUnresolved`

Logout readiness requires a lifecycle that admits events (`Open` or
`FinalizationRefused`) and a waiter whose completion is not uncertain. A native
finalization refusal does not by itself block Logout after its local publication
has succeeded. `FinalizationPublicationFailed` remains closed until the recorded
result is reconciled locally. The event registry keeps ownership of the existing
request; recreating a waiter or resetting the module is not a completion proof.

Local detection/handling owner: `EventRegistry::logout_ready` in
`src/native/events.rs`, using `Lifecycle::admits_events` and the waiter state.


<a id="cause-SlotEventPolling"></a>

### `SlotEventPolling`

Finalization admission found an issued polling event. The poll lease has not returned to Idle. Let that existing poll finish before another local finalization admission; this refusal neither cancels the poll nor records a native Finalize.


Local detection/handling phase and implementation owner:

- `EventRegistry::begin_finalize` — `src/native/events.rs`. Enclosing match alternative: `Waiter::Issued(EventMode::Poll)`.


<a id="cause-SlotEventRequestActive"></a>

### `SlotEventRequestActive`

Event preparation/reservation found another preparation or waiter active. The existing request owns the event slot. Complete or release that preparation through its owner before another reservation; this check does not create a second native waiter.


Local detection/handling phase and implementation owner:

- `EventRegistry::check_preparation` — `src/native/events.rs`. Enclosing true branch: `self.preparation_active.load(Ordering::Acquire)`.
- `EventRegistry::reserve_for` — `src/native/events.rs`. Enclosing true branch: `state.waiter != Waiter::Idle`.


<a id="cause-SlotEventSourceInUse"></a>

### `SlotEventSourceInUse`

Source selection requires an event-admitting lifecycle (`Open` or
`FinalizationRefused`) and an `Idle` waiter. A published native finalization refusal
does not require the registry to return to `Open`. An active or uncertain waiter,
or an unresolved finalization publication, preserves the selected source and its
existing lease. Reconcile a failed publication through its owner before changing
sources; an uncertain native return is not an idle state.

Local detection/handling owner: `EventRegistry::select_source` in
`src/native/events.rs`, using `Lifecycle::admits_events` and the waiter state.

