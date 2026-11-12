Cause contracts for `NativeExecutionRejection`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-CGenerateKeyUnavailable"></a>

### `CGenerateKeyUnavailable`


Local detection/handling phase and implementation owner:

- `KeyGeneration::execute_prepared` — `src/native/generation.rs`.
- `Session::generate_native_key_selected` — `src/managed/mutations/generation.rs`.
- `Session::generate_native_key_selected` — `src/managed/mutations/generation.rs`. Enclosing true branch: `state.native.table.C_GenerateKey.is_none()`.


<a id="cause-CGenerateKeyPairUnavailable"></a>

### `CGenerateKeyPairUnavailable`


Local detection/handling phase and implementation owner:

- `PairGeneration::execute_prepared` — `src/native/generation.rs`.
- `Session::generate_native_key_pair_owned` — `src/managed/mutations/generation.rs`.
- `Session::generate_native_key_pair_owned` — `src/managed/mutations/generation.rs`. Enclosing true branch: `state.native.table.C_GenerateKeyPair.is_none()`.
- `run` (module-level helper) — `src/objects/resident/runner.rs`. Enclosing true branch: `generating`.


<a id="cause-DsaSeedReturnedLength"></a>

### `DsaSeedReturnedLength`

Detected when the returned DSA seed length exceeds its owned capacity or cannot
be converted for publication. Capacity is inspected before handle registration:
a violation quarantines the graph and returns a boundary diagnostic without
claiming completion or authorizing cleanup of unregistered handles. Once the
boundary is intact and creation registered, a later publication failure retains
that creation receipt. No invalid seed slice is exposed. Do not clamp a length
or repeat generation to recover auxiliary output; preserve the returned owners
and uncertainty markers rather than assuming rollback.


Local detection/handling phase and implementation owner:

- `Parameters::validate_output_bounds` — `src/native/generation/parameters.rs`. Enclosing match alternative: `Self::Dsa { raw, seed: Seed::Output(seed), .. } if raw.ulSeedLen as u128 > seed.as_slice().len() as u128`.
- `Parameters::take_output` — `src/native/generation/parameters.rs`. Enclosing match alternative: `Self::Dsa { raw, seed: Seed::Output(seed), .. }`.


<a id="cause-BlockingEventWithoutModulePossession"></a>

### `BlockingEventWithoutModulePossession`


Local detection/handling phase and implementation owner:

- `Dispatch::reserve_blocking` — `src/native/dispatch.rs`. Enclosing true branch: `!state .holder .as_ref() .is_some_and(|(owner, _)| *owner == std::thread::current().id())`.


<a id="cause-DifferentSlotEventSourceSelected"></a>

### `DifferentSlotEventSourceSelected`


Local detection/handling phase and implementation owner:

- `EventRegistry::check_preparation` — `src/native/events.rs`. Enclosing true branch: `self.source.load(Ordering::Acquire) != 0`.
- `EventRegistry::reserve_for` — `src/native/events.rs`. Enclosing true branch: `self.source.load(Ordering::Acquire) != source.map_or(0, |id| id.value())`.


<a id="cause-FileReservationAllocation"></a>

### `FileReservationAllocation`


Local detection/handling phase and implementation owner:

- `reserve_file` (module-level helper) — `src/native.rs`.


<a id="cause-FileReservationCountExhausted"></a>

### `FileReservationCountExhausted`


Local detection/handling phase and implementation owner:

- `reserve_file` (module-level helper) — `src/native.rs`.


<a id="cause-FunctionTableExport"></a>

### `FunctionTableExport`


Local detection/handling phase and implementation owner:

- `Native::load` — `src/native/loading.rs`.


<a id="cause-GenerationExtensionOutputTaken"></a>

### `GenerationExtensionOutputTaken`


Local detection/handling phase and implementation owner:

- `Parameters::take_output` — `src/native/generation/parameters.rs`. Enclosing match alternative: `Self::Extension { graph, contract, .. }`.


<a id="cause-GenerationParameterAccounting"></a>

### `GenerationParameterAccounting`


Local detection/handling phase and implementation owner:

- `add` (module-level helper) — `src/native/generation/parameters.rs`.
- `sum` (module-level helper) — `src/native/generation/parameters/preparation.rs`.


<a id="cause-GenerationPreparationChanged"></a>

### `GenerationPreparationChanged`


Local detection/handling phase and implementation owner:

- `Storage<'a>::bind` — `src/native/generation/parameters/preparation.rs`. Enclosing true branch: `seed.capacity() != *seed_capacity`.
- `Storage<'a>::bind` — `src/native/generation/parameters/preparation.rs`. Enclosing match alternative: `_`.


<a id="cause-GenerationScalarAbiWidth"></a>

### `GenerationScalarAbiWidth`


Local detection/handling phase and implementation owner:

- `ulong` (module-level helper) — `src/native/generation/parameters.rs`.


<a id="cause-InitializationOutcomeExpected"></a>

### `InitializationOutcomeExpected`


Local detection/handling phase and implementation owner:

- `LoadingOutcome::initialized` — `src/native.rs`. Enclosing match alternative: `Self::Observed(_)`.


<a id="cause-KeyGenerationInputChanged"></a>

### `KeyGenerationInputChanged`


Local detection/handling phase and implementation owner:

- `KeyGeneration::execute_prepared` — `src/native/generation.rs`. Enclosing true branch: `!unchanged`.


<a id="cause-KeyPairGenerationInputChanged"></a>

### `KeyPairGenerationInputChanged`


Local detection/handling phase and implementation owner:

- `PairGeneration::execute_prepared` — `src/native/generation.rs`. Enclosing true branch: `!unchanged`.


<a id="cause-ModuleFinalizationAbortState"></a>

### `ModuleFinalizationAbortState`


Local detection/handling phase and implementation owner:

- `EventRegistry::abort_finalize` — `src/native/events.rs`. Enclosing true branch: `state.lifecycle != Lifecycle::Finalizing`.


<a id="cause-ModuleFinalizationDispatchState"></a>

### `ModuleFinalizationDispatchState`


Local detection/handling phase and implementation owner:

- `EventRegistry::finalize_dispatched` — `src/native/events.rs`. Enclosing true branch: `state.lifecycle != Lifecycle::Finalizing`.


<a id="cause-ModuleFinalizationReturnState"></a>

### `ModuleFinalizationReturnState`

Local publication of a recorded native finalization result found an incompatible
lifecycle. Publication accepts `FinalizationIssued`, the state corresponding to
that same returned code, or `FinalizationPublicationFailed` carrying that exact
code. The last two permit local reconciliation; they do not authorize another
native call or replacement of the recorded result.

Local detection/handling owner: `EventRegistry::finish_finalize` in
`src/native/events.rs`.


<a id="cause-ModuleFinalizationState"></a>

### `ModuleFinalizationState`

Finalization is already prepared, issued, pending or successfully completed,
its local publication failed, or its local admission was withdrawn and this is
not explicit recovery. A failed publication must first be reconciled using the
recorded result; it does not authorize another native finalization.
A returned native refusal permits a new explicit finalization request without
granting recovery's handling of a poisoned registry. Drop does not retry that
refusal; a successful native return is never dispatched again.

Local detection/handling owner: `EventRegistry::begin_finalize` in
`src/native/events.rs`. Native completion and local publication remain distinct.

<a id="cause-ModuleIdentityReservationAbsent"></a>

### `ModuleIdentityReservationAbsent`

The runtime cannot establish the image/file reservation needed to finalize,
publish a recorded result, or transfer authority to a successor. Keep its
retained owners and result receipts. Waiting or issuing another `C_Finalize`
does not restore a missing reservation and must not be used as a repair.

Local reconciliation of an already returned result can succeed only if the
exact reservations remain verifiable. Their actual absence prevents continued
use of that generation; it is not a transient native operation still in flight.
An earlier publication failure caused by a poisoned registry can also reach
this rejection during successor admission; the original failure remains relevant.

Local detection/handling owners:

- `EventRegistry::begin_finalize` — `src/native/events.rs`: reservation absent before dispatch.
- `EventRegistry::release_if_complete` — `src/native/events.rs`: local reservation release cannot be validated.
- `EventRegistry::reserve_successor` — `src/native/events.rs`: publication remains unresolved after local reconciliation.
- `reserve_finalize` and `finalization_refused` — `src/native/image_reservation.rs`: an expected image generation is absent.


<a id="cause-NativeAdmissionAlreadyBound"></a>

### `NativeAdmissionAlreadyBound`


Local detection/handling phase and implementation owner:

- `Uncertainty::bind_admission` — `src/native.rs`.


<a id="cause-NativeAdmissionLifecycle"></a>

### `NativeAdmissionLifecycle`


Local detection/handling phase and implementation owner:

- `Uncertainty::check_native_authority` — `src/native.rs`. Enclosing match alternative: `_`.


<a id="cause-NativeCallCountersIncomplete"></a>

### `NativeCallCountersIncomplete`


Local detection/handling phase and implementation owner:

- `CallCounters::snapshot` — `src/native.rs`. Enclosing true branch: `self.incomplete`.


<a id="cause-NativeDataAllocation"></a>

### `NativeDataAllocation`


Local detection/handling phase and implementation owner:

- `CallData<T>::new` — `src/native/frame.rs`.
- `NativeFrame<SessionFrame<'a, T, G>>::session_with` — `src/native/frame.rs`.


<a id="cause-NativeFinalizationSuccessAbsent"></a>

### `NativeFinalizationSuccessAbsent`


Local detection/handling phase and implementation owner:

- `Native::repair_finalization` — `src/native.rs`. Enclosing true branch: `!self.finalization_succeeded()`.


<a id="cause-NativeFrameAllocation"></a>

### `NativeFrameAllocation`


Local detection/handling phase and implementation owner:

- `NativeFrame<SessionFrame<'a, T, G>>::session_with` — `src/native/frame.rs`.
- `NativeFrame<T>::new` — `src/native/frame.rs`.


<a id="cause-NativeFrameCompletionUnproven"></a>

### `NativeFrameCompletionUnproven`

Detected when transferring a native frame's payload back to an ordinary Rust
owner, in `NativeFrame::into_inner`. The frame is not in the owned/completed
disposition, or its body is absent. The requested value is not returned.
For an uncompleted frame, destruction transfers its body to the installed
recovery owner; without such an owner it retains the body and image rather than
freeing memory that native code may still use. An absent body creates no new
ownership or release proof. This refusal can occur after a native call: it is
not permission to repeat initialization or the operation. Propagate the complete
enclosing error, preserve any public recovery owner, and use only that owner's
documented completion/cleanup path. There is no public frame-extraction retry.


An accepted signature Init transfer checks the returned phase, intact
inspection prerequisite and independent native uncertainty before publication.
Its local failure does not erase an intact successful Init result.

Local detection/handling phase and implementation owner:

- `FrameReturn<'a>::accepted_init` — `src/native/frame/replacement.rs`. Enclosing true branch: `self.scope != CallScope::Session || self.disposition.get() != Disposition::Active || self.call.get() != CallPhase::Returned(fe11_sys::CKR_OK) || kind.function() != function || native.is_uncertain()`.
- `NativeFrame<T>::into_inner` — `src/native/frame.rs`. Enclosing true branch: `self.disposition.get() != Disposition::Owned`.
- `NativeFrame<T>::into_inner` — `src/native/frame.rs`.


<a id="cause-NativeInitializationRetired"></a>

### `NativeInitializationRetired`


This local diagnostic reports an initialization already known to be retired.
Admission retains its own ordering for lifecycle and runtime-owner refusals.
Resident mutation cleanup also reports this fact before issuing any cleanup
call, unless an unfinished loan takes priority. The diagnostic does not prove
completion of other loans or release their reservations. A direct
`CKR_CRYPTOKI_NOT_INITIALIZED` refusal with no resident cleanup work is returned
unchanged instead of adding a failure.

Local detection/handling phase and implementation owner:

- `Uncertainty::check_native_authority` — `src/native.rs`. Enclosing true branch: `self.initialization_lost()`.
- `run_with_native` (module-level helper) — `src/managed/mutations/create/resident/runner.rs`. Cleanup preparation: known initialization retirement, after unfinished-loan checks.
- `run` (module-level helper) — `src/managed/mutations/copy/resident/runner.rs`. Cleanup preparation: known initialization retirement, after unfinished-loan checks.
- `run` (module-level helper) — `src/managed/mutations/outputs/runner.rs`. Cleanup preparation: known initialization retirement, after unfinished-loan checks.


<a id="cause-NotificationRetirementOwnerOccupied"></a>

### `NotificationRetirementOwnerOccupied`


Local detection/handling phase and implementation owner:

- `Native::finalize_admitted` — `src/native.rs`. Enclosing true branch: `!retired.is_empty()`.


<a id="cause-NullFunctionTable"></a>

### `NullFunctionTable`


Local detection/handling phase and implementation owner:

- `Native::load` — `src/native/loading.rs`. Enclosing true branch: `(*ptr).is_null()`.


<a id="cause-ObjectCreationInputChanged"></a>

### `ObjectCreationInputChanged`


Local detection/handling phase and implementation owner:

- `execute_prepared` (module-level helper) — `src/native/creation.rs`. Enclosing true branch: `!unchanged`.


<a id="cause-PredecessorFileReservationAbsent"></a>

### `PredecessorFileReservationAbsent`


Local detection/handling phase and implementation owner:

- `EventRegistry::reserve_successor` — `src/native/events.rs`. Enclosing true branch: `!super::release_file(identity)`.


<a id="cause-ProcessExportAllocation"></a>

### `ProcessExportAllocation`


Local detection/handling phase and implementation owner:

- `Native::load` — `src/native/loading.rs`. Enclosing true branch: `!exports.contains(&(*entry as usize))`.
- `open_scope` (module-level helper) — `src/native/process_image.rs`.


<a id="cause-RetiredRuntimeHasNoFinalizeAuthority"></a>

### `RetiredRuntimeHasNoFinalizeAuthority`


Local detection/handling phase and implementation owner:

- `Native::finalize_admitted` — `src/native.rs`. Enclosing true branch: `self.uncertainty_flag().initialization_lost() && !self.finalization_succeeded()`.


<a id="cause-RuntimeOwnerWithdrawn"></a>

### `RuntimeOwnerWithdrawn`


Local detection/handling phase and implementation owner:

- `Uncertainty::check_native_authority` — `src/native.rs`. Enclosing true branch: `self .owner_withdrawn .load(std::sync::atomic::Ordering::Acquire)`.


<a id="cause-RuntimeRetirementNotEstablished"></a>

### `RuntimeRetirementNotEstablished`


Local detection/handling phase and implementation owner:

- `Native::successor_ready` — `src/native.rs`. Enclosing true branch: `!self.finalization_succeeded() && !self.uncertainty_flag().initialization_lost()`.


<a id="cause-RuntimeSuccessorAlreadyPublished"></a>

### `RuntimeSuccessorAlreadyPublished`


Local detection/handling phase and implementation owner:

- `EventRegistry::reserve_successor` — `src/native/events.rs`. Enclosing true branch: `self.successor_published.load(Ordering::Acquire)`.


<a id="cause-SerializedCallbackDepth"></a>

### `SerializedCallbackDepth`


Local detection/handling phase and implementation owner:

- `Dispatch::callback` — `src/native/dispatch.rs`.


<a id="cause-SerializedDispatchDepth"></a>

### `SerializedDispatchDepth`


Local detection/handling phase and implementation owner:

- `Dispatch::enter_on` — `src/native/dispatch.rs`. Enclosing match alternative: `Some((owner, count)) if *owner == thread`.


<a id="cause-SerializedModuleCallbackReentry"></a>

### `SerializedModuleCallbackReentry`


Local detection/handling phase and implementation owner:

- `Dispatch::check_callback` — `src/native/dispatch.rs`. Enclosing true branch: `crate::notify::in_callback_for(self.image)`.


<a id="cause-SlotEventAdmissionAlreadyBound"></a>

### `SlotEventAdmissionAlreadyBound`


Local detection/handling phase and implementation owner:

- `EventRegistry::bind_admission` — `src/native/events.rs`.


<a id="cause-SlotEventAdmissionClosed"></a>

### `SlotEventAdmissionClosed`

Event preparation or reservation found finalization admission closed. Preparation
checks its atomic closure flag; reservation validates the authoritative lifecycle
under the registry mutex. `Open` and `FinalizationRefused` admit events after the
native refusal has been published locally. `FinalizationPublicationFailed` keeps
reservation closed until reconciliation of the recorded result. An accepted
lifecycle does not override the separate source-selection or waiter-ownership
checks.

Local detection/handling owners: `EventRegistry::check_preparation` and
`EventRegistry::reserve_for` in `src/native/events.rs`.


<a id="cause-SlotEventCompletionUnproven"></a>

### `SlotEventCompletionUnproven`


Local detection/handling phase and implementation owner:

- `EventRegistry::begin_finalize` — `src/native/events.rs`. Enclosing match alternative: `Waiter::Uncertain`.


<a id="cause-SlotEventNativeReturnUnproven"></a>

### `SlotEventNativeReturnUnproven`


Local detection/handling phase and implementation owner:

- `EventLease::finish` — `src/native/events.rs`. Enclosing true branch: `self.phase != LeasePhase::NativeReturned`.


<a id="cause-SlotEventOwnerState"></a>

### `SlotEventOwnerState`


Local detection/handling phase and implementation owner:

- `State::returned_waiter` — `src/native/events.rs`. Enclosing true branch: `self.waiter != Waiter::Issued(mode)`.


<a id="cause-TableObservationExpected"></a>

### `TableObservationExpected`


Local detection/handling phase and implementation owner:

- `LoadingOutcome::observed` — `src/native.rs`. Enclosing match alternative: `Self::Initialized(_, _)`.


<a id="cause-UnqualifiedInterfaceVersion"></a>

### `UnqualifiedInterfaceVersion`


Local detection/handling phase and implementation owner:

- `qualified_table_version` (module-level helper) — `src/native.rs`. Enclosing true branch: `!matches!(expected, (2, 20) | (2, 30) | (2, 40)) || (version.major, version.minor) != expected`.

