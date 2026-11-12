
## Reading the local detection sites

The table names the **local detection phase**, the Rust owner implementing it,
and every current source site that emits or examines the cause. Paths are relative
to the library crate; line numbers identify this source distribution. Several
sites mean that the same cause can arise in several phases. A helper's local
check is not a claim that its enclosing public request has made no native call.
The source sites also identify checks carried through closures, macros and
deferred-rejection fields; not every mention is a newly emitted public error.

## Effect and recovery contract

`InventoryByteQuota` reports that an inventory exceeds the cumulative
`AttributeReadPlan::maximum_bytes` selected by its caller. The quota covers
available metadata bytes, including each object's native class value. Class
and detail readers use the remaining allowance and can refuse a size or sum
before the parent publishes a row. This local refusal does not change the
quota, prove that no native call occurred, or grant permission to replay calls.
The diagnostic has no secondary-cause payload. Native errors and existing
compound errors retain their own information; preserve the complete returned
error and use its owner's documented cleanup path. The diagnostic does not
purge objects, enlarge the allowance or retry the inventory automatically.
Native buffer-capacity and arithmetic failures remain distinct from this quota.

A synchronous session that has never attempted object creation can close while
other sessions on the same token are active, provided it has no retained call,
search or advanced owner and another current local session remains. Closing a
creator, an asynchronous session or the last local session retains the stronger
coordination required by its possible effects. Token/module drain admissions and
poisoned, uncertain or retained session state also use that protected path.
The native module still determines the outcome; a local population observation
does not establish native exclusivity.

`TokenActivityDuringSessionClose` describes contention during close admission,
not proof that every session on a token must be idle. A completed local close
does not leave a token-wide `SessionClosePending` signal. If its native execution
or local publication remains unfinished, its receipt retains that signal before
session possession ends. Recovery uses the protected close path and the recorded
phase, without replaying an already issued close. The signal stops subsequent
admissions; it does not cancel readers already admitted. Preserve the owning
session and complete error chain, and use its explicit cleanup API. No automatic
retry or native completion is implied by either diagnostic.

A cause value is not an operation state or a completion receipt. It does not
transfer a handle, session, buffer, ticket or image, and cloning it grants no
authority over those resources. The listed implementation owner must be read
together with the public return value that still owns the request:

* `Error::OperationCompleted` records a successful native effect. Preserve the
  cause, but never repeat that effect to retry its local publication.
  For a second classic signature Init, it names the accepted Init whose local
  continuation could not be published, not completion of the signature sequence.
  A parameter-boundary anomaly is not wrapped as a successful effect.
* `Error::NativeAndLocalFailure` and `Error::CleanupFailed` retain both failures.
  Preserve their complete chain. A local cause does not erase the native result,
  prove rollback, or authorize a second cleanup call.
* `Error::Native` retains the function, return code and `may_have_effect`.
  Neither `Busy` nor `Rejected` nested inside another error overrides that data.
* `Error::OutputSizeRejected` retains a size observation rejected by a local
  bound. For state capture, `CKR_OK` describes the successful size query only;
  it does not claim that state bytes were captured. The caller's maximum and
  the native length remain visible without allocating past that maximum.
* `Error::NativeOutputAndLocalFailure` retains an observed size and an independent
  local cause in preallocated storage. For wrapping with an integrity violation,
  the length remains untrusted and the native frame stays quarantined. It does
  not authorize use of partial output, allocation or a retry.
* `Error::CipherBufferRequired` and `Error::SignatureBufferRequired` preserve
  a synchronous facade's complete storage request. The session retains its
  operation; the error itself grants no ticket or replay authority. Explicit
  ticket retrieval and storage selection are required before continuation.
  If parking also fails, `CleanupFailed` retains this request and the failure.
* `Error::OutputBufferTooSmall` retains the native length and supplied capacity.
  The length is an observation, not permission to allocate or repeat the call.
  Encapsulation encloses it in `ObjectsMayRemain`: a small ciphertext buffer
  does not establish that no key was created. An accompanying integrity failure
  remains in `NativeOutputAndLocalFailure` alongside the size observation.
  A later cleanup failure may enclose this chain in `CleanupFailed` without
  consuming the same diagnostic storage twice. No partial ciphertext
  or uncertain key handle is returned; creation tracking remains until resolved.
* A creation result or `CreationObservationFailure` still owning created objects
  must be handled through that owner. Retry only its supported observation step,
  or explicitly destroy its objects; do not repeat Create/Generate/Derive/Unwrap.
* A session retaining a synchronous cipher, digest or signature operation may
  return a ticket through its corresponding `take_*_ticket` method. Recover that
  existing ticket before using a documented continuation. Do not submit a new
  Init as a substitute for recovering it: an accepted same-family classic Init
  deliberately replaces a clean signature owner and invalidates its old ticket.
  Not every retained operation is resumable;
  an uncertain one can permit only cleanup, or remain unreleasable.
* An Advanced operation is addressed by its existing ticket and owning session.
  Inspect/poll/cancel only through that owner's API and obey its returned state.
  Do not infer a valid next transition from this enum or recreate the ticket.
* A runtime/session lifecycle refusal keeps its existing generation identity.
  Resolve the outstanding owner or lifecycle transition before requesting the
  same local admission again. A retired reference cannot be rebound by retrying.
* A parser or parameter constructor returns no native result of its own. Correct
  its input and reconstruct only that local value; this does not authorize replay
  of a public request that previously consumed it or produced native effects.

If contextual authentication fails after OAEP initialization, the authentication
error describes that call and its own observed inputs. It does not attest to the
integrity of the separate retained OAEP descriptor graph. No Decrypt call or
plaintext publication follows this failure; the initialized frame remains owned.
The OAEP input check after authentication applies only when authentication
succeeds. A caller must not interpret an authentication refusal as an integrity
verdict for every other buffer retained by the native operation.

For local resource admission, `Busy` may allow the caller-selected `WaitUntil`
policy to wait for the original admission request. Preserve its deadline and
cancellation. It does not wait for cryptographic execution or repair an uncertain
native call. A `ResourceLimitExceeded` request exceeds the caller's ceiling;
waiting cannot admit it. `Unsupported` requires another explicitly selected
capability or representation; there is no automatic fallback.

The safe default for an unrecognized non-exhaustive variant is to return the
**whole error** to the owner of the workflow, without replay, automatic reset,
or destruction of retained native operands. The per-cause entries below refine
this contract where the reason identifies a particular recovery barrier.

## Typed handling example

This deliberately makes no recovery call: the workflow owner must decide from
the complete error and its retained operation, not from a formatted string.

```rust,no_run
fn return_to_owner(error: fe11::Error) -> Result<(), fe11::Error> {
    if let fe11::Error::Busy(fe11::BusyReason::NativeExecution(
        fe11::NativeExecutionBusy::RuntimeNativeCompletionUnproven,
    )) = &error {
        // Keep the existing runtime; do not create its successor here.
        return Err(error);
    }
    // Includes compound errors and future non-exhaustive reason variants.
    Err(error)
}
```

## Capacity requests versus invalid native output

A cause whose name contains Capacity or Length is not a buffer-negotiation
request. Only the public operation's typed buffer-request result and its retained
Waiting state authorize the corresponding local resize method. A length rejected
after CKR_OK can mean native output corruption: the operation can be Failed and
its operands retained, even though a larger allocation would fit that number.
Another poll/Init must not be used to recover such output. Semantic length checks
after a completed call can instead withhold a result while preserving a completed
effect diagnostic. In both cases preserve the complete error and owner; no native
replay follows from this local cause. Each concrete cause's phase distinguishes
these cases from pre-dispatch arithmetic or record-reconstruction failures.


Interface inventories use `ModuleBuilder::observe_interfaces` with explicit
descriptor, attempt and name-byte bounds. `NativeOutputSize` and
`OutputBufferTooSmall` use the native function's units: interface descriptors
for `C_GetInterfaceList`, bytes for byte-producing functions. A list observation
is independent of table selection and contains owned names, standard version
prefixes and all flags. Nonstandard table contents remain opaque. No Initialize
or Finalize call is issued; loading the trusted native image can run constructors.
