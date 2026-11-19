# Fe11 API guide

Fe11 0.1.1 is a Rust PKCS#11 library licensed under Apache-2.0. It loads an application-selected native module and exposes its operations through Rust owners for sessions, objects, parameters and operation memory. The Rust package and crate are named `fe11`.

The application chooses keys, mechanisms, parameters and templates. The native module evaluates their cryptographic compatibility and applies its policies. Fe11 manages ABI representation, lengths, conversions, buffer capacity, pointer stability, resource identity, access coordination and memory lifetime.

The [API reference](API-REFERENCE.md) provides the public declarations and method contracts. [CONTRACTS.md](CONTRACTS.md) describes effects, diagnostics and recovery. [VALIDATION.md](VALIDATION.md) records the scope of validation.

## Components and builds

| Directory or package | Responsibility |
| --- | --- |
| `library` / `fe11` | PKCS#11 API, resource owners and native calls |
| `verify-engine-api` | Versioned C ABI for software verification and hashing |
| `verify-engine` | Explicitly selected software verification and hashing component |
| `fe11-sys`, in its own repository | Raw PKCS#11 declarations and ABI layouts |

Rust **1.81** is the minimum. The workspace default selects the library; `--workspace` includes the optional engine. Build the library with:

```text
cargo build -p fe11 --release
```

The supported ABI profiles are Linux x86_64 GNU (LP64, natural C alignment) and Windows x86_64 MSVC (LLP64, one-byte-packed PKCS#11 structures). The integrator establishes the native module's actual layout against the selected profile. Its advertised PKCS#11 version and product name are separate observations.

[BUILDING.txt](BUILDING.txt) covers local builds, the two-repository setup and the engine's static OpenSSL installation. [SBOM.json](SBOM.json), [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md) and `LICENSES` identify reference dependencies and their notices. The engine documentation describes [software verification capabilities and selection](verify-engine/README.md).

## Loading and initialization

`Module::builder` selects a native file. `Module::process_builder` selects exports already visible in the current process and retains their images. Both discover the requested interface directly. After selection, Fe11 reserves the initializer's image to coordinate initialization and finalization. Initialization and attachment are distinct actions; a second initialization preserves a native `CRYPTOKI_ALREADY_INITIALIZED` refusal.

`DiscoverySelection::Deferred` defers initial discoveries to explicit requests. Required function pointers follow the chosen route and its resource management:

| Route | Functions required before its first effect |
| --- | --- |
| Initialized open | `C_Initialize`, `C_Finalize`, `C_GetInfo` |
| Session open | `C_OpenSession`, `C_CloseSession` |
| Object creation, copy, generation, derivation, unwrap or KEM | Selected creation function and `C_DestroyObject` |
| Object search | `C_FindObjectsInit`, `C_FindObjects`, `C_FindObjectsFinal` |
| Digest, signature, verification or cipher | Route's Init and terminal function; Update for multipart |
| SignRecover / VerifyRecover | Init and corresponding recovery call |
| Native messages | Selected family's route functions, including finalization |
| Isolated read or action | Requested function |

Optional object description is separate from creation: references to created objects remain available when attribute observation fails. A partial function table can be inspected and used for available routes. When `C_GetMechanismInfo` is absent, advertised identifiers remain available with `MechanismObservation::Unavailable`.

`ModuleBuilder::observe_functions(&self)` observes the selected table before initialization, including an absent `C_Initialize` pointer. The builder remains usable; `open` resolves and checks the selected image again. Observations describe their own load attempt.

`ModuleBuilder::observe_interfaces(InterfaceInventoryLimits)` returns an owned inventory of native interface names and flags. The caller supplies count, retry, per-name and aggregate-name limits. Order and duplicates are preserved; version prefixes are exposed for the standard `PKCS 11` name. Other tables remain opaque.

Loading may execute native constructors. Discovery retains images while the application coordinates concurrent discovery and lifecycle changes through completion of table and name copying. Image retention protects code lifetime; the initializer reservation subsequently coordinates Initialize or Attach. An observation grants inspection results, while an initialized owner carries lifecycle authority.

`InitializationOptions` selects `NativeConcurrency`:

- `Concurrent` supplies `CKF_OS_LOCKING_OK` and permits concurrent calls.
- `Serialized` omits that bit and serializes participating calls. A blocking slot wait keeps `close` busy while the call is active; `Poll` provides a short explicit query. Reentry from `Notify` into the same instance is refused before waiting.
- Cooperative administrative waits under `WaitUntil` release dispatch so existing owners can progress. Resume revalidates guards against the same absolute deadline and cancellation signal.

Serialization covers participants registered with the shared runtime. The application coordinates other callers. `cannot_create_os_threads` transmits the corresponding native choice. `InitializationReserved` owns an explicitly declared extension `pReserved`; its unsafe contract establishes ABI and referent validity. Its owner remains retained through finalization, including quarantine after an uncertain outcome. The ordinary reserved value is NULL.

## Loader provenance and persistent identity

`ModuleProvenance` distinguishes file and process selection. File pinning, integrity checks, dependency search and loader observations are explicit choices with platform-specific contracts. The application establishes trust in native code and loader configuration. Image comparison occurs after loading and any native constructors.

Persistent identity requires an observation of the actual file backing the selected image. On Windows, process selection supplies a local binding. On Linux, a persistent binding requires the selected exports and initializer to match the same opened and mapped file; otherwise the binding remains local. Native Get/SetOperationState and local continuation retain their ordinary scope. Function addresses identify the current process context, while persistent records require stable provenance.

## Shared runtime and coexistence

Other processes can use the token under its PKCS#11 rules. Within a process, `ModuleBuilder::open_shared` creates a `RuntimeOwner` and a client view; `RuntimeOwner::client` creates additional views sharing admission and budgets while opening distinct sessions. Collective actions belong to the owner. Dropping a client leaves the runtime active; dropping its owner retires local access without a native call.

Token initialization uses an observed administrative target. Idle local sessions can reach the module and receive SESSION_EXISTS; pending calls, unresolved local session transitions and retained memory remain protected. For blank and initialized tokens alike, certain SESSION_EXISTS, PIN_INCORRECT, PIN_LOCKED and TOKEN_WRITE_PROTECTED refusals preserve the target and sessions when inputs are unchanged, following the return-value meanings in PKCS#11 section 5.1.6. Reuse revalidates token identity and initialization state. PIN retry counters may change: context preservation is not an absence-of-effect claim.

Other native initialization returns retire the slot's contexts, including sessions belonging to other clients. Native resources may remain open and counted, while old handles cannot be closed individually. Recovery then requires closing the module's usable sessions across all clients and slots before explicit finalization, subject to retained native loans, pending calls and lifecycle authority. A new token generation's TokenDrain does not recover these old owners. The application still coordinates sessions the native module cannot detect.

External native libraries participate through the unsafe attachment and foreign-participant interfaces. Their adapter registers active calls, sessions, callbacks and memory loans. The application coordinates Finalize, CloseAllSessions and token-wide InitToken preconditions. [COEXISTENCE.txt](COEXISTENCE.txt) gives the complete coordination and recovery contracts.

For a private-key operation that requires contextual authentication, keep its
operation ticket and call `authenticate_context` after the successful Init.
Fe11 checks that it can attribute the login to the operation. If another active
operation could own the key, the call returns `AmbiguousContextKey` before the
PIN reaches the module. An application that manages the ordering of native
operations can instead call `authenticate_session_context` on its session with
`ContextAuthentication::login(pin)` or `ContextAuthentication::login_user(pin,
name)`. The module selects the active key. Both routes preserve native PIN
errors, including the token-wide effect of a locked PIN. A length query, an
Update, dropping the ticket, or logging out does not establish that the
operation has ended. Obtain native completion, cancel the operation, or close
the session before using a sibling operation that could consume its grant.

Role and attribute observations describe values obtained at a point in time. Fe11 preserves native results and retires contexts whose invalidity has been established. The application then chooses a new session, token refresh or runtime successor. Outstanding memory owners retain their credits until native completion is established, including across generation changes.

## Objects, templates and observations

`NativeObjectRef` owns native identity and the resources needed to use it. `ManagedObjectRef` adds a descriptive view of that same identity. Native creation first publishes references in `CreatedObjects<T>`; observation results are reported separately. `CreationObservationFailure` preserves created resources when the caller selects `into_observation`. The caller can inspect, use or destroy those objects explicitly.

Templates preserve the request. Omitting `CKA_ALLOWED_MECHANISMS`, supplying an empty list and supplying a nonempty list are distinct requests. Order and repetitions are preserved. Extractability, token residency, privacy and usages are native attributes selected by the caller.

`ObjectObservationPlan`, `MechanismObservationPlan` and content, history, mutation and reference observations select what to read. Reports distinguish observed values, unavailable values and errors. Labels, IDs, selectors and result indices remain explicit application choices. DER/SPKI and typed parameters enforce their representation contracts; the native module handles cryptographic key compatibility.

Resource limits are explicit and configurable. A submission limit applies to that submission; cumulative stream counters are tracked separately. `ResourceAdmission` and `WaitUntil` govern local capacity waits with a preserved deadline and cancellation signal. Native C calls follow their native completion contract.

### Iterating while a cryptographic operation is initialized

On a synchronous session, `iter_native_objects` submits a search to the module while a digest, cipher, signing or verification ticket is between calls. If the module returns `CKR_OPERATION_ACTIVE`, the caller can continue using the original ticket. If it accepts the search, the iterator owns the cursor independently.

Handle errors from `next()` explicitly. A refill that returns `OperationOwnershipBusy::AdvancedOperation` or `NativeOperationCallPending` can resume. Advance or finish the cryptographic operation, then call `next()` again. Discarding these errors with `.flatten()` or `.filter_map(Result::ok)` can loop indefinitely. Other refill errors end iteration.

While a batch returned by `C_FindObjects` awaits publication, the iterator can hold catalogue access across a busy return. This can block object changes coordinated by the same Fe11 runtime for the same token, including changes from its other sessions. Retry after resolving the contention, or call `finish()` before requesting those changes. A batch ready for the caller holds no catalogue exclusion. Other participants can change the token independently.

Use `finish()` to observe cleanup errors. Drop makes one nonwaiting admission attempt. An admitted native Final runs synchronously. If the end of the search cannot be established, Fe11 retains its storage and withdraws the session from ordinary use until close.

Finish and drop the iterator before moving its `Session` into `into_advanced()` for state restoration. A successful native `C_SetOperationState` cancels ongoing cryptographic and object search operations in the destination session. The saved cryptographic state contains no search cursor.

## Operations and parameter representation

Typed APIs cover digest, signature and verification, cipher, MAC, generation, derivation, key transport, encapsulation/decapsulation and native messages. Each route preserves native errors. SignRecover and VerifyRecover use their recovery-specific functions. Prehash selection, RSA-PSS and OAEP parameters, Edwards and PQC variants, AEAD layouts and length encodings follow the selected route.

`MechanismExtension` binds an extension declaration to an instance and exact route. Owned blocks, relocated pointers, directions and output declarations remain live across the relevant calls. The integrator's unsafe contract establishes the actual native layout. Standard typed variants provide their established layouts. Extension generation preserves the selected GenerateKey or GenerateKeyPair call, exact templates, created objects and auxiliary outputs.

## Streams and continuation

Operation tickets own logical sessions, keys, parameters and buffers. Cooperative progression uses explicit caller-driven continuation. The current public execution mode is synchronous; native PKCS#11 3.2 asynchronous execution remains outside the enabled mode.

Caller-fed digest and cipher streams distinguish open input from native phase. An empty fragment is an Update; input closure explicitly requests finalization. Consumed input is released and erased as defined by its owner. `StreamProgress` tracks submissions, consumed bytes, absorbed keys, produced bytes and delivered bytes separately. A capacity retry retains the pending submission.

`begin_encrypt_stream`, `begin_decrypt_stream`, `cipher_update`, `finish_cipher_stream` and `take_cipher_stream_output` use the cipher owner. The final result excludes output already delivered. Output types identify unauthenticated plaintext. AEAD plaintext remains retained through the final native verdict. CCM requires the total plaintext length for `ulDataLen`, excluding the tag; GCM accepts progressive input.

Classic signatures use `begin_native_sign_stream`, `begin_native_verify_stream`, `signature_update` and `finish_signature_stream`. Typed MAC routes start with `begin_native_mac_stream` or `begin_native_mac_verify_stream`. Start stops at Init to allow contextual authentication. Classic verification receives its expected signature at closure; VerifySignature owns it from Init. `poll_signature` preserves temporarily empty open input; `signature_progress` exposes closure and established counters.

Ordinary batch facades delegate to these owners while preserving Single/Multipart and exact input boundaries. After a capacity refusal, `take_signature_ticket` retrieves the facade's ticket once, with the native code preserved. The original output ceiling remains applicable; the start API selects capacity and ceiling for later negotiation. Captures reconstruct address-free parameters for continuation, preserving exclusive ownership for mutable-key signatures.

For cipher and signature owners, `BUFFER_TOO_SMALL` retains the exact call where the native function guarantees non-consumption. The caller selects the new capacity before continuation. Uncertain returns retain owners, pointer graphs and referents until completion is established. Ticket disposal preserves those obligations.

### Native message signatures

Message routes retain Init parameters, per-message parameters, submitted fragments and accumulated results. Single and Begin/Next paths retain their distinct call boundaries. `finish_signature_message` accepts a final fragment, including an empty one. Verify supplies the expected signature with Single or the final fragment. Input limits cover the current submission, including its expected signature.

`finish_signature_messages` explicitly requests process Final after zero or more messages. An active message or unfinished observation is completed first. Signatures remain retained through the process's final result; Verify preserves an invalid native verdict across later successful messages. `SignatureBufferRequired` retains its submission for capacity selection and continuation.

Captures preserve the wait between messages/fragments, pending fragment, results and cumulative verdict. Batch facades feed the same owners with their complete-input arguments.

### Persistence

The current archive signature is `BPKIOP09`. Captures contain opaque native state, parameters, retained calls, undelivered output and progression. Progressive routes, including Message*, retain the pending input instead of replay history. Native state-save or restoration refusals remain visible.

Local transfer remains exclusive. The application supplies archive authenticity, freshness and replay protection. A capture describes output delivery at its capture point; later application consumption must also be accounted for by the caller. [CONTRACTS.md](CONTRACTS.md) specifies record validation and restoration.

## Reinitialization, cleanup and native loss

A successful second `C_SignInit` or `C_VerifyInit` with intact parameters replaces a classic same-family operation when control and resource-wait ownership permit transfer. Its continuation uses the new inputs and invalidates the previous ticket. A native refusal preserves the previous ticket.

A mixed owner, another operation family, retained control/wait or independent uncertainty can prevent local publication of the new continuation. Fe11 reports successful Init through `Error::OperationCompleted` with the local cause and retires ordinary session use. With returned execution, intact parameters and no independent uncertainty, Logout and Session::close remain available; both parameter graphs stay retained until native closure. Boundary anomalies keep their own diagnostics and quarantine.

A poisoned token registry prevents new native session-close or completion calls under `ModuleDrain`, including `reap_sessions`; it does not turn a generic native error into a new cleanup restriction. Explicit module finalization retains its own recovery conditions.

After sessions close, `Module::close` finalizes the module; `ModuleDrain` supplies explicit recovery under its contract. Module closure checks recovery conditions for retired sessions whose calls have returned, preserving another drain's permit and pending executions. A failed session close retains its native receipt for local recovery without repeating C_CloseSession.

After a native error, Logout remains available when initialization and its owner are valid and relevant executions have returned. Its result leaves operation graphs governed by their closure obligations. Explicitly retired initialization is identified by `NativeExecutionRejection::NativeInitializationRetired`, distinct from a native PKCS#11 return. A direct `CKR_CRYPTOKI_NOT_INITIALIZED` with no cleanup work preserves its cause without adding a cleanup failure.

## Native validation flags

`Session::validation_flags(type)` and `AdvancedSession::validation_flags(type)` expose `C_GetSessionValidationFlags`. The caller orders the read; associating it with earlier operations requires the appropriate sequencing.

| Route | Flag observation |
| --- | --- |
| Capture-capable Advanced digest, signature/MAC, cipher, GCM, recover, dual and message tickets with `ValidationCaptureMode::Capture` | Observation attached to the terminal ticket |
| `AdvancedSession::verify_signature_native` and `verify_signature_native_mac` | Selected capture, returned as `Option<ValidationReport>` |
| Synchronous Session facades for Sign/Verify/MAC, AES/RSA, Recover, OTP, CMS/KIP, extensions and messages | Separate explicit `validation_flags` read |
| `validation_flags` and `digest_with_validation` | Explicit requests independent of automatic capture selection |

`set_validation_capture` configures the relevant owners. Missing functions, read refusals and returned flags remain distinct outcomes, separate from the cryptographic verdict.

## Concurrent classic operations on one session

Digest, encrypt, decrypt, sign and verify each have a distinct ticket after a
successful Init. Keep both tickets when a module accepts two operations. Pass
each ticket to its own update, final or poll method. A returned
`CKR_OPERATION_ACTIVE` from a second Init leaves the original ticket available.
A synchronous call which parked a continuation can be recovered by direction
with `take_classic_ticket`.

A session state image covers all active operations. Start capture with one
ticket. The captured state lists the selected operation first in
`grouped_operations()`. Use `start_group_state_restore` to specify each
destination key binding and the two native key arguments. Supply every live
destination ticket once, or an empty slice for an idle destination.
After `poll_state_restore` returns `Restored(primary)`, use
`primary.take_restored_companions()` to take the other tickets by direction.
The module decides whether it can save the session and accept the supplied keys.

A ticket-scoped context login identifies the active key of its operation.
The existing standalone dual-operation ticket retains its contextual login
for its private-key role. Use `authenticate_session_context` for an explicit
session-wide request when the caller leaves key selection to the module.

## Output diagnostics

Output-size diagnostics retain the function, native code, reported size and caller bound. Units follow the native function: bytes for byte outputs, descriptor counts for interface inventories. Local integrity failures remain visible alongside native observations.

`CipherBufferRequired` and `SignatureBufferRequired` preserve capacity requests. Parking failure retains that request inside `CleanupFailed`. Continuation and resizing require the caller's explicit action and appropriate owner.

Incomplete PQC private representation after successful `C_GetAttributeValue` is reported with `OperationCompleted`. Completed AEAD output is checked against known input lengths, cumulative counters and mechanism parameters. Archive readers validate the information actually represented by their format; archive authentication remains the application's responsibility.

## Contributing

Contributions preserve existing operations and document their effects on memory, uncertain returns, concurrency, captures and API consumers. Safety comments accompany unsafe boundaries. Consult [CONTRIBUTING.md](CONTRIBUTING.md) and the [validation record](VALIDATION.md).
