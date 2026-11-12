# Usage contracts

This guide describes operation ownership, effects and recovery. The API reference documents each method's parameters and guarantees. Operation availability is established against the selected native module.

## Diagnostics

`Error::Rejected`, `Error::Busy` and `Error::Unsupported` carry `RejectionReason`, `BusyReason` and `UnsupportedReason`, respectively. These non-exhaustive types group causes by technical responsibility and support typed handling independently of `Display` text.

Interpret a local cause together with the enclosing error, its other causes and any retained operation owner. Earlier native work may already have had effects. `Error::Native` preserves the function, PKCS#11 code and `may_have_effect`. Composite errors retain post-call publication, cleanup and validation failures. Determine whether retry is valid from the operation contract and retained state.

`ResourceLimitExceeded` preserves `ResourceKind`, the requested amount and the caller's limit. `Busy` describes local unavailability. `WaitUntil` governs admission to local resources, preserving the original deadline and cancellation across recovery. Native C execution follows its own completion contract.

## Creation, references and observations

`CreatedObjects<T>` separates created objects, observations and auxiliary outputs. An observation failure after creation leaves the created resources owned. If `into_observation` fails, `CreationObservationFailure` retains them. The application chooses their subsequent use or explicit destruction; repeating Create, Generate, Derive, Unwrap or KEM would be a new native mutation.

`NativeObjectRef` supports operations on an object directly. `ManagedObjectRef` and `NativeObjectView` carry observations of that same identity. Attribute, mechanism, history and content read plans specify the observations requested by the application. Those observations describe returned data; cryptographic possession and policy compliance require their own evidence.

A login transition may stale an observation while the retained reference can still be used for a new native request. The module decides current authorization and handle validity. Fe11 retains the reference's identity across that request. Retired generations, closed creators and observed destruction remain relevant, including when the module reuses a handle value.

A new search can present `C_FindObjectsInit` while a previous iterator exists. A native refusal retires the new attempt and preserves the previous iterator. `C_FindObjects` and `C_FindObjectsFinal` have their own execution results.

A second classic Sign/Verify Init can reach the module with its own storage. A definite refusal releases that attempt and preserves the active ticket. An intact success replaces a same-family classic operation when there is no coexisting control or resource wait: the new continuation and ticket start fresh, with the same unique cell and admission. The old ticket loses authority over the new operation.

For another family (Recover or VerifySignature), a mixed owner such as a dual operation, a coexisting control/wait, or independent uncertainty, Fe11 retains the owners after native success and retires ordinary use. `OperationCompleted` identifies the successful Init and its local cause. Finalization and retry remain explicit application choices.

## Initialization, sessions and authentication

`InitializationOptions` selects concurrency. `Concurrent` requests `CKF_OS_LOCKING_OK`; `Serialized` requires the coordination documented by the API. Application-supplied locking callbacks have their own lifetime contract. The module executes as trusted native code in the host process.

Provenance distinguishes a file image from process exports. File observations explicitly represent unavailability. Process provenance has its own persistence capabilities. [COEXISTENCE.txt](COEXISTENCE.txt) describes shared initialization and external participation.

When initialization returns `CRYPTOKI_ALREADY_INITIALIZED`, finalization authority and callbacks remain with the existing owner. Discovery directly calls the selected exports and retains their images. The application coordinates discovery with lifecycle changes, particularly `C_Finalize`, until the returned tables and names are copied. Image retention protects loaded-image lifetime; runtime finalization requires separate coordination. After selection, the initializer's image is reserved before Initialize or Attach, and generation/finalization authority rules apply. Unproven native completion retains arguments and their owners.

Calls on one session are serialized. A native `SESSION_CLOSED` returned by an admitted call is propagated as observed. `SessionDropBehavior::KeepOpen` leaves closure to an explicit request. A receipt of native closure lets local publication recovery reuse that outcome instead of dispatching another `C_CloseSession`.

`Session::login_as`, `login_user` and `logout` act through that session with token-wide authentication effects as defined by PKCS#11. `TokenContext` and drain interfaces remain available. `ContextAuthentication` binds `CKU_CONTEXT_SPECIFIC` to its operation.

The module decides SO/read-only-session compatibility during `C_OpenSession` and `C_Login`/`C_LoginUser`. `initialize_user_pin` dispatches `C_InitPIN`; `change_pin` dispatches `C_SetPIN`, whose applicable role depends on native state. Each request is explicit: a refusal may consume a PIN attempt, so retry requires the caller's decision. PIN owners remain retained after uncertain returns.

## Streams, capacities and captures

An open stream ends through an explicit finalization request. An empty fragment remains an Update. After `take_cipher_stream_output`, the final result contains only bytes still undelivered; count each output prefix once. AEAD plaintext is published after final authentication. CCM receives its explicit native text length.

Digest, signature/MAC and cipher owners retain consumed inputs, parameters, credits and unpublished outputs. `take_digest_ticket`, `take_signature_ticket` and `take_cipher_ticket` recover a ticket retained by a synchronous facade, preserving the existing native state. An owner retained after an error may permit only cleanup.

Extension digests use `begin_extension_digest_stream`, `digest_update`/`digest_key` and `finish_extension_digest_stream`. A complete Single request uses `C_Digest`; Multipart keeps its Updates and Final. `extension_digest_output_requirement` describes insufficient output capacity. `provide_extension_digest_output_capacity` prepares local storage for subsequent progression.

Extension ciphers use `begin_extension_cipher_stream`, `cipher_update` and `finish_cipher_stream`. Their outputs include the declared bytes and auxiliary outputs. Authentication of arbitrary extension plaintext follows the extension's declared contract. Supplying output capacity preserves the existing Init/Update progression.

`Session` progresses AEAD messages with `poll_aead`; `AdvancedSession` uses `poll` and its selected pacing. Native references can be used directly. Declared GCM extensions require an ABI-validity assertion for their concrete graph on each unsafe call. Init outputs are finalized after MessageFinal. `DeclaredGcmMessages` records `CallerAssertedLayout` provenance and provides live-operation results; capture and export are available through the supported standard representations.

An auxiliary-capacity violation is handled before handle publication: the graph remains quarantined, with destruction authority requiring its own evidence. After validation of that boundary and recording creation, a local publication failure in `NativeDerivationOutput::Extension` retains the created object. Recovery handles that existing outcome rather than issuing another DeriveKey. Read-only extensions have no auxiliary output, and a single-object derivation contract requires every returned handle to be represented.

`BPKIOP09` captures retain pointer-free graphs, progression, counters, output requirements and mutable-key owners. Import resumes the represented continuation. The application supplies archive authenticity and import coordination separately from its checksum. `StateRestoreKeys.extension` binds imported extension graphs. Format versions are interpreted under their own contracts rather than converted implicitly.

Standard AEAD messages compare produced text length with accepted text length independently of allocation capacity. Their tag is separate; classic AEAD ciphers concatenate it. Stream counters use 128 bits and include outputs already delivered. A bounded inconsistency after native success preserves that success in the diagnostic, allowing the caller to distinguish it from an unexecuted request.

Progressive-message format 9 records, per row, whether the accepted-text counter is available and its 128-bit value. Encoding writes the low word and then the high word, each in Writer's big-endian order. New captures use this format. Packet size and metadata receive credit before allocation, with caller-selected export limits. Refusal dispositions and abandoned outputs are retained separately.

Formats 3/4 remain readable and restorable. Their missing per-row accepted-input history remains explicitly absent after import and recapture into format 9. New deltas continue in parent progression; a new row starts with an exact zero counter. Terminal per-message equality requires the corresponding history. Represented capacities, phases, outputs, refusals, nonce and tag relationships are still checked. Structural validation and authentication of caller-supplied history are separate responsibilities. Formats 0/7/8 retain their relationships with the represented original input.

The current execution model uses synchronous native calls with cooperative local progression. Native asynchronous PKCS#11 3.2 operation is outside the enabled execution modes.

## Explicit parameters and observations

`NativeHkdfParameters` distinguishes `info=None` (NULL/0) from `Some(&[])` (a present pointer with zero length). Extract and expand are independent. `NativePqcContext.context` similarly distinguishes absent and empty contexts; omitting the entire parameter structure is a separate choice. Prehashed routes retain their explicit digest identifier.

For GCM, `ulIvLen` preserves the byte length representable in the ABI. `ulIvBits` is eight times that length when representable, otherwise zero. The module decides whether it accepts the supplied IV.

`Module::library_info`, `slot_ids`, `slot_info`, `token_info`, `mechanism_ids` and `mechanism_info` perform the requested reads and preserve native fixed fields, flags and sentinel values. The caller retains earlier snapshots separately. `MechanismObservation::Unavailable` distinguishes an absent information function from a mechanism absent from the advertised list.

`ModuleBuilder::observe_functions` observes entry points before Initialize. It performs discovery while the application retains lifecycle responsibility. A later open resolves the image again; that later selection has its own result. Explicitly requested loading controls apply to both paths.

`validation_flags` is an explicit read, separate from the cryptographic result. It transmits the requested type for the application to interpret. Correlated capture is available on supporting Advanced ticket owners and helpers that return a report. Synchronous facades provide separate explicit reads. Missing functions and refusals remain distinct from a successful observation of zero flags.

For CCM message records, the declared text length remains binding on a completed result even when accepted-input history is absent. A successful terminal-length assertion requires a completed message; incomplete or rejected messages retain their own dispositions.
