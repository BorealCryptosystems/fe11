Cause contracts for `VerificationEngineRejection`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-AbsoluteVerificationEnginePathRequired"></a>

### `AbsoluteVerificationEnginePathRequired`


Local detection/handling phase and implementation owner:

- `open` (module-level helper) — `src/verify_engine/loading.rs`. Enclosing true branch: `!builder.path.is_absolute()`.


<a id="cause-VerificationEngineAllocationFailed"></a>

### `VerificationEngineAllocationFailed`


Local detection/handling phase and implementation owner:

- `check_status` (module-level helper) — `src/verify_engine/calls.rs`. Enclosing match alternative: `api::status::ALLOCATION_FAILURE`.


<a id="cause-VerificationEngineCapabilityUnavailable"></a>

### `VerificationEngineCapabilityUnavailable`


Local detection/handling phase and implementation owner:

- `check_status` (module-level helper) — `src/verify_engine/calls.rs`. Enclosing match alternative: `api::status::UNAVAILABLE`.


<a id="cause-VerificationEngineDigestUnavailable"></a>

### `VerificationEngineDigestUnavailable`


Local detection/handling phase and implementation owner:

- `VerifyEngine::digest_output` — `src/verify_engine/calls.rs`.


<a id="cause-VerificationEngineFunctionMapping"></a>

### `VerificationEngineFunctionMapping`


Local detection/handling phase and implementation owner:

- `image_for_address` (module-level helper) — `src/verify_engine/platform.rs`. Enclosing true branch: `unsafe { libc::dladdr(address as *const _, &mut information) } == 0 || information.dli_fbase.is_null()`.
- `image_for_address` (module-level helper) — `src/verify_engine/platform.rs`. Enclosing true branch: `unsafe { GetModuleHandleExW( FROM_ADDRESS | UNCHANGED_REFCOUNT, address as *const u16, &mut module, ) } == 0 || module.is_null()`.


<a id="cause-VerificationEngineGetterBelongsToAnotherImage"></a>

### `VerificationEngineGetterBelongsToAnotherImage`


Local detection/handling phase and implementation owner:

- `identify` (module-level helper) — `src/verify_engine/platform.rs`. Enclosing true branch: `identity != handle as usize`.


<a id="cause-VerificationEngineImagePinFailedLoadedImageRetained"></a>

### `VerificationEngineImagePinFailedLoadedImageRetained`


Local detection/handling phase and implementation owner:

- `pin_loaded_image` (module-level helper) — `src/verify_engine/platform.rs`. Enclosing true branch: `unsafe { GetModuleHandleExW(PIN | FROM_ADDRESS, handle as *const u16, &mut pinned) } == 0 || pinned as usize != handle as usize`.


<a id="cause-VerificationEngineInformationShape"></a>

### `VerificationEngineInformationShape`


Local detection/handling phase and implementation owner:

- `open` (module-level helper) — `src/verify_engine/loading.rs`. Enclosing true branch: `version.abi_version != api::ABI_VERSION || version.structure_size as usize != size_of::<api::Information>()`.


<a id="cause-VerificationEngineInformationUnavailable"></a>

### `VerificationEngineInformationUnavailable`


Local detection/handling phase and implementation owner:

- `open` (module-level helper) — `src/verify_engine/loading.rs`.


<a id="cause-VerificationEngineInterfaceChangedInPinnedImage"></a>

### `VerificationEngineInterfaceChangedInPinnedImage`


Local detection/handling phase and implementation owner:

- `retain` (module-level helper) — `src/verify_engine/loading.rs`. Enclosing true branch: `addresses(&existing.table) != addresses(&candidate.table)`.


<a id="cause-VerificationEngineInterfaceExport"></a>

### `VerificationEngineInterfaceExport`


Local detection/handling phase and implementation owner:

- `open` (module-level helper) — `src/verify_engine/loading.rs`.


<a id="cause-VerificationEngineInterfaceShape"></a>

### `VerificationEngineInterfaceShape`


Local detection/handling phase and implementation owner:

- `validate` (module-level helper) — `src/verify_engine/loading.rs`. Enclosing true branch: `table.abi_version != api::ABI_VERSION || table.structure_size as usize != size_of::<api::Interface>() || table.information.is_none() || (table.verify.is_some() && table.probe.is_none()) || (table.digest.is_some() && table.release.is_none())`.


<a id="cause-VerificationEngineInvalidRequest"></a>

### `VerificationEngineInvalidRequest`


Local detection/handling phase and implementation owner:

- `check_status` (module-level helper) — `src/verify_engine/calls.rs`. Enclosing match alternative: `api::status::INVALID_REQUEST`.


<a id="cause-VerificationEngineIsNotARegularFile"></a>

### `VerificationEngineIsNotARegularFile`


Local detection/handling phase and implementation owner:

- `open` (module-level helper) — `src/verify_engine/loading.rs`. Enclosing true branch: `!source .file .metadata() .map_err(|_| { Error::Rejected(crate::RejectionReason::VerificationEngine( crate::VerificationEngineRejection::VerificationEngineMetadata, )) })? .is_file()`.


<a id="cause-VerificationEngineLoad"></a>

### `VerificationEngineLoad`


Local detection/handling phase and implementation owner:

- `load` (module-level helper) — `src/verify_engine/platform.rs`.


<a id="cause-VerificationEngineLoadingPlatformUnavailable"></a>

### `VerificationEngineLoadingPlatformUnavailable`


Local detection/handling phase and implementation owner:

- `load` (module-level helper) — `src/verify_engine/platform.rs`.
- `image_for_address` (module-level helper) — `src/verify_engine/platform.rs`.


<a id="cause-VerificationEngineMetadata"></a>

### `VerificationEngineMetadata`


Local detection/handling phase and implementation owner:

- `open` (module-level helper) — `src/verify_engine/loading.rs`.


<a id="cause-VerificationEngineNullFunction"></a>

### `VerificationEngineNullFunction`


Local detection/handling phase and implementation owner:

- `image_for_address` (module-level helper) — `src/verify_engine/platform.rs`. Enclosing true branch: `address == 0`.


<a id="cause-VerificationEngineOperationFailed"></a>

### `VerificationEngineOperationFailed`


Local detection/handling phase and implementation owner:

- `check_status` (module-level helper) — `src/verify_engine/calls.rs`. Enclosing match alternative: `api::status::ENGINE_FAILURE`.


<a id="cause-VerificationEngineOutputShape"></a>

### `VerificationEngineOutputShape`


Local detection/handling phase and implementation owner:

- `Output<'_>::check_shape` — `src/verify_engine/calls.rs`. Enclosing true branch: `self.bytes.owner.is_null() || self.bytes.bytes.length != expected_length || expected_length > isize::MAX as usize || (expected_length != 0 && self.bytes.bytes.pointer.is_null())`.


<a id="cause-VerificationEngineProbeUnavailable"></a>

### `VerificationEngineProbeUnavailable`


Local detection/handling phase and implementation owner:

- `VerifyEngine::probe` — `src/verify_engine/calls.rs`.


<a id="cause-VerificationEngineRead"></a>

### `VerificationEngineRead`


Local detection/handling phase and implementation owner:

- `open` (module-level helper) — `src/verify_engine/loading.rs`.


<a id="cause-VerificationEngineReleaseUnavailable"></a>

### `VerificationEngineReleaseUnavailable`


Local detection/handling phase and implementation owner:

- `VerifyEngine::digest_output` — `src/verify_engine/calls.rs`.


<a id="cause-VerificationEngineSourceChangedProcessRestartRequired"></a>

### `VerificationEngineSourceChangedProcessRestartRequired`


Local detection/handling phase and implementation owner:

- `retain` (module-level helper) — `src/verify_engine/loading.rs`. Enclosing true branch: `existing.source_identity == candidate.source_identity && existing.source_sha256 != candidate.source_sha256`.


<a id="cause-VerificationEngineTableFunctionBelongsToAnotherImage"></a>

### `VerificationEngineTableFunctionBelongsToAnotherImage`


Local detection/handling phase and implementation owner:

- `require_same_image` (module-level helper) — `src/verify_engine/platform.rs`. Enclosing true branch: `image_for_address(address)? != identity`.


<a id="cause-VerificationEngineUnknownStatus"></a>

### `VerificationEngineUnknownStatus`


Local detection/handling phase and implementation owner:

- `check_status` (module-level helper) — `src/verify_engine/calls.rs`. Enclosing match alternative: `_`.


<a id="cause-VerificationEngineVerificationResult"></a>

### `VerificationEngineVerificationResult`


Local detection/handling phase and implementation owner:

- `VerifyEngine::verify` — `src/verify_engine/calls.rs`. Enclosing match alternative: `_`.


<a id="cause-VerificationEngineVerificationUnavailable"></a>

### `VerificationEngineVerificationUnavailable`


Local detection/handling phase and implementation owner:

- `Context::selected` — `src/crypto/public_verifier.rs`. Enclosing true branch: `!engine.info().verification_service`.
- `VerifyEngine::verify` — `src/verify_engine/calls.rs`.
