Cause contracts for `RecoveryRecordRejection`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-DetachedCapacityWidth"></a>

### `DetachedCapacityWidth`


Local detection/handling phase and implementation owner:

- `DetachedRecord<'a>::read_with` — `src/advanced/record/detached.rs`.


<a id="cause-DetachedCaptureFunction"></a>

### `DetachedCaptureFunction`


Local detection/handling phase and implementation owner:

- `DetachedRecord<'a>::read_with` — `src/advanced/record/detached.rs`. Enclosing true branch: `function.name() != "C_GetOperationState"`.


<a id="cause-DetachedCaptureOutputCeiling"></a>

### `DetachedCaptureOutputCeiling`


Local detection/handling phase and implementation owner:

- `DetachedRecord<'a>::read_with` — `src/advanced/record/detached.rs`. Enclosing true branch: `wire_capacity > limits.bytes`.


<a id="cause-DetachedIdentifierWidth"></a>

### `DetachedIdentifierWidth`


Local detection/handling phase and implementation owner:

- `DetachedRecord<'a>::read_with` — `src/advanced/record/detached.rs`.


<a id="cause-DetachedNativeFunctionMismatch"></a>

### `DetachedNativeFunctionMismatch`


Local detection/handling phase and implementation owner:

- `DetachedRecord<'a>::read_with` — `src/advanced/record/detached.rs`. Enclosing true branch: `function.name() != descriptor.phase.name()`.


<a id="cause-DetachedNativeIdentifierWidth"></a>

### `DetachedNativeIdentifierWidth`


Local detection/handling phase and implementation owner:

- `DetachedRecord<'a>::read_with` — `src/advanced/record/detached.rs`.


<a id="cause-DetachedOutputCapacityMismatch"></a>

### `DetachedOutputCapacityMismatch`

Detected when decoding a detached record whose wire capacity differs from
the capacity implied by its function and validated descriptor. No joined owner
is established by this check. Reject the archive through its consuming API,
retaining any explicitly returned failure owner; do not clamp capacity or change
the function name. The original native operation remains independently owned.


Local detection/handling phase and implementation owner:

- `DetachedRecord<'a>::read_with` — `src/advanced/record/detached.rs`. Enclosing true branch: `wire_capacity != capacity.unwrap_or(0)`.


<a id="cause-DualRecoveryFamily"></a>

### `DualRecoveryFamily`


Local detection/handling phase and implementation owner:

- `DualRecovery<'a>::read_with` — `src/advanced/record/dual_recovery.rs`. Enclosing match alternative: `_`.


<a id="cause-DualRecoveryHistoricalCompletion"></a>

### `DualRecoveryHistoricalCompletion`


Local detection/handling phase and implementation owner:

- `DualRecovery<'a>::read_with` — `src/advanced/record/dual_recovery.rs`. Enclosing true branch: `observations.next().is_some()`.


<a id="cause-DualRecoveryHistoricalObservation"></a>

### `DualRecoveryHistoricalObservation`


Local detection/handling phase and implementation owner:

- `DualRecovery<'a>::read_with` — `src/advanced/record/dual_recovery.rs`. Enclosing true branch: `o.function != "C_DecryptFinal" || o.message_index.is_some()`.


<a id="cause-DualRecoveryKind"></a>

### `DualRecoveryKind`


Local detection/handling phase and implementation owner:

- `DualRecovery<'a>::read_with` — `src/advanced/record/dual_recovery.rs`. Enclosing true branch: `kind != Kind::DualRecovery`.


<a id="cause-DualRecoveryOutput"></a>

### `DualRecoveryOutput`


Local detection/handling phase and implementation owner:

- `DualRecovery<'a>::read_with` — `src/advanced/record/dual_recovery.rs`. Enclosing true branch: `descriptor .validate_detached(&keys, &messages, None, limits)? .is_some()`.


<a id="cause-DualRecoveryProfile"></a>

### `DualRecoveryProfile`


Local detection/handling phase and implementation owner:

- `DualRecovery<'a>::read_with` — `src/advanced/record/dual_recovery.rs`. Enclosing true branch: `descriptor.mechanism != CKM_AES_GCM as u64 || descriptor.phase.name() != initial || descriptor.validation_requested`.


<a id="cause-DualRecoveryValidationCapacity"></a>

### `DualRecoveryValidationCapacity`


Local detection/handling phase and implementation owner:

- `DualRecovery<'a>::read_with` — `src/advanced/record/dual_recovery.rs`. Enclosing true branch: `v.maximum() != 2`.


<a id="cause-RecoveryExcessObservation"></a>

### `RecoveryExcessObservation`


Local detection/handling phase and implementation owner:

- `RecoveryManifest<'a>::read_with` — `src/advanced/record/recovery_manifest.rs`. Enclosing true branch: `observations.next().is_some()`.


<a id="cause-RecoveryFinalObservation"></a>

### `RecoveryFinalObservation`


Local detection/handling phase and implementation owner:

- `RecoveryManifest<'a>::read_with` — `src/advanced/record/recovery_manifest.rs`. Enclosing true branch: `finished != section.messages.len() || o.function != "C_MessageDecryptFinal" || o.message_index.is_some()`.


<a id="cause-RecoveryHistoricalPrefix"></a>

### `RecoveryHistoricalPrefix`


Local detection/handling phase and implementation owner:

- `RecoveryManifest<'a>::read_with` — `src/advanced/record/recovery_manifest.rs`. Enclosing true branch: `carried > finished`.


<a id="cause-RecoveryIdentityWidth"></a>

### `RecoveryIdentityWidth`


Local detection/handling phase and implementation owner:

- `RecoveryOrigin::read` — `src/advanced/record/recovery_manifest.rs`.


<a id="cause-RecoveryManifestKind"></a>

### `RecoveryManifestKind`


Local detection/handling phase and implementation owner:

- `RecoveryManifest<'a>::read_with` — `src/advanced/record/recovery_manifest.rs`. Enclosing true branch: `kind != Kind::GcmRecoveryManifest`.


<a id="cause-RecoveryObservationAbsent"></a>

### `RecoveryObservationAbsent`


Local detection/handling phase and implementation owner:

- `RecoveryManifest<'a>::read_with` — `src/advanced/record/recovery_manifest.rs`. Enclosing true branch: `let Some(v) = &validation`.


<a id="cause-RecoveryObservationAssociation"></a>

### `RecoveryObservationAssociation`


Local detection/handling phase and implementation owner:

- `RecoveryManifest<'a>::read_with` — `src/advanced/record/recovery_manifest.rs`. Enclosing true branch: `o.function != name || o.message_index != Some(i)`.


<a id="cause-RecoveryRecordKind"></a>

### `RecoveryRecordKind`


Local detection/handling phase and implementation owner:

- `RecoverySection<'a>::read_with` — `src/advanced/record/recovery.rs`. Enclosing true branch: `kind != Kind::GcmRecovery`.


<a id="cause-RecoveryTokenIdentity"></a>

### `RecoveryTokenIdentity`


Local detection/handling phase and implementation owner:

- `RecoveryOrigin::check_token` — `src/advanced/record/recovery_manifest.rs`. Enclosing true branch: `self.manufacturer != id.manufacturer || self.model != id.model || self.serial != id.serial`.


<a id="cause-RestoreCapacityWidth"></a>

### `RestoreCapacityWidth`


Local detection/handling phase and implementation owner:

- `RestorationRecord<'a>::read_with` — `src/advanced/record/restoration.rs`.


<a id="cause-RestoreIdentifierWidth"></a>

### `RestoreIdentifierWidth`


Local detection/handling phase and implementation owner:

- `RestorationRecord<'a>::read_with` — `src/advanced/record/restoration.rs`.


<a id="cause-RestoreKeyEncoding"></a>

### `RestoreKeyEncoding`


Local detection/handling phase and implementation owner:

- `encoding` (module-level helper) — `src/advanced/record/restoration.rs`. Enclosing match alternative: `_`.


<a id="cause-RestoreNativeIdentifierWidth"></a>

### `RestoreNativeIdentifierWidth`


Local detection/handling phase and implementation owner:

- `RestorationRecord<'a>::read_with` — `src/advanced/record/restoration.rs`.


<a id="cause-RestoreObservationSlotWidth"></a>

### `RestoreObservationSlotWidth`


Local detection/handling phase and implementation owner:

- `RestorationRecord<'a>::read_with` — `src/advanced/record/restoration.rs`.


<a id="cause-RestoreTransferCapacity"></a>

### `RestoreTransferCapacity`


Local detection/handling phase and implementation owner:

- `RestorationRecord<'a>::read_with` — `src/advanced/record/restoration.rs`. Enclosing true branch: `wire_capacity != capacity.unwrap_or(0)`.


<a id="cause-RestoreTransferFunction"></a>

### `RestoreTransferFunction`


Local detection/handling phase and implementation owner:

- `capacity` (module-level helper) — `src/advanced/record/restoration.rs`. Enclosing match alternative: `_`.


<a id="cause-RestoreTransferKeyRoles"></a>

### `RestoreTransferKeyRoles`


Local detection/handling phase and implementation owner:

- `RestorationRecord<'a>::read_with` — `src/advanced/record/restoration.rs`. Enclosing true branch: `encryption.is_some() != saved.keys.cipher.is_some() || authentication.is_some() != saved.keys.authentication.is_some()`.


<a id="cause-RestoreTransferKind"></a>

### `RestoreTransferKind`


Local detection/handling phase and implementation owner:

- `RestorationRecord<'a>::read_with` — `src/advanced/record/restoration.rs`. Enclosing true branch: `kind != Kind::DetachedRestore`.


<a id="cause-TerminalObservationFunction"></a>

### `TerminalObservationFunction`


Local detection/handling phase and implementation owner:

- `DetachedRecord<'a>::read_with` — `src/advanced/record/detached.rs`. Enclosing true branch: `function.name() != "C_GetSessionValidationFlags"`.


<a id="cause-TerminalValidityCode"></a>

### `TerminalValidityCode`


Local detection/handling phase and implementation owner:

- `DetachedRecord<'a>::read_with` — `src/advanced/record/detached.rs`. Enclosing true branch: `kind == Kind::DetachedValidation`.
