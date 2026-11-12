Cause contracts for `DerivedObjectCreationRejection`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-KeaDiagnosticAccounting"></a>

### `KeaDiagnosticAccounting`


Local detection/handling phase and implementation owner:

No direct construction site is present in the current sources. This public
variant remains available; the common error contract still governs handling.


<a id="cause-KeaObservationPreparationAbsent"></a>

### `KeaObservationPreparationAbsent`


Local detection/handling phase and implementation owner:

- `Session::derive_kea_selected` — `src/managed/mutations/kea.rs`. Enclosing true branch: `let Some(reservation) = reservation`.


<a id="cause-KeaObservationRegistryAbsent"></a>

### `KeaObservationRegistryAbsent`


Local detection/handling phase and implementation owner:

- `Session::derive_kea_selected` — `src/managed/mutations/kea.rs`. Enclosing true branch: `let Some(reservation) = reservation`.


<a id="cause-KeaOutputAbsent"></a>

### `KeaOutputAbsent`


Local detection/handling phase and implementation owner:

- `Session::derive_kea_selected` — `src/managed/mutations/kea.rs`. Enclosing true branch: `let Some(reservation) = reservation`.


<a id="cause-KeaPublicationPhase"></a>

### `KeaPublicationPhase`


Local detection/handling phase and implementation owner:

- `Session::derive_kea_selected` — `src/managed/mutations/kea.rs`. Enclosing true branch: `let Some(reservation) = reservation`.
- `Session::derive_kea_selected` — `src/managed/mutations/kea.rs`. Enclosing true branch: `let Some(reservation) = reservation`.
- `Session::derive_kea_selected` — `src/managed/mutations/kea.rs`. Enclosing true branch: `handle.is_some()`.


<a id="cause-KeaRandomDiagnosticAbsent"></a>

### `KeaRandomDiagnosticAbsent`


Local detection/handling phase and implementation owner:

- `Session::derive_kea_selected` — `src/managed/mutations/kea.rs`.


<a id="cause-KeaRequestAccounting"></a>

### `KeaRequestAccounting`


Local detection/handling phase and implementation owner:

- `Session::derive_kea_selected` — `src/managed/mutations/kea.rs`.
- `Session::derive_kea_selected` — `src/managed/mutations/kea.rs`.
- `Session::derive_kea_selected` — `src/managed/mutations/kea.rs`.
- `Session::derive_kea_selected` — `src/managed/mutations/kea.rs`. Enclosing true branch: `actual > admitted`.


<a id="cause-Sp800AllocatorCapacity"></a>

### `Sp800AllocatorCapacity`


Local detection/handling phase and implementation owner:

- `Session::derive_sp800_108_selected` — `src/managed/mutations/sp800.rs`.


<a id="cause-Sp800ArrayAllocation"></a>

### `Sp800ArrayAllocation`


Local detection/handling phase and implementation owner:

- `empty` (module-level helper) — `src/managed/mutations/sp800.rs`.
- `empty` (module-level helper) — `src/native/derivation/sp800/preparation.rs`.


<a id="cause-Sp800MissingTemplateStorage"></a>

### `Sp800MissingTemplateStorage`


Local detection/handling phase and implementation owner:

- `Session::derive_sp800_108_selected` — `src/managed/mutations/sp800.rs`.
- `Session::derive_sp800_108_selected` — `src/managed/mutations/sp800.rs`.


<a id="cause-Sp800OutputKind"></a>

### `Sp800OutputKind`


Local detection/handling phase and implementation owner:

- `Session::derive_sp800_108_selected` — `src/managed/mutations/sp800.rs`.


<a id="cause-Sp800PrimaryOutputRequired"></a>

### `Sp800PrimaryOutputRequired`


Local detection/handling phase and implementation owner:

- `Session::derive_sp800_108_selected` — `src/managed/mutations/sp800.rs`. Enclosing true branch: `N == 0`.
- `Sp800Frame::allocation_bytes` — `src/native/derivation/sp800.rs`.


<a id="cause-Sp800RequestAccounting"></a>

### `Sp800RequestAccounting`


Local detection/handling phase and implementation owner:

- `Session::derive_sp800_108_selected` — `src/managed/mutations/sp800.rs`.
- `Session::derive_sp800_108_selected` — `src/managed/mutations/sp800.rs`.
- `Session::derive_sp800_108_selected` — `src/managed/mutations/sp800.rs`.
- `Session::derive_sp800_108_selected` — `src/managed/mutations/sp800.rs`.
- `Session::derive_sp800_108_selected` — `src/managed/mutations/sp800.rs`. Enclosing true branch: `actual > admitted`.


<a id="cause-Sp800ResultAccounting"></a>

### `Sp800ResultAccounting`


Local detection/handling phase and implementation owner:

- `Session::derive_sp800_108_selected` — `src/managed/mutations/sp800.rs`.
- `Session::derive_sp800_108_selected` — `src/managed/mutations/sp800.rs`.


<a id="cause-Sp800SourceCountOverflow"></a>

### `Sp800SourceCountOverflow`


Local detection/handling phase and implementation owner:

- `Session::derive_sp800_108_selected` — `src/managed/mutations/sp800.rs`.


<a id="cause-Sp800TemplateAccounting"></a>

### `Sp800TemplateAccounting`


Local detection/handling phase and implementation owner:

- `Session::derive_sp800_108_selected` — `src/managed/mutations/sp800.rs`.
- `Session::derive_sp800_108_selected` — `src/managed/mutations/sp800.rs`.


<a id="cause-BaseDerivationSnapshotAbsent"></a>

### `BaseDerivationSnapshotAbsent`


Local detection/handling phase and implementation owner:

- `Session::derive_native_input` — `src/managed/mutations/derivation.rs`.


<a id="cause-DerivationRequestStorageAccounting"></a>

### `DerivationRequestStorageAccounting`


Local detection/handling phase and implementation owner:

- `Session::derive_native_input` — `src/managed/mutations/derivation.rs`.
- `Session::derive_native_input` — `src/managed/mutations/derivation.rs`.
- `Session::derive_native_input` — `src/managed/mutations/derivation.rs`.
- `Session::derive_native_input` — `src/managed/mutations/derivation.rs`. Enclosing true branch: `actual > admitted`.


<a id="cause-DerivedOutputKind"></a>

### `DerivedOutputKind`


Local detection/handling phase and implementation owner:

- `Session::derive_native_input` — `src/managed/mutations/derivation.rs`.


<a id="cause-InternalDerivationSourceComposition"></a>

### `InternalDerivationSourceComposition`


Local detection/handling phase and implementation owner:

- `Session::derive_native_input` — `src/managed/mutations/derivation.rs`.


<a id="cause-KeyTransportRequestStorageAccounting"></a>

### `KeyTransportRequestStorageAccounting`


Local detection/handling phase and implementation owner:

- `Session::create_key_transport` — `src/managed/mutations/native_transport.rs`.
- `Session::create_key_transport` — `src/managed/mutations/native_transport.rs`.
- `Session::create_key_transport` — `src/managed/mutations/native_transport.rs`.
- `Session::create_key_transport` — `src/managed/mutations/native_transport.rs`. Enclosing true branch: `actual > admitted`.


<a id="cause-MutatingKeyTransportRequiresARetainedKey"></a>

### `MutatingKeyTransportRequiresARetainedKey`


Local detection/handling phase and implementation owner:

- `Session::create_key_transport` — `src/managed/mutations/native_transport.rs`. Enclosing true branch: `mutates && key.is_none()`.
- `Session::create_key_transport` — `src/managed/mutations/native_transport.rs`. Enclosing true branch: `mutates`.


<a id="cause-SecondaryDerivationSnapshotAbsent"></a>

### `SecondaryDerivationSnapshotAbsent`


Local detection/handling phase and implementation owner:

- `Session::derive_native_input` — `src/managed/mutations/derivation.rs`.


<a id="cause-SecondaryTransportSnapshotAbsent"></a>

### `SecondaryTransportSnapshotAbsent`


Local detection/handling phase and implementation owner:

- `Session::create_key_transport` — `src/managed/mutations/native_transport.rs`.


<a id="cause-TransportObjectAbsent"></a>

### `TransportObjectAbsent`


Local detection/handling phase and implementation owner:

- `Session::create_key_transport` — `src/managed/mutations/native_transport.rs`.


<a id="cause-TransportOutputKind"></a>

### `TransportOutputKind`


Local detection/handling phase and implementation owner:

- `Session::create_key_transport` — `src/managed/mutations/native_transport.rs`.


<a id="cause-UnchangingKeaPreparationWasInvalidated"></a>

### `UnchangingKeaPreparationWasInvalidated`


Local detection/handling phase and implementation owner:

- `Session::derive_kea_selected` — `src/managed/mutations/kea.rs`. Enclosing false branch: `let Some(destinations) = &destinations`.

