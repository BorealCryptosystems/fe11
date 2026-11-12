Cause contracts for `NativeDerivationRejection`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-CDeriveKeyUnavailable"></a>

### `CDeriveKeyUnavailable`


Local detection/handling phase and implementation owner:

- `Derivation::execute_prepared` — `src/native/derivation.rs`.
- `Session::derive_with` — `src/crypto/derivation/operations/execution.rs`.
- `execute_derivation` (module-level helper) — `src/crypto/derivation/operations/execution.rs`.
- `Session::derive_native_input` — `src/managed/mutations/derivation.rs`.
- `Session::derive_native_input` — `src/managed/mutations/derivation.rs`. Enclosing true branch: `state.native.table.C_DeriveKey.is_none()`.
- `Session::derive_kea_selected` — `src/managed/mutations/kea.rs`.
- `Session::derive_kea_selected` — `src/managed/mutations/kea.rs`. Enclosing true branch: `state.native.table.C_DeriveKey.is_none()`.
- `Session::derive_tls_key_material_selected` — `src/managed/mutations/key_material.rs`.
- `Session::derive_tls_key_material_selected` — `src/managed/mutations/key_material.rs`. Enclosing true branch: `state.native.table.C_DeriveKey.is_none()`.
- `Session::derive_sp800_108_selected` — `src/managed/mutations/sp800.rs`.
- `Session::derive_sp800_108_selected` — `src/managed/mutations/sp800.rs`. Enclosing true branch: `state.native.table.C_DeriveKey.is_none()`.
- `KeyMaterial::execute_prepared` — `src/native/derivation/key_material.rs`.
- `Sp800Frame::execute_prepared` — `src/native/derivation/sp800.rs`.
- `Kea::execute_prepared` — `src/native/derivation/kea.rs`.
- `derive` (module-level helper) — `src/native/derivation/prf.rs`.


<a id="cause-IkeParameterAccounting"></a>

### `IkeParameterAccounting`


Local detection/handling phase and implementation owner:

- `IkeStorage<'a>::allocated_bytes` — `src/native/derivation/ike.rs`.
- `Ike::payload_bytes` — `src/native/derivation/ike.rs`.


<a id="cause-KeaCreationDiagnosticsAbsent"></a>

### `KeaCreationDiagnosticsAbsent`


Local detection/handling phase and implementation owner:

- `Kea::execute_prepared` — `src/native/derivation/kea.rs`. Enclosing true branch: `creating && cleanup.is_none()`.


<a id="cause-KeaCreationPhase"></a>

### `KeaCreationPhase`


Local detection/handling phase and implementation owner:

- `Completed::into_created_parts` — `src/native/derivation/kea.rs`.


<a id="cause-KeaCreationScope"></a>

### `KeaCreationScope`


Local detection/handling phase and implementation owner:

- `Kea::execute_prepared` — `src/native/derivation/kea.rs`. Enclosing true branch: `creating != has_creation`.


<a id="cause-KeaNativeInputMutation"></a>

### `KeaNativeInputMutation`


Local detection/handling phase and implementation owner:

- `Kea::execute_prepared` — `src/native/derivation/kea.rs`. Enclosing true branch: `!unchanged`.


<a id="cause-KeaOutputAliasesSource"></a>

### `KeaOutputAliasesSource`


Local detection/handling phase and implementation owner:

- `Kea::execute_prepared` — `src/native/derivation/kea.rs`. Enclosing true branch: `data.handle == base`.


<a id="cause-KeaParameterAccounting"></a>

### `KeaParameterAccounting`


Local detection/handling phase and implementation owner:

- `KeaStorage::allocated_bytes` — `src/native/derivation/kea.rs`.
- `Kea::allocation_bytes` — `src/native/derivation/kea.rs`.


<a id="cause-KeaSharedRandomLength"></a>

### `KeaSharedRandomLength`


Local detection/handling phase and implementation owner:

- `Kea::allocation_bytes` — `src/native/derivation/kea.rs`. Enclosing true branch: `request.random_a.len() != request.random_b.len()`.


<a id="cause-Sp800IvStorageChanged"></a>

### `Sp800IvStorageChanged`


Local detection/handling phase and implementation owner:

- `Sp800Frame::from_storage` — `src/native/derivation/sp800.rs`. Enclosing match alternative: `_`.


<a id="cause-Sp800ArrayStorageOverflow"></a>

### `Sp800ArrayStorageOverflow`


Local detection/handling phase and implementation owner:

- `size` (module-level helper) — `src/native/derivation/sp800.rs`.


<a id="cause-Sp800NativeInputMutation"></a>

### `Sp800NativeInputMutation`


Local detection/handling phase and implementation owner:

- `Sp800Frame::execute_prepared` — `src/native/derivation/sp800.rs`. Enclosing true branch: `!unchanged`.


<a id="cause-Sp800OutputAliasesSource"></a>

### `Sp800OutputAliasesSource`


Local detection/handling phase and implementation owner:

- `Sp800Frame::execute_prepared` — `src/native/derivation/sp800.rs`. Enclosing true branch: `source_alias`.


<a id="cause-Sp800StorageOverflow"></a>

### `Sp800StorageOverflow`


Local detection/handling phase and implementation owner:

- `sum` (module-level helper) — `src/native/derivation/sp800.rs`.


<a id="cause-Sp800TemplateCountChanged"></a>

### `Sp800TemplateCountChanged`


Local detection/handling phase and implementation owner:

- `Sp800Frame::from_storage` — `src/native/derivation/sp800.rs`. Enclosing true branch: `templates.values.len() != storage.handles.len()`.
- `Sp800Frame::bind` — `src/native/derivation/sp800.rs`. Enclosing true branch: `self.handles.is_empty() || self.handles.len() != self.templates.len()`.


<a id="cause-TlsPrfFrameAccounting"></a>

### `TlsPrfFrameAccounting`


Local detection/handling phase and implementation owner:

- `prepare` (module-level helper) — `src/native/derivation/prf.rs`.


<a id="cause-TlsPrfNativeInputMutation"></a>

### `TlsPrfNativeInputMutation`


Local detection/handling phase and implementation owner:

- `derive` (module-level helper) — `src/native/derivation/prf.rs`. Enclosing true branch: `inspection.violated()`.


<a id="cause-TlsPrfOutputLengthChanged"></a>

### `TlsPrfOutputLengthChanged`

Detected after TLS/WTLS PRF returned success but changed the selected output
length. A length exceeding the owned capacity quarantines the native frame and
returns a boundary failure, without a completion claim. A changed but bounded
length permits termination and retains the successful-call receipt while
withholding publication. Neither outcome is a new size query.
Do not truncate it, reinterpret parameters or repeat the PRF as a publication
retry. Preserve the full diagnostic; this PRF path creates no native objects.


Local detection/handling phase and implementation owner:

- `derive` (module-level helper) — `src/native/derivation/prf.rs`. Enclosing true branch: `rv == CKR_OK && data.length > data.expected`.
- `derive` (module-level helper) — `src/native/derivation/prf.rs`. Enclosing true branch: `data.length != data.expected`.


<a id="cause-TlsPrfSourcePermissionAbsent"></a>

### `TlsPrfSourcePermissionAbsent`


Local detection/handling phase and implementation owner:

- `prepare` (module-level helper) — `src/native/derivation/prf.rs`. Enclosing match alternative: `Ok(_)`.


<a id="cause-TlsPrfStorageAccounting"></a>

### `TlsPrfStorageAccounting`


Local detection/handling phase and implementation owner:

- `Prf::allocation_bytes` — `src/native/derivation/prf.rs`.
- `prepare` (module-level helper) — `src/native/derivation/prf.rs`.


<a id="cause-TlsContextStorageChanged"></a>

### `TlsContextStorageChanged`


Local detection/handling phase and implementation owner:

- `Kdf::from_storage` — `src/native/derivation/tls.rs`. Enclosing match alternative: `_`.


<a id="cause-TlsMasterStorageChanged"></a>

### `TlsMasterStorageChanged`


Local detection/handling phase and implementation owner:

- `MasterStorage::randoms` — `src/native/derivation/tls.rs`. Enclosing match alternative: `_`.
- `MasterStorage::session` — `src/native/derivation/tls.rs`. Enclosing match alternative: `_`.


<a id="cause-TlsParameterAccounting"></a>

### `TlsParameterAccounting`


Local detection/handling phase and implementation owner:

- `RandomsStorage::allocated_bytes` — `src/native/derivation/tls.rs`.
- `payload` (module-level helper) — `src/native/derivation/tls.rs`.
- `KdfStorage::allocated_bytes` — `src/native/derivation/tls.rs`.


<a id="cause-DerivationFrameAccounting"></a>

### `DerivationFrameAccounting`


Local detection/handling phase and implementation owner:

- `Derivation::allocation_bytes` — `src/native/derivation.rs`.
- `Input<'r, 'a>::allocation_bytes` — `src/native/derivation/input.rs`. Enclosing match alternative: `Self::Recipe { request, .. }`.
- `Storage<'_, '_>::allocated_bytes` — `src/native/derivation/input.rs`. Enclosing match alternative: `Self::Recipe { graph, .. }`.
- `DerivationStorage<'r, 'a>::allocated_bytes` — `src/native/derivation/preparation.rs`.


<a id="cause-DerivationInfoStoragePresence"></a>

### `DerivationInfoStoragePresence`


Local detection/handling phase and implementation owner:

- `Parameters::basic_from_storage` — `src/native/derivation.rs`. Enclosing true branch: `info.is_some() != parameters.info.is_some()`.


<a id="cause-DerivationNativeInputChanged"></a>

### `DerivationNativeInputChanged`


Local detection/handling phase and implementation owner:

- `Derivation::execute_prepared` — `src/native/derivation.rs`. Enclosing true branch: `!unchanged`.


<a id="cause-DerivationParameterOwnershipChanged"></a>

### `DerivationParameterOwnershipChanged`


Local detection/handling phase and implementation owner:

- `Parameters::output` — `src/native/derivation.rs`. Enclosing match alternative: `Self::Extension(graph)`.


<a id="cause-DerivationParameterStorageAccounting"></a>

### `DerivationParameterStorageAccounting`


Local detection/handling phase and implementation owner:

- `Parameters::payload_bytes` — `src/native/derivation.rs`.
- `DerivationStorage<'r, 'a>::allocated_bytes` — `src/native/derivation/preparation.rs`. Enclosing match alternative: `Storage::Basic { first, second }`.


<a id="cause-DerivationScalarAbiWidth"></a>

### `DerivationScalarAbiWidth`


Local detection/handling phase and implementation owner:

- `native_ulong` (module-level helper) — `src/native/derivation.rs`.


<a id="cause-DerivationStorageVariantChanged"></a>

### `DerivationStorageVariantChanged`


Local detection/handling phase and implementation owner:

- `Parameters::basic_from_storage` — `src/native/derivation.rs`. Enclosing match alternative: `_`.
- `DerivationStorage<'r, 'a>::allocate` — `src/native/derivation/preparation.rs`. Enclosing match alternative: `_`.
- `DerivationStorage<'r, 'a>::bind` — `src/native/derivation/preparation.rs`. Enclosing match alternative: `_`.


<a id="cause-DeriveReturnedBaseHandle"></a>

### `DeriveReturnedBaseHandle`


Local detection/handling phase and implementation owner:

- `Derivation::execute_prepared` — `src/native/derivation.rs`. Enclosing true branch: `data.output == base`.
- `execute_derivation` (module-level helper) — `src/crypto/derivation/operations/execution.rs`. Enclosing true branch: `data.created == handle`.


<a id="cause-DeriveReturnedSecondarySourceHandle"></a>

### `DeriveReturnedSecondarySourceHandle`


Local detection/handling phase and implementation owner:

- `Derivation::execute_prepared` — `src/native/derivation.rs`. Enclosing true branch: `data.output == secondary`.


<a id="cause-KeyMaterialIvStorage"></a>

### `KeyMaterialIvStorage`


Local detection/handling phase and implementation owner:

- `KeyMaterial::allocation_bytes` — `src/native/derivation/key_material.rs`.


<a id="cause-KeyMaterialIvWidth"></a>

### `KeyMaterialIvWidth`


Local detection/handling phase and implementation owner:

- `iv_bytes` (module-level helper) — `src/native/derivation/key_material.rs`.


<a id="cause-KeyMaterialNativeInputMutation"></a>

### `KeyMaterialNativeInputMutation`


Local detection/handling phase and implementation owner:

- `KeyMaterial::execute_prepared` — `src/native/derivation/key_material.rs`. Enclosing true branch: `!unchanged`.


<a id="cause-KeyMaterialOutputAliasesSource"></a>

### `KeyMaterialOutputAliasesSource`


Local detection/handling phase and implementation owner:

- `KeyMaterial::execute_prepared` — `src/native/derivation/key_material.rs`. Enclosing true branch: `data.handles[..data.count].contains(&base)`.


<a id="cause-KeyMaterialRandomStorage"></a>

### `KeyMaterialRandomStorage`


Local detection/handling phase and implementation owner:

- `KeyMaterial::allocation_bytes` — `src/native/derivation/key_material.rs`.


<a id="cause-KeyMaterialStorage"></a>

### `KeyMaterialStorage`


Local detection/handling phase and implementation owner:

- `KeyMaterialStorage::allocated_bytes` — `src/native/derivation/key_material.rs`.
- `KeyMaterial::allocation_bytes` — `src/native/derivation/key_material.rs`.


<a id="cause-MessagingParameterAccounting"></a>

### `MessagingParameterAccounting`


Local detection/handling phase and implementation owner:

- `MessagingStorage<'a>::allocated_bytes` — `src/native/derivation/messaging.rs`.
- `Messaging::payload_bytes` — `src/native/derivation/messaging.rs`.


<a id="cause-MissingDerivationDataStorage"></a>

### `MissingDerivationDataStorage`


Local detection/handling phase and implementation owner:

- `Parameters::basic_from_storage` — `src/native/derivation.rs`. Enclosing match alternative: `NativeKeyDerivation::ConcatenateData { .. } | NativeKeyDerivation::XorData { .. }`.


<a id="cause-MissingDerivationInputStorage"></a>

### `MissingDerivationInputStorage`


Local detection/handling phase and implementation owner:

- `Parameters::basic_from_storage` — `src/native/derivation.rs`. Enclosing match alternative: `NativeKeyDerivation::GostR3410 { kdf, peer_public: _, ukm: _, }`.
- `Parameters::basic_from_storage` — `src/native/derivation.rs`. Enclosing match alternative: `NativeKeyDerivation::DhPkcs { .. }`.
- `Parameters::basic_from_storage` — `src/native/derivation.rs`. Enclosing match alternative: `NativeKeyDerivation::Ecdh { kdf, peer_public: _, shared_data: _, .. }`.
- `Parameters::basic_from_storage` — `src/native/derivation.rs`. Enclosing match alternative: `NativeKeyDerivation::X942Dh { kdf, peer_public: _, other_info: _, }`.


<a id="cause-MissingDerivationSaltStorage"></a>

### `MissingDerivationSaltStorage`


Local detection/handling phase and implementation owner:

- `Parameters::basic_from_storage` — `src/native/derivation.rs`. Enclosing match alternative: `NativeHkdfSalt::Data(_)`.


<a id="cause-MissingKeyMaterialOutput"></a>

### `MissingKeyMaterialOutput`


Local detection/handling phase and implementation owner:

- `KeyMaterial::check_output_presence` — `src/native/derivation/key_material.rs`. Enclosing true branch: `self.missing_required`.


<a id="cause-OwnedInputLengthOverflow"></a>

### `OwnedInputLengthOverflow`


Local detection/handling phase and implementation owner:

- `InputBytesStorage::allocated_bytes` — `src/native/derivation.rs`.
- `InputBytesStorage::bind_parts` — `src/native/derivation.rs`.


<a id="cause-PreparedInputLengthChanged"></a>

### `PreparedInputLengthChanged`


Local detection/handling phase and implementation owner:

- `InputBytesStorage::bind_parts` — `src/native/derivation.rs`. Enclosing true branch: `bytes.value.as_slice().len() != length`.
- `InputBytes::from_buffers` — `src/native/derivation.rs`. Enclosing true branch: `value.as_slice().len() != witness.as_slice().len()`.
- `InputBytes::fill_before_dispatch` — `src/native/derivation.rs`. Enclosing true branch: `self.value.as_slice().len() != input.len() || self.witness.as_slice().len() != input.len()`.
- `Storage::bind_parts` — `src/mechanism_extension/operation/input.rs`. Enclosing true branch: `value.capacity() != length || witness.capacity() != length`.


<a id="cause-TwoPairAgreementStorageAccounting"></a>

### `TwoPairAgreementStorageAccounting`


Local detection/handling phase and implementation owner:

- `AgreementStorage<'a>::allocated_bytes` — `src/native/derivation/agreement.rs`.
- `Agreement::payload_bytes` — `src/native/derivation/agreement.rs`.
