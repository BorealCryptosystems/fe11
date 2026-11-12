Cause contracts for `KeyTransportRejection`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-AesKekAlgorithm"></a>

### `AesKekAlgorithm`


Local detection/handling phase and implementation owner:

- `AesKeyEncryptionSpec::validate` — `src/transport/kek.rs`. Enclosing true branch: `!matches!( self.key.algorithm, crate::SymmetricAlgorithm::Aes128 | crate::SymmetricAlgorithm::Aes192 | crate::SymmetricAlgorithm::Aes256 )`.


<a id="cause-AesKekMaterialLength"></a>

### `AesKekMaterialLength`


Local detection/handling phase and implementation owner:

- `Session::import_aes_key_encryption_key` — `src/transport/kek.rs`. Enclosing true branch: `material.as_slice().len() != spec.key.algorithm.key_length()`.


<a id="cause-AesKekMechanismReportAbsent"></a>

### `AesKekMechanismReportAbsent`


Local detection/handling phase and implementation owner:

- `Destination<'_>::finish_observed` — `src/transport/operations.rs`. Enclosing match alternative: `(Self::AesKek(spec), KeyEvidence::Key(evidence))`.


<a id="cause-CDecryptUnavailable"></a>

### `CDecryptUnavailable`


Local detection/handling phase and implementation owner:

- `Session::decrypt_oaep_selected` — `src/oaep.rs`.
- `Session::decrypt_oaep_selected` — `src/oaep.rs`.


<a id="cause-CDecryptInitUnavailable"></a>

### `CDecryptInitUnavailable`


Local detection/handling phase and implementation owner:

- `Session::decrypt_oaep_selected` — `src/oaep.rs`.
- `Session::decrypt_oaep_selected` — `src/oaep.rs`.


<a id="cause-CEncryptUnavailable"></a>

### `CEncryptUnavailable`


Local detection/handling phase and implementation owner:

- `Session::encrypt_oaep` — `src/oaep.rs`.
- `Session::encrypt_oaep` — `src/oaep.rs`.


<a id="cause-CEncryptInitUnavailable"></a>

### `CEncryptInitUnavailable`


Local detection/handling phase and implementation owner:

- `Session::encrypt_oaep` — `src/oaep.rs`.
- `Session::encrypt_oaep` — `src/oaep.rs`.


<a id="cause-CUnwrapKeyUnavailable"></a>

### `CUnwrapKeyUnavailable`


Local detection/handling phase and implementation owner:

- `Unwrap::resolve` — `src/transport/operations/resolved.rs`. Enclosing match alternative: `None`.
- `Session::unwrap_destination` — `src/transport/operations/unwrap.rs`. Enclosing false branch: `matches!(call, MutationCall::UnwrapAuthenticated)`.


<a id="cause-CUnwrapKeyAuthenticatedUnavailableInSelectedInterface"></a>

### `CUnwrapKeyAuthenticatedUnavailableInSelectedInterface`


Local detection/handling phase and implementation owner:

- `Unwrap::resolve` — `src/transport/operations/resolved.rs`. Enclosing match alternative: `Some((aad, aad_len))`.
- `Session::unwrap_destination` — `src/transport/operations/unwrap.rs`. Enclosing true branch: `matches!(call, MutationCall::UnwrapAuthenticated)`.


<a id="cause-CWrapKeyUnavailable"></a>

### `CWrapKeyUnavailable`


Local detection/handling phase and implementation owner:

- `Wrap::resolve` — `src/transport/operations/resolved.rs`. Enclosing match alternative: `None`.


<a id="cause-CWrapKeyAuthenticatedUnavailableInSelectedInterface"></a>

### `CWrapKeyAuthenticatedUnavailableInSelectedInterface`


Local detection/handling phase and implementation owner:

- `Wrap::resolve` — `src/transport/operations/resolved.rs`. Enclosing match alternative: `Some((aad, aad_len))`.


<a id="cause-GcmSelectionSize"></a>

### `GcmSelectionSize`


Local detection/handling phase and implementation owner:

- `GcmStorage<'a>::allocation_bytes` — `src/transport/authenticated.rs`.
- `GcmStorage<'a>::allocated_bytes` — `src/transport/authenticated.rs`.


<a id="cause-MgfIdentifierConversion"></a>

### `MgfIdentifierConversion`


Local detection/handling phase and implementation owner:

- `OaepParams<'_>::validate` — `src/oaep.rs`.
- `native_params` (module-level helper) — `src/oaep.rs`.
- `PssParams::checked` — `src/session/pss.rs`.


<a id="cause-OaepMgfIdentifierWidth"></a>

### `OaepMgfIdentifierWidth`


Local detection/handling phase and implementation owner:

- `OaepStorage<'a>::allocate` — `src/transport/oaep.rs`.
- `TransportInputs::validate_unwrap` — `src/transport/operations.rs`. Enclosing match alternative: `UnwrapParameters::RsaOaep { label, hash, mgf }`.
- `TransportStorage<'a>::unwrap_allocation_bytes` — `src/transport/operations/preparation.rs`. Enclosing match alternative: `UnwrapParameters::RsaOaep { label, hash, mgf }`.
- `TransportStorage<'a>::wrap_allocation_bytes` — `src/transport/operations/preparation.rs`. Enclosing match alternative: `WrapParameters::RsaOaep { label, hash, mgf }`.


<a id="cause-OaepHashIdentifierWidth"></a>

### `OaepHashIdentifierWidth`


Local detection/handling phase and implementation owner:

- `OaepStorage<'a>::allocate` — `src/transport/oaep.rs`.
- `TransportInputs::validate_unwrap` — `src/transport/operations.rs`. Enclosing match alternative: `UnwrapParameters::RsaOaep { label, hash, mgf }`.
- `TransportStorage<'a>::unwrap_allocation_bytes` — `src/transport/operations/preparation.rs`. Enclosing match alternative: `UnwrapParameters::RsaOaep { label, hash, mgf }`.
- `TransportStorage<'a>::wrap_allocation_bytes` — `src/transport/operations/preparation.rs`. Enclosing match alternative: `WrapParameters::RsaOaep { label, hash, mgf }`.


<a id="cause-OaepInputChangedDuringContextAuthentication"></a>

### `OaepInputChangedDuringContextAuthentication`


Local detection/handling phase and implementation owner:

- `Session::decrypt_oaep_selected` — `src/oaep.rs`. Enclosing true branch: `!call.descriptors_unchanged(params) || call.input != ciphertext`.


<a id="cause-OaepInputDescriptorChanged"></a>

### `OaepInputDescriptorChanged`


Local detection/handling phase and implementation owner:

- `Session::encrypt_oaep` — `src/oaep.rs`. Enclosing true branch: `rv != CKR_PENDING && (!call.descriptors_unchanged(params) || call.input.as_slice() != expected_input.as_slice())`.
- `Session::encrypt_oaep` — `src/oaep.rs`. Enclosing true branch: `rv != CKR_PENDING && (!call.descriptors_unchanged(params) || call.input.as_slice() != expected_input.as_slice())`.
- `Session::decrypt_oaep_selected` — `src/oaep.rs`. Enclosing true branch: `rv != CKR_PENDING && !call.descriptors_unchanged(params)`.
- `Session::decrypt_oaep_selected` — `src/oaep.rs`. Enclosing true branch: `!call.descriptors_unchanged(params) || call.input != ciphertext`.


<a id="cause-OaepLabelAllocation"></a>

### `OaepLabelAllocation`


Local detection/handling phase and implementation owner:

- `OaepParams<'_>::checked_label` — `src/oaep.rs`.


<a id="cause-OaepPlaintextAllocation"></a>

### `OaepPlaintextAllocation`


Local detection/handling phase and implementation owner:

- `SecretPlaintext::new` — `src/oaep.rs`.


<a id="cause-OaepStorageAccounting"></a>

### `OaepStorageAccounting`


Local detection/handling phase and implementation owner:

- `accounting` (module-level helper) — `src/oaep/preparation.rs`.


<a id="cause-RsaKekSpkiSize"></a>

### `RsaKekSpkiSize`


Local detection/handling phase and implementation owner:

- `Session::validate_transport_public` — `src/transport/rsa.rs`. Enclosing true branch: `p.bits != spec.bits`.


<a id="cause-RsaCiphertextAllocation"></a>

### `RsaCiphertextAllocation`


Local detection/handling phase and implementation owner:

- `bytes` (module-level helper) — `src/oaep/preparation.rs`.


<a id="cause-RsaCiphertextCapacity"></a>

### `RsaCiphertextCapacity`


Local detection/handling phase and implementation owner:

- `Session::encrypt_oaep` — `src/oaep.rs`. Enclosing true branch: `rv == fe11_sys::CKR_OK`.
- `Session::encrypt_oaep` — `src/oaep.rs`.


<a id="cause-RsaCiphertextLength"></a>

### `RsaCiphertextLength`


Local detection/handling phase and implementation owner:

- `Session::encrypt_oaep` — `src/oaep.rs`. Enclosing true branch: `length != capacity`.


<a id="cause-RsaImportedPrivateProtection"></a>

### `RsaImportedPrivateProtection`


Local detection/handling phase and implementation owner:

- `Session::import_rsa_unwrapping_key` — `src/transport/rsa.rs`.


<a id="cause-RsaMechanismReportAbsent"></a>

### `RsaMechanismReportAbsent`


Local detection/handling phase and implementation owner:

- `Session::import_rsa_unwrapping_key` — `src/transport/rsa.rs`.


<a id="cause-RsaPrivateMaterialFamily"></a>

### `RsaPrivateMaterialFamily`


Local detection/handling phase and implementation owner:

- `Session::import_rsa_unwrapping_key` — `src/transport/rsa.rs`.


<a id="cause-RsaPrivateMechanismReportAbsent"></a>

### `RsaPrivateMechanismReportAbsent`


Local detection/handling phase and implementation owner:

- `Session::find_rsa_unwrapping_key` — `src/transport/rsa.rs`.


<a id="cause-RsaPublicPublicationAbsent"></a>

### `RsaPublicPublicationAbsent`


Local detection/handling phase and implementation owner:

- `Session::import_rsa_wrapping_key` — `src/transport/rsa.rs`.


<a id="cause-RsaRestoredHistoryReportAbsent"></a>

### `RsaRestoredHistoryReportAbsent`


Local detection/handling phase and implementation owner:

- `PreparedRsaRestore<'_>::finish_observed` — `src/transport/rsa.rs`.


<a id="cause-RsaRestoredMechanismReportAbsent"></a>

### `RsaRestoredMechanismReportAbsent`


Local detection/handling phase and implementation owner:

- `PreparedRsaRestore<'_>::finish_observed` — `src/transport/rsa.rs`.


<a id="cause-AuthenticatedUnwrapParameters"></a>

### `AuthenticatedUnwrapParameters`


Local detection/handling phase and implementation owner:

- `GcmStorage<'a>::allocation_bytes` — `src/transport/authenticated.rs`. Enclosing true branch: `expected_tag.is_some_and(|tag| tag.len() != tag_bytes) || expected_tag.is_some() && origin.generated()`.
- `TransportInputs::validate_unwrap` — `src/transport/operations.rs`. Enclosing true branch: `tag.len() != nonce.tag_bytes()? || nonce.generated()`.


<a id="cause-HashIdentifierConversion"></a>

### `HashIdentifierConversion`


Local detection/handling phase and implementation owner:

- `OaepParams<'_>::validate` — `src/oaep.rs`.
- `native_params` (module-level helper) — `src/oaep.rs`.


<a id="cause-ImportedKekHistoryReportAbsent"></a>

### `ImportedKekHistoryReportAbsent`


Local detection/handling phase and implementation owner:

- `Session::introduce_aes_kek` — `src/transport/kek.rs`.


<a id="cause-ImportedSymmetricHistoryReportAbsent"></a>

### `ImportedSymmetricHistoryReportAbsent`


Local detection/handling phase and implementation owner:

- `Session::introduce_symmetric` — `src/transport/secret_keys.rs`.


<a id="cause-KeyMechanismReportAbsent"></a>

### `KeyMechanismReportAbsent`


Local detection/handling phase and implementation owner:

- `Session::introduce_aes_kek` — `src/transport/kek.rs`.
- `Session::introduce_symmetric` — `src/transport/secret_keys.rs`.
- `Session::import_agreement_key` — `src/crypto/derivation/introduced.rs`.
- `Session::import_pqc_private_key` — `src/crypto/pqc_material/import.rs`.
- `Session::import_signing_key_selected` — `src/crypto/signing/introduced.rs`.
- `Session::find_introduced_signing_key_selected` — `src/crypto/signing/introduced.rs`.


<a id="cause-NativeKekCreationUnavailable"></a>

### `NativeKekCreationUnavailable`


Local detection/handling phase and implementation owner:

- `Session::introduce_aes_kek` — `src/transport/kek.rs`.


<a id="cause-NativeIntroductionUnavailable"></a>

### `NativeIntroductionUnavailable`


Local detection/handling phase and implementation owner:

- `Session::introduce_symmetric` — `src/transport/secret_keys.rs`.


<a id="cause-NativePlaintextLength"></a>

### `NativePlaintextLength`


Local detection/handling phase and implementation owner:

- `Session::decrypt_oaep_selected` — `src/oaep.rs`. Enclosing true branch: `rv == fe11_sys::CKR_OK`.
- `Session::decrypt_oaep_selected` — `src/oaep.rs`.


<a id="cause-PrivateTemplateStorageAllocation"></a>

### `PrivateTemplateStorageAllocation`


Local detection/handling phase and implementation owner:

- `reserve` (module-level helper) — `src/transport/secret_template/preparation.rs`.


<a id="cause-PrivateTemplateStorageSize"></a>

### `PrivateTemplateStorageSize`


Local detection/handling phase and implementation owner:

- `add` (module-level helper) — `src/transport/secret_template/preparation.rs`.
- `NativeSecretStorage<'a>::allocation_bytes` — `src/transport/secret_template/preparation.rs`.
- `NativeSecretStorage<'a>::allocated_bytes` — `src/transport/secret_template/preparation.rs`.


<a id="cause-RestorationAlreadyConsumed"></a>

### `RestorationAlreadyConsumed`


Local detection/handling phase and implementation owner:

- `Session::unwrap_destination` — `src/transport/operations/unwrap.rs`.


<a id="cause-RestorationEvidenceFamilyMismatch"></a>

### `RestorationEvidenceFamilyMismatch`


Local detection/handling phase and implementation owner:

- `Destination<'_>::finish_observed` — `src/transport/operations.rs`. Enclosing match alternative: `_`.


<a id="cause-RestoredHistoryReportAbsent"></a>

### `RestoredHistoryReportAbsent`


Local detection/handling phase and implementation owner:

- `Destination<'_>::finish_observed` — `src/transport/operations.rs`. Enclosing match alternative: `(Self::Symmetric(spec), KeyEvidence::Key(evidence))`.
- `Destination<'_>::finish_observed` — `src/transport/operations.rs`. Enclosing match alternative: `(Self::AesKek(spec), KeyEvidence::Key(evidence))`.


<a id="cause-TransportAttributeCountOverflow"></a>

### `TransportAttributeCountOverflow`


Local detection/handling phase and implementation owner:

- `NativeSecretStorage<'a>::allocation_bytes` — `src/transport/secret_template/preparation.rs`.
- `NativeSecretStorage<'a>::allocate` — `src/transport/secret_template/preparation.rs`.


<a id="cause-TransportDuplicateTemplateField"></a>

### `TransportDuplicateTemplateField`


Local detection/handling phase and implementation owner:

- `NativeSecretStorage<'a>::allocate` — `src/transport/secret_template/preparation.rs`. Enclosing true branch: `identifiers.windows(2).any(|pair| pair[0] == pair[1])`.


<a id="cause-TransportHandleBinding"></a>

### `TransportHandleBinding`


Local detection/handling phase and implementation owner:

- `bound` (module-level helper) — `src/transport/operations.rs`. Enclosing true branch: `session.managed_handle(s, key)? != h`.


<a id="cause-TransportMixedPrivateRepresentations"></a>

### `TransportMixedPrivateRepresentations`


Local detection/handling phase and implementation owner:

- `NativeSecretStorage<'a>::allocate` — `src/transport/secret_template/preparation.rs`. Enclosing true branch: `source .iter() .any(|(kind, _)| matches!(*kind, CKA_SEED | CKA_VALUE)) && source .iter() .any(|(kind, _)| !matches!(*kind, CKA_SEED | CKA_VALUE))`.


<a id="cause-TransportPrivateTemplateField"></a>

### `TransportPrivateTemplateField`


Local detection/handling phase and implementation owner:

- `NativeSecretStorage<'a>::allocate` — `src/transport/secret_template/preparation.rs`. Enclosing true branch: `!private_field(*kind)`.


<a id="cause-TransportPublicTemplateField"></a>

### `TransportPublicTemplateField`


Local detection/handling phase and implementation owner:

- `NativeSecretStorage<'a>::allocate` — `src/transport/secret_template/preparation.rs`. Enclosing true branch: `private_field(descriptor.r#type)`.


<a id="cause-TransportSecretLength"></a>

### `TransportSecretLength`


Local detection/handling phase and implementation owner:

- `Session::import_symmetric_key` — `src/transport/secret_keys.rs`. Enclosing true branch: `material.as_slice().len() != spec.key.algorithm.key_length()`.


<a id="cause-UnwrapReturnedKekHandle"></a>

### `UnwrapReturnedKekHandle`


Local detection/handling phase and implementation owner:

- `execute_unwrap` (module-level helper) — `src/transport/operations/unwrap.rs`. Enclosing true branch: `data.output == key_handle`.


<a id="cause-UnwrappingInputsChanged"></a>

### `UnwrappingInputsChanged`


Local detection/handling phase and implementation owner:

- `execute_unwrap` (module-level helper) — `src/transport/operations/unwrap.rs`. Enclosing true branch: `!valid`.


<a id="cause-UnwrappingStorageSize"></a>

### `UnwrappingStorageSize`


Local detection/handling phase and implementation owner:

- `Session::unwrap_destination` — `src/transport/operations/unwrap.rs`.
- `Session::unwrap_destination` — `src/transport/operations/unwrap.rs`.
- `Session::unwrap_destination` — `src/transport/operations/unwrap.rs`.
- `Session::unwrap_destination` — `src/transport/operations/unwrap.rs`.
- `Session::unwrap_destination` — `src/transport/operations/unwrap.rs`. Enclosing true branch: `actual > admitted`.


<a id="cause-WrappedOutputExceedsCapacity"></a>

### `WrappedOutputExceedsCapacity`


Local detection/handling phase and implementation owner:

- `wrap_with_fixed_prefix` (module-level helper) — `src/mechanism_extension/transport.rs`. Enclosing true branch: `overflow`.
- `Session::wrap_key` — `src/transport/operations/wrap.rs`. Enclosing true branch: `overflow`.


<a id="cause-WrappingParametersChanged"></a>

### `WrappingParametersChanged`


Local detection/handling phase and implementation owner:

- `Session::wrap_key` — `src/transport/operations/wrap.rs`. Enclosing false branch: `overflow`.


<a id="cause-WrappingSizeRepresentation"></a>

### `WrappingSizeRepresentation`


Local detection/handling phase and implementation owner:

- `wrap_output_capacity` (module-level helper) — `src/transport/operations.rs`.


<a id="cause-WrappingStorageSize"></a>

### `WrappingStorageSize`


Local detection/handling phase and implementation owner:

- `Session::wrap_key` — `src/transport/operations/wrap.rs`.
- `Session::wrap_key` — `src/transport/operations/wrap.rs`.
- `Session::wrap_key` — `src/transport/operations/wrap.rs`.
- `Session::wrap_key` — `src/transport/operations/wrap.rs`. Enclosing true branch: `actual > admitted`.

