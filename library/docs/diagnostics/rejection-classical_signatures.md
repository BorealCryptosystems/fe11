Cause contracts for `ClassicalSignaturesRejection`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-CDigestUnavailable"></a>

### `CDigestUnavailable`


Local detection/handling phase and implementation owner:

- `Session::native_digest_guarded` — `src/crypto.rs`. Enclosing false branch: `multipart`.


<a id="cause-CDigestFinalUnavailable"></a>

### `CDigestFinalUnavailable`


Local detection/handling phase and implementation owner:

- `Session::native_digest_guarded` — `src/crypto.rs`. Enclosing true branch: `multipart`.


<a id="cause-CDigestInitUnavailable"></a>

### `CDigestInitUnavailable`


Local detection/handling phase and implementation owner:

- `Session::native_digest_guarded` — `src/crypto.rs`.


<a id="cause-CDigestUpdateUnavailable"></a>

### `CDigestUpdateUnavailable`


Local detection/handling phase and implementation owner:

- `Session::native_digest_guarded` — `src/crypto.rs`. Enclosing true branch: `multipart`.


<a id="cause-CSignFinalUnavailable"></a>

### `CSignFinalUnavailable`


Local detection/handling phase and implementation owner:

- `Session::sign_native_frame` — `src/crypto/native_signature.rs`. Enclosing true branch: `multipart`.
- `Session::pqc_sign_parts_guarded` — `src/crypto/pqc/frame.rs`. Enclosing true branch: `multipart`.


<a id="cause-CSignUpdateUnavailable"></a>

### `CSignUpdateUnavailable`


Local detection/handling phase and implementation owner:

- `Session::sign_native_frame` — `src/crypto/native_signature.rs`. Enclosing true branch: `multipart`.
- `Session::pqc_sign_parts_guarded` — `src/crypto/pqc/frame.rs`. Enclosing true branch: `multipart`.


<a id="cause-CVerifyFinalUnavailable"></a>

### `CVerifyFinalUnavailable`


Local detection/handling phase and implementation owner:

- `Session::verify_native_mechanism` — `src/crypto/ecdsa.rs`. Enclosing true branch: `multipart`.
- `Session::pqc_verify_parts_guarded` — `src/crypto/pqc/frame.rs`. Enclosing true branch: `multipart`.


<a id="cause-CVerifyUpdateUnavailable"></a>

### `CVerifyUpdateUnavailable`


Local detection/handling phase and implementation owner:

- `Session::verify_native_mechanism` — `src/crypto/ecdsa.rs`. Enclosing true branch: `multipart`.
- `Session::pqc_verify_parts_guarded` — `src/crypto/pqc/frame.rs`. Enclosing true branch: `multipart`.


<a id="cause-DsaSpkiDer"></a>

### `DsaSpkiDer`


Local detection/handling phase and implementation owner:

- `dsa_der` (module-level helper) — `src/crypto/dsa.rs`.


<a id="cause-DsaSpkiEncoding"></a>

### `DsaSpkiEncoding`


Local detection/handling phase and implementation owner:

- `dsa_der` (module-level helper) — `src/crypto/dsa.rs`.


<a id="cause-DsaAlgorithm"></a>

### `DsaAlgorithm`


Local detection/handling phase and implementation owner:

- `dsa_der` (module-level helper) — `src/crypto/dsa.rs`. Enclosing true branch: `spki.algorithm.oid != ObjectIdentifier::new_unwrap("1.2.840.10040.4.1")`.


<a id="cause-DsaDigestWidth"></a>

### `DsaDigestWidth`


Local detection/handling phase and implementation owner:

- `DsaVerificationDigest::from_bytes` — `src/crypto/historical.rs`. Enclosing true branch: `bytes.len() != algorithm.output_length()`.


<a id="cause-DsaDomainDer"></a>

### `DsaDomainDer`


Local detection/handling phase and implementation owner:

- `dsa_der` (module-level helper) — `src/crypto/dsa.rs`.


<a id="cause-DsaDomainMissing"></a>

### `DsaDomainMissing`


Local detection/handling phase and implementation owner:

- `dsa_der` (module-level helper) — `src/crypto/dsa.rs`.


<a id="cause-DsaPublicEncoding"></a>

### `DsaPublicEncoding`


Local detection/handling phase and implementation owner:

- `dsa_der` (module-level helper) — `src/crypto/dsa.rs`.


<a id="cause-DsaPublicInteger"></a>

### `DsaPublicInteger`


Local detection/handling phase and implementation owner:

- `dsa_der` (module-level helper) — `src/crypto/dsa.rs`.


<a id="cause-DsaREncoding"></a>

### `DsaREncoding`


Local detection/handling phase and implementation owner:

- `VerificationKey::dsa_signature_to_der` — `src/crypto/signature_encoding.rs`.


<a id="cause-DsaSEncoding"></a>

### `DsaSEncoding`


Local detection/handling phase and implementation owner:

- `VerificationKey::dsa_signature_to_der` — `src/crypto/signature_encoding.rs`.


<a id="cause-DsaScalarWidth"></a>

### `DsaScalarWidth`


Local detection/handling phase and implementation owner:

- `VerificationKey::dsa_signature_from_der` — `src/crypto/signature_encoding.rs`. Enclosing true branch: `v.len() > width`.


<a id="cause-DsaSignatureDer"></a>

### `DsaSignatureDer`


Local detection/handling phase and implementation owner:

- `VerificationKey::dsa_signature_from_der` — `src/crypto/signature_encoding.rs`.


<a id="cause-DsaSignatureAllocation"></a>

### `DsaSignatureAllocation`


Local detection/handling phase and implementation owner:

- `VerificationKey::dsa_signature_from_der` — `src/crypto/signature_encoding.rs`.


<a id="cause-DsaSignatureEncoding"></a>

### `DsaSignatureEncoding`


Local detection/handling phase and implementation owner:

- `VerificationKey::dsa_signature_from_der` — `src/crypto/signature_encoding.rs`.
- `VerificationKey::dsa_signature_to_der` — `src/crypto/signature_encoding.rs`.


<a id="cause-DsaSignatureWidth"></a>

### `DsaSignatureWidth`


Local detection/handling phase and implementation owner:

- `dsa_raw_width` (module-level helper) — `src/crypto/signature_encoding.rs`.
- `VerificationKey::dsa_signature_to_der` — `src/crypto/signature_encoding.rs`. Enclosing true branch: `raw.len() != dsa_raw_width(order)?`.


<a id="cause-DsaUnusedBits"></a>

### `DsaUnusedBits`


Local detection/handling phase and implementation owner:

- `dsa_der` (module-level helper) — `src/crypto/dsa.rs`.


<a id="cause-DigestinfoEncoding"></a>

### `DigestinfoEncoding`


Local detection/handling phase and implementation owner:

- `encode_digest_info_into` (module-level helper) — `src/crypto/rsa.rs`.


<a id="cause-DigestinfoInput"></a>

### `DigestinfoInput`


Local detection/handling phase and implementation owner:

- `encode_digest_info_into` (module-level helper) — `src/crypto/rsa.rs`.
- `encoded_digest_info_length` (module-level helper) — `src/crypto/rsa.rs`.


<a id="cause-DigestinfoInputLength"></a>

### `DigestinfoInputLength`


Local detection/handling phase and implementation owner:

- `encoded_digest_info_length` (module-level helper) — `src/crypto/rsa.rs`.


<a id="cause-DigestinfoLength"></a>

### `DigestinfoLength`


Local detection/handling phase and implementation owner:

- `encode_digest_info_into` (module-level helper) — `src/crypto/rsa.rs`.
- `encode_digest_info_into` (module-level helper) — `src/crypto/rsa.rs`.
- `encoded_digest_info_length` (module-level helper) — `src/crypto/rsa.rs`.


<a id="cause-DigestinfoLengthConversion"></a>

### `DigestinfoLengthConversion`


Local detection/handling phase and implementation owner:

- `encoded_digest_info_length` (module-level helper) — `src/crypto/rsa.rs`.


<a id="cause-DigestinfoPreparedLength"></a>

### `DigestinfoPreparedLength`


Local detection/handling phase and implementation owner:

- `encode_digest_info_into` (module-level helper) — `src/crypto/rsa.rs`. Enclosing true branch: `target.len() != length`.


<a id="cause-EcdsaDer"></a>

### `EcdsaDer`


Local detection/handling phase and implementation owner:

- `from_der` (module-level helper) — `src/crypto/signature_encoding.rs`.


<a id="cause-EcdsaDerEncoding"></a>

### `EcdsaDerEncoding`


Local detection/handling phase and implementation owner:

- `to_der` (module-level helper) — `src/crypto/signature_encoding.rs`.
- `from_der` (module-level helper) — `src/crypto/signature_encoding.rs`.


<a id="cause-EcdsaDerSize"></a>

### `EcdsaDerSize`


Local detection/handling phase and implementation owner:

- `from_der` (module-level helper) — `src/crypto/signature_encoding.rs`. Enclosing true branch: `der.len() > 2 * width + 10`.


<a id="cause-EcdsaREncoding"></a>

### `EcdsaREncoding`


Local detection/handling phase and implementation owner:

- `to_der` (module-level helper) — `src/crypto/signature_encoding.rs`.


<a id="cause-EcdsaSEncoding"></a>

### `EcdsaSEncoding`


Local detection/handling phase and implementation owner:

- `to_der` (module-level helper) — `src/crypto/signature_encoding.rs`.


<a id="cause-EcdsaScalarWidth"></a>

### `EcdsaScalarWidth`


Local detection/handling phase and implementation owner:

- `from_der` (module-level helper) — `src/crypto/signature_encoding.rs`. Enclosing true branch: `bytes.len() > width`.


<a id="cause-EcdsaSignatureWidth"></a>

### `EcdsaSignatureWidth`


Local detection/handling phase and implementation owner:

- `to_der` (module-level helper) — `src/crypto/signature_encoding.rs`. Enclosing true branch: `!valid_ecdsa_verification(curve, raw)`.


<a id="cause-EcdsaVerifyFunctionsUnavailable"></a>

### `EcdsaVerifyFunctionsUnavailable`


Local detection/handling phase and implementation owner:

- `Session::verify_ecdsa_parts` — `src/crypto/ecdsa.rs`. Enclosing true branch: `s.native.table.C_VerifyInit.is_none() || s.native.table.C_Verify.is_none()`.


<a id="cause-EddsaInstanceOrContextLength"></a>

### `EddsaInstanceOrContextLength`


Local detection/handling phase and implementation owner:

- `EdDsaParameters::new` — `src/crypto/eddsa/parameters.rs`. Enclosing true branch: `context.len() > 255 || (variant == EdDsaVariant::Ed25519 && !context.is_empty())`.


<a id="cause-EddsaMechanismOrContextLength"></a>

### `EddsaMechanismOrContextLength`


Local detection/handling phase and implementation owner:

- `SignatureMechanism::new` — `src/crypto/native_signature/parameters.rs`. Enclosing true branch: `kind != CKM_EDDSA || context.len() > EDDSA_CONTEXT_MAX`.


<a id="cause-PssDigestAlgorithm"></a>

### `PssDigestAlgorithm`


Local detection/handling phase and implementation owner:

- `Session::verify_rsa_pss_digest` — `src/crypto/rsa.rs`. Enclosing true branch: `digest.algorithm != parameters.hash`.


<a id="cause-PssEncodedMgf"></a>

### `PssEncodedMgf`


Local detection/handling phase and implementation owner:

- `RsaPssParameters::from_native` — `src/crypto/rsa.rs`.


<a id="cause-PssEncodedHash"></a>

### `PssEncodedHash`


Local detection/handling phase and implementation owner:

- `RsaPssParameters::from_native` — `src/crypto/rsa.rs`.


<a id="cause-PssSaltWidth"></a>

### `PssSaltWidth`


Local detection/handling phase and implementation owner:

- `RsaPssParameters::from_native` — `src/crypto/rsa.rs`.


<a id="cause-PssVerifyFunctionsUnavailable"></a>

### `PssVerifyFunctionsUnavailable`


Local detection/handling phase and implementation owner:

- `Session::verify_rsa_pss_parts` — `src/crypto/rsa.rs`. Enclosing true branch: `s.native.table.C_VerifyInit.is_none() || s.native.table.C_Verify.is_none()`.


<a id="cause-RsaDiscoveryEvidenceSequence"></a>

### `RsaDiscoveryEvidenceSequence`


Local detection/handling phase and implementation owner:

- `Initial::allocate` — `src/crypto/rsa_observation.rs`. Enclosing true branch: `spec.introduction.is_some() || spec.mechanisms.is_some()`.


<a id="cause-RsaEncodingContinuationChanged"></a>

### `RsaEncodingContinuationChanged`


Local detection/handling phase and implementation owner:

- `Owner::attach` — `src/crypto/rsa_observation.rs`. Enclosing true branch: `self.need() != Some(Need::Encoding(candidate.need()))`.


<a id="cause-RsaEncodingPhase"></a>

### `RsaEncodingPhase`


Local detection/handling phase and implementation owner:

- `Owner::attach` — `src/crypto/rsa_observation.rs`. Enclosing match alternative: `Candidate::Encoding(candidate)`.


<a id="cause-RsaObservationCompletionPhase"></a>

### `RsaObservationCompletionPhase`


Local detection/handling phase and implementation owner:

- `Owner::advance` — `src/crypto/rsa_observation.rs`. Enclosing match alternative: `_`.


<a id="cause-RsaObservationIncomplete"></a>

### `RsaObservationIncomplete`


Local detection/handling phase and implementation owner:

- `Owner::result` — `src/crypto/rsa_observation.rs`. Enclosing match alternative: `_`.


<a id="cause-RsaObservationMetadataPhase"></a>

### `RsaObservationMetadataPhase`


Local detection/handling phase and implementation owner:

- `Owner::attach` — `src/crypto/rsa_observation.rs`. Enclosing match alternative: `_`.


<a id="cause-RsaObservationStopped"></a>

### `RsaObservationStopped`


Local detection/handling phase and implementation owner:

- `Owner::advance` — `src/crypto/rsa_observation.rs`. Enclosing match alternative: `Phase::Stopped`.


<a id="cause-RsaObservationStorageSize"></a>

### `RsaObservationStorageSize`


Local detection/handling phase and implementation owner:

- `add` (module-level helper) — `src/crypto/rsa_observation.rs`.


<a id="cause-RsaPreparedDigestProfile"></a>

### `RsaPreparedDigestProfile`


Local detection/handling phase and implementation owner:

- `Session::sign_rsa_digest_view_with_context` — `src/crypto/signing/signatures.rs`. Enclosing match alternative: `_`.


<a id="cause-RsaPreparedSigningPermission"></a>

### `RsaPreparedSigningPermission`


Local detection/handling phase and implementation owner:

- `Session::sign_rsa_digest_view_with_context` — `src/crypto/signing/signatures.rs`. Enclosing true branch: `!matches!(key.algorithm, ClassicalKeyAlgorithm::Rsa { .. })`.


<a id="cause-RsaPublicPreparationAbsent"></a>

### `RsaPublicPreparationAbsent`


Local detection/handling phase and implementation owner:

- `Owner::advance` — `src/crypto/rsa_observation.rs`. Enclosing match alternative: `Phase::Identity(read)`.


<a id="cause-RsaSigningIdentity"></a>

### `RsaSigningIdentity`


Local detection/handling phase and implementation owner:

- `Session::validate_signing_public` — `src/crypto/signing/signatures.rs`. Enclosing true branch: `key.bits != bits`.


<a id="cause-RsaSigningProfileFamily"></a>

### `RsaSigningProfileFamily`


Local detection/handling phase and implementation owner:

- `ClassicalKeyAlgorithm::validate_profiles` — `src/crypto/signing.rs`. Enclosing match alternative: `_`.


<a id="cause-RsaTransportAlgorithm"></a>

### `RsaTransportAlgorithm`


Local detection/handling phase and implementation owner:

- `PreparedClassicalPair::finish_rsa_transport` — `src/crypto/signing/owned/transport.rs`.


<a id="cause-RsaVerifyFunctionsUnavailable"></a>

### `RsaVerifyFunctionsUnavailable`


Local detection/handling phase and implementation owner:

- `Session::verify_rsa_parts` — `src/crypto/rsa.rs`. Enclosing true branch: `s.native.table.C_VerifyInit.is_none() || s.native.table.C_Verify.is_none()`.


<a id="cause-RustSha1DigestUnavailable"></a>

### `RustSha1DigestUnavailable`


Local detection/handling phase and implementation owner:

- `DsaVerificationHash::software_hash` — `src/crypto/historical.rs`. Enclosing match alternative: `Self::Sha1`.


<a id="cause-SpkiSize"></a>

### `SpkiSize`


Local detection/handling phase and implementation owner:

- `dsa_der` (module-level helper) — `src/crypto/dsa.rs`. Enclosing true branch: `bytes.is_empty()`.
- `rsa_der` (module-level helper) — `src/crypto/integer_key.rs`. Enclosing true branch: `spki_der.is_empty()`.
- `curve_spki` (module-level helper) — `src/crypto/public_key.rs`. Enclosing true branch: `der.is_empty()`.


<a id="cause-ClassicalCreationRequestAbsent"></a>

### `ClassicalCreationRequestAbsent`


Local detection/handling phase and implementation owner:

- `PreparedClassicalPair::generation_request` — `src/crypto/signing/owned.rs`. Enclosing match alternative: `PairSource::Existing { .. }`.
- `ClassicalPairPlan<'_>::generation_identity` — `src/crypto/signing/owned/preparation.rs`.
- `ClassicalPairPlan<'_>::generation_mechanism` — `src/crypto/signing/owned/preparation.rs`.
- `ClassicalPairPlan<'_>::generation_templates_as` — `src/crypto/signing/owned/preparation.rs`.


<a id="cause-ClassicalHistoryOwnerAbsent"></a>

### `ClassicalHistoryOwnerAbsent`


Local detection/handling phase and implementation owner:

- `PreparedClassicalPair::observe_history` — `src/crypto/signing/owned/transport.rs`.


<a id="cause-ClassicalIdentityAllocation"></a>

### `ClassicalIdentityAllocation`


Local detection/handling phase and implementation owner:

- `ClassicalPairPlan<'_>::allocate` — `src/crypto/signing/owned/preparation.rs`. Enclosing match alternative: `ClassicalPairInput::Existing { id, spki, profiles, .. }`.


<a id="cause-ClassicalPairOwnerSizeOverflow"></a>

### `ClassicalPairOwnerSizeOverflow`


Local detection/handling phase and implementation owner:

- `classical_owner_bytes` (module-level helper) — `src/crypto/signing/owned.rs`.


<a id="cause-ClassicalPairPreparationChanged"></a>

### `ClassicalPairPreparationChanged`


Local detection/handling phase and implementation owner:

- `ClassicalPairPlan<'_>::allocated_bytes` — `src/crypto/signing/owned/preparation.rs`. Enclosing match alternative: `_`.
- `ClassicalPairPlan<'_>::prepare_owner` — `src/crypto/signing/owned/preparation.rs`. Enclosing match alternative: `_`.
- `ClassicalPairPlan<'_>::prepare_owner` — `src/crypto/signing/owned/preparation.rs`. Enclosing match alternative: `_`.
- `ClassicalPairPlan<'_>::finish_owner` — `src/crypto/signing/owned/preparation.rs`. Enclosing true branch: `!matches!( (&input.input, &candidate.storage), ( ClassicalPairInput::Existing { .. }, ClassicalBoundStorage::Existing { .. } ) | ( ClassicalPairInput::Generation { .. }, ClassicalBoundStorage::Generation { .. } ) )`.


<a id="cause-ClassicalPrehashStorageAccounting"></a>

### `ClassicalPrehashStorageAccounting`


Local detection/handling phase and implementation owner:

- `accounting` (module-level helper) — `src/crypto/native_signature/prehash.rs`.


<a id="cause-ClassicalProfileAllocation"></a>

### `ClassicalProfileAllocation`


Local detection/handling phase and implementation owner:

- `profile_storage` (module-level helper) — `src/crypto/signing/owned.rs`.
- `ClassicalPairPlan<'_>::allocate` — `src/crypto/signing/owned/preparation.rs`. Enclosing match alternative: `ClassicalPairInput::Existing { id, spki, profiles, .. }`.


<a id="cause-ClassicalProfileCapacityOverflow"></a>

### `ClassicalProfileCapacityOverflow`


Local detection/handling phase and implementation owner:

- `profile_bytes` (module-level helper) — `src/crypto/signing/owned.rs`.
- `signature_profile_bytes` (module-level helper) — `src/crypto/signing/owned.rs`.


<a id="cause-ClassicalPublicObservationsAbsent"></a>

### `ClassicalPublicObservationsAbsent`


Local detection/handling phase and implementation owner:

- `PreparedClassicalPair::public_material` — `src/crypto/signing/owned.rs`. Enclosing match alternative: `PairSource::Generation { public: GeneratedPublic::AwaitingObservation | GeneratedPublic::Preparing(_) | GeneratedPublic::Prepared(_), .. }`.
- `PreparedClassicalPair::validate` — `src/crypto/signing/owned.rs`. Enclosing true branch: `!private && matches!(&self.source, PairSource::Generation { .. })`.
- `PreparedClassicalPair::finish` — `src/crypto/signing/owned.rs`. Enclosing match alternative: `_`.
- `PreparedClassicalPair::commit_transport_result` — `src/crypto/signing/owned/transport.rs`.


<a id="cause-ClassicalPublicRepresentationMismatch"></a>

### `ClassicalPublicRepresentationMismatch`


Local detection/handling phase and implementation owner:

- `ClassicalPublicMaterial::new` — `src/crypto/signing/owned.rs`. Enclosing true branch: `!matches!( (algorithm, observed), ( ClassicalKeyAlgorithm::Rsa { .. }, ClassicalKeyAlgorithm::Rsa { .. } ) ) && observed != algorithm`.


<a id="cause-ClassicalSignaturePreparationDiffers"></a>

### `ClassicalSignaturePreparationDiffers`


Local detection/handling phase and implementation owner:

- `Storage::bind` — `src/crypto/native_signature/storage.rs`. Enclosing true branch: `input > self.input.len() || signature != self.signature.len()`.


<a id="cause-ClassicalSignatureStorageAccounting"></a>

### `ClassicalSignatureStorageAccounting`


Local detection/handling phase and implementation owner:

- `accounting` (module-level helper) — `src/crypto/native_signature/storage.rs`.


<a id="cause-CryptoInputCeilings"></a>

### `CryptoInputCeilings`


Local detection/handling phase and implementation owner:

- `InputLimits::validate_lengths` — `src/crypto.rs`. Enclosing true branch: `self.maximum_parts > module.maximum_parts || self.maximum_total_bytes > module.maximum_total_bytes || count > self.maximum_parts`.


<a id="cause-CryptoInputCountChanged"></a>

### `CryptoInputCountChanged`


Local detection/handling phase and implementation owner:

- `InputLimits::validate_lengths` — `src/crypto.rs`. Enclosing true branch: `observed == count`.
- `InputLimits::validate_lengths` — `src/crypto.rs`. Enclosing true branch: `observed != count`.


<a id="cause-CryptoTotalCeiling"></a>

### `CryptoTotalCeiling`


Local detection/handling phase and implementation owner:

- `InputLimits::validate_lengths` — `src/crypto.rs`. Enclosing true branch: `total > self.maximum_total_bytes`.


<a id="cause-CryptoTotalOverflow"></a>

### `CryptoTotalOverflow`


Local detection/handling phase and implementation owner:

- `InputLimits::validate_lengths` — `src/crypto.rs`.


<a id="cause-CurveOid"></a>

### `CurveOid`


Local detection/handling phase and implementation owner:

- `PublicEncoding<'a>::new` — `src/crypto/signing/public_encoding.rs`.


<a id="cause-DestinationSelectionSize"></a>

### `DestinationSelectionSize`


Local detection/handling phase and implementation owner:

- `retained_object_observation_bytes` (module-level helper) — `src/crypto.rs`.
- `retained_object_observation_bytes` (module-level helper) — `src/crypto.rs`.
- `report_storage` (module-level helper) — `src/advanced/admission/destination.rs`.


<a id="cause-DigestInputChanged"></a>

### `DigestInputChanged`


Local detection/handling phase and implementation owner:

- `Session::native_digest_guarded` — `src/crypto.rs`. Enclosing true branch: `!call.mechanism_unchanged(kind) || &call.input.as_slice()[..expected.len()] != *expected || call.input.as_slice()[expected.len()..] .iter() .any(|byte| *byte != 0)`.
- `Session::native_digest_guarded` — `src/crypto.rs`. Enclosing true branch: `!call.mechanism_unchanged(kind) || call.input.as_slice() != pieces[0]`.


<a id="cause-DigestLength"></a>

### `DigestLength`


Local detection/handling phase and implementation owner:

- `PreparedDigest::from_bytes` — `src/crypto.rs`. Enclosing true branch: `bytes.len() != algorithm.output_length()`.


<a id="cause-DigestMechanismChanged"></a>

### `DigestMechanismChanged`


Local detection/handling phase and implementation owner:

- `Session::native_digest_guarded` — `src/crypto.rs`. Enclosing true branch: `!call.mechanism_unchanged(kind)`.
- `Session::native_digest_guarded` — `src/crypto.rs`. Enclosing true branch: `!call.mechanism_unchanged(kind) || &call.input.as_slice()[..last.len()] != *last || call.input.as_slice()[last.len()..] .iter() .any(|byte| *byte != 0)`.


<a id="cause-DigestOutputLength"></a>

### `DigestOutputLength`

The bytes do not match the selected digest's semantic output length. This
cause is shared by local result conversion and post-native publication:

* `take_budgeted`/selection conversion refuses to move or publish a wrongly
  sized result. Its caller supplies the existing completion/owner evidence.
* The direct digest sequence detects an in-allocation but semantically invalid
  native result; invalid_value preserves the successful completed effect when
  known. It is distinct from an out-of-allocation capacity anomaly.
* The Advanced digest marks its step Failed and returns its prepared completion
  diagnostic after the successful final native call.

No path turns this cause into an output-size query. Do not pad/truncate the
digest, select another algorithm to relabel it, or replay a completed digest.
Preserve the enclosing completion diagnostic and the result/operation owner.


Local detection/handling phase and implementation owner:

- `PreparedDigest::take_budgeted` — `src/crypto.rs`. Enclosing true branch: `bytes.as_slice().len() != algorithm.output_length()`.
- `Session::native_digest_guarded` — `src/crypto.rs`. Enclosing true branch: `length != capacity`.
- `complete_step` (module-level helper) — `src/advanced/digest.rs`. Enclosing true branch: `!op.frame.selection.accepts_length(*op.frame.length as usize)`.
- `DigestSelection::result` — `src/advanced/digest/selection.rs`. Enclosing match alternative: `Self::LegacySha256`.


<a id="cause-GeneratedCurveParameters"></a>

### `GeneratedCurveParameters`


Local detection/handling phase and implementation owner:

- `validate_identity_fields` (module-level helper) — `src/crypto/signing.rs`. Enclosing true branch: `!matches!(algorithm, ClassicalKeyAlgorithm::Rsa { .. }) && values.bytes(CKA_EC_PARAMS)? != algorithm.params(semantics.parameter_encoding)`.


<a id="cause-HashedSignatureFamily"></a>

### `HashedSignatureFamily`


Local detection/handling phase and implementation owner:

- `Session::hashed_sign_native_with_context` — `src/crypto/signing/signatures.rs`. Enclosing match alternative: `_`.


<a id="cause-HistoricalPssParameters"></a>

### `HistoricalPssParameters`


Local detection/handling phase and implementation owner:

- `HistoricalPssParameters::checked` — `src/crypto/historical.rs`. Enclosing true branch: `self.hash != HistoricalHash::Sha1 || self.mgf_hash != HistoricalHash::Sha1`.


<a id="cause-HistoricalDigestProfile"></a>

### `HistoricalDigestProfile`


Local detection/handling phase and implementation owner:

- `Session::verify_historical_digest` — `src/crypto/historical.rs`. Enclosing true branch: `profile.hash() != Some(digest.algorithm)`.


<a id="cause-HistoricalDigestUnavailableInRustEngine"></a>

### `HistoricalDigestUnavailableInRustEngine`


Local detection/handling phase and implementation owner:

- `HistoricalProfile::software_hash` — `src/crypto/historical.rs`. Enclosing match alternative: `_`.


<a id="cause-HistoricalDigestWidth"></a>

### `HistoricalDigestWidth`


Local detection/handling phase and implementation owner:

- `HistoricalDigest::from_bytes` — `src/crypto/historical.rs`. Enclosing true branch: `bytes.len() != algorithm.output_length()`.


<a id="cause-HistoricalPreparedDigestLength"></a>

### `HistoricalPreparedDigestLength`


Local detection/handling phase and implementation owner:

- `HistoricalProfile::digest_input_into` — `src/crypto/historical.rs`. Enclosing true branch: `target.len() != bytes.len()`.


<a id="cause-HistoricalVerificationFunctionsUnavailable"></a>

### `HistoricalVerificationFunctionsUnavailable`


Local detection/handling phase and implementation owner:

- `Session::verify_historical_parts` — `src/crypto/historical.rs`. Enclosing true branch: `s.native.table.C_VerifyInit.is_none() || s.native.table.C_Verify.is_none()`.


<a id="cause-MessageRsaSigningKeyRequired"></a>

### `MessageRsaSigningKeyRequired`


Local detection/handling phase and implementation owner:

- `SigningKey::message_pss_bits` — `src/crypto/signing.rs`.


<a id="cause-NativeDigestCapacity"></a>

### `NativeDigestCapacity`


Local detection/handling phase and implementation owner:

- `Session::native_digest_guarded` — `src/crypto.rs`. Enclosing true branch: `rv == fe11_sys::CKR_OK`.
- `Session::native_digest_guarded` — `src/crypto.rs`. Enclosing true branch: `rv == fe11_sys::CKR_OK`.
- `Session::native_digest_guarded` — `src/crypto.rs`.


<a id="cause-NativeDigestPreparationChanged"></a>

### `NativeDigestPreparationChanged`


Local detection/handling phase and implementation owner:

- `Session::native_digest_guarded` — `src/crypto.rs`. Enclosing true branch: `!prepared.mechanism_unchanged(kind) || prepared.input.len() != input_capacity || prepared.output.len() != capacity || prepared.length != bounds::ck_length(capacity)?`.


<a id="cause-NativeDigestStorageAccounting"></a>

### `NativeDigestStorageAccounting`


Local detection/handling phase and implementation owner:

- `accounting` (module-level helper) — `src/crypto/native_digest.rs`.


<a id="cause-NativePointDer"></a>

### `NativePointDer`


Local detection/handling phase and implementation owner:

- `PublicEncoding<'a>::new` — `src/crypto/signing/public_encoding.rs`. Enclosing true branch: `algorithm.curve().is_some() || semantics.point_encoding == crate::EdwardsPointEncoding::DerOctetString`.


<a id="cause-NativePointEncoding"></a>

### `NativePointEncoding`


Local detection/handling phase and implementation owner:

- `PublicEncoding<'a>::new` — `src/crypto/signing/public_encoding.rs`. Enclosing true branch: `algorithm.curve().is_some() || semantics.point_encoding == crate::EdwardsPointEncoding::DerOctetString`.


<a id="cause-NativeSignatureEncoding"></a>

### `NativeSignatureEncoding`


Local detection/handling phase and implementation owner:

- `Session::sign_native_frame` — `src/crypto/native_signature.rs`. Enclosing true branch: `length != call.signature.len() || !encoding.valid(call.signature.as_slice())`.


<a id="cause-NativeSignatureOutputLength"></a>

### `NativeSignatureOutputLength`

Detected after the native signature return succeeded but its length is outside
the provided allocation. Sequence::invalid_output records uncertain completion
and marks the runtime uncertain. No signature is published and this cause is not
a negotiated capacity request. Keep the enclosing session/sequence recovery state;
do not allocate from the untrusted length and repeat Sign. Explicit cleanup must
meet its own native-completion conditions; no automatic retry is established.


Local detection/handling phase and implementation owner:

- `Session::sign_native_frame` — `src/crypto/native_signature.rs`. Enclosing true branch: `rv == CKR_OK`.
- `Session::sign_native_frame` — `src/crypto/native_signature.rs`.


<a id="cause-NoncanonicalDsaSpki"></a>

### `NoncanonicalDsaSpki`


Local detection/handling phase and implementation owner:

- `dsa_der` (module-level helper) — `src/crypto/dsa.rs`. Enclosing true branch: `!super::canonical::matches(&spki, bytes).map_err(|_| { Error::Rejected(crate::RejectionReason::ClassicalSignatures( crate::ClassicalSignaturesRejection::DsaSpkiEncoding, )) })?`.


<a id="cause-NoncanonicalDsaPublicValue"></a>

### `NoncanonicalDsaPublicValue`


Local detection/handling phase and implementation owner:

- `dsa_der` (module-level helper) — `src/crypto/dsa.rs`. Enclosing true branch: `!super::canonical::matches(&y, raw).map_err(|_| { Error::Rejected(crate::RejectionReason::ClassicalSignatures( crate::ClassicalSignaturesRejection::DsaPublicEncoding, )) })?`.


<a id="cause-NoncanonicalDsaSignature"></a>

### `NoncanonicalDsaSignature`


Local detection/handling phase and implementation owner:

- `VerificationKey::dsa_signature_from_der` — `src/crypto/signature_encoding.rs`. Enclosing true branch: `!super::canonical::matches(&scalars, bytes).map_err(|_| { Error::Rejected(crate::RejectionReason::ClassicalSignatures( crate::ClassicalSignaturesRejection::DsaSignatureEncoding, )) })?`.


<a id="cause-NoncanonicalEcdsaDer"></a>

### `NoncanonicalEcdsaDer`


Local detection/handling phase and implementation owner:

- `from_der` (module-level helper) — `src/crypto/signature_encoding.rs`. Enclosing true branch: `!super::canonical::matches(&scalars, der).map_err(|_| { Error::Rejected(crate::RejectionReason::ClassicalSignatures( crate::ClassicalSignaturesRejection::EcdsaDerEncoding, )) })?`.


<a id="cause-NoncanonicalNativePoint"></a>

### `NoncanonicalNativePoint`


Local detection/handling phase and implementation owner:

- `PublicEncoding<'a>::new` — `src/crypto/signing/public_encoding.rs`. Enclosing true branch: `!crate::crypto::canonical::matches(&point, encoded).map_err(|_| { Error::Rejected(crate::RejectionReason::ClassicalSignatures( crate::ClassicalSignaturesRejection::NativePointEncoding, )) })?`.


<a id="cause-NotADsaReference"></a>

### `NotADsaReference`


Local detection/handling phase and implementation owner:

- `Session::historical_gate` — `src/crypto/historical.rs`. Enclosing match alternative: `HistoricalProfile::Dsa(_)`.
- `VerificationKey::dsa_signature_from_der` — `src/crypto/signature_encoding.rs`.
- `VerificationKey::dsa_signature_to_der` — `src/crypto/signature_encoding.rs`.


<a id="cause-NotAnEcdsaReference"></a>

### `NotAnEcdsaReference`


Local detection/handling phase and implementation owner:

- `Session::ecdsa_gate` — `src/crypto/ecdsa.rs`.
- `Session::historical_gate` — `src/crypto/historical.rs`. Enclosing match alternative: `HistoricalProfile::EcdsaSha1`.
- `VerificationKey::ecdsa_signature_to_der` — `src/crypto/signature_encoding.rs`.
- `VerificationKey::ecdsa_signature_from_der` — `src/crypto/signature_encoding.rs`.


<a id="cause-NotAnRsaReference"></a>

### `NotAnRsaReference`


Local detection/handling phase and implementation owner:

- `Session::historical_gate` — `src/crypto/historical.rs`. Enclosing match alternative: `_`.
- `Session::rsa_reference_handle` — `src/crypto/rsa.rs`.


<a id="cause-ObjectControlByteCount"></a>

### `ObjectControlByteCount`


Local detection/handling phase and implementation owner:

- `retained_object_observation_bytes` (module-level helper) — `src/crypto.rs`.


<a id="cause-PairObjectControlByteCount"></a>

### `PairObjectControlByteCount`


Local detection/handling phase and implementation owner:

- `retained_object_observation_bytes` (module-level helper) — `src/crypto.rs`. Enclosing true branch: `self.is_pair()`.


<a id="cause-PreparedDigestEncodingLength"></a>

### `PreparedDigestEncodingLength`


Local detection/handling phase and implementation owner:

- `SigningRequest::encode_digest_into` — `src/crypto/signing.rs`. Enclosing true branch: `target.len() != digest.as_bytes().len()`.


<a id="cause-PublicPointBitString"></a>

### `PublicPointBitString`


Local detection/handling phase and implementation owner:

- `PublicEncoding<'a>::new` — `src/crypto/signing/public_encoding.rs`.


<a id="cause-RestoredSigningHistoryReportAbsent"></a>

### `RestoredSigningHistoryReportAbsent`


Local detection/handling phase and implementation owner:

- `PreparedSigningRestore<'_>::finish_observed` — `src/crypto/signing/introduced.rs`.


<a id="cause-RestoredSigningMechanismReportAbsent"></a>

### `RestoredSigningMechanismReportAbsent`


Local detection/handling phase and implementation owner:

- `PreparedSigningRestore<'_>::finish_observed` — `src/crypto/signing/introduced.rs`.


<a id="cause-SignatureCompletionUnproven"></a>

### `SignatureCompletionUnproven`


Local detection/handling phase and implementation owner:

- `Session::sign_native_frame` — `src/crypto/native_signature.rs`. Enclosing true branch: `!sequence.termination_known()`.


<a id="cause-SignatureHasNoDerConversion"></a>

### `SignatureHasNoDerConversion`


Local detection/handling phase and implementation owner:

- `ClassicalSignature::to_der` — `src/crypto/signing.rs`. Enclosing match alternative: `_`.


<a id="cause-SignatureInputChanged"></a>

### `SignatureInputChanged`


Local detection/handling phase and implementation owner:

- `Session::sign_native_frame` — `src/crypto/native_signature.rs`. Enclosing true branch: `!call.mechanism.unchanged(kind, parameters) || !call.input_unchanged(expected)`.
- `Session::sign_native_frame` — `src/crypto/native_signature.rs`. Enclosing true branch: `!call.mechanism.unchanged(kind, parameters) || !call.input_unchanged(last)`.


<a id="cause-SignatureParametersChanged"></a>

### `SignatureParametersChanged`


Local detection/handling phase and implementation owner:

- `Session::sign_native_frame` — `src/crypto/native_signature.rs`. Enclosing true branch: `!call.mechanism.unchanged(kind, parameters)`.


<a id="cause-SignatureParametersChangedDuringContextAuthentication"></a>

### `SignatureParametersChangedDuringContextAuthentication`


Local detection/handling phase and implementation owner:

- `Session::sign_native_frame` — `src/crypto/native_signature.rs`. Enclosing true branch: `!call.mechanism.unchanged(kind, parameters)`.


<a id="cause-SigningFunctionsUnavailable"></a>

### `SigningFunctionsUnavailable`


Local detection/handling phase and implementation owner:

- `Session::sign_classical_parts_with_context` — `src/crypto/signing/signatures.rs`. Enclosing true branch: `s.native.table.C_SignInit.is_none() || missing_sign`.


<a id="cause-SigningIntroductionReportAbsent"></a>

### `SigningIntroductionReportAbsent`


Local detection/handling phase and implementation owner:

- `Session::import_signing_key_selected` — `src/crypto/signing/introduced.rs`.


<a id="cause-SigningProfileFamily"></a>

### `SigningProfileFamily`


Local detection/handling phase and implementation owner:

- `ClassicalKeyAlgorithm::validate_profiles` — `src/crypto/signing.rs`. Enclosing true branch: `!valid`.


<a id="cause-SigningProfilesAlreadyPublished"></a>

### `SigningProfilesAlreadyPublished`


Local detection/handling phase and implementation owner:

- `PreparedClassicalPair::finish_private` — `src/crypto/signing/owned.rs`.
- `PreparedClassicalPair::finish_transport` — `src/crypto/signing/owned/transport.rs`.


<a id="cause-SinglePartDigestRequiresOneInput"></a>

### `SinglePartDigestRequiresOneInput`


Local detection/handling phase and implementation owner:

- `Session::native_digest_guarded` — `src/crypto.rs`. Enclosing true branch: `!multipart && parts.len() != 1`.
- `Plan::new` — `src/crypto/native_digest.rs`. Enclosing true branch: `!multipart && parts.len() != 1`.


<a id="cause-TransportHistoryAbsent"></a>

### `TransportHistoryAbsent`


Local detection/handling phase and implementation owner:

- `PreparedClassicalPair::prepare_transport_report` — `src/crypto/signing/owned/transport.rs`.


<a id="cause-TransportHistoryOwnerAbsent"></a>

### `TransportHistoryOwnerAbsent`


Local detection/handling phase and implementation owner:

- `PreparedClassicalPair::commit_transport_result` — `src/crypto/signing/owned/transport.rs`.


<a id="cause-TransportPublicationAbsent"></a>

### `TransportPublicationAbsent`


Local detection/handling phase and implementation owner:

- `PreparedClassicalPair::prepare_transport_report` — `src/crypto/signing/owned/transport.rs`.
- `PreparedClassicalPair::commit_transport_result` — `src/crypto/signing/owned/transport.rs`. Enclosing true branch: `material.transport.is_none()`.


<a id="cause-VerificationCompletionUnproven"></a>

### `VerificationCompletionUnproven`


Local detection/handling phase and implementation owner:

- `Session::verify_native_mechanism` — `src/crypto/ecdsa.rs`. Enclosing true branch: `!sequence.termination_known()`.


<a id="cause-VerificationInputChanged"></a>

### `VerificationInputChanged`


Local detection/handling phase and implementation owner:

- `Session::verify_native_mechanism` — `src/crypto/ecdsa.rs`. Enclosing true branch: `!call.mechanism.unchanged(kind, parameters) || !call.input_unchanged(expected)`.
- `Session::verify_native_mechanism` — `src/crypto/ecdsa.rs`. Enclosing true branch: `!call.mechanism.unchanged(kind, parameters) || !call.input_unchanged(last) || call.signature.as_slice() != signature`.


<a id="cause-VerificationParametersChanged"></a>

### `VerificationParametersChanged`


Local detection/handling phase and implementation owner:

- `Session::verify_native_mechanism` — `src/crypto/ecdsa.rs`. Enclosing true branch: `!call.mechanism.unchanged(kind, parameters)`.


<a id="cause-VerificationProfilesAlreadyPublished"></a>

### `VerificationProfilesAlreadyPublished`


Local detection/handling phase and implementation owner:

- `PreparedClassicalPair::finish` — `src/crypto/signing/owned.rs`.


<a id="cause-VerificationSelectorPublicIdentity"></a>

### `VerificationSelectorPublicIdentity`


Local detection/handling phase and implementation owner:

- `EdwardsParameterEncoding::read` — `src/crypto/edwards_options.rs`.
- `Admission::finish_terminal` — `src/advanced/admission/publication.rs`. Enclosing true branch: `let Err(cause) = result`.

