Cause contracts for `KeyEncodingRejection`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-EcCurveEncoding"></a>

### `EcCurveEncoding`


Local detection/handling phase and implementation owner:

- `curve_spki` (module-level helper) — `src/crypto/public_key.rs`. Enclosing match alternative: `oid if oid == ObjectIdentifier::new_unwrap("1.2.840.10045.2.1")`.


<a id="cause-EcCurveOutsideCatalogue"></a>

### `EcCurveOutsideCatalogue`


Local detection/handling phase and implementation owner:

- `curve_spki` (module-level helper) — `src/crypto/public_key.rs`. Enclosing match alternative: `oid if oid == ObjectIdentifier::new_unwrap("1.2.840.10045.2.1")`.


<a id="cause-EcNamedCurveRequired"></a>

### `EcNamedCurveRequired`


Local detection/handling phase and implementation owner:

- `curve_spki` (module-level helper) — `src/crypto/public_key.rs`. Enclosing match alternative: `oid if oid == ObjectIdentifier::new_unwrap("1.2.840.10045.2.1")`.


<a id="cause-EcParameters"></a>

### `EcParameters`


Local detection/handling phase and implementation owner:

- `curve_spki` (module-level helper) — `src/crypto/public_key.rs`. Enclosing match alternative: `oid if oid == ObjectIdentifier::new_unwrap("1.2.840.10045.2.1")`.


<a id="cause-EcPublicEncoding"></a>

### `EcPublicEncoding`


Local detection/handling phase and implementation owner:

- `validate_weierstrass_encoding` (module-level helper) — `src/crypto/public_key.rs`. Enclosing true branch: `encoded.len() != 1 + 2 * curve.domain().width || encoded.first() != Some(&4)`.


<a id="cause-Ed25519PublicWidth"></a>

### `Ed25519PublicWidth`


Local detection/handling phase and implementation owner:

- `validate_edwards_encoding` (module-level helper) — `src/crypto/public_key.rs`. Enclosing match alternative: `EdwardsCurve::Ed25519`.


<a id="cause-Ed448PublicWidth"></a>

### `Ed448PublicWidth`


Local detection/handling phase and implementation owner:

- `validate_edwards_encoding` (module-level helper) — `src/crypto/public_key.rs`. Enclosing match alternative: `EdwardsCurve::Ed448`.


<a id="cause-EdwardsParametersMustBeAbsent"></a>

### `EdwardsParametersMustBeAbsent`


Local detection/handling phase and implementation owner:

- `curve_spki` (module-level helper) — `src/crypto/public_key.rs`. Enclosing true branch: `spki.algorithm.parameters.is_some()`.


<a id="cause-RsaNullParametersRequired"></a>

### `RsaNullParametersRequired`


Local detection/handling phase and implementation owner:

- `rsa_der` (module-level helper) — `src/crypto/integer_key.rs`.


<a id="cause-RsaSpkiDer"></a>

### `RsaSpkiDer`


Local detection/handling phase and implementation owner:

- `rsa_der` (module-level helper) — `src/crypto/integer_key.rs`.


<a id="cause-RsaSpkiAlgorithm"></a>

### `RsaSpkiAlgorithm`


Local detection/handling phase and implementation owner:

- `rsa_der` (module-level helper) — `src/crypto/integer_key.rs`. Enclosing true branch: `spki.algorithm.oid != ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1")`.


<a id="cause-RsaSpkiEncoding"></a>

### `RsaSpkiEncoding`


Local detection/handling phase and implementation owner:

- `rsa_der` (module-level helper) — `src/crypto/integer_key.rs`.


<a id="cause-RsaExponentEncoding"></a>

### `RsaExponentEncoding`


Local detection/handling phase and implementation owner:

- `RsaSpki<'a>::new` — `src/crypto/integer_key/encoding.rs`.


<a id="cause-RsaModulusEncoding"></a>

### `RsaModulusEncoding`


Local detection/handling phase and implementation owner:

- `RsaSpki<'a>::new` — `src/crypto/integer_key/encoding.rs`.


<a id="cause-RsaParameters"></a>

### `RsaParameters`


Local detection/handling phase and implementation owner:

- `rsa_der` (module-level helper) — `src/crypto/integer_key.rs`.


<a id="cause-RsaPublicDer"></a>

### `RsaPublicDer`


Local detection/handling phase and implementation owner:

- `rsa_der` (module-level helper) — `src/crypto/integer_key.rs`.


<a id="cause-RsaPublicEncoding"></a>

### `RsaPublicEncoding`


Local detection/handling phase and implementation owner:

- `rsa_der` (module-level helper) — `src/crypto/integer_key.rs`.


<a id="cause-RsaUnusedBits"></a>

### `RsaUnusedBits`


Local detection/handling phase and implementation owner:

- `rsa_der` (module-level helper) — `src/crypto/integer_key.rs`.


<a id="cause-SpkiDer"></a>

### `SpkiDer`


Local detection/handling phase and implementation owner:

- `curve_spki` (module-level helper) — `src/crypto/public_key.rs`.


<a id="cause-SpkiEncoding"></a>

### `SpkiEncoding`


Local detection/handling phase and implementation owner:

- `curve_spki` (module-level helper) — `src/crypto/public_key.rs`.


<a id="cause-SpkiUnusedBits"></a>

### `SpkiUnusedBits`


Local detection/handling phase and implementation owner:

- `curve_spki` (module-level helper) — `src/crypto/public_key.rs`.


<a id="cause-CurveSpkiAlgorithm"></a>

### `CurveSpkiAlgorithm`


Local detection/handling phase and implementation owner:

- `curve_spki` (module-level helper) — `src/crypto/public_key.rs`. Enclosing match alternative: `_`.


<a id="cause-KeyEvidenceAllocation"></a>

### `KeyEvidenceAllocation`


Local detection/handling phase and implementation owner:

- `Initial::allocate` — `src/crypto/key_evidence.rs`.
- `Initial::allocate` — `src/crypto/key_evidence.rs`.


<a id="cause-KeyEvidenceCompletionPhase"></a>

### `KeyEvidenceCompletionPhase`


Local detection/handling phase and implementation owner:

- `Owner::advance` — `src/crypto/key_evidence.rs`. Enclosing match alternative: `_`.


<a id="cause-KeyEvidenceIdentityAbsent"></a>

### `KeyEvidenceIdentityAbsent`


Local detection/handling phase and implementation owner:

- `Initial::allocate` — `src/crypto/key_evidence.rs`. Enclosing true branch: `fields.is_empty()`.


<a id="cause-KeyEvidenceIncomplete"></a>

### `KeyEvidenceIncomplete`


Local detection/handling phase and implementation owner:

- `Owner::result` — `src/crypto/key_evidence.rs`. Enclosing match alternative: `_`.


<a id="cause-KeyEvidenceMechanismRecipeAbsent"></a>

### `KeyEvidenceMechanismRecipeAbsent`


Local detection/handling phase and implementation owner:

- `Owner::after_history` — `src/crypto/key_evidence.rs`. Enclosing match alternative: `Some(storage)`.
- `Owner::begin_evidence` — `src/crypto/key_evidence.rs`. Enclosing match alternative: `Some(storage)`.


<a id="cause-KeyEvidencePhase"></a>

### `KeyEvidencePhase`


Local detection/handling phase and implementation owner:

- `Owner::attach` — `src/crypto/key_evidence.rs`. Enclosing match alternative: `_`.


<a id="cause-KeyEvidenceStopped"></a>

### `KeyEvidenceStopped`


Local detection/handling phase and implementation owner:

- `Owner::advance` — `src/crypto/key_evidence.rs`. Enclosing match alternative: `Phase::Stopped`.


<a id="cause-KeyEvidenceStorageSize"></a>

### `KeyEvidenceStorageSize`


Local detection/handling phase and implementation owner:

- `add` (module-level helper) — `src/crypto/key_evidence.rs`.
- `identity_bytes` (module-level helper) — `src/crypto/key_evidence.rs`.
- `field_bytes` (module-level helper) — `src/crypto/key_evidence.rs`.


<a id="cause-MultiPrimeRsaUnsupported"></a>

### `MultiPrimeRsaUnsupported`


Local detection/handling phase and implementation owner:

- `parse_pkcs8` (module-level helper) — `src/crypto/private_material.rs`. Enclosing true branch: `rsa.version != 0`.


<a id="cause-NoncanonicalRsaSpki"></a>

### `NoncanonicalRsaSpki`


Local detection/handling phase and implementation owner:

- `rsa_der` (module-level helper) — `src/crypto/integer_key.rs`. Enclosing true branch: `!super::canonical::matches(&spki, spki_der).map_err(|_| { Error::Rejected(crate::RejectionReason::KeyEncoding( crate::KeyEncodingRejection::RsaSpkiEncoding, )) })?`.


<a id="cause-NoncanonicalRsaPublicKey"></a>

### `NoncanonicalRsaPublicKey`


Local detection/handling phase and implementation owner:

- `rsa_der` (module-level helper) — `src/crypto/integer_key.rs`. Enclosing true branch: `!super::canonical::matches(&key, raw).map_err(|_| { Error::Rejected(crate::RejectionReason::KeyEncoding( crate::KeyEncodingRejection::RsaPublicEncoding, )) })?`.


<a id="cause-NoncanonicalSpki"></a>

### `NoncanonicalSpki`


Local detection/handling phase and implementation owner:

- `curve_spki` (module-level helper) — `src/crypto/public_key.rs`. Enclosing true branch: `!super::canonical::matches(&spki, der).map_err(|_| { Error::Rejected(crate::RejectionReason::KeyEncoding( crate::KeyEncodingRejection::SpkiEncoding, )) })?`.


<a id="cause-PrivateEcDer"></a>

### `PrivateEcDer`


Local detection/handling phase and implementation owner:

- `parse_pkcs8` (module-level helper) — `src/crypto/private_material.rs`. Enclosing match alternative: `ClassicalKeyAlgorithm::Ecdsa(_)`.


<a id="cause-PrivateEcAlgorithm"></a>

### `PrivateEcAlgorithm`


Local detection/handling phase and implementation owner:

- `parse_pkcs8` (module-level helper) — `src/crypto/private_material.rs`. Enclosing true branch: `key.algorithm.oid != EC`.


<a id="cause-PrivateEcNamedCurveAbsent"></a>

### `PrivateEcNamedCurveAbsent`


Local detection/handling phase and implementation owner:

- `parse_pkcs8` (module-level helper) — `src/crypto/private_material.rs`. Enclosing match alternative: `ClassicalKeyAlgorithm::Ecdsa(_)`.


<a id="cause-PrivateEcParameters"></a>

### `PrivateEcParameters`


Local detection/handling phase and implementation owner:

- `parse_pkcs8` (module-level helper) — `src/crypto/private_material.rs`. Enclosing match alternative: `ClassicalKeyAlgorithm::Ecdsa(_)`.


<a id="cause-PrivateEcVersion"></a>

### `PrivateEcVersion`


Local detection/handling phase and implementation owner:

- `parse_pkcs8` (module-level helper) — `src/crypto/private_material.rs`. Enclosing true branch: `ec.version != 1`.


<a id="cause-PrivateEdwardsAlgorithm"></a>

### `PrivateEdwardsAlgorithm`


Local detection/handling phase and implementation owner:

- `parse_pkcs8` (module-level helper) — `src/crypto/private_material.rs`. Enclosing match alternative: `_`.


<a id="cause-PrivateEdwardsNestedOctetString"></a>

### `PrivateEdwardsNestedOctetString`


Local detection/handling phase and implementation owner:

- `parse_pkcs8` (module-level helper) — `src/crypto/private_material.rs`. Enclosing match alternative: `ClassicalKeyAlgorithm::Ed25519 | ClassicalKeyAlgorithm::Ed448`.


<a id="cause-PrivateEdwardsParameters"></a>

### `PrivateEdwardsParameters`


Local detection/handling phase and implementation owner:

- `parse_pkcs8` (module-level helper) — `src/crypto/private_material.rs`. Enclosing true branch: `key.algorithm.parameters.is_some()`.


<a id="cause-PrivateEdwardsSeedLength"></a>

### `PrivateEdwardsSeedLength`


Local detection/handling phase and implementation owner:

- `parse_pkcs8` (module-level helper) — `src/crypto/private_material.rs`. Enclosing true branch: `seed.as_bytes().len() != width`.


<a id="cause-PrivatePkcs8Der"></a>

### `PrivatePkcs8Der`


Local detection/handling phase and implementation owner:

- `parse_pkcs8` (module-level helper) — `src/crypto/private_material.rs`.


<a id="cause-PrivatePkcs8Size"></a>

### `PrivatePkcs8Size`


Local detection/handling phase and implementation owner:

- `parse_pkcs8` (module-level helper) — `src/crypto/private_material.rs`. Enclosing true branch: `bytes.is_empty() || input_bytes > maximum_input_bytes`.


<a id="cause-PrivatePkcs8Version"></a>

### `PrivatePkcs8Version`


Local detection/handling phase and implementation owner:

- `parse_pkcs8` (module-level helper) — `src/crypto/private_material.rs`. Enclosing true branch: `key.version != 0`.


<a id="cause-PrivateRsaDer"></a>

### `PrivateRsaDer`


Local detection/handling phase and implementation owner:

- `parse_pkcs8` (module-level helper) — `src/crypto/private_material.rs`. Enclosing match alternative: `ClassicalKeyAlgorithm::Rsa { .. }`.


<a id="cause-PrivateRsaParameters"></a>

### `PrivateRsaParameters`


Local detection/handling phase and implementation owner:

- `parse_pkcs8` (module-level helper) — `src/crypto/private_material.rs`. Enclosing match alternative: `ClassicalKeyAlgorithm::Rsa { .. }`.


<a id="cause-PrivateRsaParametersAbsent"></a>

### `PrivateRsaParametersAbsent`


Local detection/handling phase and implementation owner:

- `parse_pkcs8` (module-level helper) — `src/crypto/private_material.rs`. Enclosing match alternative: `ClassicalKeyAlgorithm::Rsa { .. }`.


<a id="cause-PrivateRsaProfile"></a>

### `PrivateRsaProfile`


Local detection/handling phase and implementation owner:

- `parse_pkcs8` (module-level helper) — `src/crypto/private_material.rs`. Enclosing true branch: `key.algorithm.oid != RSA`.


<a id="cause-PrivateInputAllocationSize"></a>

### `PrivateInputAllocationSize`


Local detection/handling phase and implementation owner:

- `PreparedPrivateInput::allocation_bytes` — `src/crypto/private_material.rs`.


<a id="cause-PrivateInputAlreadyCharged"></a>

### `PrivateInputAlreadyCharged`


Local detection/handling phase and implementation owner:

- `PreparedPrivateInput::charge_with` — `src/crypto/private_material.rs`. Enclosing true branch: `self.credit.get().is_some()`.
- `PreparedPrivateInput::charge_with` — `src/crypto/private_material.rs`.


<a id="cause-PrivateInputSizeOverflow"></a>

### `PrivateInputSizeOverflow`


Local detection/handling phase and implementation owner:

- `parse_pkcs8` (module-level helper) — `src/crypto/private_material.rs`.


<a id="cause-PublicDerAllocation"></a>

### `PublicDerAllocation`


Local detection/handling phase and implementation owner:

- `PublicDerStorage::allocate` — `src/crypto/integer_key.rs`.
- `PublicDerStorage::encode` — `src/crypto/integer_key.rs`. Enclosing true branch: `length > self.bytes.capacity()`.
- `PublicDerStorage::bind` — `src/crypto/integer_key.rs`. Enclosing true branch: `source.len() > self.bytes.capacity()`.


<a id="cause-PublicDerEncoding"></a>

### `PublicDerEncoding`


Local detection/handling phase and implementation owner:

- `PublicDerStorage::encode` — `src/crypto/integer_key.rs`.


<a id="cause-PublicDerLength"></a>

### `PublicDerLength`


Local detection/handling phase and implementation owner:

- `PublicDerStorage::encode` — `src/crypto/integer_key.rs`.
- `PublicDerStorage::encode` — `src/crypto/integer_key.rs`. Enclosing true branch: `encoded.len() != length`.
- `PublicDerCandidate::encode` — `src/crypto/integer_key.rs`.
- `Owner::advance` — `src/crypto/rsa_observation.rs`. Enclosing match alternative: `Phase::Public(read)`.
- `Owner::advance` — `src/objects/pair_observation.rs`. Enclosing match alternative: `Phase::Private { public, read }`.
- `PublicEncoding<'a>::length` — `src/crypto/signing/public_encoding.rs`.


<a id="cause-PublicDerWidth"></a>

### `PublicDerWidth`


Local detection/handling phase and implementation owner:

- `PublicDerStorage::encode` — `src/crypto/integer_key.rs`.
- `PublicDerCandidate::prepare_retaining` — `src/crypto/integer_key.rs`.
- `PublicDerCandidate::prepare_retaining` — `src/crypto/integer_key.rs`. Enclosing true branch: `let Some((public, private)) = &copies`.
- `PublicDerCandidate::encode` — `src/crypto/integer_key.rs`.
- `Owner::advance` — `src/crypto/rsa_observation.rs`. Enclosing match alternative: `Phase::Public(read)`.
- `Owner::advance` — `src/objects/pair_observation.rs`. Enclosing match alternative: `Phase::Private { public, read }`.
- `PublicEncoding<'a>::length` — `src/crypto/signing/public_encoding.rs`.


<a id="cause-PublicImportMechanismRecipeAbsent"></a>

### `PublicImportMechanismRecipeAbsent`


Local detection/handling phase and implementation owner:

- `Owner::advance` — `src/crypto/public_import/observation.rs`. Enclosing true branch: `let Some(read) = self.mechanisms.take()`.


<a id="cause-PublicImportMetadataLength"></a>

### `PublicImportMetadataLength`


Local detection/handling phase and implementation owner:

- `PublicImportMetadata::plan_with_fingerprint` — `src/public_key_import.rs`.
- `ByteParts<'a>::joined` — `src/attributes/byte_parts.rs`.


<a id="cause-PublicImportObservationAllocation"></a>

### `PublicImportObservationAllocation`


Local detection/handling phase and implementation owner:

- `copy` (module-level helper) — `src/crypto/public_import/observation.rs`.


<a id="cause-PublicImportObservationCompletionPhase"></a>

### `PublicImportObservationCompletionPhase`


Local detection/handling phase and implementation owner:

- `Owner::advance` — `src/crypto/public_import/observation.rs`. Enclosing match alternative: `_`.


<a id="cause-PublicImportObservationFieldsAbsent"></a>

### `PublicImportObservationFieldsAbsent`


Local detection/handling phase and implementation owner:

- `Initial::allocate` — `src/crypto/public_import/observation.rs`. Enclosing true branch: `description.identity.is_empty()`.


<a id="cause-PublicImportObservationIncomplete"></a>

### `PublicImportObservationIncomplete`


Local detection/handling phase and implementation owner:

- `Owner::result` — `src/crypto/public_import/observation.rs`. Enclosing match alternative: `_`.


<a id="cause-PublicImportObservationPhase"></a>

### `PublicImportObservationPhase`


Local detection/handling phase and implementation owner:

- `Owner::attach` — `src/crypto/public_import/observation.rs`. Enclosing match alternative: `_`.


<a id="cause-PublicImportObservationStopped"></a>

### `PublicImportObservationStopped`


Local detection/handling phase and implementation owner:

- `Owner::advance` — `src/crypto/public_import/observation.rs`. Enclosing match alternative: `Phase::Stopped`.


<a id="cause-PublicImportObservationStorageSize"></a>

### `PublicImportObservationStorageSize`


Local detection/handling phase and implementation owner:

- `add` (module-level helper) — `src/crypto/public_import/observation.rs`.


<a id="cause-PublicPublicationPreparationPairing"></a>

### `PublicPublicationPreparationPairing`


Local detection/handling phase and implementation owner:

- `Plan<'_>::bind` — `src/crypto/public_import/publication.rs`. Enclosing match alternative: `_`.
- `create_public_prepared` (module-level helper) — `src/managed/mutations/create/resident/public.rs`. Enclosing match alternative: `_`.


<a id="cause-UnsignedIntegerBitLength"></a>

### `UnsignedIntegerBitLength`


Local detection/handling phase and implementation owner:

- `bit_length` (module-level helper) — `src/crypto/integer_key.rs`.
