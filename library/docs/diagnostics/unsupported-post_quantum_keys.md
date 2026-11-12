Cause contracts for `PostQuantumKeysUnsupported`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-CCreateObjectUnavailable"></a>

### `CCreateObjectUnavailable`


Local detection/handling phase and implementation owner:

- `Session::import_pqc_private_key` — `src/crypto/pqc_material/import.rs`.


<a id="cause-Pkcs1132ExternalShakePrehashHasNoStandardizedHashIdentifier"></a>

### `Pkcs1132ExternalShakePrehashHasNoStandardizedHashIdentifier`


Local detection/handling phase and implementation owner:

- `PqcHash::digest_mechanism` — `src/crypto/pqc/hash.rs`. Enclosing match alternative: `Self::Shake128 | Self::Shake256`.


<a id="cause-Pkcs1132HasNoCombinedPqcSignatureForTruncatedSha512"></a>

### `Pkcs1132HasNoCombinedPqcSignatureForTruncatedSha512`


Local detection/handling phase and implementation owner:

- `PqcHash::combined_mechanisms` — `src/crypto/pqc/hash.rs`. Enclosing match alternative: `Self::Sha512_224 | Self::Sha512_256`.


<a id="cause-Pkcs11PqcExternalPrehashIsSinglePartOnly"></a>

### `Pkcs11PqcExternalPrehashIsSinglePartOnly`


Local detection/handling phase and implementation owner:

- `multipart_mode` (module-level helper) — `src/crypto/pqc/multipart.rs`. Enclosing match alternative: `PqcSignatureMode::Prehashed(_)`.
- `Input<'a>::validate` — `src/crypto/pqc/verify_signature.rs`. Enclosing true branch: `matches!(parameters.mode(), PqcSignatureMode::Prehashed(_))`.


<a id="cause-PqcPrivateRepresentationFamilyOrParameter"></a>

### `PqcPrivateRepresentationFamilyOrParameter`


Local detection/handling phase and implementation owner:

- `PqcPrivateKeyAlgorithm::from_native` — `src/crypto/pqc_material.rs`. Enclosing match alternative: `_`.


<a id="cause-PurePqcMultipartVerificationRequiresVerifysignature"></a>

### `PurePqcMultipartVerificationRequiresVerifysignature`


Local detection/handling phase and implementation owner:

- `multipart_mode` (module-level helper) — `src/crypto/pqc/multipart.rs`. Enclosing match alternative: `PqcSignatureMode::Pure if verification`.


<a id="cause-VerifysignatureRequiresThePkcs1132Interface"></a>

### `VerifysignatureRequiresThePkcs1132Interface`


Local detection/handling phase and implementation owner:

- `Session::verify_pqc_signature_input` — `src/crypto/pqc/verify_signature.rs`.
