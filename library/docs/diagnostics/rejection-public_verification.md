Cause contracts for `PublicVerificationRejection`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-CCreateObjectUnavailable"></a>

### `CCreateObjectUnavailable`


Local detection/handling phase and implementation owner:

- `Session::create_verification_key` — `src/crypto/verification.rs`.
- `execute_prepared` (module-level helper) — `src/native/creation.rs`.
- `Session::import_rsa_wrapping_key` — `src/transport/rsa.rs`.
- `Session::import_rsa_wrapping_key` — `src/transport/rsa.rs`.
- `Session::import_rsa_unwrapping_key` — `src/transport/rsa.rs`.
- `Session::import_rsa_unwrapping_key` — `src/transport/rsa.rs`.
- `Session::import_agreement_key` — `src/crypto/derivation/introduced.rs`.
- `Session::import_kem_public_key` — `src/crypto/kem/admission.rs`.
- `Session::import_pqc_verification_key` — `src/crypto/pqc/public_import.rs`.
- `Session::import_signing_key_selected` — `src/crypto/signing/introduced.rs`.
- `Session::import_signing_key_selected` — `src/crypto/signing/introduced.rs`.
- `Session::create_content` — `src/managed/mutations/storage.rs`.
- `create` (module-level helper) — `src/managed/mutations/create/resident/typed.rs`.


<a id="cause-EcPointEncoding"></a>

### `EcPointEncoding`


Local detection/handling phase and implementation owner:

- `CurveInput<'a>::parse` — `src/crypto/verification/preparation.rs`. Enclosing match alternative: `CurvePublicKey::Weierstrass(curve, point)`.


<a id="cause-EddsaInstanceAndKeyCurveDiffer"></a>

### `EddsaInstanceAndKeyCurveDiffer`


Local detection/handling phase and implementation owner:

- `Session::verify_eddsa_parts` — `src/crypto/verification.rs`. Enclosing true branch: `key.edwards != Some(parameters.curve())`.


<a id="cause-EdwardsPointEncoding"></a>

### `EdwardsPointEncoding`


Local detection/handling phase and implementation owner:

- `CurveInput<'a>::parse` — `src/crypto/verification/preparation.rs`. Enclosing match alternative: `CurvePublicKey::Edwards(curve, point)`.


<a id="cause-MessageRsaVerificationKeyRequired"></a>

### `MessageRsaVerificationKeyRequired`


Local detection/handling phase and implementation owner:

- `VerificationKey::message_pss_bits` — `src/crypto/verification.rs`.


<a id="cause-NotAnEdwardsReference"></a>

### `NotAnEdwardsReference`


Local detection/handling phase and implementation owner:

- `Session::verify_pure_eddsa_parts` — `src/crypto/verification.rs`. Enclosing match alternative: `_`.


<a id="cause-PublicSpkiDer"></a>

### `PublicSpkiDer`


Local detection/handling phase and implementation owner:

- `public_algorithm_oid` (module-level helper) — `src/crypto/verification.rs`.


<a id="cause-PublicVerificationInputAllocation"></a>

### `PublicVerificationInputAllocation`


Local detection/handling phase and implementation owner:

- `copy` (module-level helper) — `src/crypto/verification/owned.rs`.


<a id="cause-PublicVerificationOwnerSize"></a>

### `PublicVerificationOwnerSize`


Local detection/handling phase and implementation owner:

- `verification_bytes` (module-level helper) — `src/crypto/verification/owned.rs`.


<a id="cause-VerificationEngineNotSelected"></a>

### `VerificationEngineNotSelected`


Local detection/handling phase and implementation owner:

- `Context::selected` — `src/crypto/public_verifier.rs`.


<a id="cause-VerificationEngineRequestFailed"></a>

### `VerificationEngineRequestFailed`


Local detection/handling phase and implementation owner:

- `failure` (module-level helper) — `src/crypto/public_verifier.rs`. Enclosing match alternative: `_`.


<a id="cause-VerificationIdentityAlreadyObserved"></a>

### `VerificationIdentityAlreadyObserved`


Local detection/handling phase and implementation owner:

- `PreparedVerification::validate_identity` — `src/crypto/verification/owned.rs`. Enclosing true branch: `self.observation != ObservationStage::AwaitingIdentity`.


<a id="cause-VerificationMaterialRequiresPublicIdentity"></a>

### `VerificationMaterialRequiresPublicIdentity`


Local detection/handling phase and implementation owner:

- `PreparedVerification::validate_material` — `src/crypto/verification/owned.rs`. Enclosing true branch: `self.observation != ObservationStage::ReadPermitted`.


<a id="cause-VerificationPublicObservationIncomplete"></a>

### `VerificationPublicObservationIncomplete`


Local detection/handling phase and implementation owner:

- `PreparedVerification::finish` — `src/crypto/verification/owned.rs`.


<a id="cause-VerificationPublicationAbsent"></a>

### `VerificationPublicationAbsent`


Local detection/handling phase and implementation owner:

- `Session::create_verification_key` — `src/crypto/verification.rs`.


<a id="cause-VerificationPublicationAllocation"></a>

### `VerificationPublicationAllocation`


Local detection/handling phase and implementation owner:

- `copy` (module-level helper) — `src/crypto/verification/publication.rs`.


<a id="cause-VerificationPublicationAlreadyTransferred"></a>

### `VerificationPublicationAlreadyTransferred`


Local detection/handling phase and implementation owner:

- `PreparedVerification::finish` — `src/crypto/verification/owned.rs`.


<a id="cause-VerificationPublicationSize"></a>

### `VerificationPublicationSize`


Local detection/handling phase and implementation owner:

- `bytes` (module-level helper) — `src/crypto/verification/publication.rs`.
