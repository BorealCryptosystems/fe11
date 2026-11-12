Cause contracts for `KeyDerivationRejection`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-EcdhKdfIdentifierWidth"></a>

### `EcdhKdfIdentifierWidth`


Local detection/handling phase and implementation owner:

- `EcdhKdf::raw` — `src/crypto/derivation.rs`.


<a id="cause-HkdfDerivationPathRequired"></a>

### `HkdfDerivationPathRequired`


Local detection/handling phase and implementation owner:

- `DerivationPath::hkdf_parameters` — `src/crypto/derivation.rs`. Enclosing match alternative: `Self::Ecdh(_)`.


<a id="cause-HkdfHashIdentifierWidth"></a>

### `HkdfHashIdentifierWidth`


Local detection/handling phase and implementation owner:

- `DerivationPath::hkdf_parameters` — `src/crypto/derivation.rs`.


<a id="cause-HkdfSaltOwnerUnavailable"></a>

### `HkdfSaltOwnerUnavailable`


Local detection/handling phase and implementation owner:

- `SaltReference::reference` — `src/crypto/derivation/operations.rs`.


<a id="cause-HkdfSaltReferenceUnavailable"></a>

### `HkdfSaltReferenceUnavailable`


Local detection/handling phase and implementation owner:

- `SaltReference::reference` — `src/crypto/derivation/operations.rs`.


<a id="cause-KemOutputEvidenceFamilyMismatch"></a>

### `KemOutputEvidenceFamilyMismatch`


Local detection/handling phase and implementation owner:

- `finish_observed` (module-level helper) — `src/crypto/derivation/kem_output.rs`. Enclosing match alternative: `_`.


<a id="cause-MlKemSharedSecretLengthIs32Bytes"></a>

### `MlKemSharedSecretLengthIs32Bytes`


Local detection/handling phase and implementation owner:

- `validate` (module-level helper) — `src/crypto/derivation/kem_output.rs`. Enclosing true branch: `spec.length != 32`.
- `validate_symmetric` (module-level helper) — `src/crypto/derivation/kem_output.rs`. Enclosing true branch: `spec.algorithm.key_length() != 32`.


<a id="cause-MontgomerySpkiDer"></a>

### `MontgomerySpkiDer`


Local detection/handling phase and implementation owner:

- `MontgomeryPublicKey::from_spki` — `src/crypto/derivation/montgomery.rs`.


<a id="cause-MontgomerySpkiAlgorithm"></a>

### `MontgomerySpkiAlgorithm`


Local detection/handling phase and implementation owner:

- `MontgomeryPublicKey::from_spki` — `src/crypto/derivation/montgomery.rs`. Enclosing match alternative: `_`.


<a id="cause-MontgomerySpkiEncoding"></a>

### `MontgomerySpkiEncoding`


Local detection/handling phase and implementation owner:

- `MontgomeryPublicKey::to_spki` — `src/crypto/derivation/montgomery.rs`.


<a id="cause-MontgomerySpkiNoncanonical"></a>

### `MontgomerySpkiNoncanonical`


Local detection/handling phase and implementation owner:

- `MontgomeryPublicKey::from_spki` — `src/crypto/derivation/montgomery.rs`. Enclosing true branch: `key.to_spki()? != encoded`.


<a id="cause-MontgomerySpkiParametersMustBeAbsent"></a>

### `MontgomerySpkiParametersMustBeAbsent`


Local detection/handling phase and implementation owner:

- `MontgomeryPublicKey::from_spki` — `src/crypto/derivation/montgomery.rs`. Enclosing true branch: `spki.algorithm.parameters.is_some()`.


<a id="cause-MontgomerySpkiUnusedBits"></a>

### `MontgomerySpkiUnusedBits`


Local detection/handling phase and implementation owner:

- `MontgomeryPublicKey::from_spki` — `src/crypto/derivation/montgomery.rs`.


<a id="cause-MontgomeryAgreementDomainMismatch"></a>

### `MontgomeryAgreementDomainMismatch`


Local detection/handling phase and implementation owner:

- `Session::derive_montgomery` — `src/crypto/derivation/operations.rs`. Enclosing true branch: `base.spec.domain != peer.domain()`.


<a id="cause-MontgomeryGenerationResultOwnerMismatch"></a>

### `MontgomeryGenerationResultOwnerMismatch`


Local detection/handling phase and implementation owner:

- `Session::generate_montgomery_key` — `src/crypto/derivation/keys.rs`. Enclosing match alternative: `_`.


<a id="cause-MontgomeryPublicAllocation"></a>

### `MontgomeryPublicAllocation`


Local detection/handling phase and implementation owner:

- `MontgomeryPublicKey::observation_storage` — `src/crypto/derivation/montgomery.rs`.
- `MontgomeryPublicKey::from_native` — `src/crypto/derivation/montgomery.rs`.


<a id="cause-MontgomeryPublicBitString"></a>

### `MontgomeryPublicBitString`


Local detection/handling phase and implementation owner:

- `MontgomeryPublicKey::to_spki` — `src/crypto/derivation/montgomery.rs`.


<a id="cause-MontgomeryPublicCoordinateWidth"></a>

### `MontgomeryPublicCoordinateWidth`


Local detection/handling phase and implementation owner:

- `MontgomeryPublicKey::observe_native` — `src/crypto/derivation/montgomery.rs`. Enclosing true branch: `bytes.len() != self.domain.public_key_length()`.
- `MontgomeryPublicKey::from_native` — `src/crypto/derivation/montgomery.rs`. Enclosing true branch: `bytes.len() != domain.public_key_length()`.


<a id="cause-OaepRequiresASecretKeyDestination"></a>

### `OaepRequiresASecretKeyDestination`


Local detection/handling phase and implementation owner:

- `Session::unwrap_agreement_key` — `src/crypto/derivation/introduced.rs`. Enclosing true branch: `matches!(parameters, crate::UnwrapParameters::RsaOaep { .. })`.
- `Session::unwrap_signing_key_selected` — `src/crypto/signing/introduced.rs`. Enclosing true branch: `matches!(parameters, crate::UnwrapParameters::RsaOaep { .. })`.


<a id="cause-Rfc7748NamedDomainHasNoImplicitRfc8410Conversion"></a>

### `Rfc7748NamedDomainHasNoImplicitRfc8410Conversion`


Local detection/handling phase and implementation owner:

- `MontgomeryDomain::spki_oid` — `src/crypto/derivation/montgomery.rs`. Enclosing match alternative: `Self::Curve25519 | Self::Curve448`.


<a id="cause-WeierstrassGenerationResultOwnerMismatch"></a>

### `WeierstrassGenerationResultOwnerMismatch`


Local detection/handling phase and implementation owner:

- `Session::generate_agreement_key` — `src/crypto/derivation/keys.rs`. Enclosing match alternative: `_`.


<a id="cause-AgreementOid"></a>

### `AgreementOid`


Local detection/handling phase and implementation owner:

- `with_weierstrass_spki` (module-level helper) — `src/crypto/derivation/owned.rs`.


<a id="cause-AgreementSpkiEncoding"></a>

### `AgreementSpkiEncoding`


Local detection/handling phase and implementation owner:

- `weierstrass_material_size` (module-level helper) — `src/crypto/derivation/owned.rs`.
- `observe_weierstrass` (module-level helper) — `src/crypto/derivation/owned.rs`.


<a id="cause-AgreementCurveMismatch"></a>

### `AgreementCurveMismatch`


Local detection/handling phase and implementation owner:

- `Session::derive_introduced_parts` — `src/crypto/derivation/introduced_operations.rs`. Enclosing true branch: `base.spec.key.curve != peer.curve`.
- `Session::derive_ecdh` — `src/crypto/derivation/operations.rs`. Enclosing true branch: `base.spec.curve != peer.curve`.


<a id="cause-AgreementHistoryAlreadyObserved"></a>

### `AgreementHistoryAlreadyObserved`


Local detection/handling phase and implementation owner:

- `PreparedAgreementPair::observe_history` — `src/crypto/derivation/owned.rs`. Enclosing true branch: `self.history_observation.is_some()`.


<a id="cause-AgreementHistoryObservationAbsent"></a>

### `AgreementHistoryObservationAbsent`


Local detection/handling phase and implementation owner:

- `PreparedAgreementPair::finish` — `src/crypto/derivation/owned.rs`.


<a id="cause-AgreementNativeDomain"></a>

### `AgreementNativeDomain`


Local detection/handling phase and implementation owner:

- `PreparedAgreementPair::validate` — `src/crypto/derivation/owned.rs`. Enclosing true branch: `values.bytes(CKA_EC_PARAMS)? != self.request().parameters()`.


<a id="cause-AgreementNativePointDer"></a>

### `AgreementNativePointDer`


Local detection/handling phase and implementation owner:

- `observe_weierstrass` (module-level helper) — `src/crypto/derivation/owned.rs`.


<a id="cause-AgreementOwnerSize"></a>

### `AgreementOwnerSize`


Local detection/handling phase and implementation owner:

- `AgreementPairPlan::requested_bytes` — `src/crypto/derivation/owned.rs`.
- `AgreementPairPlan::allocated_bytes` — `src/crypto/derivation/owned.rs`.


<a id="cause-AgreementPeerDomain"></a>

### `AgreementPeerDomain`


Local detection/handling phase and implementation owner:

- `AgreementPeer::from_spki` — `src/crypto/derivation.rs`. Enclosing match alternative: `_`.


<a id="cause-AgreementPointBitString"></a>

### `AgreementPointBitString`


Local detection/handling phase and implementation owner:

- `with_weierstrass_spki` (module-level helper) — `src/crypto/derivation/owned.rs`.


<a id="cause-AgreementPointEncoding"></a>

### `AgreementPointEncoding`


Local detection/handling phase and implementation owner:

- `observe_weierstrass` (module-level helper) — `src/crypto/derivation/owned.rs`.


<a id="cause-AgreementPointNoncanonical"></a>

### `AgreementPointNoncanonical`


Local detection/handling phase and implementation owner:

- `observe_weierstrass` (module-level helper) — `src/crypto/derivation/owned.rs`. Enclosing true branch: `!super::super::canonical::matches(&point, raw).map_err(|_| { Error::Rejected(crate::RejectionReason::KeyDerivation( crate::KeyDerivationRejection::AgreementPointEncoding, )) })?`.


<a id="cause-AgreementPrivateFamily"></a>

### `AgreementPrivateFamily`


Local detection/handling phase and implementation owner:

- `Session::import_agreement_key` — `src/crypto/derivation/introduced.rs`.


<a id="cause-AgreementPublicAllocation"></a>

### `AgreementPublicAllocation`


Local detection/handling phase and implementation owner:

- `PublicMaterial::allocate` — `src/crypto/derivation/owned.rs`.


<a id="cause-AgreementPublicIdentityAlreadyObserved"></a>

### `AgreementPublicIdentityAlreadyObserved`


Local detection/handling phase and implementation owner:

- `PreparedAgreementPair::validate` — `src/crypto/derivation/owned.rs`. Enclosing true branch: `!matches!(self.public, PublicState::AwaitingIdentity(_))`.


<a id="cause-AgreementPublicMaterialRequiresIdentity"></a>

### `AgreementPublicMaterialRequiresIdentity`


Local detection/handling phase and implementation owner:

- `PreparedAgreementPair::observe_public` — `src/crypto/derivation/owned.rs`.


<a id="cause-AgreementPublicObservationIncomplete"></a>

### `AgreementPublicObservationIncomplete`


Local detection/handling phase and implementation owner:

- `PreparedAgreementPair::public_complete` — `src/crypto/derivation/owned.rs`. Enclosing false branch: `matches!(self.public, PublicState::Observed(_))`.


<a id="cause-AgreementPublicSize"></a>

### `AgreementPublicSize`


Local detection/handling phase and implementation owner:

- `weierstrass_material_size` (module-level helper) — `src/crypto/derivation/owned.rs`.
- `weierstrass_material_size` (module-level helper) — `src/crypto/derivation/owned.rs`.
- `observe_weierstrass` (module-level helper) — `src/crypto/derivation/owned.rs`. Enclosing true branch: `encoded.len() != expected`.


<a id="cause-AgreementPublicStorageFamily"></a>

### `AgreementPublicStorageFamily`


Local detection/handling phase and implementation owner:

- `PublicMaterial::observe` — `src/crypto/derivation/owned.rs`. Enclosing match alternative: `_`.


<a id="cause-AgreementPublicationFamilyMismatch"></a>

### `AgreementPublicationFamilyMismatch`


Local detection/handling phase and implementation owner:

- `PreparedAgreementPair::finish` — `src/crypto/derivation/owned.rs`. Enclosing match alternative: `_`.


<a id="cause-AgreementRequestAlreadyPublished"></a>

### `AgreementRequestAlreadyPublished`


Local detection/handling phase and implementation owner:

- `PreparedAgreementPair::finish` — `src/crypto/derivation/owned.rs`.


<a id="cause-AgreementRequestSize"></a>

### `AgreementRequestSize`


Local detection/handling phase and implementation owner:

- `AgreementRequest::retained_bytes` — `src/crypto/derivation/owned.rs`.


<a id="cause-DerivationBaseAlreadyPublished"></a>

### `DerivationBaseAlreadyPublished`


Local detection/handling phase and implementation owner:

- `PreparedDerivationBase::finish` — `src/crypto/derivation/base.rs`.


<a id="cause-DerivationBaseHistoryAlreadyObserved"></a>

### `DerivationBaseHistoryAlreadyObserved`


Local detection/handling phase and implementation owner:

- `PreparedDerivationBase::observe_history` — `src/crypto/derivation/base.rs`. Enclosing true branch: `self.observation.is_some()`.


<a id="cause-DerivationBaseHistoryObservationAbsent"></a>

### `DerivationBaseHistoryObservationAbsent`


Local detection/handling phase and implementation owner:

- `PreparedDerivationBase::finish` — `src/crypto/derivation/base.rs`.


<a id="cause-DerivationBaseIntegerEncoding"></a>

### `DerivationBaseIntegerEncoding`


Local detection/handling phase and implementation owner:

- `Identity::validate` — `src/crypto/derivation/observation.rs`.


<a id="cause-DerivationBaseOwnerSize"></a>

### `DerivationBaseOwnerSize`


Local detection/handling phase and implementation owner:

- `DerivationBasePlan::requested_bytes` — `src/crypto/derivation/base.rs`.


<a id="cause-DerivationBasePublicationReportMismatch"></a>

### `DerivationBasePublicationReportMismatch`


Local detection/handling phase and implementation owner:

- `PreparedDerivationBase::finish` — `src/crypto/derivation/base.rs`. Enclosing match alternative: `_`.


<a id="cause-DerivationBaseRequestSize"></a>

### `DerivationBaseRequestSize`


Local detection/handling phase and implementation owner:

- `DerivationBaseRequest::retained_bytes` — `src/crypto/derivation/base.rs`.


<a id="cause-DerivationBaseRequestedIdentityMismatch"></a>

### `DerivationBaseRequestedIdentityMismatch`


Local detection/handling phase and implementation owner:

- `Identity::validate` — `src/crypto/derivation/observation.rs`. Enclosing true branch: `CK_ULONG::from_ne_bytes(raw) != expected`.
- `Identity::validate` — `src/crypto/derivation/observation.rs`. Enclosing false branch: `matches!(self, Self::IntroducedEc(_))`.
- `Admission::finish_terminal` — `src/advanced/admission/publication.rs`. Enclosing true branch: `let Err(cause) = result`.


<a id="cause-DerivationCallAbsent"></a>

### `DerivationCallAbsent`


Local detection/handling phase and implementation owner:

- `DerivationOwner::take_dispatch` — `src/crypto/derivation/resident.rs`.


<a id="cause-DerivationCandidateKind"></a>

### `DerivationCandidateKind`


Local detection/handling phase and implementation owner:

- `run` (module-level helper) — `src/crypto/derivation/resident/runner.rs`. Enclosing match alternative: `_`.


<a id="cause-DerivationCompletionPhase"></a>

### `DerivationCompletionPhase`


Local detection/handling phase and implementation owner:

- `DerivationOwner::advance` — `src/crypto/derivation/resident.rs`. Enclosing match alternative: `_`.


<a id="cause-DerivationCompletionUnknown"></a>

### `DerivationCompletionUnknown`


Local detection/handling phase and implementation owner:

- `run` (module-level helper) — `src/crypto/derivation/resident/runner.rs`. Enclosing true branch: `held.native.is_uncertain()`.


<a id="cause-DerivationContinuationChanged"></a>

### `DerivationContinuationChanged`


Local detection/handling phase and implementation owner:

- `run` (module-level helper) — `src/crypto/derivation/resident/runner.rs`. Enclosing true branch: `owner.need()? != Some(need)`.


<a id="cause-DerivationDestinationAbsent"></a>

### `DerivationDestinationAbsent`


Local detection/handling phase and implementation owner:

- `DerivationOwner::activate_destination` — `src/crypto/derivation/resident.rs`.


<a id="cause-DerivationDestinationPhase"></a>

### `DerivationDestinationPhase`


Local detection/handling phase and implementation owner:

- `DerivationOwner::activate_destination` — `src/crypto/derivation/resident.rs`. Enclosing true branch: `!matches!(self.phase, Phase::DestinationReady(_))`.


<a id="cause-DerivationDispatchPhase"></a>

### `DerivationDispatchPhase`


Local detection/handling phase and implementation owner:

- `DerivationOwner::take_dispatch` — `src/crypto/derivation/resident.rs`.


<a id="cause-DerivationGraphOverflow"></a>

### `DerivationGraphOverflow`


Local detection/handling phase and implementation owner:

- `Session::derive_with` — `src/crypto/derivation/operations/execution.rs`.
- `Session::derive_with` — `src/crypto/derivation/operations/execution.rs`.
- `Session::derive_with` — `src/crypto/derivation/operations/execution.rs`.
- `Session::derive_with` — `src/crypto/derivation/operations/execution.rs`.
- `Session::derive_with` — `src/crypto/derivation/operations/execution.rs`. Enclosing true branch: `actual > admitted`.


<a id="cause-DerivationIncomplete"></a>

### `DerivationIncomplete`


Local detection/handling phase and implementation owner:

- `DerivationOwner::result` — `src/crypto/derivation/resident.rs`.


<a id="cause-DerivationIsNotAResourceRequest"></a>

### `DerivationIsNotAResourceRequest`


Local detection/handling phase and implementation owner:

- `run` (module-level helper) — `src/crypto/derivation/resident/runner.rs`. Enclosing match alternative: `Need::Native | Need::Destination`.


<a id="cause-DerivationNativeInputMutation"></a>

### `DerivationNativeInputMutation`


Local detection/handling phase and implementation owner:

- `execute_derivation` (module-level helper) — `src/crypto/derivation/operations/execution.rs`. Enclosing true branch: `!unchanged`.


<a id="cause-DerivationNativeLifetimeAbsent"></a>

### `DerivationNativeLifetimeAbsent`


Local detection/handling phase and implementation owner:

- `DerivationOwner::admit` — `src/crypto/derivation/resident.rs`.


<a id="cause-DerivationObservationAttachmentPhase"></a>

### `DerivationObservationAttachmentPhase`


Local detection/handling phase and implementation owner:

- `Owner::attach` — `src/crypto/derivation/observation.rs`. Enclosing match alternative: `_`.


<a id="cause-DerivationObservationGraphSize"></a>

### `DerivationObservationGraphSize`


Local detection/handling phase and implementation owner:

- `add` (module-level helper) — `src/crypto/derivation/resident/preparation.rs`.


<a id="cause-DerivationObservationIncomplete"></a>

### `DerivationObservationIncomplete`


Local detection/handling phase and implementation owner:

- `Owner::result` — `src/crypto/derivation/observation.rs`. Enclosing match alternative: `_`.


<a id="cause-DerivationObservationStopped"></a>

### `DerivationObservationStopped`


Local detection/handling phase and implementation owner:

- `Owner::advance` — `src/crypto/derivation/observation.rs`. Enclosing match alternative: `Phase::Stopped`.
- `DerivationOwner::advance` — `src/crypto/derivation/resident.rs`. Enclosing match alternative: `_`.


<a id="cause-DerivationObservationStorageSize"></a>

### `DerivationObservationStorageSize`


Local detection/handling phase and implementation owner:

- `add` (module-level helper) — `src/crypto/derivation/observation.rs`.


<a id="cause-DerivationObservationTransition"></a>

### `DerivationObservationTransition`


Local detection/handling phase and implementation owner:

- `Owner::advance` — `src/crypto/derivation/observation.rs`. Enclosing match alternative: `_`.


<a id="cause-DerivationOwnerAbsent"></a>

### `DerivationOwnerAbsent`


Local detection/handling phase and implementation owner:

- `run` (module-level helper) — `src/crypto/derivation/resident/runner.rs`.
- `run` (module-level helper) — `src/crypto/derivation/resident/runner.rs`. Enclosing true branch: `need == Need::Destination`.
- `run` (module-level helper) — `src/crypto/derivation/resident/runner.rs`. Enclosing true branch: `need == Need::Native`.
- `run` (module-level helper) — `src/crypto/derivation/resident/runner.rs`.
- `run` (module-level helper) — `src/crypto/derivation/resident/runner.rs`. Enclosing true branch: `published`.


<a id="cause-DerivationParameterOverflow"></a>

### `DerivationParameterOverflow`


Local detection/handling phase and implementation owner:

- `lengths` (module-level helper) — `src/crypto/derivation/operations.rs`.
- `ParameterPlan<'a>::allocation_bytes` — `src/crypto/derivation/operations.rs`.
- `ParameterPlan<'a>::allocation_bytes` — `src/crypto/derivation/operations.rs`.
- `ParameterStorage::allocated_bytes` — `src/crypto/derivation/operations.rs`.


<a id="cause-DerivationPossessionAbsent"></a>

### `DerivationPossessionAbsent`


Local detection/handling phase and implementation owner:

- `run` (module-level helper) — `src/crypto/derivation/resident/runner.rs`.


<a id="cause-DerivationPublicationQuotaAbsent"></a>

### `DerivationPublicationQuotaAbsent`


Local detection/handling phase and implementation owner:

- `DerivationOwner::returned` — `src/crypto/derivation/resident.rs`.


<a id="cause-DerivationResourceNeedAbsent"></a>

### `DerivationResourceNeedAbsent`


Local detection/handling phase and implementation owner:

- `run` (module-level helper) — `src/crypto/derivation/resident/runner.rs`.


<a id="cause-DerivationReturnPhase"></a>

### `DerivationReturnPhase`


Local detection/handling phase and implementation owner:

- `DerivationOwner::returned` — `src/crypto/derivation/resident.rs`.


<a id="cause-DerivationStorageRecipeMismatch"></a>

### `DerivationStorageRecipeMismatch`


Local detection/handling phase and implementation owner:

- `ParameterStorage::bind` — `src/crypto/derivation/operations.rs`. Enclosing match alternative: `_`.
- `ParameterStorage::bind` — `src/crypto/derivation/operations.rs`. Enclosing match alternative: `_`.


<a id="cause-DeriveReturnedSaltHandle"></a>

### `DeriveReturnedSaltHandle`


Local detection/handling phase and implementation owner:

- `execute_derivation` (module-level helper) — `src/crypto/derivation/operations/execution.rs`. Enclosing true branch: `data.created == salt_handle`.


<a id="cause-DerivedMechanismRecipeAbsent"></a>

### `DerivedMechanismRecipeAbsent`


Local detection/handling phase and implementation owner:

- `Owner::advance` — `src/crypto/derivation/output_observation.rs`. Enclosing match alternative: `Some(storage)`.


<a id="cause-DerivedObjectAbsent"></a>

### `DerivedObjectAbsent`


Local detection/handling phase and implementation owner:

- `DerivationOwner::created` — `src/crypto/derivation/resident.rs`. Enclosing match alternative: `_`.
- `Session::derive_native_input` — `src/managed/mutations/derivation.rs`.


<a id="cause-DerivedOutputAttachmentPhase"></a>

### `DerivedOutputAttachmentPhase`


Local detection/handling phase and implementation owner:

- `Owner::attach` — `src/crypto/derivation/output_observation.rs`. Enclosing match alternative: `_`.


<a id="cause-DerivedOutputEvidenceKind"></a>

### `DerivedOutputEvidenceKind`


Local detection/handling phase and implementation owner:

- `Session::derive_native` — `src/crypto/derivation/operations/execution.rs`. Enclosing match alternative: `_`.


<a id="cause-DerivedOutputIncomplete"></a>

### `DerivedOutputIncomplete`


Local detection/handling phase and implementation owner:

- `Owner::result` — `src/crypto/derivation/output_observation.rs`. Enclosing match alternative: `_`.


<a id="cause-DerivedOutputObservationStopped"></a>

### `DerivedOutputObservationStopped`


Local detection/handling phase and implementation owner:

- `Owner::advance` — `src/crypto/derivation/output_observation.rs`. Enclosing match alternative: `Phase::Stopped`.


<a id="cause-DerivedOutputObservationStorageSize"></a>

### `DerivedOutputObservationStorageSize`


Local detection/handling phase and implementation owner:

- `add` (module-level helper) — `src/crypto/derivation/output_observation.rs`.


<a id="cause-DerivedOutputPreparationAbsent"></a>

### `DerivedOutputPreparationAbsent`


Local detection/handling phase and implementation owner:

- `DerivationOwner::advance` — `src/crypto/derivation/resident.rs`. Enclosing match alternative: `Phase::Child { parent, destination, read, }`.


<a id="cause-DerivedOutputTransition"></a>

### `DerivedOutputTransition`


Local detection/handling phase and implementation owner:

- `Owner::advance` — `src/crypto/derivation/output_observation.rs`. Enclosing match alternative: `_`.


<a id="cause-DerivedReferencePreparationAbsent"></a>

### `DerivedReferencePreparationAbsent`


Local detection/handling phase and implementation owner:

- `DerivationOwner::admit` — `src/crypto/derivation/resident.rs`.


<a id="cause-DerivedReferenceQuotaTransferred"></a>

### `DerivedReferenceQuotaTransferred`


Local detection/handling phase and implementation owner:

- `DerivationOwner::admit` — `src/crypto/derivation/resident.rs`.


<a id="cause-ExistingDerivationBaseHasNoGenerationRequest"></a>

### `ExistingDerivationBaseHasNoGenerationRequest`


Local detection/handling phase and implementation owner:

- `base_generation_template` (module-level helper) — `src/crypto/derivation/base.rs`.


<a id="cause-FamilyInputPlanAbsent"></a>

### `FamilyInputPlanAbsent`


Local detection/handling phase and implementation owner:

- `DerivationBasePlan::finish_owner` — `src/crypto/derivation/base.rs`. Enclosing true branch: `plan.is_none()`.
- `AgreementPairPlan::finish_owner` — `src/crypto/derivation/owned.rs`. Enclosing true branch: `plan.is_none()`.
- `KemOwnerPlan<'_>::finish_owner` — `src/crypto/kem/owned.rs`.
- `PqcOwnerPlan<'_>::finish_owner` — `src/crypto/pqc/owned.rs`.
- `VerificationPlan<'_>::finish_owner` — `src/crypto/verification/owned.rs`. Enclosing true branch: `plan.is_none()`.
- `ClassicalPairPlan<'_>::finish_owner` — `src/crypto/signing/owned/preparation.rs`.


<a id="cause-FamilyOwnerStorageAbsent"></a>

### `FamilyOwnerStorageAbsent`


Local detection/handling phase and implementation owner:

- `DerivationBasePlan::finish_owner` — `src/crypto/derivation/base.rs`. Enclosing true branch: `prepared.is_none()`.
- `AgreementPairPlan::finish_owner` — `src/crypto/derivation/owned.rs`. Enclosing true branch: `prepared.is_none()`.
- `KemOwnerPlan<'_>::finish_owner` — `src/crypto/kem/owned.rs`.
- `PqcOwnerPlan<'_>::finish_owner` — `src/crypto/pqc/owned.rs`.
- `VerificationPlan<'_>::finish_owner` — `src/crypto/verification/owned.rs`. Enclosing true branch: `prepared.is_none()`.
- `ClassicalPairPlan<'_>::finish_owner` — `src/crypto/signing/owned/preparation.rs`.


<a id="cause-FindAgreementKeyResultOwnerMismatch"></a>

### `FindAgreementKeyResultOwnerMismatch`


Local detection/handling phase and implementation owner:

- `Session::find_agreement_key` — `src/crypto/derivation/keys.rs`. Enclosing match alternative: `_`.


<a id="cause-FindHkdfKeyResultOwnerMismatch"></a>

### `FindHkdfKeyResultOwnerMismatch`


Local detection/handling phase and implementation owner:

- `Session::find_hkdf_key` — `src/crypto/derivation/keys.rs`. Enclosing match alternative: `_`.


<a id="cause-FindMontgomeryKeyResultOwnerMismatch"></a>

### `FindMontgomeryKeyResultOwnerMismatch`


Local detection/handling phase and implementation owner:

- `Session::find_montgomery_key` — `src/crypto/derivation/keys.rs`. Enclosing match alternative: `_`.


<a id="cause-GenerateHkdfKeyResultOwnerMismatch"></a>

### `GenerateHkdfKeyResultOwnerMismatch`


Local detection/handling phase and implementation owner:

- `Session::generate_hkdf_key` — `src/crypto/derivation/keys.rs`. Enclosing match alternative: `_`.


<a id="cause-HistoryObservationDescriptorAllocation"></a>

### `HistoryObservationDescriptorAllocation`


Local detection/handling phase and implementation owner:

- `HistoryObservationPlan::fields` — `src/crypto/derivation/history.rs`.


<a id="cause-ImportedAgreementHistoryReportAbsent"></a>

### `ImportedAgreementHistoryReportAbsent`


Local detection/handling phase and implementation owner:

- `Session::import_agreement_key` — `src/crypto/derivation/introduced.rs`.


<a id="cause-IntroducedAgreementDestination"></a>

### `IntroducedAgreementDestination`


Local detection/handling phase and implementation owner:

- `Session::derive_introduced_parts` — `src/crypto/derivation/introduced_operations.rs`.


<a id="cause-IntroducedAgreementIdentityOrDomain"></a>

### `IntroducedAgreementIdentityOrDomain`


Local detection/handling phase and implementation owner:

- `Identity::validate` — `src/crypto/derivation/observation.rs`. Enclosing true branch: `matches!(self, Self::IntroducedEc(_))`.


<a id="cause-IntroducedAgreementSelectionResultOwnerMismatch"></a>

### `IntroducedAgreementSelectionResultOwnerMismatch`


Local detection/handling phase and implementation owner:

- `Session::find_introduced_agreement_key` — `src/crypto/derivation/introduced.rs`. Enclosing match alternative: `_`.


<a id="cause-IntroducedDerivationEvidenceKind"></a>

### `IntroducedDerivationEvidenceKind`


Local detection/handling phase and implementation owner:

- `Session::derive_introduced_parts` — `src/crypto/derivation/introduced_operations.rs`.


<a id="cause-IntroducedDerivationProvenanceKind"></a>

### `IntroducedDerivationProvenanceKind`


Local detection/handling phase and implementation owner:

- `Session::derive_introduced_parts` — `src/crypto/derivation/introduced_operations.rs`.


<a id="cause-KeyHistoryClass"></a>

### `KeyHistoryClass`


Local detection/handling phase and implementation owner:

- `Session::key_history` — `src/crypto/derivation/keys.rs`. Enclosing true branch: `!matches!( key.class(), ManagedClass::PrivateKey | ManagedClass::SecretKey )`.


<a id="cause-OrdinaryDerivationProvenanceKind"></a>

### `OrdinaryDerivationProvenanceKind`


Local detection/handling phase and implementation owner:

- `Session::derive_native` — `src/crypto/derivation/operations/execution.rs`.


<a id="cause-ParentObservationPreparationAbsent"></a>

### `ParentObservationPreparationAbsent`


Local detection/handling phase and implementation owner:

- `Initial::bind_mutation_retained` — `src/crypto/derivation/observation.rs`.
- `Initial::allocated_bytes` — `src/crypto/derivation/resident/preparation.rs`.


<a id="cause-RestoredAgreementHistoryReportAbsent"></a>

### `RestoredAgreementHistoryReportAbsent`


Local detection/handling phase and implementation owner:

- `PreparedAgreementRestore::finish_observed` — `src/crypto/derivation/introduced.rs`.


<a id="cause-RestoredAgreementMechanismReportAbsent"></a>

### `RestoredAgreementMechanismReportAbsent`


Local detection/handling phase and implementation owner:

- `PreparedAgreementRestore::finish_observed` — `src/crypto/derivation/introduced.rs`.


<a id="cause-SingleBaseGenerationRequiresHkdf"></a>

### `SingleBaseGenerationRequiresHkdf`


Local detection/handling phase and implementation owner:

- `DerivationBasePlan::new` — `src/crypto/derivation/base.rs`. Enclosing true branch: `generation.is_some() && !matches!(&request, DerivationBaseRequest::Hkdf(_))`.
- `base_generation_template` (module-level helper) — `src/crypto/derivation/base.rs`. Enclosing match alternative: `_`.


<a id="cause-TransportAgreementGenerationResultOwnerMismatch"></a>

### `TransportAgreementGenerationResultOwnerMismatch`


Local detection/handling phase and implementation owner:

- `Session::generate_transport_agreement_key` — `src/crypto/derivation/introduced.rs`. Enclosing match alternative: `_`.
