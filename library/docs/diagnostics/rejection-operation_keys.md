Cause contracts for `OperationKeysRejection`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-PssRequiresAnRsaReference"></a>

### `PssRequiresAnRsaReference`


Local detection/handling phase and implementation owner:

- `KeyLease::for_rejoin_selected_retained` — `src/advanced/keys.rs`. Enclosing true branch: `parameters.is_some()`.


<a id="cause-CheckpointRsaKeySize"></a>

### `CheckpointRsaKeySize`


Local detection/handling phase and implementation owner:

- `KeyLease::check_checkpoint` — `src/advanced/keys.rs`. Enclosing true branch: `!matches!(self.material, KeyLeaseMaterial::Rsa { bits } if (bits / 8 + usize::from(bits % 8 != 0)) == size)`.


<a id="cause-CheckpointAlgorithmAbsent"></a>

### `CheckpointAlgorithmAbsent`


Local detection/handling phase and implementation owner:

- `KeyLease::checkpoint_profile` — `src/advanced/keys.rs`. Enclosing match alternative: `KeyLeaseMaterial::Rsa { .. }`.


<a id="cause-CheckpointDestinationKeyBinding"></a>

### `CheckpointDestinationKeyBinding`


Local detection/handling phase and implementation owner:

- `KeyLease::check_checkpoint` — `src/advanced/keys.rs`. Enclosing true branch: `self.description.is_some() && ((expected.class.is_some() && actual.class != expected.class) || (expected.key_type.is_some() && actual.key_type != expected.key_type))`.


<a id="cause-CheckpointDestinationKeyProfile"></a>

### `CheckpointDestinationKeyProfile`


Local detection/handling phase and implementation owner:

- `KeyLease::check_checkpoint` — `src/advanced/keys.rs`. Enclosing true branch: `self.checkpoint_profile()? != profile`.


<a id="cause-CipherDestinationAbsent"></a>

### `CipherDestinationAbsent`


Local detection/handling phase and implementation owner:

- `Acquired::bind` — `src/advanced/keys/restoration.rs`. Enclosing match alternative: `Self::Native { binding, role: NativeRole::Cipher, }`.


<a id="cause-CipherWriterDeclarationRequired"></a>

### `CipherWriterDeclarationRequired`


Local detection/handling phase and implementation owner:

- `KeyLease::check_cipher_binding` — `src/advanced/keys.rs`. Enclosing true branch: `!binding.contract.mutates_key()`.
- `Destination<'a>::cipher_imported` — `src/advanced/signature/binding.rs`. Enclosing true branch: `!contract.mutates_key()`.


<a id="cause-CipherWriterRevocationState"></a>

### `CipherWriterRevocationState`


Local detection/handling phase and implementation owner:

- `KeyLease::check_cipher_binding` — `src/advanced/keys.rs`. Enclosing match alternative: `_`.


<a id="cause-DigestDeclarationOnAnotherFamily"></a>

### `DigestDeclarationOnAnotherFamily`


Local detection/handling phase and implementation owner:

- `Prepared<'a>::captured` — `src/advanced/keys/restoration.rs`. Enclosing true branch: `keys.extension.is_some() && !matches!(body, OperationBody::Digest(_) | OperationBody::Cipher(_))`.
- `Prepared<'a>::imported` — `src/advanced/keys/restoration.rs`. Enclosing true branch: `keys.extension.is_some() && descriptor.family != record::Family::Digest && !descriptor.family.is_cipher()`.


<a id="cause-ForeignOrStaleMessageKey"></a>

### `ForeignOrStaleMessageKey`


Local detection/handling phase and implementation owner:

- `KeyLease::from_native_retained` — `src/advanced/keys.rs`. Enclosing true branch: `!Arc::ptr_eq(&session.inner, &managed.inner) || session.uid != identity.session || session.entry.slot != identity.slot || session.snapshot.generation != identity.generation`.
- `KeyReaders<N>::prepare_in_context` — `src/advanced/keys/preparation.rs`. Enclosing true branch: `!Arc::ptr_eq(&session.inner, &key.inner) || session.uid != identity.session || session.entry.slot != identity.slot || session.snapshot.generation != identity.generation`.


<a id="cause-ForeignOrStaleNativeWriterKey"></a>

### `ForeignOrStaleNativeWriterKey`


Local detection/handling phase and implementation owner:

- `KeyLease::from_native_writer` — `src/advanced/keys.rs`. Enclosing true branch: `!Arc::ptr_eq(&session.inner, &key.inner) || session.uid != identity.session || session.entry.slot != identity.slot || session.snapshot.generation != identity.generation`.


<a id="cause-KeyLeaseCandidateAlreadyOccupied"></a>

### `KeyLeaseCandidateAlreadyOccupied`


Local detection/handling phase and implementation owner:

- `KeyLease::from_native_writer` — `src/advanced/keys.rs`. Enclosing true branch: `candidate.is_some()`.
- `KeyLease::from_native_retained` — `src/advanced/keys.rs`. Enclosing true branch: `candidate.is_some()`.


<a id="cause-MessageDestinationAbsent"></a>

### `MessageDestinationAbsent`


Local detection/handling phase and implementation owner:

- `Acquired::bind` — `src/advanced/keys/restoration.rs`. Enclosing match alternative: `Self::NativeMessages(_)`.


<a id="cause-MessageHasNoCipherKeyRole"></a>

### `MessageHasNoCipherKeyRole`


Local detection/handling phase and implementation owner:

- `Prepared<'a>::captured` — `src/advanced/keys/restoration.rs`. Enclosing true branch: `keys.encryption.is_some()`.
- `Prepared<'a>::imported` — `src/advanced/keys/restoration.rs`. Enclosing true branch: `keys.encryption.is_some()`.


<a id="cause-NativeDestinationStorageAccounting"></a>

### `NativeDestinationStorageAccounting`


Local detection/handling phase and implementation owner:

- `Plan::allocation_bytes` — `src/advanced/key_storage.rs`.
- `Storage::allocated_bytes` — `src/advanced/key_storage.rs`.


<a id="cause-NativeDestinationStorageWithoutNativeRole"></a>

### `NativeDestinationStorageWithoutNativeRole`


Local detection/handling phase and implementation owner:

- `Prepared<'a>::attach_storage` — `src/advanced/keys/restoration.rs`. Enclosing true branch: `storage.revocation.is_some() || storage.transfers.iter().any(Option::is_some) || storage.permissions.is_some()`.


<a id="cause-NativeKeyWriterAlreadyTransferred"></a>

### `NativeKeyWriterAlreadyTransferred`


Local detection/handling phase and implementation owner:

- `PreparedTransfer::bind` — `src/advanced/key_roles.rs`. Enclosing true branch: `owner.permit.get().is_none()`.


<a id="cause-NativeSecretCipherHasNoPssParameterContract"></a>

### `NativeSecretCipherHasNoPssParameterContract`


Local detection/handling phase and implementation owner:

- `KeyLease::for_rejoin_selected_retained` — `src/advanced/keys.rs`. Enclosing true branch: `parameters.is_some()`.


<a id="cause-NativeTransferStorageAccounting"></a>

### `NativeTransferStorageAccounting`


Local detection/handling phase and implementation owner:

- `transfer_bytes` (module-level helper) — `src/advanced/key_storage.rs`.


<a id="cause-NativeWriterRevocationAbsent"></a>

### `NativeWriterRevocationAbsent`


Local detection/handling phase and implementation owner:

- `KeyLease::from_native_writer` — `src/advanced/keys.rs`.
- `Grant::bind` — `src/advanced/cipher/key_preparation.rs`. Enclosing match alternative: `Self::Writer(roles)`.


<a id="cause-RecoveryReferenceHasNoPssParameterContract"></a>

### `RecoveryReferenceHasNoPssParameterContract`


Local detection/handling phase and implementation owner:

- `KeyLease::for_rejoin_selected_retained` — `src/advanced/keys.rs`. Enclosing true branch: `parameters.is_some()`.


<a id="cause-RejoinSigningMechanism"></a>

### `RejoinSigningMechanism`


Local detection/handling phase and implementation owner:

- `KeyLease::for_rejoin_selected_retained` — `src/advanced/keys.rs`. Enclosing true branch: `mechanism != parameters.mechanism(crate::HashExecution::Pkcs11Combined)?`.


<a id="cause-RejoinSigningParameters"></a>

### `RejoinSigningParameters`


Local detection/handling phase and implementation owner:

- `KeyLease::for_rejoin_selected_retained` — `src/advanced/keys.rs`. Enclosing match alternative: `StateKeyReference::Signing(key)`.


<a id="cause-RejoinVerificationMechanism"></a>

### `RejoinVerificationMechanism`


Local detection/handling phase and implementation owner:

- `KeyLease::for_rejoin_selected_retained` — `src/advanced/keys.rs`. Enclosing true branch: `mechanism != parameters.mechanism(crate::HashExecution::Pkcs11Combined)?`.


<a id="cause-RejoinVerificationParameters"></a>

### `RejoinVerificationParameters`


Local detection/handling phase and implementation owner:

- `KeyLease::for_rejoin_selected_retained` — `src/advanced/keys.rs`. Enclosing match alternative: `StateKeyReference::Verification(key)`.


<a id="cause-RestorationBindingAlreadyConsumed"></a>

### `RestorationBindingAlreadyConsumed`


Local detection/handling phase and implementation owner:

- `Acquired::bind` — `src/advanced/keys/restoration.rs`. Enclosing match alternative: `Self::Consumed`.


<a id="cause-RestoreKeyIdentityMismatch"></a>

### `RestoreKeyIdentityMismatch`


Local detection/handling phase and implementation owner:

- `KeyLease::rebind_selected_retained` — `src/advanced/keys.rs`. Enclosing true branch: `old.slot != new.slot || old.generation != new.generation || !self.material.same_parameters(&destination.material)`.


<a id="cause-RevokedMessageKey"></a>

### `RevokedMessageKey`


Local detection/handling phase and implementation owner:

- `KeyLease::check` — `src/advanced/keys.rs`. Enclosing true branch: `self.identity.revoked.load(Ordering::Acquire) && !self.permission.owns_revocation()`.


<a id="cause-SignatureDestinationAbsent"></a>

### `SignatureDestinationAbsent`


Local detection/handling phase and implementation owner:

- `Acquired::bind` — `src/advanced/keys/restoration.rs`. Enclosing match alternative: `Self::Native { role: NativeRole::Signature, .. }`.


<a id="cause-SignatureReferenceOnAnotherOperationFamily"></a>

### `SignatureReferenceOnAnotherOperationFamily`


Local detection/handling phase and implementation owner:

- `Prepared<'a>::readers` — `src/advanced/keys/restoration.rs`. Enclosing true branch: `[keys.encryption, keys.authentication] .into_iter() .flatten() .any(|key| { matches!( key.reference, crate::StateKeyReference::NativeSignature { .. } | crate::StateKeyReference::NativeMessages { .. } ) })`.


<a id="cause-SignatureReferenceRequiresItsSignatureOwner"></a>

### `SignatureReferenceRequiresItsSignatureOwner`


Local detection/handling phase and implementation owner:

- `KeyLease::for_rejoin_selected_retained` — `src/advanced/keys.rs`. Enclosing match alternative: `StateKeyReference::NativeSignature { .. } | StateKeyReference::NativeMessages { .. }`.


<a id="cause-UnboundNativeKeyWriter"></a>

### `UnboundNativeKeyWriter`


Local detection/handling phase and implementation owner:

- `PreparedTransfer::bind` — `src/advanced/key_roles.rs`. Enclosing match alternative: `Roles::Transferred(owner)`.


<a id="cause-UnexpectedReaderPreparationStorage"></a>

### `UnexpectedReaderPreparationStorage`


Local detection/handling phase and implementation owner:

- `Prepared<'a>::prepare_with` — `src/advanced/keys/restoration.rs`. Enclosing true branch: `storage.revocation.is_some() || storage.transfers.iter().any(Option::is_some) || storage.permissions.is_some()`.


<a id="cause-UnsubmittedNativeWriterCannotBeDuplicated"></a>

### `UnsubmittedNativeWriterCannotBeDuplicated`


Local detection/handling phase and implementation owner:

- `Permission::duplicate` — `src/advanced/keys/permission.rs`. Enclosing match alternative: `Self::Write { revocation: Revocation::Prepared(_), .. }`.
