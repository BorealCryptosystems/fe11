Cause contracts for `CombinedOperationsRejection`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-DualAesKeyRequired"></a>

### `DualAesKeyRequired`


Local detection/handling phase and implementation owner:

- `AdvancedSession::prepare_dual_selected` — `src/advanced/dual/api.rs`. Enclosing true branch: `!matches!( key.algorithm, SymmetricAlgorithm::Aes128 | SymmetricAlgorithm::Aes192 | SymmetricAlgorithm::Aes256 )`.
- `AdvancedSession::start_dual_gcm_recovery` — `src/advanced/dual/recovery.rs`. Enclosing true branch: `!matches!( key.algorithm, SymmetricAlgorithm::Aes128 | SymmetricAlgorithm::Aes192 | SymmetricAlgorithm::Aes256 )`.


<a id="cause-DualAesProfile"></a>

### `DualAesProfile`


Local detection/handling phase and implementation owner:

- `Authentication::profile` — `src/advanced/dual/authentication.rs`. Enclosing true branch: `!(profile::AES128..=profile::AES256).contains(&cipher)`.


<a id="cause-DualHmacHash"></a>

### `DualHmacHash`


Local detection/handling phase and implementation owner:

- `Authentication::from_record` — `src/advanced/dual/authentication.rs`. Enclosing true branch: `d.family.is_dual_mac()`.


<a id="cause-DualHmacKeyRequired"></a>

### `DualHmacKeyRequired`


Local detection/handling phase and implementation owner:

- `HmacAlgorithm::from_key` — `src/advanced/dual/authentication.rs`. Enclosing match alternative: `_`.


<a id="cause-DualMacKeyAbsent"></a>

### `DualMacKeyAbsent`


Local detection/handling phase and implementation owner:

- `check_record_key` (module-level helper) — `src/advanced/dual/authentication.rs`. Enclosing true branch: `let Some(mac) = selection.mac()`.


<a id="cause-DualMacKeyAlgorithm"></a>

### `DualMacKeyAlgorithm`


Local detection/handling phase and implementation owner:

- `AdvancedSession::prepare_dual_selected` — `src/advanced/dual/api.rs`. Enclosing true branch: `Some(HmacAlgorithm::from_key(mac.algorithm)?) != authentication.mac()`.
- `AdvancedSession::start_dual_gcm_recovery` — `src/advanced/dual/recovery.rs`. Enclosing true branch: `Some(authentication::HmacAlgorithm::from_key(mac.algorithm)?) != authentication.mac()`.


<a id="cause-DualMacKeyType"></a>

### `DualMacKeyType`


Local detection/handling phase and implementation owner:

- `check_record_key` (module-level helper) — `src/advanced/dual/authentication.rs`. Enclosing true branch: `key.key_type != Some(CKK_GENERIC_SECRET as u64) && key.key_type != Some(mac.key_type() as u64)`.


<a id="cause-DualMacSelection"></a>

### `DualMacSelection`


Local detection/handling phase and implementation owner:

- `AdvancedSession::install_prepared_dual` — `src/advanced/dual/api.rs`. Enclosing match alternative: `(Some(k), Some(b))`.


<a id="cause-DualAlreadyPublished"></a>

### `DualAlreadyPublished`


Local detection/handling phase and implementation owner:

- `DualOperation::result` — `src/advanced/dual/operation.rs`.


<a id="cause-DualAsynchronousOutputIdentity"></a>

### `DualAsynchronousOutputIdentity`


Local detection/handling phase and implementation owner:

- `DualOperation::drive` — `src/advanced/dual/operation.rs`. Enclosing true branch: `self.completion.ulVersion != 0 || self.completion.pValue != pointer || rv == CKR_OK && self.completion.ulValue as u128 > capacity as u128`.
- `DualOperation::drive` — `src/advanced/dual/operation.rs`. Enclosing true branch: `self.completion.ulVersion != 0 || self.completion.pValue != pointer || self.completion.ulValue as usize > capacity`.


<a id="cause-DualAuthenticationFamily"></a>

### `DualAuthenticationFamily`


Local detection/handling phase and implementation owner:

- `Authentication::from_record` — `src/advanced/dual/authentication.rs`. Enclosing true branch: `!d.family.is_dual()`.


<a id="cause-DualAuthenticationOwner"></a>

### `DualAuthenticationOwner`


Local detection/handling phase and implementation owner:

- `DualStorage::for_dimensions` — `src/advanced/dual.rs`. Enclosing true branch: `mode.mac() != authentication.mac().is_some() || (mode == Mode::DecryptVerify) != expected.is_some()`.
- `AuthenticationOwner::check_binding` — `src/advanced/dual/authentication.rs`. Enclosing true branch: `mode.mac() != selection.mac().is_some()`.
- `AuthenticationOwner::check_binding` — `src/advanced/dual/authentication.rs`. Enclosing match alternative: `_`.
- `RecordPlan<'a>::bind` — `src/advanced/dual/snapshot/record_plan.rs`. Enclosing true branch: `self.shape.mode == Mode::DecryptVerify`.


<a id="cause-DualAuthenticationParameterIdentity"></a>

### `DualAuthenticationParameterIdentity`


Local detection/handling phase and implementation owner:

- `DualOperation::finish_step` — `src/advanced/dual/operation.rs`. Enclosing true branch: `self.auth_mechanism.mechanism != auth_kind || !self.auth_mechanism.pParameter.is_null() || self.auth_mechanism.ulParameterLen != 0`.


<a id="cause-DualAuthenticationResultRole"></a>

### `DualAuthenticationResultRole`


Local detection/handling phase and implementation owner:

- `DualOperation::result` — `src/advanced/dual/operation.rs`. Enclosing match alternative: `_`.


<a id="cause-DualAuthenticationRoles"></a>

### `DualAuthenticationRoles`


Local detection/handling phase and implementation owner:

- `AdvancedSession::prepare_dual_selected` — `src/advanced/dual/api.rs`. Enclosing true branch: `mode.mac() != authentication.mac().is_some() || mode.mac() != mac.is_some() || (mode == Mode::DecryptVerify) != expected.is_some()`.


<a id="cause-DualCheckpointOutputRange"></a>

### `DualCheckpointOutputRange`


Local detection/handling phase and implementation owner:

- `DualOperation::write_terminal_messages` — `src/advanced/dual/operation.rs`. Enclosing false branch: `terminal && !self.valid`.


<a id="cause-DualCheckpointUnavailable"></a>

### `DualCheckpointUnavailable`


Local detection/handling phase and implementation owner:

- `DualOperation::write_terminal_messages` — `src/advanced/dual/operation.rs`. Enclosing true branch: `self.pending || !self.valid && !terminal || self.step == DualStep::Failed`.


<a id="cause-DualCipherProfile"></a>

### `DualCipherProfile`


Local detection/handling phase and implementation owner:

- `cipher_profile` (module-level helper) — `src/advanced/dual/authentication.rs`. Enclosing match alternative: `_`.


<a id="cause-DualContextCeiling"></a>

### `DualContextCeiling`


Local detection/handling phase and implementation owner:

- `AdvancedSession::prepare_dual_selected` — `src/advanced/dual/api.rs`. Enclosing true branch: `input .checked_add(aad) .and_then(|n| { n.checked_add(iv_bytes).and_then(|n| { n.checked_add(if mode.mac() { authentication.length() } else { 0 }) }) }) .map_or(true, |n| n > limits.maximum_total_bytes)`.
- `RecordPlan<'a>::with_projection` — `src/advanced/dual/snapshot/record_plan.rs`. Enclosing true branch: `input .checked_add(message.params.aad.map_or(0, <[u8]>::len)) .and_then(|n| n.checked_add(nonce.len())) .and_then(|n| { n.checked_add(if mode.mac() { authentication.length() } else { 0 }) }) .map_or(true, |n| n > ceilings.maximum_total_bytes)`.


<a id="cause-DualDigestHash"></a>

### `DualDigestHash`


Local detection/handling phase and implementation owner:

- `Authentication::from_record` — `src/advanced/dual/authentication.rs`. Enclosing false branch: `d.family.is_dual_mac()`.


<a id="cause-DualDigestOrMacLength"></a>

### `DualDigestOrMacLength`


Local detection/handling phase and implementation owner:

- `DualOperation::finish_step` — `src/advanced/dual/operation.rs`. Enclosing true branch: `self.auth_output() && *self.auth_length as u128 != self.authentication.selection().length() as u128`.


<a id="cause-DualExactOutputLength"></a>

### `DualExactOutputLength`

Detected at a completed dual CipherFinal when the accumulated output length
is outside the selected cipher's semantic interval. The dual operation enters
Failed and returns its preallocated completion diagnostic; the successful native
effect is retained in that diagnostic. This is not storage negotiation or a
request to repeat the final call. Withhold the result, preserve the full error
and operation owner, and do not replay the completed cipher/authentication steps.


Local detection/handling phase and implementation owner:

- `DualOperation::finish_step` — `src/advanced/dual/operation.rs`. Enclosing true branch: `self.step == DualStep::CipherFinal`.


<a id="cause-DualFailedExplicitCleanupRequired"></a>

### `DualFailedExplicitCleanupRequired`


Local detection/handling phase and implementation owner:

- `DualOperation::drive` — `src/advanced/dual/operation.rs`. Enclosing true branch: `self.step == DualStep::Failed`.


<a id="cause-DualFullMacLength"></a>

### `DualFullMacLength`


Local detection/handling phase and implementation owner:

- `DualStorage::for_dimensions` — `src/advanced/dual.rs`. Enclosing true branch: `expected.is_some_and(|v| v.len() != authentication.length())`.
- `AdvancedSession::prepare_dual_selected` — `src/advanced/dual/api.rs`. Enclosing true branch: `expected.is_some_and(|value| value.len() != authentication.length())`.
- `PreparedSnapshot::fill_request` — `src/advanced/dual/snapshot.rs`. Enclosing true branch: `self.body.auth.as_slice().len() != expected.len()`.
- `RecordPlan<'a>::bind` — `src/advanced/dual/snapshot/record_plan.rs`. Enclosing true branch: `expected.len() != body.auth.as_slice().len()`.


<a id="cause-DualHashAbsent"></a>

### `DualHashAbsent`


Local detection/handling phase and implementation owner:

- `Authentication::from_record` — `src/advanced/dual/authentication.rs`.


<a id="cause-DualInputOverflow"></a>

### `DualInputOverflow`


Local detection/handling phase and implementation owner:

- `AdvancedSession::prepare_dual_selected` — `src/advanced/dual/api.rs`.


<a id="cause-DualMessageAbsent"></a>

### `DualMessageAbsent`


Local detection/handling phase and implementation owner:

- `record_selection` (module-level helper) — `src/advanced/dual/authentication.rs`.


<a id="cause-DualMessageCount"></a>

### `DualMessageCount`


Local detection/handling phase and implementation owner:

- `record_selection` (module-level helper) — `src/advanced/dual/authentication.rs`. Enclosing true branch: `messages.len() != 1`.


<a id="cause-DualMetadataOverflow"></a>

### `DualMetadataOverflow`


Local detection/handling phase and implementation owner:

- `DualStorage::for_dimensions` — `src/advanced/dual.rs`.
- `DualOperation::snapshot_shape` — `src/advanced/dual/snapshot.rs`.


<a id="cause-DualNativeFunctionsUnavailable"></a>

### `DualNativeFunctionsUnavailable`


Local detection/handling phase and implementation owner:

- `check_dual_functions` (module-level helper) — `src/advanced/dual.rs`. Enclosing true branch: `!cipher_available || !auth_available || !update_available`.


<a id="cause-DualNotActive"></a>

### `DualNotActive`


Local detection/handling phase and implementation owner:

- `DualOperation::function` — `src/advanced/dual/operation.rs`. Enclosing match alternative: `_`.
- `Call::resolve` — `src/advanced/dual/resolved_call.rs`. Enclosing match alternative: `_`.


<a id="cause-DualNotCapturable"></a>

### `DualNotCapturable`


Local detection/handling phase and implementation owner:

- `DualOperation::snapshot_shape` — `src/advanced/dual/snapshot.rs`. Enclosing true branch: `self.pending || !self.valid || matches!( self.step, DualStep::AuthInit | DualStep::Done | DualStep::Failed )`.


<a id="cause-DualNotComplete"></a>

### `DualNotComplete`


Local detection/handling phase and implementation owner:

- `DualOperation::result` — `src/advanced/dual/operation.rs`. Enclosing true branch: `!self.complete()`.


<a id="cause-DualOperationNotJoinable"></a>

### `DualOperationNotJoinable`


Local detection/handling phase and implementation owner:

- `DualOperation::joined_capacity` — `src/advanced/dual/operation.rs`. Enclosing true branch: `!self.pending`.


<a id="cause-DualOperationStorageSize"></a>

### `DualOperationStorageSize`


Local detection/handling phase and implementation owner:

- `DualStorage::for_dimensions` — `src/advanced/dual.rs`.
- `AdvancedSession::prepare_dual_selected` — `src/advanced/dual/api.rs`.
- `AdvancedSession::prepare_dual_selected` — `src/advanced/dual/api.rs`.


<a id="cause-DualOutputAbsent"></a>

### `DualOutputAbsent`


Local detection/handling phase and implementation owner:

- `DualOperation::write_terminal_messages` — `src/advanced/dual/operation.rs`.
- `DualOperation::joined_capacity` — `src/advanced/dual/operation.rs`. Enclosing true branch: `self.cipher_output()`.
- `DualOperation::snapshot_shape` — `src/advanced/dual/snapshot.rs`.
- `DualOperation::describe_snapshot` — `src/advanced/dual/snapshot.rs`.
- `PreparedSnapshot::copy_from` — `src/advanced/dual/snapshot.rs`.


<a id="cause-DualOutputOverflow"></a>

### `DualOutputOverflow`


Local detection/handling phase and implementation owner:

- `DualStorage::for_dimensions` — `src/advanced/dual.rs`.
- `Shape::allocate_request` — `src/advanced/dual/snapshot.rs`.
- `RecordPlan<'a>::allocate` — `src/advanced/dual/snapshot/record_plan.rs`.


<a id="cause-DualOutputProgression"></a>

### `DualOutputProgression`


Local detection/handling phase and implementation owner:

- `DualOperation::joined_capacity` — `src/advanced/dual/operation.rs`. Enclosing true branch: `self.cipher_output()`.


<a id="cause-DualRecoveryCipherKey"></a>

### `DualRecoveryCipherKey`


Local detection/handling phase and implementation owner:

- `AdvancedSession::install_prepared_dual` — `src/advanced/dual/api.rs`. Enclosing true branch: `let Some((profile, bindings)) = &recovery`.


<a id="cause-DualRecoveryEmptyMessage"></a>

### `DualRecoveryEmptyMessage`


Local detection/handling phase and implementation owner:

- `AdvancedSession::start_dual_gcm_recovery` — `src/advanced/dual/recovery.rs`.


<a id="cause-DualRecoveryKeyRoles"></a>

### `DualRecoveryKeyRoles`


Local detection/handling phase and implementation owner:

- `AdvancedSession::install_prepared_dual` — `src/advanced/dual/api.rs`. Enclosing match alternative: `_`.
- `AdvancedSession::start_dual_gcm_recovery` — `src/advanced/dual/recovery.rs`. Enclosing true branch: `mode.mac() != mac.is_some()`.


<a id="cause-DualRecoveryRequiresUnfinishedGcmDecryption"></a>

### `DualRecoveryRequiresUnfinishedGcmDecryption`


Local detection/handling phase and implementation owner:

- `DualOperation::write_recovery` — `src/advanced/dual/recovery.rs`. Enclosing true branch: `!self.mode.decrypt() || !self.cipher.gcm() || !self.valid || matches!(self.step, DualStep::Done | DualStep::Failed) || self.output.is_none()`.


<a id="cause-DualSnapshotAccounting"></a>

### `DualSnapshotAccounting`


Local detection/handling phase and implementation owner:

- `DualOperation::snapshot_shape` — `src/advanced/dual/snapshot.rs`.
- `DualOperation::snapshot_shape` — `src/advanced/dual/snapshot.rs`.
- `DualOperation::snapshot_shape` — `src/advanced/dual/snapshot.rs`.
- `DualOperation::snapshot_shape` — `src/advanced/dual/snapshot.rs`.
- `Shape::for_request` — `src/advanced/dual/snapshot.rs`.
- `Shape::layout_bytes` — `src/advanced/dual/snapshot.rs`.
- `Shape::allocate_layout` — `src/advanced/dual/snapshot.rs`.
- `Storage::metadata_bytes` — `src/advanced/dual/snapshot.rs`.
- `Storage::metadata_bytes` — `src/advanced/dual/snapshot.rs`.
- `Storage::allocated_bytes` — `src/advanced/dual/snapshot.rs`.
- `RecordPlan<'a>::with_projection` — `src/advanced/dual/snapshot/record_plan.rs`.


<a id="cause-DuplicateDualCompletion"></a>

### `DuplicateDualCompletion`


Local detection/handling phase and implementation owner:

- `DualOperation::finish_step` — `src/advanced/dual/operation.rs`. Enclosing match alternative: `_`.


<a id="cause-LegacyDualAuthenticationWidth"></a>

### `LegacyDualAuthenticationWidth`


Local detection/handling phase and implementation owner:

- `DualOperation::result` — `src/advanced/dual/operation.rs`. Enclosing match alternative: `(mode, Authentication::LegacyDigestSha256 | Authentication::LegacyHmacSha256)`.


<a id="cause-LegacyDualHash"></a>

### `LegacyDualHash`


Local detection/handling phase and implementation owner:

- `Authentication::from_record` — `src/advanced/dual/authentication.rs`. Enclosing true branch: `hash != CKM_SHA256 as u64`.


<a id="cause-ReconstructionActiveFlagsWidth"></a>

### `ReconstructionActiveFlagsWidth`


Local detection/handling phase and implementation owner:

- `PreparedDual::finish_record` — `src/advanced/dual.rs`.


<a id="cause-ReconstructionDualAad"></a>

### `ReconstructionDualAad`


Local detection/handling phase and implementation owner:

- `RecordPlan<'a>::with_projection` — `src/advanced/dual/snapshot/record_plan.rs`. Enclosing true branch: `descriptor.mechanism == CKM_AES_GCM as u64`.


<a id="cause-ReconstructionDualMessage"></a>

### `ReconstructionDualMessage`


Local detection/handling phase and implementation owner:

- `RecordPlan<'a>::with_projection` — `src/advanced/dual/snapshot/record_plan.rs`.


<a id="cause-ReconstructionDualMode"></a>

### `ReconstructionDualMode`


Local detection/handling phase and implementation owner:

- `RecordPlan<'a>::with_projection` — `src/advanced/dual/snapshot/record_plan.rs`. Enclosing match alternative: `_`.


<a id="cause-ReconstructionDualNonce"></a>

### `ReconstructionDualNonce`


Local detection/handling phase and implementation owner:

- `RecordPlan<'a>::with_projection` — `src/advanced/dual/snapshot/record_plan.rs`.
- `RecordPlan<'a>::bind` — `src/advanced/dual/snapshot/record_plan.rs`.


<a id="cause-ReconstructionDualPhase"></a>

### `ReconstructionDualPhase`


Local detection/handling phase and implementation owner:

- `PreparedDual::finish_record` — `src/advanced/dual.rs`. Enclosing match alternative: `_`.


<a id="cause-RecoveryRequiresDualGcmDecryption"></a>

### `RecoveryRequiresDualGcmDecryption`


Local detection/handling phase and implementation owner:

- `AdvancedSession::capture_dual_gcm_recovery` — `src/advanced/dual/recovery.rs`.


<a id="cause-RestorationDualKeyRoles"></a>

### `RestorationDualKeyRoles`


Local detection/handling phase and implementation owner:

- `DualOperation::restore_keys` — `src/advanced/dual/operation.rs`. Enclosing match alternative: `_`.


<a id="cause-RestorationEncryptionKeyRequired"></a>

### `RestorationEncryptionKeyRequired`


Local detection/handling phase and implementation owner:

- `DualOperation::restore_keys` — `src/advanced/dual/operation.rs`.
- `AeadMessageOperation::restore_keys` — `src/advanced/gcm/rejoin.rs`.


<a id="cause-TerminalDualAuthenticationWidth"></a>

### `TerminalDualAuthenticationWidth`


Local detection/handling phase and implementation owner:

- `DualOperation::set_terminal` — `src/advanced/dual/operation.rs`. Enclosing true branch: `authentication.len() != self.authentication.selection().length()`.
