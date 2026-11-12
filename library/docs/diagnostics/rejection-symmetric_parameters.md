Cause contracts for `SymmetricParametersRejection`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-Value32BitStreamCounterLength"></a>

### `Value32BitStreamCounterLength`


Local detection/handling phase and implementation owner:

- `StreamCounter::from_wire` — `src/symmetric/stream.rs`. Enclosing match alternative: `32`.


<a id="cause-Value64BitStreamCounterLength"></a>

### `Value64BitStreamCounterLength`


Local detection/handling phase and implementation owner:

- `StreamCounter::from_wire` — `src/symmetric/stream.rs`. Enclosing match alternative: `64`.


<a id="cause-AeadCompletionSelectionMismatch"></a>

### `AeadCompletionSelectionMismatch`


Local detection/handling phase and implementation owner:

- `AeadCompletion::into_legacy` — `src/symmetric/aead_selection.rs`. Enclosing match alternative: `Self::Stream(_)`.
- `AeadCompletion::into_stream` — `src/symmetric/aead_selection.rs`. Enclosing match alternative: `Self::Legacy(_)`.


<a id="cause-AeadKeyUsedForMac"></a>

### `AeadKeyUsedForMac`


Local detection/handling phase and implementation owner:

- `Session::symmetric_mac` — `src/symmetric/operations.rs`. Enclosing match alternative: `_`.
- `Session::symmetric_mac` — `src/symmetric/operations.rs`.


<a id="cause-AeadOutputLengthOverflow"></a>

### `AeadOutputLengthOverflow`

Detected in local output-bound arithmetic before a candidate output length
can be produced: tag addition, wrapping overhead/alignment or block rounding
cannot fit usize. This helper makes no native call. Correct/reduce the request
dimensions rather than increasing credits, truncating or wrapping the length.
An enclosing existing operation retains its own prior-effect/ownership contract;
this local calculation does not authorize its replay.


Local detection/handling phase and implementation owner:

- `ClassicAeadParameters<'_>::output_bounds` — `src/symmetric/classic_aead.rs`. Enclosing false branch: `decrypt`.


<a id="cause-AeadRequiresAnAdmittedSecretKey"></a>

### `AeadRequiresAnAdmittedSecretKey`


Local detection/handling phase and implementation owner:

- `Session::stream_aead` — `src/symmetric/operations.rs`. Enclosing true branch: `key.identity.class != crate::ManagedClass::SecretKey || key.identity.key_type.is_none()`.


<a id="cause-AeadRequiresItsAuthenticatedOutputOwner"></a>

### `AeadRequiresItsAuthenticatedOutputOwner`


Local detection/handling phase and implementation owner:

- `AesCipherParameters::from_selection` — `src/symmetric/classic.rs`. Enclosing match alternative: `DualCipher::Gcm { .. }`.


<a id="cause-AeadRetainedSelectionAccounting"></a>

### `AeadRetainedSelectionAccounting`


Local detection/handling phase and implementation owner:

- `Session::owned_aead_route` — `src/symmetric/operations.rs`. Enclosing true branch: `!message_route`.
- `Session::owned_aead_route` — `src/symmetric/operations.rs`.


<a id="cause-AesCfb1IvWidth"></a>

### `AesCfb1IvWidth`


Local detection/handling phase and implementation owner:

- `CipherParameters<'a>::from_fixed` — `src/symmetric/block.rs`. Enclosing match alternative: `CKM_AES_CFB1`.


<a id="cause-AesKwpIvWidth"></a>

### `AesKwpIvWidth`


Local detection/handling phase and implementation owner:

- `CipherParameters<'a>::from_fixed` — `src/symmetric/block.rs`. Enclosing false branch: `iv.is_empty()`.


<a id="cause-AesCipherMechanism"></a>

### `AesCipherMechanism`


Local detection/handling phase and implementation owner:

- `output_bounds` (module-level helper) — `src/symmetric/cipher.rs`. Enclosing match alternative: `_`.


<a id="cause-AesCipherMechanismWidth"></a>

### `AesCipherMechanismWidth`


Local detection/handling phase and implementation owner:

- `output_bounds` (module-level helper) — `src/symmetric/cipher.rs`.


<a id="cause-AesInputIsNotBlockAligned"></a>

### `AesInputIsNotBlockAligned`


Local detection/handling phase and implementation owner:

- `output_bounds` (module-level helper) — `src/symmetric/cipher.rs`. Enclosing false branch: `decrypt`.


<a id="cause-AesKeyWrapIvWidth"></a>

### `AesKeyWrapIvWidth`


Local detection/handling phase and implementation owner:

- `CipherParameters<'a>::from_fixed` — `src/symmetric/block.rs`. Enclosing false branch: `iv.is_empty()`.


<a id="cause-AesKeyWrapContractAbsent"></a>

### `AesKeyWrapContractAbsent`


Local detection/handling phase and implementation owner:

- `Snapshot::for_block` — `src/symmetric/cipher/snapshot.rs`. Enclosing match alternative: `CipherParameters::AesKeyWrapPad { .. } | CipherParameters::AesKeyWrap { .. } | CipherParameters::AesKeyWrapKwp { .. } | CipherParameters::AesKeyWrapPkcs7 { .. }`.


<a id="cause-AesKeyWrapMechanism"></a>

### `AesKeyWrapMechanism`


Local detection/handling phase and implementation owner:

- `key_wrap_bounds` (module-level helper) — `src/symmetric/block.rs`. Enclosing match alternative: `_`.


<a id="cause-AesKeyWrapOutputLengthOverflow"></a>

### `AesKeyWrapOutputLengthOverflow`

Detected in local output-bound arithmetic before a candidate output length
can be produced: tag addition, wrapping overhead/alignment or block rounding
cannot fit usize. This helper makes no native call. Correct/reduce the request
dimensions rather than increasing credits, truncating or wrapping the length.
An enclosing existing operation retains its own prior-effect/ownership contract;
this local calculation does not authorize its replay.


Local detection/handling phase and implementation owner:

- `key_wrap_bounds` (module-level helper) — `src/symmetric/block.rs`.


<a id="cause-AesKeyWrapRequiresASinglePartOperation"></a>

### `AesKeyWrapRequiresASinglePartOperation`


Local detection/handling phase and implementation owner:

- `CipherParameters<'a>::validate_route` — `src/symmetric/block.rs`. Enclosing true branch: `matches!( self, Self::AesKeyWrap { .. } | Self::AesKeyWrapPad { .. } | Self::AesKeyWrapKwp { .. } | Self::AesKeyWrapPkcs7 { .. } ) && route != crate::MessageRoute::Single`.


<a id="cause-AesMechanismWidth"></a>

### `AesMechanismWidth`


Local detection/handling phase and implementation owner:

- `CipherFrame::classic_request` — `src/symmetric/cipher.rs`.


<a id="cause-AesOutputOverflow"></a>

### `AesOutputOverflow`


Local detection/handling phase and implementation owner:

- `output_bounds` (module-level helper) — `src/symmetric/cipher.rs`. Enclosing false branch: `decrypt`.


<a id="cause-AesCtrCounterAbiWidth"></a>

### `AesCtrCounterAbiWidth`


Local detection/handling phase and implementation owner:

- `counter_width` (module-level helper) — `src/symmetric/cipher.rs`.


<a id="cause-AesCtrCounterWidth"></a>

### `AesCtrCounterWidth`


Local detection/handling phase and implementation owner:

- `counter_width` (module-level helper) — `src/symmetric/cipher.rs`. Enclosing true branch: `!(1..=128).contains(&bits)`.


<a id="cause-CcmAadLength"></a>

### `CcmAadLength`


Local detection/handling phase and implementation owner:

- `validate_ccm_fields` (module-level helper) — `src/symmetric/ccm.rs`. Enclosing true branch: `layout == super::AeadParameterLayout::Classic && aad_length as u128 > u32::MAX as u128`.


<a id="cause-CcmMacRepresentationDoesNotMatchRoute"></a>

### `CcmMacRepresentationDoesNotMatchRoute`


Local detection/handling phase and implementation owner:

- `dimensions` (module-level helper) — `src/symmetric/ccm.rs`. Enclosing match alternative: `_`.


<a id="cause-CcmMacWidth"></a>

### `CcmMacWidth`


Local detection/handling phase and implementation owner:

- `dimensions` (module-level helper) — `src/symmetric/ccm.rs`.
- `Session::classic_ccm` — `src/symmetric/ccm.rs`. Enclosing true branch: `request.decrypt()`.


<a id="cause-CcmMessageRequiresSeparateMac"></a>

### `CcmMessageRequiresSeparateMac`


Local detection/handling phase and implementation owner:

- `Session::ccm` — `src/symmetric/ccm.rs`. Enclosing match alternative: `Request::DecryptAppended`.


<a id="cause-CcmMessageRouteRequired"></a>

### `CcmMessageRouteRequired`


Local detection/handling phase and implementation owner:

- `Session::ccm` — `src/symmetric/ccm.rs`.


<a id="cause-CcmCiphertextShorterThanMac"></a>

### `CcmCiphertextShorterThanMac`


Local detection/handling phase and implementation owner:

- `dimensions` (module-level helper) — `src/symmetric/ccm.rs`. Enclosing match alternative: `Request::DecryptAppended if !route.message()`.


<a id="cause-CcmDataLength"></a>

### `CcmDataLength`


Local detection/handling phase and implementation owner:

- `validate_ccm_fields` (module-level helper) — `src/symmetric/ccm.rs`.


<a id="cause-CcmDataLengthExceedsNonceEncoding"></a>

### `CcmDataLengthExceedsNonceEncoding`


Local detection/handling phase and implementation owner:

- `validate_ccm_fields` (module-level helper) — `src/symmetric/ccm.rs`. Enclosing true branch: `q < 8 && length >= (1u64 << (8 * q))`.


<a id="cause-CcmFixedBitsAbiWidth"></a>

### `CcmFixedBitsAbiWidth`


Local detection/handling phase and implementation owner:

- `validate_ccm_fields` (module-level helper) — `src/symmetric/ccm.rs`.


<a id="cause-CcmFixedBitsExceedNonce"></a>

### `CcmFixedBitsExceedNonce`


Local detection/handling phase and implementation owner:

- `validate_ccm_fields` (module-level helper) — `src/symmetric/ccm.rs`. Enclosing true branch: `!decrypt && fixed_bits > nonce_length as u64 * 8`.


<a id="cause-CcmNonceLength"></a>

### `CcmNonceLength`


Local detection/handling phase and implementation owner:

- `validate_ccm_fields` (module-level helper) — `src/symmetric/ccm.rs`. Enclosing true branch: `!(7..=13).contains(&nonce_length)`.


<a id="cause-CcmRequiresAnAesKey"></a>

### `CcmRequiresAnAesKey`


Local detection/handling phase and implementation owner:

- `Session::classic_ccm` — `src/symmetric/ccm.rs`. Enclosing true branch: `!matches!( key.algorithm, SymmetricAlgorithm::Aes128 | SymmetricAlgorithm::Aes192 | SymmetricAlgorithm::Aes256 )`.


<a id="cause-CcmRequiresDeclaredPlaintextLength"></a>

### `CcmRequiresDeclaredPlaintextLength`


Local detection/handling phase and implementation owner:

- `ClassicAeadParameters<'_>::validate_stream_parameters` — `src/symmetric/classic_aead.rs`. Enclosing match alternative: `Self::Ccm { nonce, aad, mac_length, }`.


<a id="cause-CkmNullHasNoParameters"></a>

### `CkmNullHasNoParameters`


Local detection/handling phase and implementation owner:

- `CipherParameters<'a>::from_fixed` — `src/symmetric/block.rs`. Enclosing false branch: `iv.is_empty()`.


<a id="cause-CtrBitsOnStructuredCipherParameters"></a>

### `CtrBitsOnStructuredCipherParameters`


Local detection/handling phase and implementation owner:

- `CipherFrame::block_record_request_with_options` — `src/symmetric/cipher.rs`. Enclosing true branch: `counter_bits.is_some()`.


<a id="cause-CtrCounterBlockWidth"></a>

### `CtrCounterBlockWidth`


Local detection/handling phase and implementation owner:

- `CipherFrame::record_request` — `src/symmetric/cipher.rs`. Enclosing true branch: `kind == CKM_AES_CTR as u64`.
- `CipherFrame::fill_native_iv` — `src/symmetric/cipher/snapshot.rs`. Enclosing match alternative: `Parameters::Ctr { native, .. }`.


<a id="cause-CtrCounterWidthAbsent"></a>

### `CtrCounterWidthAbsent`


Local detection/handling phase and implementation owner:

- `CipherFrame::record_request` — `src/symmetric/cipher.rs`. Enclosing true branch: `kind == CKM_AES_CTR as u64`.


<a id="cause-CamelliaCtrWidthAbsent"></a>

### `CamelliaCtrWidthAbsent`


Local detection/handling phase and implementation owner:

- `CipherFrame::block_record_request_with_options` — `src/symmetric/cipher.rs`. Enclosing true branch: `native_kind == CKM_CAMELLIA_CTR`.


<a id="cause-CamelliaCounterBlockWidth"></a>

### `CamelliaCounterBlockWidth`


Local detection/handling phase and implementation owner:

- `CipherFrame::block_record_request_with_options` — `src/symmetric/cipher.rs`. Enclosing true branch: `native_kind == CKM_CAMELLIA_CTR`.
- `CipherFrame::fill_native_iv` — `src/symmetric/cipher/snapshot.rs`. Enclosing match alternative: `Parameters::CamelliaCtr { native, .. }`.


<a id="cause-ChachaNonceWidth"></a>

### `ChachaNonceWidth`


Local detection/handling phase and implementation owner:

- `StreamAeadNonce::from_record` — `src/symmetric/poly1305.rs`. Enclosing match alternative: `(kind, 8) if kind == CKM_CHACHA20_POLY1305 as u64`.
- `StreamAeadNonce::from_record` — `src/symmetric/poly1305.rs`. Enclosing match alternative: `(kind, 12) if kind == CKM_CHACHA20_POLY1305 as u64`.
- `StreamAeadNonce::from_record` — `src/symmetric/poly1305.rs`. Enclosing match alternative: `(kind, 24) if kind == CKM_CHACHA20_POLY1305 as u64`.


<a id="cause-Chacha20IetfMessageLength"></a>

### `Chacha20IetfMessageLength`


Local detection/handling phase and implementation owner:

- `StreamCipherParameters::output_bounds` — `src/symmetric/stream.rs`. Enclosing true branch: `matches!(self, Self::ChaCha20Ietf { .. }) && input as u128 > (1u128 << 38)`.


<a id="cause-EcbDoesNotHaveIvParameters"></a>

### `EcbDoesNotHaveIvParameters`


Local detection/handling phase and implementation owner:

- `CipherFrame::classic_request` — `src/symmetric/cipher.rs`. Enclosing false branch: `iv.is_empty()`.


<a id="cause-EcbHasNoIv"></a>

### `EcbHasNoIv`


Local detection/handling phase and implementation owner:

- `CipherParameters<'a>::from_fixed` — `src/symmetric/block.rs`. Enclosing false branch: `iv.is_empty()`.
- `CipherParameters<'a>::from_fixed` — `src/symmetric/block.rs`. Enclosing false branch: `iv.is_empty()`.
- `CipherParameters<'a>::from_fixed` — `src/symmetric/block.rs`. Enclosing false branch: `iv.is_empty()`.
- `CipherParameters<'a>::from_fixed` — `src/symmetric/block.rs`. Enclosing false branch: `iv.is_empty()`.
- `CipherParameters<'a>::from_fixed` — `src/symmetric/block.rs`. Enclosing false branch: `iv.is_empty()`.
- `CipherParameters<'a>::from_fixed` — `src/symmetric/block.rs`. Enclosing false branch: `iv.is_empty()`.
- `CipherParameters<'a>::from_fixed` — `src/symmetric/block.rs`. Enclosing false branch: `iv.is_empty()`.


<a id="cause-GcmIvLength"></a>

### `GcmIvLength`


Local detection/handling phase and implementation owner:

- `AeadNonce::validate_gcm_dimensions` — `src/symmetric.rs`.


<a id="cause-GcmMessageSelectionRequired"></a>

### `GcmMessageSelectionRequired`


Local detection/handling phase and implementation owner:

- `Session::owned_aead_route` — `src/symmetric/operations.rs`. Enclosing match alternative: `OwnedAeadSelection::Stream(_)`.


<a id="cause-GcmFixedBitsAbiWidth"></a>

### `GcmFixedBitsAbiWidth`


Local detection/handling phase and implementation owner:

- `AeadNonce::validate_gcm_dimensions` — `src/symmetric.rs`.


<a id="cause-GcmGeneratorAbiWidth"></a>

### `GcmGeneratorAbiWidth`


Local detection/handling phase and implementation owner:

- `AeadNonce::generator` — `src/symmetric.rs`. Enclosing match alternative: `Self::Gcm { generator, .. }`.
- `AeadNonce::validate_gcm_dimensions` — `src/symmetric.rs`.


<a id="cause-GcmMessageEncryptionRouteRequired"></a>

### `GcmMessageEncryptionRouteRequired`


Local detection/handling phase and implementation owner:

- `Session::owned_aead_route` — `src/symmetric/operations.rs`. Enclosing true branch: `message_init.is_some() && (decrypt || multipart || !selection.gcm_message_capable())`.


<a id="cause-GcmNormativeParameterBounds"></a>

### `GcmNormativeParameterBounds`


Local detection/handling phase and implementation owner:

- `AeadNonce::validate_gcm` — `src/symmetric.rs`. Enclosing true branch: `self.fixed_bits() > self.iv().len() as u64 * 8`.
- `AeadNonce::validate_gcm_message_encrypt` — `src/symmetric.rs`. Enclosing true branch: `self.fixed_bits() > self.iv().len() as u64 * 8`.
- `AeadNonce::validate_gcm_dimensions` — `src/symmetric.rs`. Enclosing true branch: `len == 0 || len > u32::MAX as u64 || layout == AeadParameterLayout::Classic && aad_len as u128 > u32::MAX as u128`.
- `RecordSelection<'a>::validate` — `src/advanced/aead_parameters.rs`. Enclosing true branch: `!decrypt && self.scalars.fixed_bits > self.iv.len() as u64 * 8`.
- `ClassicAeadParameters<'_>::validate_stream_parameters` — `src/symmetric/classic_aead.rs`. Enclosing true branch: `iv.is_empty() || iv.len() as u128 > u32::MAX as u128 || aad.len() as u128 > u32::MAX as u128`.


<a id="cause-GcmTagAbiWidth"></a>

### `GcmTagAbiWidth`


Local detection/handling phase and implementation owner:

- `CipherFrame::allocation_bytes` — `src/symmetric/cipher.rs`. Enclosing match alternative: `DualCipher::Gcm { nonce, aad }`.
- `Snapshot::from_buffers` — `src/symmetric/cipher/snapshot.rs`. Enclosing match alternative: `ParameterShape::Gcm(selection)`.


<a id="cause-GcmTagBitLength"></a>

### `GcmTagBitLength`


Local detection/handling phase and implementation owner:

- `AeadNonce::tag_bytes` — `src/symmetric.rs`. Enclosing true branch: `self.tag_bits() > 128`.
- `AeadNonce::validate_gcm_dimensions` — `src/symmetric.rs`. Enclosing true branch: `tag_bits > 128`.
- `RecordSelection<'a>::tag_bytes` — `src/advanced/aead_parameters.rs`. Enclosing match alternative: `CipherKind::Gcm`.


<a id="cause-GostEcbHasNoParameter"></a>

### `GostEcbHasNoParameter`


Local detection/handling phase and implementation owner:

- `CipherParameters<'a>::from_fixed` — `src/symmetric/block.rs`. Enclosing false branch: `iv.is_empty()`.


<a id="cause-GostIvWidth"></a>

### `GostIvWidth`


Local detection/handling phase and implementation owner:

- `CipherFrame::block_record_request_with_options` — `src/symmetric/cipher.rs`. Enclosing false branch: `iv.is_empty()`.


<a id="cause-GostOutputLengthOverflow"></a>

### `GostOutputLengthOverflow`

Detected in local output-bound arithmetic before a candidate output length
can be produced: tag addition, wrapping overhead/alignment or block rounding
cannot fit usize. This helper makes no native call. Correct/reduce the request
dimensions rather than increasing credits, truncating or wrapping the length.
An enclosing existing operation retains its own prior-effect/ownership contract;
this local calculation does not authorize its replay.


Local detection/handling phase and implementation owner:

- `CipherParameters<'a>::output_bounds` — `src/symmetric/block.rs`. Enclosing match alternative: `Self::Gost28147 { .. }`.


<a id="cause-HmacKeyTypeOnAead"></a>

### `HmacKeyTypeOnAead`


Local detection/handling phase and implementation owner:

- `SymmetricAlgorithm::key_type` — `src/symmetric.rs`. Enclosing true branch: `kind.is_some()`.


<a id="cause-HmacKeyTypeRequired"></a>

### `HmacKeyTypeRequired`


Local detection/handling phase and implementation owner:

- `SymmetricAlgorithm::key_type` — `src/symmetric.rs`. Enclosing match alternative: `None`.


<a id="cause-IetfAeadNonceWidth"></a>

### `IetfAeadNonceWidth`


Local detection/handling phase and implementation owner:

- `Session::owned_aead_route` — `src/symmetric/operations.rs`. Enclosing match alternative: `OwnedAeadSelection::Legacy { algorithm: SymmetricAlgorithm::ChaCha20, nonce, }`.


<a id="cause-IetfChacha20Poly1305Parameters"></a>

### `IetfChacha20Poly1305Parameters`


Local detection/handling phase and implementation owner:

- `OwnedAeadSelection::validate` — `src/symmetric/aead_selection.rs`. Enclosing true branch: `nonce.iv().len() != 12 || nonce.tag_bits() != 128 || nonce.generated() || nonce.fixed_bits() != 0`.


<a id="cause-MacKeyUsedForAead"></a>

### `MacKeyUsedForAead`


Local detection/handling phase and implementation owner:

- `OwnedAeadSelection::validate` — `src/symmetric/aead_selection.rs`. Enclosing true branch: `algorithm.mac()`.


<a id="cause-MacOutputUnavailable"></a>

### `MacOutputUnavailable`


Local detection/handling phase and implementation owner:

- `Session::compute_mac` — `src/symmetric/operations.rs`.
- `Session::compute_mac_multipart` — `src/symmetric/operations.rs`.
- `Session::compute_introduced_mac` — `src/transport/secret_keys.rs`.
- `Session::compute_introduced_mac_multipart` — `src/transport/secret_keys.rs`.


<a id="cause-RcCipherIvLength"></a>

### `RcCipherIvLength`


Local detection/handling phase and implementation owner:

- `RcCipherParameters<'a>::validate` — `src/symmetric/structured.rs`. Enclosing true branch: `self.iv_bytes().len() != expected`.


<a id="cause-RcParameterNativeWidth"></a>

### `RcParameterNativeWidth`


Local detection/handling phase and implementation owner:

- `scalar` (module-level helper) — `src/symmetric/structured.rs`.


<a id="cause-RcRecordMechanismOptionsMismatch"></a>

### `RcRecordMechanismOptionsMismatch`


Local detection/handling phase and implementation owner:

- `RcCipherParameters<'a>::from_record` — `src/symmetric/structured.rs`. Enclosing match alternative: `_`.


<a id="cause-Rc2IvWidth"></a>

### `Rc2IvWidth`


Local detection/handling phase and implementation owner:

- `RcCipherParameters<'a>::from_record` — `src/symmetric/structured.rs`. Enclosing match alternative: `(CKM_RC2_CBC, CipherOptions::Rc2 { effective_bits })`.
- `RcCipherParameters<'a>::from_record` — `src/symmetric/structured.rs`. Enclosing match alternative: `(CKM_RC2_CBC_PAD, CipherOptions::Rc2 { effective_bits })`.
- `RcNative::fill_snapshot_iv` — `src/symmetric/structured.rs`. Enclosing true branch: `let Self::Rc2Cbc(parameters) = self`.


<a id="cause-Rc5BlockSize"></a>

### `Rc5BlockSize`


Local detection/handling phase and implementation owner:

- `RcCipherParameters<'a>::block_size` — `src/symmetric/structured.rs`. Enclosing match alternative: `CipherOptions::Rc5 { word_bytes, rounds }`.


<a id="cause-SalsaNonceWidth"></a>

### `SalsaNonceWidth`


Local detection/handling phase and implementation owner:

- `StreamAeadNonce::from_record` — `src/symmetric/poly1305.rs`. Enclosing match alternative: `(kind, 8) if kind == CKM_SALSA20_POLY1305 as u64`.
- `StreamAeadNonce::from_record` — `src/symmetric/poly1305.rs`. Enclosing match alternative: `(kind, 24) if kind == CKM_SALSA20_POLY1305 as u64`.


<a id="cause-BlockCipherIvWidth"></a>

### `BlockCipherIvWidth`


Local detection/handling phase and implementation owner:

- `CipherParameters<'a>::from_fixed` — `src/symmetric/block.rs`. Enclosing match alternative: `CKM_CAST_CBC`.
- `CipherParameters<'a>::from_fixed` — `src/symmetric/block.rs`. Enclosing match alternative: `CKM_CAST_CBC_PAD`.
- `CipherParameters<'a>::from_fixed` — `src/symmetric/block.rs`. Enclosing match alternative: `CKM_CAST3_CBC`.
- `CipherParameters<'a>::from_fixed` — `src/symmetric/block.rs`. Enclosing match alternative: `CKM_CAST3_CBC_PAD`.
- `CipherParameters<'a>::from_fixed` — `src/symmetric/block.rs`. Enclosing match alternative: `CKM_CAST5_CBC`.
- `CipherParameters<'a>::from_fixed` — `src/symmetric/block.rs`. Enclosing match alternative: `CKM_CAST5_CBC_PAD`.
- `CipherParameters<'a>::from_fixed` — `src/symmetric/block.rs`. Enclosing match alternative: `CKM_DES_CBC`.
- `CipherParameters<'a>::from_fixed` — `src/symmetric/block.rs`. Enclosing match alternative: `CKM_DES_CBC_PAD`.
- `CipherParameters<'a>::from_fixed` — `src/symmetric/block.rs`. Enclosing match alternative: `CKM_DES3_CBC`.
- `CipherParameters<'a>::from_fixed` — `src/symmetric/block.rs`. Enclosing match alternative: `CKM_DES3_CBC_PAD`.
- `CipherParameters<'a>::from_fixed` — `src/symmetric/block.rs`. Enclosing match alternative: `CKM_CDMF_CBC`.
- `CipherParameters<'a>::from_fixed` — `src/symmetric/block.rs`. Enclosing match alternative: `CKM_CDMF_CBC_PAD`.
- `CipherParameters<'a>::from_fixed` — `src/symmetric/block.rs`. Enclosing match alternative: `CKM_IDEA_CBC`.
- `CipherParameters<'a>::from_fixed` — `src/symmetric/block.rs`. Enclosing match alternative: `CKM_IDEA_CBC_PAD`.
- `CipherParameters<'a>::from_fixed` — `src/symmetric/block.rs`. Enclosing match alternative: `CKM_CAMELLIA_CBC`.
- `CipherParameters<'a>::from_fixed` — `src/symmetric/block.rs`. Enclosing match alternative: `CKM_CAMELLIA_CBC_PAD`.
- `CipherParameters<'a>::from_fixed` — `src/symmetric/block.rs`. Enclosing match alternative: `CKM_ARIA_CBC`.
- `CipherParameters<'a>::from_fixed` — `src/symmetric/block.rs`. Enclosing match alternative: `CKM_ARIA_CBC_PAD`.
- `CipherParameters<'a>::from_fixed` — `src/symmetric/block.rs`. Enclosing match alternative: `CKM_SEED_CBC`.
- `CipherParameters<'a>::from_fixed` — `src/symmetric/block.rs`. Enclosing match alternative: `CKM_SEED_CBC_PAD`.
- `CipherParameters<'a>::from_fixed` — `src/symmetric/block.rs`. Enclosing match alternative: `CKM_DES_OFB64`.
- `CipherParameters<'a>::from_fixed` — `src/symmetric/block.rs`. Enclosing match alternative: `CKM_DES_OFB8`.
- `CipherParameters<'a>::from_fixed` — `src/symmetric/block.rs`. Enclosing match alternative: `CKM_DES_CFB64`.
- `CipherParameters<'a>::from_fixed` — `src/symmetric/block.rs`. Enclosing match alternative: `CKM_DES_CFB8`.
- `CipherParameters<'a>::from_fixed` — `src/symmetric/block.rs`. Enclosing match alternative: `CKM_BLOWFISH_CBC`.
- `CipherParameters<'a>::from_fixed` — `src/symmetric/block.rs`. Enclosing match alternative: `CKM_BLOWFISH_CBC_PAD`.
- `CipherParameters<'a>::from_fixed` — `src/symmetric/block.rs`. Enclosing match alternative: `CKM_TWOFISH_CBC`.
- `CipherParameters<'a>::from_fixed` — `src/symmetric/block.rs`. Enclosing match alternative: `CKM_TWOFISH_CBC_PAD`.
- `CipherParameters<'a>::from_fixed` — `src/symmetric/block.rs`. Enclosing match alternative: `CKM_AES_CTS`.
- `CipherParameters<'a>::from_fixed` — `src/symmetric/block.rs`. Enclosing match alternative: `CKM_AES_XTS`.


<a id="cause-BlockCipherInputLength"></a>

### `BlockCipherInputLength`


Local detection/handling phase and implementation owner:

- `FixedContract::output_bounds` — `src/symmetric/block.rs`. Enclosing false branch: `decrypt`.


<a id="cause-BlockCipherMechanismWidth"></a>

### `BlockCipherMechanismWidth`


Local detection/handling phase and implementation owner:

- `CipherParameters<'a>::from_fixed` — `src/symmetric/block.rs`.
- `CipherFrame::block_record_request_with_options` — `src/symmetric/cipher.rs`.


<a id="cause-BlockCipherNativeIdentifierWidth"></a>

### `BlockCipherNativeIdentifierWidth`


Local detection/handling phase and implementation owner:

- `Snapshot::for_block` — `src/symmetric/cipher/snapshot.rs`.


<a id="cause-BlockCipherPaddingLengthOverflow"></a>

### `BlockCipherPaddingLengthOverflow`


Local detection/handling phase and implementation owner:

- `FixedContract::output_bounds` — `src/symmetric/block.rs`. Enclosing match alternative: `LengthRule::Padded`.


<a id="cause-CipherParameterIdentity"></a>

### `CipherParameterIdentity`


Local detection/handling phase and implementation owner:

- `CipherFrame::validate_parameters` — `src/symmetric/cipher.rs`. Enclosing true branch: `!valid || !output_iv && self.iv.as_slice() != self.expected_iv.as_slice() || self.aad.as_slice() != self.expected_aad.as_slice()`.
- `CipherFrame::fill_snapshot` — `src/symmetric/cipher/snapshot.rs`. Enclosing true branch: `source.aad.as_slice() != source.expected_aad.as_slice()`.


<a id="cause-CipherSnapshotParameterShapeChanged"></a>

### `CipherSnapshotParameterShapeChanged`


Local detection/handling phase and implementation owner:

- `CipherFrame::fill_record_bytes` — `src/symmetric/cipher/snapshot.rs`. Enclosing true branch: `self.kind() as u64 != kind || self.iv.as_slice().len() != iv.len() || self.expected_iv.as_slice().len() != iv.len() || self.aad.as_slice().len() != aad.len() || self.expected_aad.as_slice().len() != aad.len()`.
- `CipherFrame::fill_block_request` — `src/symmetric/cipher/snapshot.rs`. Enclosing true branch: `self.kind() as u64 != selection.mechanism_number() || self.iv.as_slice().len() != selection.iv_bytes().len() || self.expected_iv.as_slice().len() != selection.iv_bytes().len()`.
- `CipherFrame::fill_snapshot` — `src/symmetric/cipher/snapshot.rs`. Enclosing true branch: `self.kind() != source.kind() || self.iv.capacity() != source.expected_iv.capacity() || self.expected_iv.capacity() != source.expected_iv.capacity() || self.aad.capacity() != source.aad.capacity() || self.expected_aad.capacity() != source.expected_aad.capacity()`.


<a id="cause-ClassicAeadResultRequired"></a>

### `ClassicAeadResultRequired`


Local detection/handling phase and implementation owner:

- `AeadPlaintext::into_classic_parts` — `src/symmetric.rs`.


<a id="cause-ClassicAeadTagLength"></a>

### `ClassicAeadTagLength`


Local detection/handling phase and implementation owner:

- `ClassicAeadParameters<'_>::tag_bits` — `src/symmetric/classic_aead.rs`. Enclosing match alternative: `_`.


<a id="cause-ClassicAesIvWidth"></a>

### `ClassicAesIvWidth`


Local detection/handling phase and implementation owner:

- `CipherFrame::classic_request` — `src/symmetric/cipher.rs`.


<a id="cause-ClassicAesMechanism"></a>

### `ClassicAesMechanism`


Local detection/handling phase and implementation owner:

- `ClassicMode::from_native` — `src/symmetric/cipher.rs`. Enclosing match alternative: `_`.
- `CipherFrame::classic_request` — `src/symmetric/cipher.rs`. Enclosing match alternative: `_`.


<a id="cause-ClassicGcmDoesNotGenerateAnIv"></a>

### `ClassicGcmDoesNotGenerateAnIv`


Local detection/handling phase and implementation owner:

- `CipherFrame::allocation_bytes` — `src/symmetric/cipher.rs`. Enclosing true branch: `nonce.generated() || nonce.fixed_bits() != 0`.
- `RecordPlan<'a>::with_projection` — `src/advanced/dual/snapshot/record_plan.rs`. Enclosing true branch: `generator != 0 || fixed_bits != 0`.
- `Snapshot::for_dual` — `src/symmetric/cipher/snapshot.rs`. Enclosing true branch: `nonce.generated() || nonce.fixed_bits() != 0`.


<a id="cause-CompletedTokenIvWidth"></a>

### `CompletedTokenIvWidth`


Local detection/handling phase and implementation owner:

- `CipherFrame::generated_iv` — `src/symmetric/cipher.rs`. Enclosing true branch: `matches!( self.parameters, Parameters::TokenIv { generated: true, .. } )`.


<a id="cause-CounterWidthOnGostParameters"></a>

### `CounterWidthOnGostParameters`


Local detection/handling phase and implementation owner:

- `CipherFrame::block_record_request_with_options` — `src/symmetric/cipher.rs`. Enclosing true branch: `counter_bits.is_some()`.


<a id="cause-CounterWidthOnFixedBlockCipher"></a>

### `CounterWidthOnFixedBlockCipher`


Local detection/handling phase and implementation owner:

- `CipherFrame::block_record_request_with_options` — `src/symmetric/cipher.rs`. Enclosing true branch: `counter_bits.is_some()`.


<a id="cause-CounterWidthOnNonCtrCipher"></a>

### `CounterWidthOnNonCtrCipher`


Local detection/handling phase and implementation owner:

- `CipherFrame::record_request` — `src/symmetric/cipher.rs`. Enclosing true branch: `counter_bits.is_some()`.


<a id="cause-DualCipherStorageSize"></a>

### `DualCipherStorageSize`


Local detection/handling phase and implementation owner:

- `CipherFrame::allocation_bytes` — `src/symmetric/cipher.rs`.
- `RecordPlan<'a>::with_projection` — `src/advanced/dual/snapshot/record_plan.rs`. Enclosing true branch: `descriptor.mechanism == CKM_AES_GCM as u64`.


<a id="cause-FixedBlockCipherContractAbsent"></a>

### `FixedBlockCipherContractAbsent`


Local detection/handling phase and implementation owner:

- `CipherParameters<'a>::from_fixed` — `src/symmetric/block.rs`. Enclosing match alternative: `_`.
- `Snapshot::for_block` — `src/symmetric/cipher/snapshot.rs`. Enclosing match alternative: `_`.


<a id="cause-NativeNonceRoute"></a>

### `NativeNonceRoute`


Local detection/handling phase and implementation owner:

- `Session::owned_aead_route` — `src/symmetric/operations.rs`. Enclosing true branch: `generated && (decrypt || multipart || !selection.gcm_message_capable())`.


<a id="cause-NonRcOptionsOnRcParameters"></a>

### `NonRcOptionsOnRcParameters`


Local detection/handling phase and implementation owner:

- `RcCipherParameters<'a>::block_size` — `src/symmetric/structured.rs`. Enclosing match alternative: `CipherOptions::CcmDataLength { .. } | CipherOptions::Stream { .. } | CipherOptions::GcmWithoutIvBits | CipherOptions::TokenIv { .. } | CipherOptions::ChaChaIetfBytes`.


<a id="cause-ParameterlessCipherHasNoIv"></a>

### `ParameterlessCipherHasNoIv`


Local detection/handling phase and implementation owner:

- `CipherParameters<'a>::from_fixed` — `src/symmetric/block.rs`. Enclosing false branch: `iv.is_empty()`.
- `CipherParameters<'a>::from_fixed` — `src/symmetric/block.rs`. Enclosing false branch: `iv.is_empty()`.
- `CipherParameters<'a>::from_fixed` — `src/symmetric/block.rs`. Enclosing false branch: `iv.is_empty()`.
- `CipherParameters<'a>::from_fixed` — `src/symmetric/block.rs`. Enclosing false branch: `iv.is_empty()`.


<a id="cause-RestoredTokenIvWidth"></a>

### `RestoredTokenIvWidth`


Local detection/handling phase and implementation owner:

- `CipherFrame::restore_generated_iv` — `src/symmetric/cipher.rs`. Enclosing true branch: `observed.len() != 24 || self.iv.capacity() != 24 || self.expected_iv.capacity() != 24`.


<a id="cause-StreamAeadMechanismNonceTuple"></a>

### `StreamAeadMechanismNonceTuple`


Local detection/handling phase and implementation owner:

- `StreamAeadNonce::from_record` — `src/symmetric/poly1305.rs`. Enclosing match alternative: `_`.


<a id="cause-StreamCounterWidth"></a>

### `StreamCounterWidth`


Local detection/handling phase and implementation owner:

- `StreamCounter::from_wire` — `src/symmetric/stream.rs`. Enclosing match alternative: `_`.


<a id="cause-StreamMechanismCounterNonceTuple"></a>

### `StreamMechanismCounterNonceTuple`


Local detection/handling phase and implementation owner:

- `StreamCipherParameters::from_record` — `src/symmetric/stream.rs`. Enclosing match alternative: `_`.


<a id="cause-StreamNonceWidth"></a>

### `StreamNonceWidth`


Local detection/handling phase and implementation owner:

- `StreamCipherParameters::from_record` — `src/symmetric/stream.rs`. Enclosing match alternative: `(CKM_CHACHA20, StreamCounter::Bits64(counter), 8)`.
- `StreamCipherParameters::from_record` — `src/symmetric/stream.rs`. Enclosing match alternative: `(CKM_CHACHA20, StreamCounter::Bits32(counter), 12)`.
- `StreamCipherParameters::from_record` — `src/symmetric/stream.rs`. Enclosing match alternative: `(CKM_CHACHA20, StreamCounter::Bits64(counter), 24)`.
- `StreamCipherParameters::from_record` — `src/symmetric/stream.rs`. Enclosing match alternative: `(CKM_SALSA20, StreamCounter::Bits64(counter), 8)`.
- `StreamCipherParameters::from_record` — `src/symmetric/stream.rs`. Enclosing match alternative: `(CKM_SALSA20, StreamCounter::Bits64(counter), 24)`.


<a id="cause-StreamSnapshotCounterAbsent"></a>

### `StreamSnapshotCounterAbsent`


Local detection/handling phase and implementation owner:

- `Snapshot::from_buffers` — `src/symmetric/cipher/snapshot.rs`. Enclosing match alternative: `ParameterShape::Stream(selection)`.


<a id="cause-StreamSnapshotCounterWidth"></a>

### `StreamSnapshotCounterWidth`


Local detection/handling phase and implementation owner:

- `StreamFrame::from_counter` — `src/symmetric/stream.rs`. Enclosing true branch: `counter.capacity() != expected_counter.bytes().len()`.


<a id="cause-StreamSnapshotSelection"></a>

### `StreamSnapshotSelection`


Local detection/handling phase and implementation owner:

- `CipherFrame::prepare_snapshot_parameters` — `src/symmetric/cipher/snapshot.rs`. Enclosing match alternative: `_`.


<a id="cause-SymmetricFragmentCeiling"></a>

### `SymmetricFragmentCeiling`


Local detection/handling phase and implementation owner:

- `input_size_lengths` (module-level helper) — `src/symmetric.rs`. Enclosing true branch: `count > limits.maximum_parts`.


<a id="cause-SymmetricFragmentCountChanged"></a>

### `SymmetricFragmentCountChanged`


Local detection/handling phase and implementation owner:

- `input_size_lengths` (module-level helper) — `src/symmetric.rs`. Enclosing true branch: `observed == count`.
- `input_size_lengths` (module-level helper) — `src/symmetric.rs`. Enclosing true branch: `observed != count`.


<a id="cause-SymmetricInputOverflow"></a>

### `SymmetricInputOverflow`


Local detection/handling phase and implementation owner:

- `input_size_lengths` (module-level helper) — `src/symmetric.rs`.


<a id="cause-SymmetricTotalInputCeiling"></a>

### `SymmetricTotalInputCeiling`


Local detection/handling phase and implementation owner:

- `input_size_lengths` (module-level helper) — `src/symmetric.rs`. Enclosing true branch: `n.saturating_sub(tag_overhead) .checked_add(aad_length) .filter(|n| *n <= limits.maximum_total_bytes) .is_none()`.


<a id="cause-TokenIvDirectionDiffersFromCipherOperation"></a>

### `TokenIvDirectionDiffersFromCipherOperation`


Local detection/handling phase and implementation owner:

- `TokenIv::validate_direction` — `src/symmetric/token_iv.rs`. Enclosing match alternative: `_`.


<a id="cause-TokenIvRecordMechanism"></a>

### `TokenIvRecordMechanism`


Local detection/handling phase and implementation owner:

- `CipherFrame::block_record_request_with_options` — `src/symmetric/cipher.rs`. Enclosing match alternative: `CipherOptions::TokenIv { generated }`.


<a id="cause-TokenIvRecordWidth"></a>

### `TokenIvRecordWidth`


Local detection/handling phase and implementation owner:

- `CipherFrame::block_record_request_with_options` — `src/symmetric/cipher.rs`. Enclosing match alternative: `CipherOptions::TokenIv { generated }`.


<a id="cause-TokenIvCipherInputAlignment"></a>

### `TokenIvCipherInputAlignment`


Local detection/handling phase and implementation owner:

- `TokenIvCipher::output_bounds` — `src/symmetric/token_iv.rs`. Enclosing true branch: `input % unit != 0`.


<a id="cause-TraditionalCcmHasNoNonceGenerationFields"></a>

### `TraditionalCcmHasNoNonceGenerationFields`


Local detection/handling phase and implementation owner:

- `dimensions` (module-level helper) — `src/symmetric/ccm.rs`. Enclosing true branch: `!route.message() && (parameters.nonce.generator != CKG_NO_GENERATE as u64 || parameters.nonce.fixed_bits != 0)`.
