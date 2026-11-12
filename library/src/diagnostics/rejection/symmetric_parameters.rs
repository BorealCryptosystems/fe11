// SPDX-License-Identifier: Apache-2.0
//! SymmetricParameters causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to symmetric parameters.
#[doc = include_str!("../../../docs/diagnostics/rejection-symmetric_parameters.md")]
pub enum SymmetricParametersRejection {
    /// 32-bit stream counter length. [Detection, owner and recovery](#cause-Value32BitStreamCounterLength).
    Value32BitStreamCounterLength,
    /// 64-bit stream counter length. [Detection, owner and recovery](#cause-Value64BitStreamCounterLength).
    Value64BitStreamCounterLength,
    /// AEAD completion selection mismatch. [Detection, owner and recovery](#cause-AeadCompletionSelectionMismatch).
    AeadCompletionSelectionMismatch,
    /// AEAD key used for MAC. [Detection, owner and recovery](#cause-AeadKeyUsedForMac).
    AeadKeyUsedForMac,
    /// AEAD output length overflow. [Detection, owner and recovery](#cause-AeadOutputLengthOverflow).
    AeadOutputLengthOverflow,
    /// AEAD requires an admitted secret key. [Detection, owner and recovery](#cause-AeadRequiresAnAdmittedSecretKey).
    AeadRequiresAnAdmittedSecretKey,
    /// AEAD requires its authenticated output owner. [Detection, owner and recovery](#cause-AeadRequiresItsAuthenticatedOutputOwner).
    AeadRequiresItsAuthenticatedOutputOwner,
    /// AEAD retained selection accounting. [Detection, owner and recovery](#cause-AeadRetainedSelectionAccounting).
    AeadRetainedSelectionAccounting,
    /// AES CFB1 IV width. [Detection, owner and recovery](#cause-AesCfb1IvWidth).
    AesCfb1IvWidth,
    /// AES KWP IV width. [Detection, owner and recovery](#cause-AesKwpIvWidth).
    AesKwpIvWidth,
    /// AES cipher mechanism. [Detection, owner and recovery](#cause-AesCipherMechanism).
    AesCipherMechanism,
    /// AES cipher mechanism width. [Detection, owner and recovery](#cause-AesCipherMechanismWidth).
    AesCipherMechanismWidth,
    /// AES input is not block aligned. [Detection, owner and recovery](#cause-AesInputIsNotBlockAligned).
    AesInputIsNotBlockAligned,
    /// AES key wrap IV width. [Detection, owner and recovery](#cause-AesKeyWrapIvWidth).
    AesKeyWrapIvWidth,
    /// AES key wrap contract absent. [Detection, owner and recovery](#cause-AesKeyWrapContractAbsent).
    AesKeyWrapContractAbsent,
    /// AES key wrap mechanism. [Detection, owner and recovery](#cause-AesKeyWrapMechanism).
    AesKeyWrapMechanism,
    /// AES key wrap output length overflow. [Detection, owner and recovery](#cause-AesKeyWrapOutputLengthOverflow).
    AesKeyWrapOutputLengthOverflow,
    /// AES key wrap requires a single-part operation. [Detection, owner and recovery](#cause-AesKeyWrapRequiresASinglePartOperation).
    AesKeyWrapRequiresASinglePartOperation,
    /// AES mechanism width. [Detection, owner and recovery](#cause-AesMechanismWidth).
    AesMechanismWidth,
    /// AES output overflow. [Detection, owner and recovery](#cause-AesOutputOverflow).
    AesOutputOverflow,
    /// AES-CTR counter ABI width. [Detection, owner and recovery](#cause-AesCtrCounterAbiWidth).
    AesCtrCounterAbiWidth,
    /// AES-CTR counter width. [Detection, owner and recovery](#cause-AesCtrCounterWidth).
    AesCtrCounterWidth,
    /// CCM AAD length. [Detection, owner and recovery](#cause-CcmAadLength).
    CcmAadLength,
    /// CCM MAC representation does not match route. [Detection, owner and recovery](#cause-CcmMacRepresentationDoesNotMatchRoute).
    CcmMacRepresentationDoesNotMatchRoute,
    /// CCM MAC width. [Detection, owner and recovery](#cause-CcmMacWidth).
    CcmMacWidth,
    /// CCM Message requires separate MAC. [Detection, owner and recovery](#cause-CcmMessageRequiresSeparateMac).
    CcmMessageRequiresSeparateMac,
    /// CCM Message route required. [Detection, owner and recovery](#cause-CcmMessageRouteRequired).
    CcmMessageRouteRequired,
    /// CCM ciphertext shorter than MAC. [Detection, owner and recovery](#cause-CcmCiphertextShorterThanMac).
    CcmCiphertextShorterThanMac,
    /// CCM data length. [Detection, owner and recovery](#cause-CcmDataLength).
    CcmDataLength,
    /// CCM data length exceeds nonce encoding. [Detection, owner and recovery](#cause-CcmDataLengthExceedsNonceEncoding).
    CcmDataLengthExceedsNonceEncoding,
    /// CCM fixed bits ABI width. [Detection, owner and recovery](#cause-CcmFixedBitsAbiWidth).
    CcmFixedBitsAbiWidth,
    /// CCM fixed bits exceed nonce. [Detection, owner and recovery](#cause-CcmFixedBitsExceedNonce).
    CcmFixedBitsExceedNonce,
    /// CCM nonce length. [Detection, owner and recovery](#cause-CcmNonceLength).
    CcmNonceLength,
    /// CCM requires an AES key. [Detection, owner and recovery](#cause-CcmRequiresAnAesKey).
    CcmRequiresAnAesKey,
    /// CCM requires declared plaintext length. [Detection, owner and recovery](#cause-CcmRequiresDeclaredPlaintextLength).
    CcmRequiresDeclaredPlaintextLength,
    /// CKM_NULL has no parameters. [Detection, owner and recovery](#cause-CkmNullHasNoParameters).
    CkmNullHasNoParameters,
    /// CTR bits on structured cipher parameters. [Detection, owner and recovery](#cause-CtrBitsOnStructuredCipherParameters).
    CtrBitsOnStructuredCipherParameters,
    /// CTR counter block width. [Detection, owner and recovery](#cause-CtrCounterBlockWidth).
    CtrCounterBlockWidth,
    /// CTR counter width absent. [Detection, owner and recovery](#cause-CtrCounterWidthAbsent).
    CtrCounterWidthAbsent,
    /// Camellia CTR width absent. [Detection, owner and recovery](#cause-CamelliaCtrWidthAbsent).
    CamelliaCtrWidthAbsent,
    /// Camellia counter block width. [Detection, owner and recovery](#cause-CamelliaCounterBlockWidth).
    CamelliaCounterBlockWidth,
    /// ChaCha nonce width. [Detection, owner and recovery](#cause-ChachaNonceWidth).
    ChachaNonceWidth,
    /// ChaCha20 IETF message length. [Detection, owner and recovery](#cause-Chacha20IetfMessageLength).
    Chacha20IetfMessageLength,
    /// ECB does not have IV parameters. [Detection, owner and recovery](#cause-EcbDoesNotHaveIvParameters).
    EcbDoesNotHaveIvParameters,
    /// ECB has no IV. [Detection, owner and recovery](#cause-EcbHasNoIv).
    EcbHasNoIv,
    /// GCM IV length. [Detection, owner and recovery](#cause-GcmIvLength).
    GcmIvLength,
    /// GCM Message selection required. [Detection, owner and recovery](#cause-GcmMessageSelectionRequired).
    GcmMessageSelectionRequired,
    /// GCM fixed bits ABI width. [Detection, owner and recovery](#cause-GcmFixedBitsAbiWidth).
    GcmFixedBitsAbiWidth,
    /// GCM generator ABI width. [Detection, owner and recovery](#cause-GcmGeneratorAbiWidth).
    GcmGeneratorAbiWidth,
    /// GCM message encryption route required. [Detection, owner and recovery](#cause-GcmMessageEncryptionRouteRequired).
    GcmMessageEncryptionRouteRequired,
    /// GCM normative parameter bounds. [Detection, owner and recovery](#cause-GcmNormativeParameterBounds).
    GcmNormativeParameterBounds,
    /// GCM tag ABI width. [Detection, owner and recovery](#cause-GcmTagAbiWidth).
    GcmTagAbiWidth,
    /// GCM tag bit length. [Detection, owner and recovery](#cause-GcmTagBitLength).
    GcmTagBitLength,
    /// GOST ECB has no parameter. [Detection, owner and recovery](#cause-GostEcbHasNoParameter).
    GostEcbHasNoParameter,
    /// GOST IV width. [Detection, owner and recovery](#cause-GostIvWidth).
    GostIvWidth,
    /// GOST output length overflow. [Detection, owner and recovery](#cause-GostOutputLengthOverflow).
    GostOutputLengthOverflow,
    /// HMAC key type on AEAD. [Detection, owner and recovery](#cause-HmacKeyTypeOnAead).
    HmacKeyTypeOnAead,
    /// HMAC key type required. [Detection, owner and recovery](#cause-HmacKeyTypeRequired).
    HmacKeyTypeRequired,
    /// IETF AEAD nonce width. [Detection, owner and recovery](#cause-IetfAeadNonceWidth).
    IetfAeadNonceWidth,
    /// IETF ChaCha20-Poly1305 parameters. [Detection, owner and recovery](#cause-IetfChacha20Poly1305Parameters).
    IetfChacha20Poly1305Parameters,
    /// MAC key used for AEAD. [Detection, owner and recovery](#cause-MacKeyUsedForAead).
    MacKeyUsedForAead,
    /// MAC output unavailable. [Detection, owner and recovery](#cause-MacOutputUnavailable).
    MacOutputUnavailable,
    /// RC cipher IV length. [Detection, owner and recovery](#cause-RcCipherIvLength).
    RcCipherIvLength,
    /// RC parameter native width. [Detection, owner and recovery](#cause-RcParameterNativeWidth).
    RcParameterNativeWidth,
    /// RC record mechanism/options mismatch. [Detection, owner and recovery](#cause-RcRecordMechanismOptionsMismatch).
    RcRecordMechanismOptionsMismatch,
    /// RC2 IV width. [Detection, owner and recovery](#cause-Rc2IvWidth).
    Rc2IvWidth,
    /// RC5 block size. [Detection, owner and recovery](#cause-Rc5BlockSize).
    Rc5BlockSize,
    /// Salsa nonce width. [Detection, owner and recovery](#cause-SalsaNonceWidth).
    SalsaNonceWidth,
    /// Block cipher IV width. [Detection, owner and recovery](#cause-BlockCipherIvWidth).
    BlockCipherIvWidth,
    /// Block cipher input length. [Detection, owner and recovery](#cause-BlockCipherInputLength).
    BlockCipherInputLength,
    /// Block cipher mechanism width. [Detection, owner and recovery](#cause-BlockCipherMechanismWidth).
    BlockCipherMechanismWidth,
    /// Block cipher native identifier width. [Detection, owner and recovery](#cause-BlockCipherNativeIdentifierWidth).
    BlockCipherNativeIdentifierWidth,
    /// Block cipher padding length overflow. [Detection, owner and recovery](#cause-BlockCipherPaddingLengthOverflow).
    BlockCipherPaddingLengthOverflow,
    /// Cipher parameter identity. [Detection, owner and recovery](#cause-CipherParameterIdentity).
    CipherParameterIdentity,
    /// Cipher snapshot parameter shape changed. [Detection, owner and recovery](#cause-CipherSnapshotParameterShapeChanged).
    CipherSnapshotParameterShapeChanged,
    /// Classic AEAD result required. [Detection, owner and recovery](#cause-ClassicAeadResultRequired).
    ClassicAeadResultRequired,
    /// Classic AEAD tag length. [Detection, owner and recovery](#cause-ClassicAeadTagLength).
    ClassicAeadTagLength,
    /// Classic AES IV width. [Detection, owner and recovery](#cause-ClassicAesIvWidth).
    ClassicAesIvWidth,
    /// Classic AES mechanism. [Detection, owner and recovery](#cause-ClassicAesMechanism).
    ClassicAesMechanism,
    /// Classic GCM does not generate an IV. [Detection, owner and recovery](#cause-ClassicGcmDoesNotGenerateAnIv).
    ClassicGcmDoesNotGenerateAnIv,
    /// Completed token IV width. [Detection, owner and recovery](#cause-CompletedTokenIvWidth).
    CompletedTokenIvWidth,
    /// Counter width on GOST parameters. [Detection, owner and recovery](#cause-CounterWidthOnGostParameters).
    CounterWidthOnGostParameters,
    /// Counter width on fixed block cipher. [Detection, owner and recovery](#cause-CounterWidthOnFixedBlockCipher).
    CounterWidthOnFixedBlockCipher,
    /// Counter width on non-CTR cipher. [Detection, owner and recovery](#cause-CounterWidthOnNonCtrCipher).
    CounterWidthOnNonCtrCipher,
    /// Dual cipher storage size. [Detection, owner and recovery](#cause-DualCipherStorageSize).
    DualCipherStorageSize,
    /// Fixed block cipher contract absent. [Detection, owner and recovery](#cause-FixedBlockCipherContractAbsent).
    FixedBlockCipherContractAbsent,
    /// Native nonce route. [Detection, owner and recovery](#cause-NativeNonceRoute).
    NativeNonceRoute,
    /// Non-RC options on RC parameters. [Detection, owner and recovery](#cause-NonRcOptionsOnRcParameters).
    NonRcOptionsOnRcParameters,
    /// Parameterless cipher has no IV. [Detection, owner and recovery](#cause-ParameterlessCipherHasNoIv).
    ParameterlessCipherHasNoIv,
    /// Restored token IV width. [Detection, owner and recovery](#cause-RestoredTokenIvWidth).
    RestoredTokenIvWidth,
    /// Stream AEAD mechanism/nonce tuple. [Detection, owner and recovery](#cause-StreamAeadMechanismNonceTuple).
    StreamAeadMechanismNonceTuple,
    /// Stream counter width. [Detection, owner and recovery](#cause-StreamCounterWidth).
    StreamCounterWidth,
    /// Stream mechanism/counter/nonce tuple. [Detection, owner and recovery](#cause-StreamMechanismCounterNonceTuple).
    StreamMechanismCounterNonceTuple,
    /// Stream nonce width. [Detection, owner and recovery](#cause-StreamNonceWidth).
    StreamNonceWidth,
    /// Stream snapshot counter absent. [Detection, owner and recovery](#cause-StreamSnapshotCounterAbsent).
    StreamSnapshotCounterAbsent,
    /// Stream snapshot counter width. [Detection, owner and recovery](#cause-StreamSnapshotCounterWidth).
    StreamSnapshotCounterWidth,
    /// Stream snapshot selection. [Detection, owner and recovery](#cause-StreamSnapshotSelection).
    StreamSnapshotSelection,
    /// Symmetric fragment ceiling. [Detection, owner and recovery](#cause-SymmetricFragmentCeiling).
    SymmetricFragmentCeiling,
    /// Symmetric fragment count changed. [Detection, owner and recovery](#cause-SymmetricFragmentCountChanged).
    SymmetricFragmentCountChanged,
    /// Symmetric input overflow. [Detection, owner and recovery](#cause-SymmetricInputOverflow).
    SymmetricInputOverflow,
    /// Symmetric total input ceiling. [Detection, owner and recovery](#cause-SymmetricTotalInputCeiling).
    SymmetricTotalInputCeiling,
    /// Token IV direction differs from cipher operation. [Detection, owner and recovery](#cause-TokenIvDirectionDiffersFromCipherOperation).
    TokenIvDirectionDiffersFromCipherOperation,
    /// Token IV record mechanism. [Detection, owner and recovery](#cause-TokenIvRecordMechanism).
    TokenIvRecordMechanism,
    /// Token IV record width. [Detection, owner and recovery](#cause-TokenIvRecordWidth).
    TokenIvRecordWidth,
    /// Token-IV cipher input alignment. [Detection, owner and recovery](#cause-TokenIvCipherInputAlignment).
    TokenIvCipherInputAlignment,
    /// Traditional CCM has no nonce generation fields. [Detection, owner and recovery](#cause-TraditionalCcmHasNoNonceGenerationFields).
    TraditionalCcmHasNoNonceGenerationFields,

}

impl std::fmt::Display for SymmetricParametersRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {

            Self::Value32BitStreamCounterLength => f.write_str("32-bit stream counter length"),
            Self::Value64BitStreamCounterLength => f.write_str("64-bit stream counter length"),
            Self::AeadCompletionSelectionMismatch => {
                f.write_str("AEAD completion selection mismatch")
            }
            Self::AeadKeyUsedForMac => f.write_str("AEAD key used for MAC"),
            Self::AeadOutputLengthOverflow => f.write_str("AEAD output length overflow"),
            Self::AeadRequiresAnAdmittedSecretKey => {
                f.write_str("AEAD requires an admitted secret key")
            }
            Self::AeadRequiresItsAuthenticatedOutputOwner => {
                f.write_str("AEAD requires its authenticated output owner")
            }
            Self::AeadRetainedSelectionAccounting => {
                f.write_str("AEAD retained selection accounting")
            }
            Self::AesCfb1IvWidth => f.write_str("AES CFB1 IV width"),
            Self::AesKwpIvWidth => f.write_str("AES KWP IV width"),
            Self::AesCipherMechanism => f.write_str("AES cipher mechanism"),
            Self::AesCipherMechanismWidth => f.write_str("AES cipher mechanism width"),
            Self::AesInputIsNotBlockAligned => f.write_str("AES input is not block aligned"),
            Self::AesKeyWrapIvWidth => f.write_str("AES key wrap IV width"),
            Self::AesKeyWrapContractAbsent => f.write_str("AES key wrap contract absent"),
            Self::AesKeyWrapMechanism => f.write_str("AES key wrap mechanism"),
            Self::AesKeyWrapOutputLengthOverflow => {
                f.write_str("AES key wrap output length overflow")
            }
            Self::AesKeyWrapRequiresASinglePartOperation => {
                f.write_str("AES key wrap requires a single-part operation")
            }
            Self::AesMechanismWidth => f.write_str("AES mechanism width"),
            Self::AesOutputOverflow => f.write_str("AES output overflow"),
            Self::AesCtrCounterAbiWidth => f.write_str("AES-CTR counter ABI width"),
            Self::AesCtrCounterWidth => f.write_str("AES-CTR counter width"),
            Self::CcmAadLength => f.write_str("CCM AAD length"),
            Self::CcmMacRepresentationDoesNotMatchRoute => {
                f.write_str("CCM MAC representation does not match route")
            }
            Self::CcmMacWidth => f.write_str("CCM MAC width"),
            Self::CcmMessageRequiresSeparateMac => f.write_str("CCM Message requires separate MAC"),
            Self::CcmMessageRouteRequired => f.write_str("CCM Message route required"),
            Self::CcmCiphertextShorterThanMac => f.write_str("CCM ciphertext shorter than MAC"),
            Self::CcmDataLength => f.write_str("CCM data length"),
            Self::CcmDataLengthExceedsNonceEncoding => {
                f.write_str("CCM data length exceeds nonce encoding")
            }
            Self::CcmFixedBitsAbiWidth => f.write_str("CCM fixed bits ABI width"),
            Self::CcmFixedBitsExceedNonce => f.write_str("CCM fixed bits exceed nonce"),
            Self::CcmNonceLength => f.write_str("CCM nonce length"),
            Self::CcmRequiresAnAesKey => f.write_str("CCM requires an AES key"),
            Self::CcmRequiresDeclaredPlaintextLength => {
                f.write_str("CCM requires declared plaintext length")
            }
            Self::CkmNullHasNoParameters => f.write_str("CKM_NULL has no parameters"),
            Self::CtrBitsOnStructuredCipherParameters => {
                f.write_str("CTR bits on structured cipher parameters")
            }
            Self::CtrCounterBlockWidth => f.write_str("CTR counter block width"),
            Self::CtrCounterWidthAbsent => f.write_str("CTR counter width absent"),
            Self::CamelliaCtrWidthAbsent => f.write_str("Camellia CTR width absent"),
            Self::CamelliaCounterBlockWidth => f.write_str("Camellia counter block width"),
            Self::ChachaNonceWidth => f.write_str("ChaCha nonce width"),
            Self::Chacha20IetfMessageLength => f.write_str("ChaCha20 IETF message length"),
            Self::EcbDoesNotHaveIvParameters => f.write_str("ECB does not have IV parameters"),
            Self::EcbHasNoIv => f.write_str("ECB has no IV"),
            Self::GcmIvLength => f.write_str("GCM IV length"),
            Self::GcmMessageSelectionRequired => f.write_str("GCM Message selection required"),
            Self::GcmFixedBitsAbiWidth => f.write_str("GCM fixed bits ABI width"),
            Self::GcmGeneratorAbiWidth => f.write_str("GCM generator ABI width"),
            Self::GcmMessageEncryptionRouteRequired => {
                f.write_str("GCM message encryption route required")
            }
            Self::GcmNormativeParameterBounds => f.write_str("GCM normative parameter bounds"),
            Self::GcmTagAbiWidth => f.write_str("GCM tag ABI width"),
            Self::GcmTagBitLength => f.write_str("GCM tag bit length"),
            Self::GostEcbHasNoParameter => f.write_str("GOST ECB has no parameter"),
            Self::GostIvWidth => f.write_str("GOST IV width"),
            Self::GostOutputLengthOverflow => f.write_str("GOST output length overflow"),
            Self::HmacKeyTypeOnAead => f.write_str("HMAC key type on AEAD"),
            Self::HmacKeyTypeRequired => f.write_str("HMAC key type required"),
            Self::IetfAeadNonceWidth => f.write_str("IETF AEAD nonce width"),
            Self::IetfChacha20Poly1305Parameters => {
                f.write_str("IETF ChaCha20-Poly1305 parameters")
            }
            Self::MacKeyUsedForAead => f.write_str("MAC key used for AEAD"),
            Self::MacOutputUnavailable => f.write_str("MAC output unavailable"),
            Self::RcCipherIvLength => f.write_str("RC cipher IV length"),
            Self::RcParameterNativeWidth => f.write_str("RC parameter native width"),
            Self::RcRecordMechanismOptionsMismatch => {
                f.write_str("RC record mechanism/options mismatch")
            }
            Self::Rc2IvWidth => f.write_str("RC2 IV width"),
            Self::Rc5BlockSize => f.write_str("RC5 block size"),
            Self::SalsaNonceWidth => f.write_str("Salsa nonce width"),
            Self::BlockCipherIvWidth => f.write_str("block cipher IV width"),
            Self::BlockCipherInputLength => f.write_str("block cipher input length"),
            Self::BlockCipherMechanismWidth => f.write_str("block cipher mechanism width"),
            Self::BlockCipherNativeIdentifierWidth => {
                f.write_str("block cipher native identifier width")
            }
            Self::BlockCipherPaddingLengthOverflow => {
                f.write_str("block cipher padding length overflow")
            }
            Self::CipherParameterIdentity => f.write_str("cipher parameter identity"),
            Self::CipherSnapshotParameterShapeChanged => {
                f.write_str("cipher snapshot parameter shape changed")
            }
            Self::ClassicAeadResultRequired => f.write_str("classic AEAD result required"),
            Self::ClassicAeadTagLength => f.write_str("classic AEAD tag length"),
            Self::ClassicAesIvWidth => f.write_str("classic AES IV width"),
            Self::ClassicAesMechanism => f.write_str("classic AES mechanism"),
            Self::ClassicGcmDoesNotGenerateAnIv => {
                f.write_str("classic GCM does not generate an IV")
            }
            Self::CompletedTokenIvWidth => f.write_str("completed token IV width"),
            Self::CounterWidthOnGostParameters => f.write_str("counter width on GOST parameters"),
            Self::CounterWidthOnFixedBlockCipher => {
                f.write_str("counter width on fixed block cipher")
            }
            Self::CounterWidthOnNonCtrCipher => f.write_str("counter width on non-CTR cipher"),
            Self::DualCipherStorageSize => f.write_str("dual cipher storage size"),
            Self::FixedBlockCipherContractAbsent => {
                f.write_str("fixed block cipher contract absent")
            }
            Self::NativeNonceRoute => f.write_str("native nonce route"),
            Self::NonRcOptionsOnRcParameters => f.write_str("non-RC options on RC parameters"),
            Self::ParameterlessCipherHasNoIv => f.write_str("parameterless cipher has no IV"),
            Self::RestoredTokenIvWidth => f.write_str("restored token IV width"),
            Self::StreamAeadMechanismNonceTuple => f.write_str("stream AEAD mechanism/nonce tuple"),
            Self::StreamCounterWidth => f.write_str("stream counter width"),
            Self::StreamMechanismCounterNonceTuple => {
                f.write_str("stream mechanism/counter/nonce tuple")
            }
            Self::StreamNonceWidth => f.write_str("stream nonce width"),
            Self::StreamSnapshotCounterAbsent => f.write_str("stream snapshot counter absent"),
            Self::StreamSnapshotCounterWidth => f.write_str("stream snapshot counter width"),
            Self::StreamSnapshotSelection => f.write_str("stream snapshot selection"),
            Self::SymmetricFragmentCeiling => f.write_str("symmetric fragment ceiling"),
            Self::SymmetricFragmentCountChanged => f.write_str("symmetric fragment count changed"),
            Self::SymmetricInputOverflow => f.write_str("symmetric input overflow"),
            Self::SymmetricTotalInputCeiling => f.write_str("symmetric total input ceiling"),
            Self::TokenIvDirectionDiffersFromCipherOperation => {
                f.write_str("token IV direction differs from cipher operation")
            }
            Self::TokenIvRecordMechanism => f.write_str("token IV record mechanism"),
            Self::TokenIvRecordWidth => f.write_str("token IV record width"),
            Self::TokenIvCipherInputAlignment => f.write_str("token-IV cipher input alignment"),
            Self::TraditionalCcmHasNoNonceGenerationFields => {
                f.write_str("traditional CCM has no nonce generation fields")
            }
        }
    }
}
