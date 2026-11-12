// SPDX-License-Identifier: Apache-2.0
//! ClassicalSignatures causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to classical signatures.
#[doc = include_str!("../../../docs/diagnostics/rejection-classical_signatures.md")]
pub enum ClassicalSignaturesRejection {
    /// C_Digest unavailable. [Detection, owner and recovery](#cause-CDigestUnavailable).
    CDigestUnavailable,
    /// C_DigestFinal unavailable. [Detection, owner and recovery](#cause-CDigestFinalUnavailable).
    CDigestFinalUnavailable,
    /// C_DigestInit unavailable. [Detection, owner and recovery](#cause-CDigestInitUnavailable).
    CDigestInitUnavailable,
    /// C_DigestUpdate unavailable. [Detection, owner and recovery](#cause-CDigestUpdateUnavailable).
    CDigestUpdateUnavailable,
    /// C_SignFinal unavailable. [Detection, owner and recovery](#cause-CSignFinalUnavailable).
    CSignFinalUnavailable,
    /// C_SignUpdate unavailable. [Detection, owner and recovery](#cause-CSignUpdateUnavailable).
    CSignUpdateUnavailable,
    /// C_VerifyFinal unavailable. [Detection, owner and recovery](#cause-CVerifyFinalUnavailable).
    CVerifyFinalUnavailable,
    /// C_VerifyUpdate unavailable. [Detection, owner and recovery](#cause-CVerifyUpdateUnavailable).
    CVerifyUpdateUnavailable,
    /// DSA SPKI DER. [Detection, owner and recovery](#cause-DsaSpkiDer).
    DsaSpkiDer,
    /// DSA SPKI encoding. [Detection, owner and recovery](#cause-DsaSpkiEncoding).
    DsaSpkiEncoding,
    /// DSA algorithm. [Detection, owner and recovery](#cause-DsaAlgorithm).
    DsaAlgorithm,
    /// DSA digest width. [Detection, owner and recovery](#cause-DsaDigestWidth).
    DsaDigestWidth,
    /// DSA domain DER. [Detection, owner and recovery](#cause-DsaDomainDer).
    DsaDomainDer,
    /// DSA domain missing. [Detection, owner and recovery](#cause-DsaDomainMissing).
    DsaDomainMissing,
    /// DSA public encoding. [Detection, owner and recovery](#cause-DsaPublicEncoding).
    DsaPublicEncoding,
    /// DSA public integer. [Detection, owner and recovery](#cause-DsaPublicInteger).
    DsaPublicInteger,
    /// DSA r encoding. [Detection, owner and recovery](#cause-DsaREncoding).
    DsaREncoding,
    /// DSA s encoding. [Detection, owner and recovery](#cause-DsaSEncoding).
    DsaSEncoding,
    /// DSA scalar width. [Detection, owner and recovery](#cause-DsaScalarWidth).
    DsaScalarWidth,
    /// DSA signature DER. [Detection, owner and recovery](#cause-DsaSignatureDer).
    DsaSignatureDer,
    /// DSA signature allocation. [Detection, owner and recovery](#cause-DsaSignatureAllocation).
    DsaSignatureAllocation,
    /// DSA signature encoding. [Detection, owner and recovery](#cause-DsaSignatureEncoding).
    DsaSignatureEncoding,
    /// DSA signature width. [Detection, owner and recovery](#cause-DsaSignatureWidth).
    DsaSignatureWidth,
    /// DSA unused bits. [Detection, owner and recovery](#cause-DsaUnusedBits).
    DsaUnusedBits,
    /// DigestInfo encoding. [Detection, owner and recovery](#cause-DigestinfoEncoding).
    DigestinfoEncoding,
    /// DigestInfo input. [Detection, owner and recovery](#cause-DigestinfoInput).
    DigestinfoInput,
    /// DigestInfo input length. [Detection, owner and recovery](#cause-DigestinfoInputLength).
    DigestinfoInputLength,
    /// DigestInfo length. [Detection, owner and recovery](#cause-DigestinfoLength).
    DigestinfoLength,
    /// DigestInfo length conversion. [Detection, owner and recovery](#cause-DigestinfoLengthConversion).
    DigestinfoLengthConversion,
    /// DigestInfo prepared length. [Detection, owner and recovery](#cause-DigestinfoPreparedLength).
    DigestinfoPreparedLength,
    /// ECDSA DER. [Detection, owner and recovery](#cause-EcdsaDer).
    EcdsaDer,
    /// ECDSA DER encoding. [Detection, owner and recovery](#cause-EcdsaDerEncoding).
    EcdsaDerEncoding,
    /// ECDSA DER size. [Detection, owner and recovery](#cause-EcdsaDerSize).
    EcdsaDerSize,
    /// ECDSA r encoding. [Detection, owner and recovery](#cause-EcdsaREncoding).
    EcdsaREncoding,
    /// ECDSA s encoding. [Detection, owner and recovery](#cause-EcdsaSEncoding).
    EcdsaSEncoding,
    /// ECDSA scalar width. [Detection, owner and recovery](#cause-EcdsaScalarWidth).
    EcdsaScalarWidth,
    /// ECDSA signature width. [Detection, owner and recovery](#cause-EcdsaSignatureWidth).
    EcdsaSignatureWidth,
    /// ECDSA verify functions unavailable. [Detection, owner and recovery](#cause-EcdsaVerifyFunctionsUnavailable).
    EcdsaVerifyFunctionsUnavailable,
    /// EdDSA instance or context length. [Detection, owner and recovery](#cause-EddsaInstanceOrContextLength).
    EddsaInstanceOrContextLength,
    /// EdDSA mechanism or context length. [Detection, owner and recovery](#cause-EddsaMechanismOrContextLength).
    EddsaMechanismOrContextLength,
    /// PSS digest algorithm. [Detection, owner and recovery](#cause-PssDigestAlgorithm).
    PssDigestAlgorithm,
    /// PSS encoded MGF. [Detection, owner and recovery](#cause-PssEncodedMgf).
    PssEncodedMgf,
    /// PSS encoded hash. [Detection, owner and recovery](#cause-PssEncodedHash).
    PssEncodedHash,
    /// PSS salt width. [Detection, owner and recovery](#cause-PssSaltWidth).
    PssSaltWidth,
    /// PSS verify functions unavailable. [Detection, owner and recovery](#cause-PssVerifyFunctionsUnavailable).
    PssVerifyFunctionsUnavailable,
    /// RSA discovery evidence sequence. [Detection, owner and recovery](#cause-RsaDiscoveryEvidenceSequence).
    RsaDiscoveryEvidenceSequence,
    /// RSA encoding continuation changed. [Detection, owner and recovery](#cause-RsaEncodingContinuationChanged).
    RsaEncodingContinuationChanged,
    /// RSA encoding phase. [Detection, owner and recovery](#cause-RsaEncodingPhase).
    RsaEncodingPhase,
    /// RSA observation completion phase. [Detection, owner and recovery](#cause-RsaObservationCompletionPhase).
    RsaObservationCompletionPhase,
    /// RSA observation incomplete. [Detection, owner and recovery](#cause-RsaObservationIncomplete).
    RsaObservationIncomplete,
    /// RSA observation metadata phase. [Detection, owner and recovery](#cause-RsaObservationMetadataPhase).
    RsaObservationMetadataPhase,
    /// RSA observation stopped. [Detection, owner and recovery](#cause-RsaObservationStopped).
    RsaObservationStopped,
    /// RSA observation storage size. [Detection, owner and recovery](#cause-RsaObservationStorageSize).
    RsaObservationStorageSize,
    /// RSA prepared digest profile. [Detection, owner and recovery](#cause-RsaPreparedDigestProfile).
    RsaPreparedDigestProfile,
    /// RSA prepared signing permission. [Detection, owner and recovery](#cause-RsaPreparedSigningPermission).
    RsaPreparedSigningPermission,
    /// RSA public preparation absent. [Detection, owner and recovery](#cause-RsaPublicPreparationAbsent).
    RsaPublicPreparationAbsent,
    /// RSA signing identity. [Detection, owner and recovery](#cause-RsaSigningIdentity).
    RsaSigningIdentity,
    /// RSA signing profile family. [Detection, owner and recovery](#cause-RsaSigningProfileFamily).
    RsaSigningProfileFamily,
    /// RSA transport algorithm. [Detection, owner and recovery](#cause-RsaTransportAlgorithm).
    RsaTransportAlgorithm,
    /// RSA verify functions unavailable. [Detection, owner and recovery](#cause-RsaVerifyFunctionsUnavailable).
    RsaVerifyFunctionsUnavailable,
    /// Rust SHA1 digest unavailable. [Detection, owner and recovery](#cause-RustSha1DigestUnavailable).
    RustSha1DigestUnavailable,
    /// SPKI size. [Detection, owner and recovery](#cause-SpkiSize).
    SpkiSize,
    /// Classical creation request absent. [Detection, owner and recovery](#cause-ClassicalCreationRequestAbsent).
    ClassicalCreationRequestAbsent,
    /// Classical history owner absent. [Detection, owner and recovery](#cause-ClassicalHistoryOwnerAbsent).
    ClassicalHistoryOwnerAbsent,
    /// Classical identity allocation. [Detection, owner and recovery](#cause-ClassicalIdentityAllocation).
    ClassicalIdentityAllocation,
    /// Classical pair owner size overflow. [Detection, owner and recovery](#cause-ClassicalPairOwnerSizeOverflow).
    ClassicalPairOwnerSizeOverflow,
    /// Classical pair preparation changed. [Detection, owner and recovery](#cause-ClassicalPairPreparationChanged).
    ClassicalPairPreparationChanged,
    /// Classical prehash storage accounting. [Detection, owner and recovery](#cause-ClassicalPrehashStorageAccounting).
    ClassicalPrehashStorageAccounting,
    /// Classical profile allocation. [Detection, owner and recovery](#cause-ClassicalProfileAllocation).
    ClassicalProfileAllocation,
    /// Classical profile capacity overflow. [Detection, owner and recovery](#cause-ClassicalProfileCapacityOverflow).
    ClassicalProfileCapacityOverflow,
    /// Classical public observations absent. [Detection, owner and recovery](#cause-ClassicalPublicObservationsAbsent).
    ClassicalPublicObservationsAbsent,
    /// Classical public representation mismatch. [Detection, owner and recovery](#cause-ClassicalPublicRepresentationMismatch).
    ClassicalPublicRepresentationMismatch,
    /// Classical signature preparation differs. [Detection, owner and recovery](#cause-ClassicalSignaturePreparationDiffers).
    ClassicalSignaturePreparationDiffers,
    /// Classical signature storage accounting. [Detection, owner and recovery](#cause-ClassicalSignatureStorageAccounting).
    ClassicalSignatureStorageAccounting,
    /// Crypto input ceilings. [Detection, owner and recovery](#cause-CryptoInputCeilings).
    CryptoInputCeilings,
    /// Crypto input count changed. [Detection, owner and recovery](#cause-CryptoInputCountChanged).
    CryptoInputCountChanged,
    /// Crypto total ceiling. [Detection, owner and recovery](#cause-CryptoTotalCeiling).
    CryptoTotalCeiling,
    /// Crypto total overflow. [Detection, owner and recovery](#cause-CryptoTotalOverflow).
    CryptoTotalOverflow,
    /// Curve OID. [Detection, owner and recovery](#cause-CurveOid).
    CurveOid,
    /// Destination selection size. [Detection, owner and recovery](#cause-DestinationSelectionSize).
    DestinationSelectionSize,
    /// Digest input changed. [Detection, owner and recovery](#cause-DigestInputChanged).
    DigestInputChanged,
    /// Digest length. [Detection, owner and recovery](#cause-DigestLength).
    DigestLength,
    /// Digest mechanism changed. [Detection, owner and recovery](#cause-DigestMechanismChanged).
    DigestMechanismChanged,
    /// Digest output length. [Detection, owner and recovery](#cause-DigestOutputLength).
    DigestOutputLength,
    /// Generated curve parameters. [Detection, owner and recovery](#cause-GeneratedCurveParameters).
    GeneratedCurveParameters,
    /// Hashed signature family. [Detection, owner and recovery](#cause-HashedSignatureFamily).
    HashedSignatureFamily,
    /// Historical PSS parameters. [Detection, owner and recovery](#cause-HistoricalPssParameters).
    HistoricalPssParameters,
    /// Historical digest profile. [Detection, owner and recovery](#cause-HistoricalDigestProfile).
    HistoricalDigestProfile,
    /// Historical digest unavailable in Rust engine. [Detection, owner and recovery](#cause-HistoricalDigestUnavailableInRustEngine).
    HistoricalDigestUnavailableInRustEngine,
    /// Historical digest width. [Detection, owner and recovery](#cause-HistoricalDigestWidth).
    HistoricalDigestWidth,
    /// Historical prepared digest length. [Detection, owner and recovery](#cause-HistoricalPreparedDigestLength).
    HistoricalPreparedDigestLength,
    /// Historical verification functions unavailable. [Detection, owner and recovery](#cause-HistoricalVerificationFunctionsUnavailable).
    HistoricalVerificationFunctionsUnavailable,
    /// Message RSA signing key required. [Detection, owner and recovery](#cause-MessageRsaSigningKeyRequired).
    MessageRsaSigningKeyRequired,
    /// Native digest capacity. [Detection, owner and recovery](#cause-NativeDigestCapacity).
    NativeDigestCapacity,
    /// Native digest preparation changed. [Detection, owner and recovery](#cause-NativeDigestPreparationChanged).
    NativeDigestPreparationChanged,
    /// Native digest storage accounting. [Detection, owner and recovery](#cause-NativeDigestStorageAccounting).
    NativeDigestStorageAccounting,
    /// Native point DER. [Detection, owner and recovery](#cause-NativePointDer).
    NativePointDer,
    /// Native point encoding. [Detection, owner and recovery](#cause-NativePointEncoding).
    NativePointEncoding,
    /// Native signature encoding. [Detection, owner and recovery](#cause-NativeSignatureEncoding).
    NativeSignatureEncoding,
    /// Native signature output length. [Detection, owner and recovery](#cause-NativeSignatureOutputLength).
    NativeSignatureOutputLength,
    /// Noncanonical DSA SPKI. [Detection, owner and recovery](#cause-NoncanonicalDsaSpki).
    NoncanonicalDsaSpki,
    /// Noncanonical DSA public value. [Detection, owner and recovery](#cause-NoncanonicalDsaPublicValue).
    NoncanonicalDsaPublicValue,
    /// Noncanonical DSA signature. [Detection, owner and recovery](#cause-NoncanonicalDsaSignature).
    NoncanonicalDsaSignature,
    /// Noncanonical ECDSA DER. [Detection, owner and recovery](#cause-NoncanonicalEcdsaDer).
    NoncanonicalEcdsaDer,
    /// Noncanonical native point. [Detection, owner and recovery](#cause-NoncanonicalNativePoint).
    NoncanonicalNativePoint,
    /// Not a DSA reference. [Detection, owner and recovery](#cause-NotADsaReference).
    NotADsaReference,
    /// Not an ECDSA reference. [Detection, owner and recovery](#cause-NotAnEcdsaReference).
    NotAnEcdsaReference,
    /// Not an RSA reference. [Detection, owner and recovery](#cause-NotAnRsaReference).
    NotAnRsaReference,
    /// Object control byte count. [Detection, owner and recovery](#cause-ObjectControlByteCount).
    ObjectControlByteCount,
    /// Pair object control byte count. [Detection, owner and recovery](#cause-PairObjectControlByteCount).
    PairObjectControlByteCount,
    /// Prepared digest encoding length. [Detection, owner and recovery](#cause-PreparedDigestEncodingLength).
    PreparedDigestEncodingLength,
    /// Public point bit string. [Detection, owner and recovery](#cause-PublicPointBitString).
    PublicPointBitString,
    /// Restored signing history report absent. [Detection, owner and recovery](#cause-RestoredSigningHistoryReportAbsent).
    RestoredSigningHistoryReportAbsent,
    /// Restored signing mechanism report absent. [Detection, owner and recovery](#cause-RestoredSigningMechanismReportAbsent).
    RestoredSigningMechanismReportAbsent,
    /// Signature completion unproven. [Detection, owner and recovery](#cause-SignatureCompletionUnproven).
    SignatureCompletionUnproven,
    /// Signature has no DER conversion. [Detection, owner and recovery](#cause-SignatureHasNoDerConversion).
    SignatureHasNoDerConversion,
    /// Signature input changed. [Detection, owner and recovery](#cause-SignatureInputChanged).
    SignatureInputChanged,
    /// Signature parameters changed. [Detection, owner and recovery](#cause-SignatureParametersChanged).
    SignatureParametersChanged,
    /// Signature parameters changed during context authentication. [Detection, owner and recovery](#cause-SignatureParametersChangedDuringContextAuthentication).
    SignatureParametersChangedDuringContextAuthentication,
    /// Signing functions unavailable. [Detection, owner and recovery](#cause-SigningFunctionsUnavailable).
    SigningFunctionsUnavailable,
    /// Signing introduction report absent. [Detection, owner and recovery](#cause-SigningIntroductionReportAbsent).
    SigningIntroductionReportAbsent,
    /// Signing profile family. [Detection, owner and recovery](#cause-SigningProfileFamily).
    SigningProfileFamily,
    /// Signing profiles already published. [Detection, owner and recovery](#cause-SigningProfilesAlreadyPublished).
    SigningProfilesAlreadyPublished,
    /// Single-part digest requires one input. [Detection, owner and recovery](#cause-SinglePartDigestRequiresOneInput).
    SinglePartDigestRequiresOneInput,
    /// Transport history absent. [Detection, owner and recovery](#cause-TransportHistoryAbsent).
    TransportHistoryAbsent,
    /// Transport history owner absent. [Detection, owner and recovery](#cause-TransportHistoryOwnerAbsent).
    TransportHistoryOwnerAbsent,
    /// Transport publication absent. [Detection, owner and recovery](#cause-TransportPublicationAbsent).
    TransportPublicationAbsent,
    /// Verification completion unproven. [Detection, owner and recovery](#cause-VerificationCompletionUnproven).
    VerificationCompletionUnproven,
    /// Verification input changed. [Detection, owner and recovery](#cause-VerificationInputChanged).
    VerificationInputChanged,
    /// Verification parameters changed. [Detection, owner and recovery](#cause-VerificationParametersChanged).
    VerificationParametersChanged,
    /// Verification profiles already published. [Detection, owner and recovery](#cause-VerificationProfilesAlreadyPublished).
    VerificationProfilesAlreadyPublished,
    /// Verification selector public identity. [Detection, owner and recovery](#cause-VerificationSelectorPublicIdentity).
    VerificationSelectorPublicIdentity,


}

impl std::fmt::Display for ClassicalSignaturesRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {


            Self::CDigestUnavailable => f.write_str("C_Digest unavailable"),
            Self::CDigestFinalUnavailable => f.write_str("C_DigestFinal unavailable"),
            Self::CDigestInitUnavailable => f.write_str("C_DigestInit unavailable"),
            Self::CDigestUpdateUnavailable => f.write_str("C_DigestUpdate unavailable"),
            Self::CSignFinalUnavailable => f.write_str("C_SignFinal unavailable"),
            Self::CSignUpdateUnavailable => f.write_str("C_SignUpdate unavailable"),
            Self::CVerifyFinalUnavailable => f.write_str("C_VerifyFinal unavailable"),
            Self::CVerifyUpdateUnavailable => f.write_str("C_VerifyUpdate unavailable"),
            Self::DsaSpkiDer => f.write_str("DSA SPKI DER"),
            Self::DsaSpkiEncoding => f.write_str("DSA SPKI encoding"),
            Self::DsaAlgorithm => f.write_str("DSA algorithm"),
            Self::DsaDigestWidth => f.write_str("DSA digest width"),
            Self::DsaDomainDer => f.write_str("DSA domain DER"),
            Self::DsaDomainMissing => f.write_str("DSA domain missing"),
            Self::DsaPublicEncoding => f.write_str("DSA public encoding"),
            Self::DsaPublicInteger => f.write_str("DSA public integer"),
            Self::DsaREncoding => f.write_str("DSA r encoding"),
            Self::DsaSEncoding => f.write_str("DSA s encoding"),
            Self::DsaScalarWidth => f.write_str("DSA scalar width"),
            Self::DsaSignatureDer => f.write_str("DSA signature DER"),
            Self::DsaSignatureAllocation => f.write_str("DSA signature allocation"),
            Self::DsaSignatureEncoding => f.write_str("DSA signature encoding"),
            Self::DsaSignatureWidth => f.write_str("DSA signature width"),
            Self::DsaUnusedBits => f.write_str("DSA unused bits"),
            Self::DigestinfoEncoding => f.write_str("DigestInfo encoding"),
            Self::DigestinfoInput => f.write_str("DigestInfo input"),
            Self::DigestinfoInputLength => f.write_str("DigestInfo input length"),
            Self::DigestinfoLength => f.write_str("DigestInfo length"),
            Self::DigestinfoLengthConversion => f.write_str("DigestInfo length conversion"),
            Self::DigestinfoPreparedLength => f.write_str("DigestInfo prepared length"),
            Self::EcdsaDer => f.write_str("ECDSA DER"),
            Self::EcdsaDerEncoding => f.write_str("ECDSA DER encoding"),
            Self::EcdsaDerSize => f.write_str("ECDSA DER size"),
            Self::EcdsaREncoding => f.write_str("ECDSA r encoding"),
            Self::EcdsaSEncoding => f.write_str("ECDSA s encoding"),
            Self::EcdsaScalarWidth => f.write_str("ECDSA scalar width"),
            Self::EcdsaSignatureWidth => f.write_str("ECDSA signature width"),
            Self::EcdsaVerifyFunctionsUnavailable => {
                f.write_str("ECDSA verify functions unavailable")
            }
            Self::EddsaInstanceOrContextLength => f.write_str("EdDSA instance or context length"),
            Self::EddsaMechanismOrContextLength => f.write_str("EdDSA mechanism or context length"),
            Self::PssDigestAlgorithm => f.write_str("PSS digest algorithm"),
            Self::PssEncodedMgf => f.write_str("PSS encoded MGF"),
            Self::PssEncodedHash => f.write_str("PSS encoded hash"),
            Self::PssSaltWidth => f.write_str("PSS salt width"),
            Self::PssVerifyFunctionsUnavailable => f.write_str("PSS verify functions unavailable"),
            Self::RsaDiscoveryEvidenceSequence => f.write_str("RSA discovery evidence sequence"),
            Self::RsaEncodingContinuationChanged => {
                f.write_str("RSA encoding continuation changed")
            }
            Self::RsaEncodingPhase => f.write_str("RSA encoding phase"),
            Self::RsaObservationCompletionPhase => f.write_str("RSA observation completion phase"),
            Self::RsaObservationIncomplete => f.write_str("RSA observation incomplete"),
            Self::RsaObservationMetadataPhase => f.write_str("RSA observation metadata phase"),
            Self::RsaObservationStopped => f.write_str("RSA observation stopped"),
            Self::RsaObservationStorageSize => f.write_str("RSA observation storage size"),
            Self::RsaPreparedDigestProfile => f.write_str("RSA prepared digest profile"),
            Self::RsaPreparedSigningPermission => f.write_str("RSA prepared signing permission"),
            Self::RsaPublicPreparationAbsent => f.write_str("RSA public preparation absent"),
            Self::RsaSigningIdentity => f.write_str("RSA signing identity"),
            Self::RsaSigningProfileFamily => f.write_str("RSA signing profile family"),
            Self::RsaTransportAlgorithm => f.write_str("RSA transport algorithm"),
            Self::RsaVerifyFunctionsUnavailable => f.write_str("RSA verify functions unavailable"),
            Self::RustSha1DigestUnavailable => f.write_str("Rust SHA1 digest unavailable"),
            Self::SpkiSize => f.write_str("SPKI size"),
            Self::ClassicalCreationRequestAbsent => {
                f.write_str("classical creation request absent")
            }
            Self::ClassicalHistoryOwnerAbsent => f.write_str("classical history owner absent"),
            Self::ClassicalIdentityAllocation => f.write_str("classical identity allocation"),
            Self::ClassicalPairOwnerSizeOverflow => {
                f.write_str("classical pair owner size overflow")
            }
            Self::ClassicalPairPreparationChanged => {
                f.write_str("classical pair preparation changed")
            }
            Self::ClassicalPrehashStorageAccounting => {
                f.write_str("classical prehash storage accounting")
            }
            Self::ClassicalProfileAllocation => f.write_str("classical profile allocation"),
            Self::ClassicalProfileCapacityOverflow => {
                f.write_str("classical profile capacity overflow")
            }
            Self::ClassicalPublicObservationsAbsent => {
                f.write_str("classical public observations absent")
            }
            Self::ClassicalPublicRepresentationMismatch => {
                f.write_str("classical public representation mismatch")
            }
            Self::ClassicalSignaturePreparationDiffers => {
                f.write_str("classical signature preparation differs")
            }
            Self::ClassicalSignatureStorageAccounting => {
                f.write_str("classical signature storage accounting")
            }
            Self::CryptoInputCeilings => f.write_str("crypto input ceilings"),
            Self::CryptoInputCountChanged => f.write_str("crypto input count changed"),
            Self::CryptoTotalCeiling => f.write_str("crypto total ceiling"),
            Self::CryptoTotalOverflow => f.write_str("crypto total overflow"),
            Self::CurveOid => f.write_str("curve OID"),
            Self::DestinationSelectionSize => f.write_str("destination selection size"),
            Self::DigestInputChanged => f.write_str("digest input changed"),
            Self::DigestLength => f.write_str("digest length"),
            Self::DigestMechanismChanged => f.write_str("digest mechanism changed"),
            Self::DigestOutputLength => f.write_str("digest output length"),
            Self::GeneratedCurveParameters => f.write_str("generated curve parameters"),
            Self::HashedSignatureFamily => f.write_str("hashed signature family"),
            Self::HistoricalPssParameters => f.write_str("historical PSS parameters"),
            Self::HistoricalDigestProfile => f.write_str("historical digest profile"),
            Self::HistoricalDigestUnavailableInRustEngine => {
                f.write_str("historical digest unavailable in Rust engine")
            }
            Self::HistoricalDigestWidth => f.write_str("historical digest width"),
            Self::HistoricalPreparedDigestLength => {
                f.write_str("historical prepared digest length")
            }
            Self::HistoricalVerificationFunctionsUnavailable => {
                f.write_str("historical verification functions unavailable")
            }
            Self::MessageRsaSigningKeyRequired => f.write_str("message RSA signing key required"),
            Self::NativeDigestCapacity => f.write_str("native digest capacity"),
            Self::NativeDigestPreparationChanged => {
                f.write_str("native digest preparation changed")
            }
            Self::NativeDigestStorageAccounting => f.write_str("native digest storage accounting"),
            Self::NativePointDer => f.write_str("native point DER"),
            Self::NativePointEncoding => f.write_str("native point encoding"),
            Self::NativeSignatureEncoding => f.write_str("native signature encoding"),
            Self::NativeSignatureOutputLength => f.write_str("native signature output length"),
            Self::NoncanonicalDsaSpki => f.write_str("noncanonical DSA SPKI"),
            Self::NoncanonicalDsaPublicValue => f.write_str("noncanonical DSA public value"),
            Self::NoncanonicalDsaSignature => f.write_str("noncanonical DSA signature"),
            Self::NoncanonicalEcdsaDer => f.write_str("noncanonical ECDSA DER"),
            Self::NoncanonicalNativePoint => f.write_str("noncanonical native point"),
            Self::NotADsaReference => f.write_str("not a DSA reference"),
            Self::NotAnEcdsaReference => f.write_str("not an ECDSA reference"),
            Self::NotAnRsaReference => f.write_str("not an RSA reference"),
            Self::ObjectControlByteCount => f.write_str("object control byte count"),
            Self::PairObjectControlByteCount => f.write_str("pair object control byte count"),
            Self::PreparedDigestEncodingLength => f.write_str("prepared digest encoding length"),
            Self::PublicPointBitString => f.write_str("public point bit string"),
            Self::RestoredSigningHistoryReportAbsent => {
                f.write_str("restored signing history report absent")
            }
            Self::RestoredSigningMechanismReportAbsent => {
                f.write_str("restored signing mechanism report absent")
            }
            Self::SignatureCompletionUnproven => f.write_str("signature completion unproven"),
            Self::SignatureHasNoDerConversion => f.write_str("signature has no DER conversion"),
            Self::SignatureInputChanged => f.write_str("signature input changed"),
            Self::SignatureParametersChanged => f.write_str("signature parameters changed"),
            Self::SignatureParametersChangedDuringContextAuthentication => {
                f.write_str("signature parameters changed during context authentication")
            }
            Self::SigningFunctionsUnavailable => f.write_str("signing functions unavailable"),
            Self::SigningIntroductionReportAbsent => {
                f.write_str("signing introduction report absent")
            }
            Self::SigningProfileFamily => f.write_str("signing profile family"),
            Self::SigningProfilesAlreadyPublished => {
                f.write_str("signing profiles already published")
            }
            Self::SinglePartDigestRequiresOneInput => {
                f.write_str("single-part digest requires one input")
            }
            Self::TransportHistoryAbsent => f.write_str("transport history absent"),
            Self::TransportHistoryOwnerAbsent => f.write_str("transport history owner absent"),
            Self::TransportPublicationAbsent => f.write_str("transport publication absent"),
            Self::VerificationCompletionUnproven => f.write_str("verification completion unproven"),
            Self::VerificationInputChanged => f.write_str("verification input changed"),
            Self::VerificationParametersChanged => f.write_str("verification parameters changed"),
            Self::VerificationProfilesAlreadyPublished => {
                f.write_str("verification profiles already published")
            }
            Self::VerificationSelectorPublicIdentity => {
                f.write_str("verification selector public identity")
            }
        }
    }
}
