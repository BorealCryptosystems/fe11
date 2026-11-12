// SPDX-License-Identifier: Apache-2.0
//! KeyTransport causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to key transport.
#[doc = include_str!("../../../docs/diagnostics/rejection-key_transport.md")]
pub enum KeyTransportRejection {
    /// AES KEK algorithm. [Detection, owner and recovery](#cause-AesKekAlgorithm).
    AesKekAlgorithm,
    /// AES KEK material length. [Detection, owner and recovery](#cause-AesKekMaterialLength).
    AesKekMaterialLength,
    /// AES KEK mechanism report absent. [Detection, owner and recovery](#cause-AesKekMechanismReportAbsent).
    AesKekMechanismReportAbsent,
    /// C_Decrypt unavailable. [Detection, owner and recovery](#cause-CDecryptUnavailable).
    CDecryptUnavailable,
    /// C_DecryptInit unavailable. [Detection, owner and recovery](#cause-CDecryptInitUnavailable).
    CDecryptInitUnavailable,
    /// C_Encrypt unavailable. [Detection, owner and recovery](#cause-CEncryptUnavailable).
    CEncryptUnavailable,
    /// C_EncryptInit unavailable. [Detection, owner and recovery](#cause-CEncryptInitUnavailable).
    CEncryptInitUnavailable,
    /// C_UnwrapKey unavailable. [Detection, owner and recovery](#cause-CUnwrapKeyUnavailable).
    CUnwrapKeyUnavailable,
    /// C_UnwrapKeyAuthenticated unavailable in selected interface. [Detection, owner and recovery](#cause-CUnwrapKeyAuthenticatedUnavailableInSelectedInterface).
    CUnwrapKeyAuthenticatedUnavailableInSelectedInterface,
    /// C_WrapKey unavailable. [Detection, owner and recovery](#cause-CWrapKeyUnavailable).
    CWrapKeyUnavailable,
    /// C_WrapKeyAuthenticated unavailable in selected interface. [Detection, owner and recovery](#cause-CWrapKeyAuthenticatedUnavailableInSelectedInterface).
    CWrapKeyAuthenticatedUnavailableInSelectedInterface,
    /// GCM selection size. [Detection, owner and recovery](#cause-GcmSelectionSize).
    GcmSelectionSize,
    /// MGF identifier conversion. [Detection, owner and recovery](#cause-MgfIdentifierConversion).
    MgfIdentifierConversion,
    /// OAEP MGF identifier width. [Detection, owner and recovery](#cause-OaepMgfIdentifierWidth).
    OaepMgfIdentifierWidth,
    /// OAEP hash identifier width. [Detection, owner and recovery](#cause-OaepHashIdentifierWidth).
    OaepHashIdentifierWidth,
    /// OAEP input changed during context authentication. [Detection, owner and recovery](#cause-OaepInputChangedDuringContextAuthentication).
    OaepInputChangedDuringContextAuthentication,
    /// OAEP input descriptor changed. [Detection, owner and recovery](#cause-OaepInputDescriptorChanged).
    OaepInputDescriptorChanged,
    /// OAEP label allocation. [Detection, owner and recovery](#cause-OaepLabelAllocation).
    OaepLabelAllocation,
    /// OAEP plaintext allocation. [Detection, owner and recovery](#cause-OaepPlaintextAllocation).
    OaepPlaintextAllocation,
    /// OAEP storage accounting. [Detection, owner and recovery](#cause-OaepStorageAccounting).
    OaepStorageAccounting,
    /// RSA KEK SPKI size. [Detection, owner and recovery](#cause-RsaKekSpkiSize).
    RsaKekSpkiSize,
    /// RSA ciphertext allocation. [Detection, owner and recovery](#cause-RsaCiphertextAllocation).
    RsaCiphertextAllocation,
    /// RSA ciphertext capacity. [Detection, owner and recovery](#cause-RsaCiphertextCapacity).
    RsaCiphertextCapacity,
    /// RSA ciphertext length. [Detection, owner and recovery](#cause-RsaCiphertextLength).
    RsaCiphertextLength,
    /// RSA imported private protection. [Detection, owner and recovery](#cause-RsaImportedPrivateProtection).
    RsaImportedPrivateProtection,
    /// RSA mechanism report absent. [Detection, owner and recovery](#cause-RsaMechanismReportAbsent).
    RsaMechanismReportAbsent,
    /// RSA private material family. [Detection, owner and recovery](#cause-RsaPrivateMaterialFamily).
    RsaPrivateMaterialFamily,
    /// RSA private mechanism report absent. [Detection, owner and recovery](#cause-RsaPrivateMechanismReportAbsent).
    RsaPrivateMechanismReportAbsent,
    /// RSA public publication absent. [Detection, owner and recovery](#cause-RsaPublicPublicationAbsent).
    RsaPublicPublicationAbsent,
    /// RSA restored history report absent. [Detection, owner and recovery](#cause-RsaRestoredHistoryReportAbsent).
    RsaRestoredHistoryReportAbsent,
    /// RSA restored mechanism report absent. [Detection, owner and recovery](#cause-RsaRestoredMechanismReportAbsent).
    RsaRestoredMechanismReportAbsent,
    /// Authenticated unwrap parameters. [Detection, owner and recovery](#cause-AuthenticatedUnwrapParameters).
    AuthenticatedUnwrapParameters,
    /// Hash identifier conversion. [Detection, owner and recovery](#cause-HashIdentifierConversion).
    HashIdentifierConversion,
    /// Imported KEK history report absent. [Detection, owner and recovery](#cause-ImportedKekHistoryReportAbsent).
    ImportedKekHistoryReportAbsent,
    /// Imported symmetric history report absent. [Detection, owner and recovery](#cause-ImportedSymmetricHistoryReportAbsent).
    ImportedSymmetricHistoryReportAbsent,
    /// Key mechanism report absent. [Detection, owner and recovery](#cause-KeyMechanismReportAbsent).
    KeyMechanismReportAbsent,
    /// Native KEK creation unavailable. [Detection, owner and recovery](#cause-NativeKekCreationUnavailable).
    NativeKekCreationUnavailable,
    /// Native introduction unavailable. [Detection, owner and recovery](#cause-NativeIntroductionUnavailable).
    NativeIntroductionUnavailable,
    /// Native plaintext length. [Detection, owner and recovery](#cause-NativePlaintextLength).
    NativePlaintextLength,
    /// Private template storage allocation. [Detection, owner and recovery](#cause-PrivateTemplateStorageAllocation).
    PrivateTemplateStorageAllocation,
    /// Private template storage size. [Detection, owner and recovery](#cause-PrivateTemplateStorageSize).
    PrivateTemplateStorageSize,
    /// Restoration already consumed. [Detection, owner and recovery](#cause-RestorationAlreadyConsumed).
    RestorationAlreadyConsumed,
    /// Restoration evidence family mismatch. [Detection, owner and recovery](#cause-RestorationEvidenceFamilyMismatch).
    RestorationEvidenceFamilyMismatch,
    /// Restored history report absent. [Detection, owner and recovery](#cause-RestoredHistoryReportAbsent).
    RestoredHistoryReportAbsent,
    /// Transport attribute count overflow. [Detection, owner and recovery](#cause-TransportAttributeCountOverflow).
    TransportAttributeCountOverflow,
    /// Transport duplicate template field. [Detection, owner and recovery](#cause-TransportDuplicateTemplateField).
    TransportDuplicateTemplateField,
    /// Transport handle binding. [Detection, owner and recovery](#cause-TransportHandleBinding).
    TransportHandleBinding,
    /// Transport mixed private representations. [Detection, owner and recovery](#cause-TransportMixedPrivateRepresentations).
    TransportMixedPrivateRepresentations,
    /// Transport private template field. [Detection, owner and recovery](#cause-TransportPrivateTemplateField).
    TransportPrivateTemplateField,
    /// Transport public template field. [Detection, owner and recovery](#cause-TransportPublicTemplateField).
    TransportPublicTemplateField,
    /// Transport secret length. [Detection, owner and recovery](#cause-TransportSecretLength).
    TransportSecretLength,
    /// Unwrap returned KEK handle. [Detection, owner and recovery](#cause-UnwrapReturnedKekHandle).
    UnwrapReturnedKekHandle,
    /// Unwrapping inputs changed. [Detection, owner and recovery](#cause-UnwrappingInputsChanged).
    UnwrappingInputsChanged,
    /// Unwrapping storage size. [Detection, owner and recovery](#cause-UnwrappingStorageSize).
    UnwrappingStorageSize,
    /// Wrapped output exceeds capacity. [Detection, owner and recovery](#cause-WrappedOutputExceedsCapacity).
    WrappedOutputExceedsCapacity,
    /// Wrapping parameters changed. [Detection, owner and recovery](#cause-WrappingParametersChanged).
    WrappingParametersChanged,
    /// Wrapping size representation. [Detection, owner and recovery](#cause-WrappingSizeRepresentation).
    WrappingSizeRepresentation,
    /// Wrapping storage size. [Detection, owner and recovery](#cause-WrappingStorageSize).
    WrappingStorageSize,


}

impl std::fmt::Display for KeyTransportRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {


            Self::AesKekAlgorithm => f.write_str("AES KEK algorithm"),
            Self::AesKekMaterialLength => f.write_str("AES KEK material length"),
            Self::AesKekMechanismReportAbsent => f.write_str("AES KEK mechanism report absent"),
            Self::CDecryptUnavailable => f.write_str("C_Decrypt unavailable"),
            Self::CDecryptInitUnavailable => f.write_str("C_DecryptInit unavailable"),
            Self::CEncryptUnavailable => f.write_str("C_Encrypt unavailable"),
            Self::CEncryptInitUnavailable => f.write_str("C_EncryptInit unavailable"),
            Self::CUnwrapKeyUnavailable => f.write_str("C_UnwrapKey unavailable"),
            Self::CUnwrapKeyAuthenticatedUnavailableInSelectedInterface => {
                f.write_str("C_UnwrapKeyAuthenticated unavailable in selected interface")
            }
            Self::CWrapKeyUnavailable => f.write_str("C_WrapKey unavailable"),
            Self::CWrapKeyAuthenticatedUnavailableInSelectedInterface => {
                f.write_str("C_WrapKeyAuthenticated unavailable in selected interface")
            }
            Self::GcmSelectionSize => f.write_str("GCM selection size"),
            Self::MgfIdentifierConversion => f.write_str("MGF identifier conversion"),
            Self::OaepMgfIdentifierWidth => f.write_str("OAEP MGF identifier width"),
            Self::OaepHashIdentifierWidth => f.write_str("OAEP hash identifier width"),
            Self::OaepInputChangedDuringContextAuthentication => {
                f.write_str("OAEP input changed during context authentication")
            }
            Self::OaepInputDescriptorChanged => f.write_str("OAEP input descriptor changed"),
            Self::OaepLabelAllocation => f.write_str("OAEP label allocation"),
            Self::OaepPlaintextAllocation => f.write_str("OAEP plaintext allocation"),
            Self::OaepStorageAccounting => f.write_str("OAEP storage accounting"),
            Self::RsaKekSpkiSize => f.write_str("RSA KEK SPKI size"),
            Self::RsaCiphertextAllocation => f.write_str("RSA ciphertext allocation"),
            Self::RsaCiphertextCapacity => f.write_str("RSA ciphertext capacity"),
            Self::RsaCiphertextLength => f.write_str("RSA ciphertext length"),
            Self::RsaImportedPrivateProtection => f.write_str("RSA imported private protection"),
            Self::RsaMechanismReportAbsent => f.write_str("RSA mechanism report absent"),
            Self::RsaPrivateMaterialFamily => f.write_str("RSA private material family"),
            Self::RsaPrivateMechanismReportAbsent => {
                f.write_str("RSA private mechanism report absent")
            }
            Self::RsaPublicPublicationAbsent => f.write_str("RSA public publication absent"),
            Self::RsaRestoredHistoryReportAbsent => {
                f.write_str("RSA restored history report absent")
            }
            Self::RsaRestoredMechanismReportAbsent => {
                f.write_str("RSA restored mechanism report absent")
            }
            Self::AuthenticatedUnwrapParameters => f.write_str("authenticated unwrap parameters"),
            Self::HashIdentifierConversion => f.write_str("hash identifier conversion"),
            Self::ImportedKekHistoryReportAbsent => {
                f.write_str("imported KEK history report absent")
            }
            Self::ImportedSymmetricHistoryReportAbsent => {
                f.write_str("imported symmetric history report absent")
            }
            Self::KeyMechanismReportAbsent => f.write_str("key mechanism report absent"),
            Self::NativeKekCreationUnavailable => f.write_str("native KEK creation unavailable"),
            Self::NativeIntroductionUnavailable => f.write_str("native introduction unavailable"),
            Self::NativePlaintextLength => f.write_str("native plaintext length"),
            Self::PrivateTemplateStorageAllocation => {
                f.write_str("private template storage allocation")
            }
            Self::PrivateTemplateStorageSize => f.write_str("private template storage size"),
            Self::RestorationAlreadyConsumed => f.write_str("restoration already consumed"),
            Self::RestorationEvidenceFamilyMismatch => {
                f.write_str("restoration evidence family mismatch")
            }
            Self::RestoredHistoryReportAbsent => f.write_str("restored history report absent"),
            Self::TransportAttributeCountOverflow => {
                f.write_str("transport attribute count overflow")
            }
            Self::TransportDuplicateTemplateField => {
                f.write_str("transport duplicate template field")
            }
            Self::TransportHandleBinding => f.write_str("transport handle binding"),
            Self::TransportMixedPrivateRepresentations => {
                f.write_str("transport mixed private representations")
            }
            Self::TransportPrivateTemplateField => f.write_str("transport private template field"),
            Self::TransportPublicTemplateField => f.write_str("transport public template field"),
            Self::TransportSecretLength => f.write_str("transport secret length"),
            Self::UnwrapReturnedKekHandle => f.write_str("unwrap returned KEK handle"),
            Self::UnwrappingInputsChanged => f.write_str("unwrapping inputs changed"),
            Self::UnwrappingStorageSize => f.write_str("unwrapping storage size"),
            Self::WrappedOutputExceedsCapacity => f.write_str("wrapped output exceeds capacity"),
            Self::WrappingParametersChanged => f.write_str("wrapping parameters changed"),
            Self::WrappingSizeRepresentation => f.write_str("wrapping size representation"),
            Self::WrappingStorageSize => f.write_str("wrapping storage size"),
        }
    }
}
