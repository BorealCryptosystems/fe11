// SPDX-License-Identifier: Apache-2.0
//! NativeDerivation causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to native derivation.
#[doc = include_str!("../../../docs/diagnostics/rejection-native_derivation.md")]
pub enum NativeDerivationRejection {
    /// C_DeriveKey unavailable. [Detection, owner and recovery](#cause-CDeriveKeyUnavailable).
    CDeriveKeyUnavailable,
    /// IKE parameter accounting. [Detection, owner and recovery](#cause-IkeParameterAccounting).
    IkeParameterAccounting,
    /// KEA creation diagnostics absent. [Detection, owner and recovery](#cause-KeaCreationDiagnosticsAbsent).
    KeaCreationDiagnosticsAbsent,
    /// KEA creation phase. [Detection, owner and recovery](#cause-KeaCreationPhase).
    KeaCreationPhase,
    /// KEA creation scope. [Detection, owner and recovery](#cause-KeaCreationScope).
    KeaCreationScope,
    /// KEA native input mutation. [Detection, owner and recovery](#cause-KeaNativeInputMutation).
    KeaNativeInputMutation,
    /// KEA output aliases source. [Detection, owner and recovery](#cause-KeaOutputAliasesSource).
    KeaOutputAliasesSource,
    /// KEA parameter accounting. [Detection, owner and recovery](#cause-KeaParameterAccounting).
    KeaParameterAccounting,
    /// KEA shared random length. [Detection, owner and recovery](#cause-KeaSharedRandomLength).
    KeaSharedRandomLength,
    /// SP800 IV storage changed. [Detection, owner and recovery](#cause-Sp800IvStorageChanged).
    Sp800IvStorageChanged,
    /// SP800 array storage overflow. [Detection, owner and recovery](#cause-Sp800ArrayStorageOverflow).
    Sp800ArrayStorageOverflow,
    /// SP800 native input mutation. [Detection, owner and recovery](#cause-Sp800NativeInputMutation).
    Sp800NativeInputMutation,
    /// SP800 output aliases source. [Detection, owner and recovery](#cause-Sp800OutputAliasesSource).
    Sp800OutputAliasesSource,
    /// SP800 storage overflow. [Detection, owner and recovery](#cause-Sp800StorageOverflow).
    Sp800StorageOverflow,
    /// SP800 template count changed. [Detection, owner and recovery](#cause-Sp800TemplateCountChanged).
    Sp800TemplateCountChanged,
    /// TLS PRF frame accounting. [Detection, owner and recovery](#cause-TlsPrfFrameAccounting).
    TlsPrfFrameAccounting,
    /// TLS PRF native input mutation. [Detection, owner and recovery](#cause-TlsPrfNativeInputMutation).
    TlsPrfNativeInputMutation,
    /// TLS PRF output length changed. [Detection, owner and recovery](#cause-TlsPrfOutputLengthChanged).
    TlsPrfOutputLengthChanged,
    /// TLS PRF source permission absent. [Detection, owner and recovery](#cause-TlsPrfSourcePermissionAbsent).
    TlsPrfSourcePermissionAbsent,
    /// TLS PRF storage accounting. [Detection, owner and recovery](#cause-TlsPrfStorageAccounting).
    TlsPrfStorageAccounting,
    /// TLS context storage changed. [Detection, owner and recovery](#cause-TlsContextStorageChanged).
    TlsContextStorageChanged,
    /// TLS master storage changed. [Detection, owner and recovery](#cause-TlsMasterStorageChanged).
    TlsMasterStorageChanged,
    /// TLS parameter accounting. [Detection, owner and recovery](#cause-TlsParameterAccounting).
    TlsParameterAccounting,
    /// Derivation frame accounting. [Detection, owner and recovery](#cause-DerivationFrameAccounting).
    DerivationFrameAccounting,
    /// Derivation info storage presence. [Detection, owner and recovery](#cause-DerivationInfoStoragePresence).
    DerivationInfoStoragePresence,
    /// Derivation native input changed. [Detection, owner and recovery](#cause-DerivationNativeInputChanged).
    DerivationNativeInputChanged,
    /// Derivation parameter ownership changed. [Detection, owner and recovery](#cause-DerivationParameterOwnershipChanged).
    DerivationParameterOwnershipChanged,
    /// Derivation parameter storage accounting. [Detection, owner and recovery](#cause-DerivationParameterStorageAccounting).
    DerivationParameterStorageAccounting,
    /// Derivation scalar ABI width. [Detection, owner and recovery](#cause-DerivationScalarAbiWidth).
    DerivationScalarAbiWidth,
    /// Derivation storage variant changed. [Detection, owner and recovery](#cause-DerivationStorageVariantChanged).
    DerivationStorageVariantChanged,
    /// Derive returned base handle. [Detection, owner and recovery](#cause-DeriveReturnedBaseHandle).
    DeriveReturnedBaseHandle,
    /// Derive returned secondary source handle. [Detection, owner and recovery](#cause-DeriveReturnedSecondarySourceHandle).
    DeriveReturnedSecondarySourceHandle,
    /// Key-material IV storage. [Detection, owner and recovery](#cause-KeyMaterialIvStorage).
    KeyMaterialIvStorage,
    /// Key-material IV width. [Detection, owner and recovery](#cause-KeyMaterialIvWidth).
    KeyMaterialIvWidth,
    /// Key-material native input mutation. [Detection, owner and recovery](#cause-KeyMaterialNativeInputMutation).
    KeyMaterialNativeInputMutation,
    /// Key-material output aliases source. [Detection, owner and recovery](#cause-KeyMaterialOutputAliasesSource).
    KeyMaterialOutputAliasesSource,
    /// Key-material random storage. [Detection, owner and recovery](#cause-KeyMaterialRandomStorage).
    KeyMaterialRandomStorage,
    /// Key-material storage. [Detection, owner and recovery](#cause-KeyMaterialStorage).
    KeyMaterialStorage,
    /// Messaging parameter accounting. [Detection, owner and recovery](#cause-MessagingParameterAccounting).
    MessagingParameterAccounting,
    /// Missing derivation data storage. [Detection, owner and recovery](#cause-MissingDerivationDataStorage).
    MissingDerivationDataStorage,
    /// Missing derivation input storage. [Detection, owner and recovery](#cause-MissingDerivationInputStorage).
    MissingDerivationInputStorage,
    /// Missing derivation salt storage. [Detection, owner and recovery](#cause-MissingDerivationSaltStorage).
    MissingDerivationSaltStorage,
    /// Missing key-material output. [Detection, owner and recovery](#cause-MissingKeyMaterialOutput).
    MissingKeyMaterialOutput,
    /// Owned input length overflow. [Detection, owner and recovery](#cause-OwnedInputLengthOverflow).
    OwnedInputLengthOverflow,
    /// Prepared input length changed. [Detection, owner and recovery](#cause-PreparedInputLengthChanged).
    PreparedInputLengthChanged,
    /// Two-pair agreement storage accounting. [Detection, owner and recovery](#cause-TwoPairAgreementStorageAccounting).
    TwoPairAgreementStorageAccounting,
}

impl std::fmt::Display for NativeDerivationRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CDeriveKeyUnavailable => f.write_str("C_DeriveKey unavailable"),
            Self::IkeParameterAccounting => f.write_str("IKE parameter accounting"),
            Self::KeaCreationDiagnosticsAbsent => f.write_str("KEA creation diagnostics absent"),
            Self::KeaCreationPhase => f.write_str("KEA creation phase"),
            Self::KeaCreationScope => f.write_str("KEA creation scope"),
            Self::KeaNativeInputMutation => f.write_str("KEA native input mutation"),
            Self::KeaOutputAliasesSource => f.write_str("KEA output aliases source"),
            Self::KeaParameterAccounting => f.write_str("KEA parameter accounting"),
            Self::KeaSharedRandomLength => f.write_str("KEA shared random length"),
            Self::Sp800IvStorageChanged => f.write_str("SP800 IV storage changed"),
            Self::Sp800ArrayStorageOverflow => f.write_str("SP800 array storage overflow"),
            Self::Sp800NativeInputMutation => f.write_str("SP800 native input mutation"),
            Self::Sp800OutputAliasesSource => f.write_str("SP800 output aliases source"),
            Self::Sp800StorageOverflow => f.write_str("SP800 storage overflow"),
            Self::Sp800TemplateCountChanged => f.write_str("SP800 template count changed"),
            Self::TlsPrfFrameAccounting => f.write_str("TLS PRF frame accounting"),
            Self::TlsPrfNativeInputMutation => f.write_str("TLS PRF native input mutation"),
            Self::TlsPrfOutputLengthChanged => f.write_str("TLS PRF output length changed"),
            Self::TlsPrfSourcePermissionAbsent => f.write_str("TLS PRF source permission absent"),
            Self::TlsPrfStorageAccounting => f.write_str("TLS PRF storage accounting"),
            Self::TlsContextStorageChanged => f.write_str("TLS context storage changed"),
            Self::TlsMasterStorageChanged => f.write_str("TLS master storage changed"),
            Self::TlsParameterAccounting => f.write_str("TLS parameter accounting"),
            Self::DerivationFrameAccounting => f.write_str("derivation frame accounting"),
            Self::DerivationInfoStoragePresence => f.write_str("derivation info storage presence"),
            Self::DerivationNativeInputChanged => f.write_str("derivation native input changed"),
            Self::DerivationParameterOwnershipChanged => {
                f.write_str("derivation parameter ownership changed")
            }
            Self::DerivationParameterStorageAccounting => {
                f.write_str("derivation parameter storage accounting")
            }
            Self::DerivationScalarAbiWidth => f.write_str("derivation scalar ABI width"),
            Self::DerivationStorageVariantChanged => {
                f.write_str("derivation storage variant changed")
            }
            Self::DeriveReturnedBaseHandle => f.write_str("derive returned base handle"),
            Self::DeriveReturnedSecondarySourceHandle => {
                f.write_str("derive returned secondary source handle")
            }
            Self::KeyMaterialIvStorage => f.write_str("key-material IV storage"),
            Self::KeyMaterialIvWidth => f.write_str("key-material IV width"),
            Self::KeyMaterialNativeInputMutation => {
                f.write_str("key-material native input mutation")
            }
            Self::KeyMaterialOutputAliasesSource => {
                f.write_str("key-material output aliases source")
            }
            Self::KeyMaterialRandomStorage => f.write_str("key-material random storage"),
            Self::KeyMaterialStorage => f.write_str("key-material storage"),
            Self::MessagingParameterAccounting => f.write_str("messaging parameter accounting"),
            Self::MissingDerivationDataStorage => f.write_str("missing derivation data storage"),
            Self::MissingDerivationInputStorage => f.write_str("missing derivation input storage"),
            Self::MissingDerivationSaltStorage => f.write_str("missing derivation salt storage"),
            Self::MissingKeyMaterialOutput => f.write_str("missing key-material output"),
            Self::OwnedInputLengthOverflow => f.write_str("owned input length overflow"),
            Self::PreparedInputLengthChanged => f.write_str("prepared input length changed"),
            Self::TwoPairAgreementStorageAccounting => {
                f.write_str("two-pair agreement storage accounting")
            }
        }
    }
}
