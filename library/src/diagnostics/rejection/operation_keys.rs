// SPDX-License-Identifier: Apache-2.0
//! OperationKeys causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to operation keys.
#[doc = include_str!("../../../docs/diagnostics/rejection-operation_keys.md")]
pub enum OperationKeysRejection {
    /// PSS requires an RSA reference. [Detection, owner and recovery](#cause-PssRequiresAnRsaReference).
    PssRequiresAnRsaReference,
    /// Checkpoint RSA key size. [Detection, owner and recovery](#cause-CheckpointRsaKeySize).
    CheckpointRsaKeySize,
    /// Checkpoint algorithm absent. [Detection, owner and recovery](#cause-CheckpointAlgorithmAbsent).
    CheckpointAlgorithmAbsent,
    /// Checkpoint destination key binding. [Detection, owner and recovery](#cause-CheckpointDestinationKeyBinding).
    CheckpointDestinationKeyBinding,
    /// Checkpoint destination key profile. [Detection, owner and recovery](#cause-CheckpointDestinationKeyProfile).
    CheckpointDestinationKeyProfile,
    /// Cipher destination absent. [Detection, owner and recovery](#cause-CipherDestinationAbsent).
    CipherDestinationAbsent,
    /// Cipher writer declaration required. [Detection, owner and recovery](#cause-CipherWriterDeclarationRequired).
    CipherWriterDeclarationRequired,
    /// Cipher writer revocation state. [Detection, owner and recovery](#cause-CipherWriterRevocationState).
    CipherWriterRevocationState,
    /// Digest declaration on another family. [Detection, owner and recovery](#cause-DigestDeclarationOnAnotherFamily).
    DigestDeclarationOnAnotherFamily,
    /// Foreign or stale message key. [Detection, owner and recovery](#cause-ForeignOrStaleMessageKey).
    ForeignOrStaleMessageKey,
    /// Foreign or stale native writer key. [Detection, owner and recovery](#cause-ForeignOrStaleNativeWriterKey).
    ForeignOrStaleNativeWriterKey,
    /// Key lease candidate already occupied. [Detection, owner and recovery](#cause-KeyLeaseCandidateAlreadyOccupied).
    KeyLeaseCandidateAlreadyOccupied,
    /// Message destination absent. [Detection, owner and recovery](#cause-MessageDestinationAbsent).
    MessageDestinationAbsent,
    /// Message has no cipher key role. [Detection, owner and recovery](#cause-MessageHasNoCipherKeyRole).
    MessageHasNoCipherKeyRole,
    /// Native destination storage accounting. [Detection, owner and recovery](#cause-NativeDestinationStorageAccounting).
    NativeDestinationStorageAccounting,
    /// Native destination storage without native role. [Detection, owner and recovery](#cause-NativeDestinationStorageWithoutNativeRole).
    NativeDestinationStorageWithoutNativeRole,
    /// Native key writer already transferred. [Detection, owner and recovery](#cause-NativeKeyWriterAlreadyTransferred).
    NativeKeyWriterAlreadyTransferred,
    /// Native secret cipher has no PSS parameter contract. [Detection, owner and recovery](#cause-NativeSecretCipherHasNoPssParameterContract).
    NativeSecretCipherHasNoPssParameterContract,
    /// Native transfer storage accounting. [Detection, owner and recovery](#cause-NativeTransferStorageAccounting).
    NativeTransferStorageAccounting,
    /// Native writer revocation absent. [Detection, owner and recovery](#cause-NativeWriterRevocationAbsent).
    NativeWriterRevocationAbsent,
    /// Recovery reference has no PSS parameter contract. [Detection, owner and recovery](#cause-RecoveryReferenceHasNoPssParameterContract).
    RecoveryReferenceHasNoPssParameterContract,
    /// Rejoin signing mechanism. [Detection, owner and recovery](#cause-RejoinSigningMechanism).
    RejoinSigningMechanism,
    /// Rejoin signing parameters. [Detection, owner and recovery](#cause-RejoinSigningParameters).
    RejoinSigningParameters,
    /// Rejoin verification mechanism. [Detection, owner and recovery](#cause-RejoinVerificationMechanism).
    RejoinVerificationMechanism,
    /// Rejoin verification parameters. [Detection, owner and recovery](#cause-RejoinVerificationParameters).
    RejoinVerificationParameters,
    /// Restoration binding already consumed. [Detection, owner and recovery](#cause-RestorationBindingAlreadyConsumed).
    RestorationBindingAlreadyConsumed,
    /// Restore key identity mismatch. [Detection, owner and recovery](#cause-RestoreKeyIdentityMismatch).
    RestoreKeyIdentityMismatch,
    /// Revoked message key. [Detection, owner and recovery](#cause-RevokedMessageKey).
    RevokedMessageKey,
    /// Signature destination absent. [Detection, owner and recovery](#cause-SignatureDestinationAbsent).
    SignatureDestinationAbsent,
    /// Signature reference on another operation family. [Detection, owner and recovery](#cause-SignatureReferenceOnAnotherOperationFamily).
    SignatureReferenceOnAnotherOperationFamily,
    /// Signature reference requires its signature owner. [Detection, owner and recovery](#cause-SignatureReferenceRequiresItsSignatureOwner).
    SignatureReferenceRequiresItsSignatureOwner,
    /// Unbound native key writer. [Detection, owner and recovery](#cause-UnboundNativeKeyWriter).
    UnboundNativeKeyWriter,
    /// Unexpected reader preparation storage. [Detection, owner and recovery](#cause-UnexpectedReaderPreparationStorage).
    UnexpectedReaderPreparationStorage,
    /// Unsubmitted native writer cannot be duplicated. [Detection, owner and recovery](#cause-UnsubmittedNativeWriterCannotBeDuplicated).
    UnsubmittedNativeWriterCannotBeDuplicated,
}

impl std::fmt::Display for OperationKeysRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PssRequiresAnRsaReference => f.write_str("PSS requires an RSA reference"),
            Self::CheckpointRsaKeySize => f.write_str("checkpoint RSA key size"),
            Self::CheckpointAlgorithmAbsent => f.write_str("checkpoint algorithm absent"),
            Self::CheckpointDestinationKeyBinding => {
                f.write_str("checkpoint destination key binding")
            }
            Self::CheckpointDestinationKeyProfile => {
                f.write_str("checkpoint destination key profile")
            }
            Self::CipherDestinationAbsent => f.write_str("cipher destination absent"),
            Self::CipherWriterDeclarationRequired => {
                f.write_str("cipher writer declaration required")
            }
            Self::CipherWriterRevocationState => f.write_str("cipher writer revocation state"),
            Self::DigestDeclarationOnAnotherFamily => {
                f.write_str("digest declaration on another family")
            }
            Self::ForeignOrStaleMessageKey => f.write_str("foreign or stale message key"),
            Self::ForeignOrStaleNativeWriterKey => {
                f.write_str("foreign or stale native writer key")
            }
            Self::KeyLeaseCandidateAlreadyOccupied => {
                f.write_str("key lease candidate already occupied")
            }
            Self::MessageDestinationAbsent => f.write_str("message destination absent"),
            Self::MessageHasNoCipherKeyRole => f.write_str("message has no cipher key role"),
            Self::NativeDestinationStorageAccounting => {
                f.write_str("native destination storage accounting")
            }
            Self::NativeDestinationStorageWithoutNativeRole => {
                f.write_str("native destination storage without native role")
            }
            Self::NativeKeyWriterAlreadyTransferred => {
                f.write_str("native key writer already transferred")
            }
            Self::NativeSecretCipherHasNoPssParameterContract => {
                f.write_str("native secret cipher has no PSS parameter contract")
            }
            Self::NativeTransferStorageAccounting => {
                f.write_str("native transfer storage accounting")
            }
            Self::NativeWriterRevocationAbsent => f.write_str("native writer revocation absent"),
            Self::RecoveryReferenceHasNoPssParameterContract => {
                f.write_str("recovery reference has no PSS parameter contract")
            }
            Self::RejoinSigningMechanism => f.write_str("rejoin signing mechanism"),
            Self::RejoinSigningParameters => f.write_str("rejoin signing parameters"),
            Self::RejoinVerificationMechanism => f.write_str("rejoin verification mechanism"),
            Self::RejoinVerificationParameters => f.write_str("rejoin verification parameters"),
            Self::RestorationBindingAlreadyConsumed => {
                f.write_str("restoration binding already consumed")
            }
            Self::RestoreKeyIdentityMismatch => f.write_str("restore key identity mismatch"),
            Self::RevokedMessageKey => f.write_str("revoked message key"),
            Self::SignatureDestinationAbsent => f.write_str("signature destination absent"),
            Self::SignatureReferenceOnAnotherOperationFamily => {
                f.write_str("signature reference on another operation family")
            }
            Self::SignatureReferenceRequiresItsSignatureOwner => {
                f.write_str("signature reference requires its signature owner")
            }
            Self::UnboundNativeKeyWriter => f.write_str("unbound native key writer"),
            Self::UnexpectedReaderPreparationStorage => {
                f.write_str("unexpected reader preparation storage")
            }
            Self::UnsubmittedNativeWriterCannotBeDuplicated => {
                f.write_str("unsubmitted native writer cannot be duplicated")
            }
        }
    }
}
