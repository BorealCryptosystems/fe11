// SPDX-License-Identifier: Apache-2.0
//! Public OperationKeysRejection values retain identity through category conversion.
use fe11::{Error, OperationKeysRejection, RejectionReason};

#[test]
fn variants_preserve_category_and_payload() {
    let cases = [
        OperationKeysRejection::PssRequiresAnRsaReference,
        OperationKeysRejection::CheckpointRsaKeySize,
        OperationKeysRejection::CheckpointAlgorithmAbsent,
        OperationKeysRejection::CheckpointDestinationKeyBinding,
        OperationKeysRejection::CheckpointDestinationKeyProfile,
        OperationKeysRejection::CipherDestinationAbsent,
        OperationKeysRejection::CipherWriterDeclarationRequired,
        OperationKeysRejection::CipherWriterRevocationState,
        OperationKeysRejection::DigestDeclarationOnAnotherFamily,
        OperationKeysRejection::ForeignOrStaleMessageKey,
        OperationKeysRejection::ForeignOrStaleNativeWriterKey,
        OperationKeysRejection::KeyLeaseCandidateAlreadyOccupied,
        OperationKeysRejection::MessageDestinationAbsent,
        OperationKeysRejection::MessageHasNoCipherKeyRole,
        OperationKeysRejection::NativeDestinationStorageAccounting,
        OperationKeysRejection::NativeDestinationStorageWithoutNativeRole,
        OperationKeysRejection::NativeKeyWriterAlreadyTransferred,
        OperationKeysRejection::NativeSecretCipherHasNoPssParameterContract,
        OperationKeysRejection::NativeTransferStorageAccounting,
        OperationKeysRejection::NativeWriterRevocationAbsent,
        OperationKeysRejection::RecoveryReferenceHasNoPssParameterContract,
        OperationKeysRejection::RejoinSigningMechanism,
        OperationKeysRejection::RejoinSigningParameters,
        OperationKeysRejection::RejoinVerificationMechanism,
        OperationKeysRejection::RejoinVerificationParameters,
        OperationKeysRejection::RestorationBindingAlreadyConsumed,
        OperationKeysRejection::RestoreKeyIdentityMismatch,
        OperationKeysRejection::RevokedMessageKey,
        OperationKeysRejection::SignatureDestinationAbsent,
        OperationKeysRejection::SignatureReferenceOnAnotherOperationFamily,
        OperationKeysRejection::SignatureReferenceRequiresItsSignatureOwner,
        OperationKeysRejection::UnboundNativeKeyWriter,
        OperationKeysRejection::UnexpectedReaderPreparationStorage,
        OperationKeysRejection::UnsubmittedNativeWriterCannotBeDuplicated,
    ];
    for value in cases {
        let category: RejectionReason = value.into();
        assert!(matches!(category, RejectionReason::OperationKeys(actual) if actual == value));
        let error = Error::Rejected(category);
        assert_eq!(error.clone(), error);
        assert!(
            matches!(&error, Error::Rejected(RejectionReason::OperationKeys(actual)) if *actual == value)
        );
        assert!(!value.to_string().is_empty());
        assert!(!category.to_string().is_empty());
        assert!(!error.to_string().is_empty());
        assert!(!format!("{value:?}").is_empty());
    }
}
