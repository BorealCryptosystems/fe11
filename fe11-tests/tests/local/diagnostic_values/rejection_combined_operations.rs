// SPDX-License-Identifier: Apache-2.0
//! Public CombinedOperationsRejection values retain identity through category conversion.
use fe11::{CombinedOperationsRejection, Error, RejectionReason};

#[test]
fn variants_preserve_category_and_payload() {
    let cases = [
        CombinedOperationsRejection::DualAesKeyRequired,
        CombinedOperationsRejection::DualAesProfile,
        CombinedOperationsRejection::DualHmacHash,
        CombinedOperationsRejection::DualHmacKeyRequired,
        CombinedOperationsRejection::DualMacKeyAbsent,
        CombinedOperationsRejection::DualMacKeyAlgorithm,
        CombinedOperationsRejection::DualMacKeyType,
        CombinedOperationsRejection::DualMacSelection,
        CombinedOperationsRejection::DualAlreadyPublished,
        CombinedOperationsRejection::DualAsynchronousOutputIdentity,
        CombinedOperationsRejection::DualAuthenticationFamily,
        CombinedOperationsRejection::DualAuthenticationOwner,
        CombinedOperationsRejection::DualAuthenticationParameterIdentity,
        CombinedOperationsRejection::DualAuthenticationResultRole,
        CombinedOperationsRejection::DualAuthenticationRoles,
        CombinedOperationsRejection::DualCheckpointOutputRange,
        CombinedOperationsRejection::DualCheckpointUnavailable,
        CombinedOperationsRejection::DualCipherProfile,
        CombinedOperationsRejection::DualContextCeiling,
        CombinedOperationsRejection::DualDigestHash,
        CombinedOperationsRejection::DualDigestOrMacLength,
        CombinedOperationsRejection::DualExactOutputLength,
        CombinedOperationsRejection::DualFailedExplicitCleanupRequired,
        CombinedOperationsRejection::DualFullMacLength,
        CombinedOperationsRejection::DualHashAbsent,
        CombinedOperationsRejection::DualInputOverflow,
        CombinedOperationsRejection::DualMessageAbsent,
        CombinedOperationsRejection::DualMessageCount,
        CombinedOperationsRejection::DualMetadataOverflow,
        CombinedOperationsRejection::DualNativeFunctionsUnavailable,
        CombinedOperationsRejection::DualNotActive,
        CombinedOperationsRejection::DualNotCapturable,
        CombinedOperationsRejection::DualNotComplete,
        CombinedOperationsRejection::DualOperationNotJoinable,
        CombinedOperationsRejection::DualOperationStorageSize,
        CombinedOperationsRejection::DualOutputAbsent,
        CombinedOperationsRejection::DualOutputOverflow,
        CombinedOperationsRejection::DualOutputProgression,
        CombinedOperationsRejection::DualRecoveryCipherKey,
        CombinedOperationsRejection::DualRecoveryEmptyMessage,
        CombinedOperationsRejection::DualRecoveryKeyRoles,
        CombinedOperationsRejection::DualRecoveryRequiresUnfinishedGcmDecryption,
        CombinedOperationsRejection::DualSnapshotAccounting,
        CombinedOperationsRejection::DuplicateDualCompletion,
        CombinedOperationsRejection::LegacyDualAuthenticationWidth,
        CombinedOperationsRejection::LegacyDualHash,
        CombinedOperationsRejection::ReconstructionActiveFlagsWidth,
        CombinedOperationsRejection::ReconstructionDualAad,
        CombinedOperationsRejection::ReconstructionDualMessage,
        CombinedOperationsRejection::ReconstructionDualMode,
        CombinedOperationsRejection::ReconstructionDualNonce,
        CombinedOperationsRejection::ReconstructionDualPhase,
        CombinedOperationsRejection::RecoveryRequiresDualGcmDecryption,
        CombinedOperationsRejection::RestorationDualKeyRoles,
        CombinedOperationsRejection::RestorationEncryptionKeyRequired,
        CombinedOperationsRejection::TerminalDualAuthenticationWidth,
    ];
    for value in cases {
        let category: RejectionReason = value.into();
        assert!(matches!(category, RejectionReason::CombinedOperations(actual) if actual == value));
        let error = Error::Rejected(category);
        assert_eq!(error.clone(), error);
        assert!(
            matches!(&error, Error::Rejected(RejectionReason::CombinedOperations(actual)) if *actual == value)
        );
        assert!(!value.to_string().is_empty());
        assert!(!category.to_string().is_empty());
        assert!(!error.to_string().is_empty());
        assert!(!format!("{value:?}").is_empty());
    }
}
