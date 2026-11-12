// SPDX-License-Identifier: Apache-2.0
//! CombinedOperations causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to combined operations.
#[doc = include_str!("../../../docs/diagnostics/rejection-combined_operations.md")]
pub enum CombinedOperationsRejection {
    /// Dual AES key required. [Detection, owner and recovery](#cause-DualAesKeyRequired).
    DualAesKeyRequired,
    /// Dual AES profile. [Detection, owner and recovery](#cause-DualAesProfile).
    DualAesProfile,
    /// Dual HMAC hash. [Detection, owner and recovery](#cause-DualHmacHash).
    DualHmacHash,
    /// Dual HMAC key required. [Detection, owner and recovery](#cause-DualHmacKeyRequired).
    DualHmacKeyRequired,
    /// Dual MAC key absent. [Detection, owner and recovery](#cause-DualMacKeyAbsent).
    DualMacKeyAbsent,
    /// Dual MAC key algorithm. [Detection, owner and recovery](#cause-DualMacKeyAlgorithm).
    DualMacKeyAlgorithm,
    /// Dual MAC key type. [Detection, owner and recovery](#cause-DualMacKeyType).
    DualMacKeyType,
    /// Dual MAC selection. [Detection, owner and recovery](#cause-DualMacSelection).
    DualMacSelection,
    /// Dual already published. [Detection, owner and recovery](#cause-DualAlreadyPublished).
    DualAlreadyPublished,
    /// Dual asynchronous output identity. [Detection, owner and recovery](#cause-DualAsynchronousOutputIdentity).
    DualAsynchronousOutputIdentity,
    /// Dual authentication family. [Detection, owner and recovery](#cause-DualAuthenticationFamily).
    DualAuthenticationFamily,
    /// Dual authentication owner. [Detection, owner and recovery](#cause-DualAuthenticationOwner).
    DualAuthenticationOwner,
    /// Dual authentication parameter identity. [Detection, owner and recovery](#cause-DualAuthenticationParameterIdentity).
    DualAuthenticationParameterIdentity,
    /// Dual authentication result role. [Detection, owner and recovery](#cause-DualAuthenticationResultRole).
    DualAuthenticationResultRole,
    /// Dual authentication roles. [Detection, owner and recovery](#cause-DualAuthenticationRoles).
    DualAuthenticationRoles,
    /// Dual checkpoint output range. [Detection, owner and recovery](#cause-DualCheckpointOutputRange).
    DualCheckpointOutputRange,
    /// Dual checkpoint unavailable. [Detection, owner and recovery](#cause-DualCheckpointUnavailable).
    DualCheckpointUnavailable,
    /// Dual cipher profile. [Detection, owner and recovery](#cause-DualCipherProfile).
    DualCipherProfile,
    /// Dual context ceiling. [Detection, owner and recovery](#cause-DualContextCeiling).
    DualContextCeiling,
    /// Dual digest hash. [Detection, owner and recovery](#cause-DualDigestHash).
    DualDigestHash,
    /// Dual digest or MAC length. [Detection, owner and recovery](#cause-DualDigestOrMacLength).
    DualDigestOrMacLength,
    /// Dual exact output length. [Detection, owner and recovery](#cause-DualExactOutputLength).
    DualExactOutputLength,
    /// Dual failed; explicit cleanup required. [Detection, owner and recovery](#cause-DualFailedExplicitCleanupRequired).
    DualFailedExplicitCleanupRequired,
    /// Dual full MAC length. [Detection, owner and recovery](#cause-DualFullMacLength).
    DualFullMacLength,
    /// Dual hash absent. [Detection, owner and recovery](#cause-DualHashAbsent).
    DualHashAbsent,
    /// Dual input overflow. [Detection, owner and recovery](#cause-DualInputOverflow).
    DualInputOverflow,
    /// Dual message absent. [Detection, owner and recovery](#cause-DualMessageAbsent).
    DualMessageAbsent,
    /// Dual message count. [Detection, owner and recovery](#cause-DualMessageCount).
    DualMessageCount,
    /// Dual metadata overflow. [Detection, owner and recovery](#cause-DualMetadataOverflow).
    DualMetadataOverflow,
    /// Dual native functions unavailable. [Detection, owner and recovery](#cause-DualNativeFunctionsUnavailable).
    DualNativeFunctionsUnavailable,
    /// Dual not active. [Detection, owner and recovery](#cause-DualNotActive).
    DualNotActive,
    /// Dual not capturable. [Detection, owner and recovery](#cause-DualNotCapturable).
    DualNotCapturable,
    /// Dual not complete. [Detection, owner and recovery](#cause-DualNotComplete).
    DualNotComplete,
    /// Dual operation not joinable. [Detection, owner and recovery](#cause-DualOperationNotJoinable).
    DualOperationNotJoinable,
    /// Dual operation storage size. [Detection, owner and recovery](#cause-DualOperationStorageSize).
    DualOperationStorageSize,
    /// Dual output absent. [Detection, owner and recovery](#cause-DualOutputAbsent).
    DualOutputAbsent,
    /// Dual output overflow. [Detection, owner and recovery](#cause-DualOutputOverflow).
    DualOutputOverflow,
    /// Dual output progression. [Detection, owner and recovery](#cause-DualOutputProgression).
    DualOutputProgression,
    /// Dual recovery cipher key. [Detection, owner and recovery](#cause-DualRecoveryCipherKey).
    DualRecoveryCipherKey,
    /// Dual recovery empty message. [Detection, owner and recovery](#cause-DualRecoveryEmptyMessage).
    DualRecoveryEmptyMessage,
    /// Dual recovery key roles. [Detection, owner and recovery](#cause-DualRecoveryKeyRoles).
    DualRecoveryKeyRoles,
    /// Dual recovery requires unfinished GCM decryption. [Detection, owner and recovery](#cause-DualRecoveryRequiresUnfinishedGcmDecryption).
    DualRecoveryRequiresUnfinishedGcmDecryption,
    /// Dual snapshot accounting. [Detection, owner and recovery](#cause-DualSnapshotAccounting).
    DualSnapshotAccounting,
    /// Duplicate dual completion. [Detection, owner and recovery](#cause-DuplicateDualCompletion).
    DuplicateDualCompletion,
    /// Legacy dual authentication width. [Detection, owner and recovery](#cause-LegacyDualAuthenticationWidth).
    LegacyDualAuthenticationWidth,
    /// Legacy dual hash. [Detection, owner and recovery](#cause-LegacyDualHash).
    LegacyDualHash,
    /// Reconstruction active flags width. [Detection, owner and recovery](#cause-ReconstructionActiveFlagsWidth).
    ReconstructionActiveFlagsWidth,
    /// Reconstruction dual AAD. [Detection, owner and recovery](#cause-ReconstructionDualAad).
    ReconstructionDualAad,
    /// Reconstruction dual message. [Detection, owner and recovery](#cause-ReconstructionDualMessage).
    ReconstructionDualMessage,
    /// Reconstruction dual mode. [Detection, owner and recovery](#cause-ReconstructionDualMode).
    ReconstructionDualMode,
    /// Reconstruction dual nonce. [Detection, owner and recovery](#cause-ReconstructionDualNonce).
    ReconstructionDualNonce,
    /// Reconstruction dual phase. [Detection, owner and recovery](#cause-ReconstructionDualPhase).
    ReconstructionDualPhase,
    /// Recovery requires dual GCM decryption. [Detection, owner and recovery](#cause-RecoveryRequiresDualGcmDecryption).
    RecoveryRequiresDualGcmDecryption,
    /// Restoration dual key roles. [Detection, owner and recovery](#cause-RestorationDualKeyRoles).
    RestorationDualKeyRoles,
    /// Restoration encryption key required. [Detection, owner and recovery](#cause-RestorationEncryptionKeyRequired).
    RestorationEncryptionKeyRequired,
    /// Terminal dual authentication width. [Detection, owner and recovery](#cause-TerminalDualAuthenticationWidth).
    TerminalDualAuthenticationWidth,


}

impl std::fmt::Display for CombinedOperationsRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {


            Self::DualAesKeyRequired => f.write_str("dual AES key required"),
            Self::DualAesProfile => f.write_str("dual AES profile"),
            Self::DualHmacHash => f.write_str("dual HMAC hash"),
            Self::DualHmacKeyRequired => f.write_str("dual HMAC key required"),
            Self::DualMacKeyAbsent => f.write_str("dual MAC key absent"),
            Self::DualMacKeyAlgorithm => f.write_str("dual MAC key algorithm"),
            Self::DualMacKeyType => f.write_str("dual MAC key type"),
            Self::DualMacSelection => f.write_str("dual MAC selection"),
            Self::DualAlreadyPublished => f.write_str("dual already published"),
            Self::DualAsynchronousOutputIdentity => {
                f.write_str("dual asynchronous output identity")
            }
            Self::DualAuthenticationFamily => f.write_str("dual authentication family"),
            Self::DualAuthenticationOwner => f.write_str("dual authentication owner"),
            Self::DualAuthenticationParameterIdentity => {
                f.write_str("dual authentication parameter identity")
            }
            Self::DualAuthenticationResultRole => f.write_str("dual authentication result role"),
            Self::DualAuthenticationRoles => f.write_str("dual authentication roles"),
            Self::DualCheckpointOutputRange => f.write_str("dual checkpoint output range"),
            Self::DualCheckpointUnavailable => f.write_str("dual checkpoint unavailable"),
            Self::DualCipherProfile => f.write_str("dual cipher profile"),
            Self::DualContextCeiling => f.write_str("dual context ceiling"),
            Self::DualDigestHash => f.write_str("dual digest hash"),
            Self::DualDigestOrMacLength => f.write_str("dual digest or MAC length"),
            Self::DualExactOutputLength => f.write_str("dual exact output length"),
            Self::DualFailedExplicitCleanupRequired => {
                f.write_str("dual failed; explicit cleanup required")
            }
            Self::DualFullMacLength => f.write_str("dual full MAC length"),
            Self::DualHashAbsent => f.write_str("dual hash absent"),
            Self::DualInputOverflow => f.write_str("dual input overflow"),
            Self::DualMessageAbsent => f.write_str("dual message absent"),
            Self::DualMessageCount => f.write_str("dual message count"),
            Self::DualMetadataOverflow => f.write_str("dual metadata overflow"),
            Self::DualNativeFunctionsUnavailable => {
                f.write_str("dual native functions unavailable")
            }
            Self::DualNotActive => f.write_str("dual not active"),
            Self::DualNotCapturable => f.write_str("dual not capturable"),
            Self::DualNotComplete => f.write_str("dual not complete"),
            Self::DualOperationNotJoinable => f.write_str("dual operation not joinable"),
            Self::DualOperationStorageSize => f.write_str("dual operation storage size"),
            Self::DualOutputAbsent => f.write_str("dual output absent"),
            Self::DualOutputOverflow => f.write_str("dual output overflow"),
            Self::DualOutputProgression => f.write_str("dual output progression"),
            Self::DualRecoveryCipherKey => f.write_str("dual recovery cipher key"),
            Self::DualRecoveryEmptyMessage => f.write_str("dual recovery empty message"),
            Self::DualRecoveryKeyRoles => f.write_str("dual recovery key roles"),
            Self::DualRecoveryRequiresUnfinishedGcmDecryption => {
                f.write_str("dual recovery requires unfinished GCM decryption")
            }
            Self::DualSnapshotAccounting => f.write_str("dual snapshot accounting"),
            Self::DuplicateDualCompletion => f.write_str("duplicate dual completion"),
            Self::LegacyDualAuthenticationWidth => f.write_str("legacy dual authentication width"),
            Self::LegacyDualHash => f.write_str("legacy dual hash"),
            Self::ReconstructionActiveFlagsWidth => {
                f.write_str("reconstruction active flags width")
            }
            Self::ReconstructionDualAad => f.write_str("reconstruction dual AAD"),
            Self::ReconstructionDualMessage => f.write_str("reconstruction dual message"),
            Self::ReconstructionDualMode => f.write_str("reconstruction dual mode"),
            Self::ReconstructionDualNonce => f.write_str("reconstruction dual nonce"),
            Self::ReconstructionDualPhase => f.write_str("reconstruction dual phase"),
            Self::RecoveryRequiresDualGcmDecryption => {
                f.write_str("recovery requires dual GCM decryption")
            }
            Self::RestorationDualKeyRoles => f.write_str("restoration dual key roles"),
            Self::RestorationEncryptionKeyRequired => {
                f.write_str("restoration encryption key required")
            }
            Self::TerminalDualAuthenticationWidth => {
                f.write_str("terminal dual authentication width")
            }
        }
    }
}
