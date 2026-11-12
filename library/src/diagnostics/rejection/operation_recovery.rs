// SPDX-License-Identifier: Apache-2.0
//! OperationRecovery causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to operation recovery.
#[doc = include_str!("../../../docs/diagnostics/rejection-operation_recovery.md")]
pub enum OperationRecoveryRejection {
    /// C_SignRecover unavailable. [Detection, owner and recovery](#cause-CSignRecoverUnavailable).
    CSignRecoverUnavailable,
    /// C_SignRecoverInit unavailable. [Detection, owner and recovery](#cause-CSignRecoverInitUnavailable).
    CSignRecoverInitUnavailable,
    /// C_VerifyRecover unavailable. [Detection, owner and recovery](#cause-CVerifyRecoverUnavailable).
    CVerifyRecoverUnavailable,
    /// C_VerifyRecoverInit unavailable. [Detection, owner and recovery](#cause-CVerifyRecoverInitUnavailable).
    CVerifyRecoverInitUnavailable,
    /// Recovery authentication key required. [Detection, owner and recovery](#cause-RecoveryAuthenticationKeyRequired).
    RecoveryAuthenticationKeyRequired,
    /// Recovery cipher key absent. [Detection, owner and recovery](#cause-RecoveryCipherKeyAbsent).
    RecoveryCipherKeyAbsent,
    /// Recovery empty batch. [Detection, owner and recovery](#cause-RecoveryEmptyBatch).
    RecoveryEmptyBatch,
    /// Recovery frame accounting overflow. [Detection, owner and recovery](#cause-RecoveryFrameAccountingOverflow).
    RecoveryFrameAccountingOverflow,
    /// Recovery functions unavailable. [Detection, owner and recovery](#cause-RecoveryFunctionsUnavailable).
    RecoveryFunctionsUnavailable,
    /// Recovery is not waiting for storage. [Detection, owner and recovery](#cause-RecoveryIsNotWaitingForStorage).
    RecoveryIsNotWaitingForStorage,
    /// Recovery mechanism does not match requested API. [Detection, owner and recovery](#cause-RecoveryMechanismDoesNotMatchRequestedApi).
    RecoveryMechanismDoesNotMatchRequestedApi,
    /// Recovery mechanism width. [Detection, owner and recovery](#cause-RecoveryMechanismWidth).
    RecoveryMechanismWidth,
    /// Recovery native input identity. [Detection, owner and recovery](#cause-RecoveryNativeInputIdentity).
    RecoveryNativeInputIdentity,
    /// Recovery not capturable. [Detection, owner and recovery](#cause-RecoveryNotCapturable).
    RecoveryNotCapturable,
    /// Recovery operation storage size. [Detection, owner and recovery](#cause-RecoveryOperationStorageSize).
    RecoveryOperationStorageSize,
    /// Recovery outcome uncertain. [Detection, owner and recovery](#cause-RecoveryOutcomeUncertain).
    RecoveryOutcomeUncertain,
    /// Recovery output capacity. [Detection, owner and recovery](#cause-RecoveryOutputCapacity).
    RecoveryOutputCapacity,
    /// Recovery output ceiling. [Detection, owner and recovery](#cause-RecoveryOutputCeiling).
    RecoveryOutputCeiling,
    /// Recovery prefix width. [Detection, owner and recovery](#cause-RecoveryPrefixWidth).
    RecoveryPrefixWidth,
    /// Recovery record descriptor. [Detection, owner and recovery](#cause-RecoveryRecordDescriptor).
    RecoveryRecordDescriptor,
    /// Recovery record family. [Detection, owner and recovery](#cause-RecoveryRecordFamily).
    RecoveryRecordFamily,
    /// Recovery record input absent. [Detection, owner and recovery](#cause-RecoveryRecordInputAbsent).
    RecoveryRecordInputAbsent,
    /// Recovery record input count. [Detection, owner and recovery](#cause-RecoveryRecordInputCount).
    RecoveryRecordInputCount,
    /// Recovery record mechanism width. [Detection, owner and recovery](#cause-RecoveryRecordMechanismWidth).
    RecoveryRecordMechanismWidth,
    /// Recovery record output profile. [Detection, owner and recovery](#cause-RecoveryRecordOutputProfile).
    RecoveryRecordOutputProfile,
    /// Recovery record parameter contract. [Detection, owner and recovery](#cause-RecoveryRecordParameterContract).
    RecoveryRecordParameterContract,
    /// Recovery record pending. [Detection, owner and recovery](#cause-RecoveryRecordPending).
    RecoveryRecordPending,
    /// Recovery record phase. [Detection, owner and recovery](#cause-RecoveryRecordPhase).
    RecoveryRecordPhase,
    /// Recovery record premature observation. [Detection, owner and recovery](#cause-RecoveryRecordPrematureObservation).
    RecoveryRecordPrematureObservation,
    /// Recovery record progression. [Detection, owner and recovery](#cause-RecoveryRecordProgression).
    RecoveryRecordProgression,
    /// Recovery reference required. [Detection, owner and recovery](#cause-RecoveryReferenceRequired).
    RecoveryReferenceRequired,
    /// Recovery reported length width. [Detection, owner and recovery](#cause-RecoveryReportedLengthWidth).
    RecoveryReportedLengthWidth,
    /// Recovery result already published. [Detection, owner and recovery](#cause-RecoveryResultAlreadyPublished).
    RecoveryResultAlreadyPublished,
    /// Recovery result consumed. [Detection, owner and recovery](#cause-RecoveryResultConsumed).
    RecoveryResultConsumed,
    /// Recovery result incomplete. [Detection, owner and recovery](#cause-RecoveryResultIncomplete).
    RecoveryResultIncomplete,
    /// Recovery snapshot shape changed. [Detection, owner and recovery](#cause-RecoverySnapshotShapeChanged).
    RecoverySnapshotShapeChanged,
    /// Recovery terminal buffer absent. [Detection, owner and recovery](#cause-RecoveryTerminalBufferAbsent).
    RecoveryTerminalBufferAbsent,
    /// Recovery terminal capacity. [Detection, owner and recovery](#cause-RecoveryTerminalCapacity).
    RecoveryTerminalCapacity,
    /// Recovery terminal observation absent. [Detection, owner and recovery](#cause-RecoveryTerminalObservationAbsent).
    RecoveryTerminalObservationAbsent,
    /// Recovery terminal output. [Detection, owner and recovery](#cause-RecoveryTerminalOutput).
    RecoveryTerminalOutput,
    /// Unexpected recovery cipher key. [Detection, owner and recovery](#cause-UnexpectedRecoveryCipherKey).
    UnexpectedRecoveryCipherKey,
}

impl std::fmt::Display for OperationRecoveryRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CSignRecoverUnavailable => f.write_str("C_SignRecover unavailable"),
            Self::CSignRecoverInitUnavailable => f.write_str("C_SignRecoverInit unavailable"),
            Self::CVerifyRecoverUnavailable => f.write_str("C_VerifyRecover unavailable"),
            Self::CVerifyRecoverInitUnavailable => f.write_str("C_VerifyRecoverInit unavailable"),
            Self::RecoveryAuthenticationKeyRequired => {
                f.write_str("recovery authentication key required")
            }
            Self::RecoveryCipherKeyAbsent => f.write_str("recovery cipher key absent"),
            Self::RecoveryEmptyBatch => f.write_str("recovery empty batch"),
            Self::RecoveryFrameAccountingOverflow => {
                f.write_str("recovery frame accounting overflow")
            }
            Self::RecoveryFunctionsUnavailable => f.write_str("recovery functions unavailable"),
            Self::RecoveryIsNotWaitingForStorage => {
                f.write_str("recovery is not waiting for storage")
            }
            Self::RecoveryMechanismDoesNotMatchRequestedApi => {
                f.write_str("recovery mechanism does not match requested API")
            }
            Self::RecoveryMechanismWidth => f.write_str("recovery mechanism width"),
            Self::RecoveryNativeInputIdentity => f.write_str("recovery native input identity"),
            Self::RecoveryNotCapturable => f.write_str("recovery not capturable"),
            Self::RecoveryOperationStorageSize => f.write_str("recovery operation storage size"),
            Self::RecoveryOutcomeUncertain => f.write_str("recovery outcome uncertain"),
            Self::RecoveryOutputCapacity => f.write_str("recovery output capacity"),
            Self::RecoveryOutputCeiling => f.write_str("recovery output ceiling"),
            Self::RecoveryPrefixWidth => f.write_str("recovery prefix width"),
            Self::RecoveryRecordDescriptor => f.write_str("recovery record descriptor"),
            Self::RecoveryRecordFamily => f.write_str("recovery record family"),
            Self::RecoveryRecordInputAbsent => f.write_str("recovery record input absent"),
            Self::RecoveryRecordInputCount => f.write_str("recovery record input count"),
            Self::RecoveryRecordMechanismWidth => f.write_str("recovery record mechanism width"),
            Self::RecoveryRecordOutputProfile => f.write_str("recovery record output profile"),
            Self::RecoveryRecordParameterContract => {
                f.write_str("recovery record parameter contract")
            }
            Self::RecoveryRecordPending => f.write_str("recovery record pending"),
            Self::RecoveryRecordPhase => f.write_str("recovery record phase"),
            Self::RecoveryRecordPrematureObservation => {
                f.write_str("recovery record premature observation")
            }
            Self::RecoveryRecordProgression => f.write_str("recovery record progression"),
            Self::RecoveryReferenceRequired => f.write_str("recovery reference required"),
            Self::RecoveryReportedLengthWidth => f.write_str("recovery reported length width"),
            Self::RecoveryResultAlreadyPublished => {
                f.write_str("recovery result already published")
            }
            Self::RecoveryResultConsumed => f.write_str("recovery result consumed"),
            Self::RecoveryResultIncomplete => f.write_str("recovery result incomplete"),
            Self::RecoverySnapshotShapeChanged => f.write_str("recovery snapshot shape changed"),
            Self::RecoveryTerminalBufferAbsent => f.write_str("recovery terminal buffer absent"),
            Self::RecoveryTerminalCapacity => f.write_str("recovery terminal capacity"),
            Self::RecoveryTerminalObservationAbsent => {
                f.write_str("recovery terminal observation absent")
            }
            Self::RecoveryTerminalOutput => f.write_str("recovery terminal output"),
            Self::UnexpectedRecoveryCipherKey => f.write_str("unexpected recovery cipher key"),
        }
    }
}
