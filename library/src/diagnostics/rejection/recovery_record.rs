// SPDX-License-Identifier: Apache-2.0
//! RecoveryRecord causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to recovery record.
#[doc = include_str!("../../../docs/diagnostics/rejection-recovery_record.md")]
pub enum RecoveryRecordRejection {
    /// Detached capacity width. [Detection, owner and recovery](#cause-DetachedCapacityWidth).
    DetachedCapacityWidth,
    /// Detached capture function. [Detection, owner and recovery](#cause-DetachedCaptureFunction).
    DetachedCaptureFunction,
    /// Detached capture output ceiling. [Detection, owner and recovery](#cause-DetachedCaptureOutputCeiling).
    DetachedCaptureOutputCeiling,
    /// Detached identifier width. [Detection, owner and recovery](#cause-DetachedIdentifierWidth).
    DetachedIdentifierWidth,
    /// Detached native function mismatch. [Detection, owner and recovery](#cause-DetachedNativeFunctionMismatch).
    DetachedNativeFunctionMismatch,
    /// Detached native identifier width. [Detection, owner and recovery](#cause-DetachedNativeIdentifierWidth).
    DetachedNativeIdentifierWidth,
    /// Detached output capacity mismatch. [Detection, owner and recovery](#cause-DetachedOutputCapacityMismatch).
    DetachedOutputCapacityMismatch,
    /// Dual recovery family. [Detection, owner and recovery](#cause-DualRecoveryFamily).
    DualRecoveryFamily,
    /// Dual recovery historical completion. [Detection, owner and recovery](#cause-DualRecoveryHistoricalCompletion).
    DualRecoveryHistoricalCompletion,
    /// Dual recovery historical observation. [Detection, owner and recovery](#cause-DualRecoveryHistoricalObservation).
    DualRecoveryHistoricalObservation,
    /// Dual recovery kind. [Detection, owner and recovery](#cause-DualRecoveryKind).
    DualRecoveryKind,
    /// Dual recovery output. [Detection, owner and recovery](#cause-DualRecoveryOutput).
    DualRecoveryOutput,
    /// Dual recovery profile. [Detection, owner and recovery](#cause-DualRecoveryProfile).
    DualRecoveryProfile,
    /// Dual recovery validation capacity. [Detection, owner and recovery](#cause-DualRecoveryValidationCapacity).
    DualRecoveryValidationCapacity,
    /// Recovery excess observation. [Detection, owner and recovery](#cause-RecoveryExcessObservation).
    RecoveryExcessObservation,
    /// Recovery final observation. [Detection, owner and recovery](#cause-RecoveryFinalObservation).
    RecoveryFinalObservation,
    /// Recovery historical prefix. [Detection, owner and recovery](#cause-RecoveryHistoricalPrefix).
    RecoveryHistoricalPrefix,
    /// Recovery identity width. [Detection, owner and recovery](#cause-RecoveryIdentityWidth).
    RecoveryIdentityWidth,
    /// Recovery manifest kind. [Detection, owner and recovery](#cause-RecoveryManifestKind).
    RecoveryManifestKind,
    /// Recovery observation absent. [Detection, owner and recovery](#cause-RecoveryObservationAbsent).
    RecoveryObservationAbsent,
    /// Recovery observation association. [Detection, owner and recovery](#cause-RecoveryObservationAssociation).
    RecoveryObservationAssociation,
    /// Recovery record kind. [Detection, owner and recovery](#cause-RecoveryRecordKind).
    RecoveryRecordKind,
    /// Recovery token identity. [Detection, owner and recovery](#cause-RecoveryTokenIdentity).
    RecoveryTokenIdentity,
    /// Restore capacity width. [Detection, owner and recovery](#cause-RestoreCapacityWidth).
    RestoreCapacityWidth,
    /// Restore identifier width. [Detection, owner and recovery](#cause-RestoreIdentifierWidth).
    RestoreIdentifierWidth,
    /// Restore key encoding. [Detection, owner and recovery](#cause-RestoreKeyEncoding).
    RestoreKeyEncoding,
    /// Restore native identifier width. [Detection, owner and recovery](#cause-RestoreNativeIdentifierWidth).
    RestoreNativeIdentifierWidth,
    /// Restore observation slot width. [Detection, owner and recovery](#cause-RestoreObservationSlotWidth).
    RestoreObservationSlotWidth,
    /// Restore transfer capacity. [Detection, owner and recovery](#cause-RestoreTransferCapacity).
    RestoreTransferCapacity,
    /// Restore transfer function. [Detection, owner and recovery](#cause-RestoreTransferFunction).
    RestoreTransferFunction,
    /// Restore transfer key roles. [Detection, owner and recovery](#cause-RestoreTransferKeyRoles).
    RestoreTransferKeyRoles,
    /// Restore transfer kind. [Detection, owner and recovery](#cause-RestoreTransferKind).
    RestoreTransferKind,
    /// Terminal observation function. [Detection, owner and recovery](#cause-TerminalObservationFunction).
    TerminalObservationFunction,
    /// Terminal validity code. [Detection, owner and recovery](#cause-TerminalValidityCode).
    TerminalValidityCode,
}

impl std::fmt::Display for RecoveryRecordRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DetachedCapacityWidth => f.write_str("detached capacity width"),
            Self::DetachedCaptureFunction => f.write_str("detached capture function"),
            Self::DetachedCaptureOutputCeiling => f.write_str("detached capture output ceiling"),
            Self::DetachedIdentifierWidth => f.write_str("detached identifier width"),
            Self::DetachedNativeFunctionMismatch => {
                f.write_str("detached native function mismatch")
            }
            Self::DetachedNativeIdentifierWidth => f.write_str("detached native identifier width"),
            Self::DetachedOutputCapacityMismatch => {
                f.write_str("detached output capacity mismatch")
            }
            Self::DualRecoveryFamily => f.write_str("dual recovery family"),
            Self::DualRecoveryHistoricalCompletion => {
                f.write_str("dual recovery historical completion")
            }
            Self::DualRecoveryHistoricalObservation => {
                f.write_str("dual recovery historical observation")
            }
            Self::DualRecoveryKind => f.write_str("dual recovery kind"),
            Self::DualRecoveryOutput => f.write_str("dual recovery output"),
            Self::DualRecoveryProfile => f.write_str("dual recovery profile"),
            Self::DualRecoveryValidationCapacity => {
                f.write_str("dual recovery validation capacity")
            }
            Self::RecoveryExcessObservation => f.write_str("recovery excess observation"),
            Self::RecoveryFinalObservation => f.write_str("recovery final observation"),
            Self::RecoveryHistoricalPrefix => f.write_str("recovery historical prefix"),
            Self::RecoveryIdentityWidth => f.write_str("recovery identity width"),
            Self::RecoveryManifestKind => f.write_str("recovery manifest kind"),
            Self::RecoveryObservationAbsent => f.write_str("recovery observation absent"),
            Self::RecoveryObservationAssociation => f.write_str("recovery observation association"),
            Self::RecoveryRecordKind => f.write_str("recovery record kind"),
            Self::RecoveryTokenIdentity => f.write_str("recovery token identity"),
            Self::RestoreCapacityWidth => f.write_str("restore capacity width"),
            Self::RestoreIdentifierWidth => f.write_str("restore identifier width"),
            Self::RestoreKeyEncoding => f.write_str("restore key encoding"),
            Self::RestoreNativeIdentifierWidth => f.write_str("restore native identifier width"),
            Self::RestoreObservationSlotWidth => f.write_str("restore observation slot width"),
            Self::RestoreTransferCapacity => f.write_str("restore transfer capacity"),
            Self::RestoreTransferFunction => f.write_str("restore transfer function"),
            Self::RestoreTransferKeyRoles => f.write_str("restore transfer key roles"),
            Self::RestoreTransferKind => f.write_str("restore transfer kind"),
            Self::TerminalObservationFunction => f.write_str("terminal observation function"),
            Self::TerminalValidityCode => f.write_str("terminal validity code"),
        }
    }
}
