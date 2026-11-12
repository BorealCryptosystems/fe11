// SPDX-License-Identifier: Apache-2.0
//! DigestContinuation causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to digest continuation.
#[doc = include_str!("../../../docs/diagnostics/rejection-digest_continuation.md")]
pub enum DigestContinuationRejection {
    /// Advanced input allocation. [Detection, owner and recovery](#cause-AdvancedInputAllocation).
    AdvancedInputAllocation,
    /// Asynchronous result identity. [Detection, owner and recovery](#cause-AsynchronousResultIdentity).
    AsynchronousResultIdentity,
    /// Asynchronous result version. [Detection, owner and recovery](#cause-AsynchronousResultVersion).
    AsynchronousResultVersion,
    /// Caller-driven digest requires a synchronous session. [Detection, owner and recovery](#cause-CallerDrivenDigestRequiresASynchronousSession).
    CallerDrivenDigestRequiresASynchronousSession,
    /// Caller-driven digest result owner. [Detection, owner and recovery](#cause-CallerDrivenDigestResultOwner).
    CallerDrivenDigestResultOwner,
    /// Consumed digest ticket. [Detection, owner and recovery](#cause-ConsumedDigestTicket).
    ConsumedDigestTicket,
    /// Declaration on a typed digest. [Detection, owner and recovery](#cause-DeclarationOnATypedDigest).
    DeclarationOnATypedDigest,
    /// Declaration without digest extension. [Detection, owner and recovery](#cause-DeclarationWithoutDigestExtension).
    DeclarationWithoutDigestExtension,
    /// Digest OID accounting. [Detection, owner and recovery](#cause-DigestOidAccounting).
    DigestOidAccounting,
    /// Digest OID selection. [Detection, owner and recovery](#cause-DigestOidSelection).
    DigestOidSelection,
    /// Digest continuation ticket unavailable. [Detection, owner and recovery](#cause-DigestContinuationTicketUnavailable).
    DigestContinuationTicketUnavailable,
    /// Digest declaration family. [Detection, owner and recovery](#cause-DigestDeclarationFamily).
    DigestDeclarationFamily,
    /// Digest destination declaration absent or unexpected. [Detection, owner and recovery](#cause-DigestDestinationDeclarationAbsentOrUnexpected).
    DigestDestinationDeclarationAbsentOrUnexpected,
    /// Digest destination declaration mismatch. [Detection, owner and recovery](#cause-DigestDestinationDeclarationMismatch).
    DigestDestinationDeclarationMismatch,
    /// Digest extension native asynchronous mode or Init replay is unavailable. [Detection, owner and recovery](#cause-DigestExtensionAsynchronousModeOrInitReplayIsUnavailable).
    DigestExtensionAsynchronousModeOrInitReplayIsUnavailable,
    /// Digest extension graph selection. [Detection, owner and recovery](#cause-DigestExtensionGraphSelection).
    DigestExtensionGraphSelection,
    /// Digest extension not capturable. [Detection, owner and recovery](#cause-DigestExtensionNotCapturable).
    DigestExtensionNotCapturable,
    /// Digest extension parameters absent. [Detection, owner and recovery](#cause-DigestExtensionParametersAbsent).
    DigestExtensionParametersAbsent,
    /// Digest extension selection. [Detection, owner and recovery](#cause-DigestExtensionSelection).
    DigestExtensionSelection,
    /// Digest extension snapshot accounting. [Detection, owner and recovery](#cause-DigestExtensionSnapshotAccounting).
    DigestExtensionSnapshotAccounting,
    /// Digest extension snapshot changed. [Detection, owner and recovery](#cause-DigestExtensionSnapshotChanged).
    DigestExtensionSnapshotChanged,
    /// Digest extension snapshot trailing bytes. [Detection, owner and recovery](#cause-DigestExtensionSnapshotTrailingBytes).
    DigestExtensionSnapshotTrailingBytes,
    /// Digest facade observer changed. [Detection, owner and recovery](#cause-DigestFacadeObserverChanged).
    DigestFacadeObserverChanged,
    /// Digest facade owner changed. [Detection, owner and recovery](#cause-DigestFacadeOwnerChanged).
    DigestFacadeOwnerChanged,
    /// Digest functions unavailable. [Detection, owner and recovery](#cause-DigestFunctionsUnavailable).
    DigestFunctionsUnavailable,
    /// Digest graph accounting. [Detection, owner and recovery](#cause-DigestGraphAccounting).
    DigestGraphAccounting,
    /// Digest has no context-authentication role. [Detection, owner and recovery](#cause-DigestHasNoContextAuthenticationRole).
    DigestHasNoContextAuthenticationRole,
    /// Digest import requires a destination ABI declaration. [Detection, owner and recovery](#cause-DigestImportRequiresADestinationAbiDeclaration).
    DigestImportRequiresADestinationAbiDeclaration,
    /// Digest injection storage size. [Detection, owner and recovery](#cause-DigestInjectionStorageSize).
    DigestInjectionStorageSize,
    /// Digest input completion unproven. [Detection, owner and recovery](#cause-DigestInputCompletionUnproven).
    DigestInputCompletionUnproven,
    /// Digest input function unavailable. [Detection, owner and recovery](#cause-DigestInputFunctionUnavailable).
    DigestInputFunctionUnavailable,
    /// Digest input phase. [Detection, owner and recovery](#cause-DigestInputPhase).
    DigestInputPhase,
    /// Digest input preparation. [Detection, owner and recovery](#cause-DigestInputPreparation).
    DigestInputPreparation,
    /// Digest input retirement count. [Detection, owner and recovery](#cause-DigestInputRetirementCount).
    DigestInputRetirementCount,
    /// Digest input size. [Detection, owner and recovery](#cause-DigestInputSize).
    DigestInputSize,
    /// Digest mechanism width. [Detection, owner and recovery](#cause-DigestMechanismWidth).
    DigestMechanismWidth,
    /// Digest native parameter identity. [Detection, owner and recovery](#cause-DigestNativeParameterIdentity).
    DigestNativeParameterIdentity,
    /// Digest operation not joinable. [Detection, owner and recovery](#cause-DigestOperationNotJoinable).
    DigestOperationNotJoinable,
    /// Digest operation storage size. [Detection, owner and recovery](#cause-DigestOperationStorageSize).
    DigestOperationStorageSize,
    /// Digest output capacity. [Detection, owner and recovery](#cause-DigestOutputCapacity).
    DigestOutputCapacity,
    /// Digest output descriptor absent. [Detection, owner and recovery](#cause-DigestOutputDescriptorAbsent).
    DigestOutputDescriptorAbsent,
    /// Digest output is not awaiting storage. [Detection, owner and recovery](#cause-DigestOutputIsNotAwaitingStorage).
    DigestOutputIsNotAwaitingStorage,
    /// Digest output waiting phase. [Detection, owner and recovery](#cause-DigestOutputWaitingPhase).
    DigestOutputWaitingPhase,
    /// Digest pending output owner. [Detection, owner and recovery](#cause-DigestPendingOutputOwner).
    DigestPendingOutputOwner,
    /// Digest reader retirement occupied. [Detection, owner and recovery](#cause-DigestReaderRetirementOccupied).
    DigestReaderRetirementOccupied,
    /// Digest reconstruction accounting. [Detection, owner and recovery](#cause-DigestReconstructionAccounting).
    DigestReconstructionAccounting,
    /// Digest replacement storage. [Detection, owner and recovery](#cause-DigestReplacementStorage).
    DigestReplacementStorage,
    /// Digest required capacity width. [Detection, owner and recovery](#cause-DigestRequiredCapacityWidth).
    DigestRequiredCapacityWidth,
    /// Digest result contract mismatch. [Detection, owner and recovery](#cause-DigestResultContractMismatch).
    DigestResultContractMismatch,
    /// Digest retirement accounting. [Detection, owner and recovery](#cause-DigestRetirementAccounting).
    DigestRetirementAccounting,
    /// Digest snapshot metadata accounting. [Detection, owner and recovery](#cause-DigestSnapshotMetadataAccounting).
    DigestSnapshotMetadataAccounting,
    /// Digest snapshot part count. [Detection, owner and recovery](#cause-DigestSnapshotPartCount).
    DigestSnapshotPartCount,
    /// Digest snapshot storage accounting. [Detection, owner and recovery](#cause-DigestSnapshotStorageAccounting).
    DigestSnapshotStorageAccounting,
    /// Digest storage size. [Detection, owner and recovery](#cause-DigestStorageSize).
    DigestStorageSize,
    /// Duplicate operation completion. [Detection, owner and recovery](#cause-DuplicateOperationCompletion).
    DuplicateOperationCompletion,
    /// Extension digest native asynchronous mode is unsupported. [Detection, owner and recovery](#cause-ExtensionDigestAsynchronousModeUnavailable).
    ExtensionDigestAsynchronousModeUnavailable,
    /// Extension digest facade incomplete. [Detection, owner and recovery](#cause-ExtensionDigestFacadeIncomplete).
    ExtensionDigestFacadeIncomplete,
    /// Extension digest facade route. [Detection, owner and recovery](#cause-ExtensionDigestFacadeRoute).
    ExtensionDigestFacadeRoute,
    /// Extension digest requires parameter output owner. [Detection, owner and recovery](#cause-ExtensionDigestRequiresParameterOutputOwner).
    ExtensionDigestRequiresParameterOutputOwner,
    /// Extension digest result owner. [Detection, owner and recovery](#cause-ExtensionDigestResultOwner).
    ExtensionDigestResultOwner,
    /// Native digest input changed. [Detection, owner and recovery](#cause-NativeDigestInputChanged).
    NativeDigestInputChanged,
    /// Native digest result owner. [Detection, owner and recovery](#cause-NativeDigestResultOwner).
    NativeDigestResultOwner,
    /// Operation failed; explicit cleanup required. [Detection, owner and recovery](#cause-OperationFailedExplicitCleanupRequired).
    OperationFailedExplicitCleanupRequired,
    /// Operation metadata length. [Detection, owner and recovery](#cause-OperationMetadataLength).
    OperationMetadataLength,
    /// Operation not active. [Detection, owner and recovery](#cause-OperationNotActive).
    OperationNotActive,
    /// Reconstruction digest message absent. [Detection, owner and recovery](#cause-ReconstructionDigestMessageAbsent).
    ReconstructionDigestMessageAbsent,
    /// Reconstruction digest phase. [Detection, owner and recovery](#cause-ReconstructionDigestPhase).
    ReconstructionDigestPhase,
    /// Record digest mechanism. [Detection, owner and recovery](#cause-RecordDigestMechanism).
    RecordDigestMechanism,
    /// Record digest parameter mechanism. [Detection, owner and recovery](#cause-RecordDigestParameterMechanism).
    RecordDigestParameterMechanism,
    /// Record digest parameter width. [Detection, owner and recovery](#cause-RecordDigestParameterWidth).
    RecordDigestParameterWidth,
    /// Record digest profile. [Detection, owner and recovery](#cause-RecordDigestProfile).
    RecordDigestProfile,
    /// Record digest width. [Detection, owner and recovery](#cause-RecordDigestWidth).
    RecordDigestWidth,
    /// Record native digest mechanism. [Detection, owner and recovery](#cause-RecordNativeDigestMechanism).
    RecordNativeDigestMechanism,
    /// Record parameterized digest profile. [Detection, owner and recovery](#cause-RecordParameterizedDigestProfile).
    RecordParameterizedDigestProfile,
    /// Single digest input count. [Detection, owner and recovery](#cause-SingleDigestInputCount).
    SingleDigestInputCount,
    /// Stale digest facade ticket. [Detection, owner and recovery](#cause-StaleDigestFacadeTicket).
    StaleDigestFacadeTicket,
    /// Uncopied digest snapshot. [Detection, owner and recovery](#cause-UncopiedDigestSnapshot).
    UncopiedDigestSnapshot,

}

impl std::fmt::Display for DigestContinuationRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {

            Self::AdvancedInputAllocation => f.write_str("advanced input allocation"),
            Self::AsynchronousResultIdentity => f.write_str("asynchronous result identity"),
            Self::AsynchronousResultVersion => f.write_str("asynchronous result version"),
            Self::CallerDrivenDigestRequiresASynchronousSession => {
                f.write_str("caller-driven digest requires a synchronous session")
            }
            Self::CallerDrivenDigestResultOwner => f.write_str("caller-driven digest result owner"),
            Self::ConsumedDigestTicket => f.write_str("consumed digest ticket"),
            Self::DeclarationOnATypedDigest => f.write_str("declaration on a typed digest"),
            Self::DeclarationWithoutDigestExtension => {
                f.write_str("declaration without digest extension")
            }
            Self::DigestOidAccounting => f.write_str("digest OID accounting"),
            Self::DigestOidSelection => f.write_str("digest OID selection"),
            Self::DigestContinuationTicketUnavailable => {
                f.write_str("digest continuation ticket unavailable")
            }
            Self::DigestDeclarationFamily => f.write_str("digest declaration family"),
            Self::DigestDestinationDeclarationAbsentOrUnexpected => {
                f.write_str("digest destination declaration absent or unexpected")
            }
            Self::DigestDestinationDeclarationMismatch => {
                f.write_str("digest destination declaration mismatch")
            }
            Self::DigestExtensionAsynchronousModeOrInitReplayIsUnavailable => f.write_str(
                "digest extension native asynchronous mode or Init replay is unavailable",
            ),
            Self::DigestExtensionGraphSelection => f.write_str("digest extension graph selection"),
            Self::DigestExtensionNotCapturable => f.write_str("digest extension not capturable"),
            Self::DigestExtensionParametersAbsent => {
                f.write_str("digest extension parameters absent")
            }
            Self::DigestExtensionSelection => f.write_str("digest extension selection"),
            Self::DigestExtensionSnapshotAccounting => {
                f.write_str("digest extension snapshot accounting")
            }
            Self::DigestExtensionSnapshotChanged => {
                f.write_str("digest extension snapshot changed")
            }
            Self::DigestExtensionSnapshotTrailingBytes => {
                f.write_str("digest extension snapshot trailing bytes")
            }
            Self::DigestFacadeObserverChanged => f.write_str("digest facade observer changed"),
            Self::DigestFacadeOwnerChanged => f.write_str("digest facade owner changed"),
            Self::DigestFunctionsUnavailable => f.write_str("digest functions unavailable"),
            Self::DigestGraphAccounting => f.write_str("digest graph accounting"),
            Self::DigestHasNoContextAuthenticationRole => {
                f.write_str("digest has no context-authentication role")
            }
            Self::DigestImportRequiresADestinationAbiDeclaration => {
                f.write_str("digest import requires a destination ABI declaration")
            }
            Self::DigestInjectionStorageSize => f.write_str("digest injection storage size"),
            Self::DigestInputCompletionUnproven => f.write_str("digest input completion unproven"),
            Self::DigestInputFunctionUnavailable => {
                f.write_str("digest input function unavailable")
            }
            Self::DigestInputPhase => f.write_str("digest input phase"),
            Self::DigestInputPreparation => f.write_str("digest input preparation"),
            Self::DigestInputRetirementCount => f.write_str("digest input retirement count"),
            Self::DigestInputSize => f.write_str("digest input size"),
            Self::DigestMechanismWidth => f.write_str("digest mechanism width"),
            Self::DigestNativeParameterIdentity => f.write_str("digest native parameter identity"),
            Self::DigestOperationNotJoinable => f.write_str("digest operation not joinable"),
            Self::DigestOperationStorageSize => f.write_str("digest operation storage size"),
            Self::DigestOutputCapacity => f.write_str("digest output capacity"),
            Self::DigestOutputDescriptorAbsent => f.write_str("digest output descriptor absent"),
            Self::DigestOutputIsNotAwaitingStorage => {
                f.write_str("digest output is not awaiting storage")
            }
            Self::DigestOutputWaitingPhase => f.write_str("digest output waiting phase"),
            Self::DigestPendingOutputOwner => f.write_str("digest pending output owner"),
            Self::DigestReaderRetirementOccupied => {
                f.write_str("digest reader retirement occupied")
            }
            Self::DigestReconstructionAccounting => f.write_str("digest reconstruction accounting"),
            Self::DigestReplacementStorage => f.write_str("digest replacement storage"),
            Self::DigestRequiredCapacityWidth => f.write_str("digest required capacity width"),
            Self::DigestResultContractMismatch => f.write_str("digest result contract mismatch"),
            Self::DigestRetirementAccounting => f.write_str("digest retirement accounting"),
            Self::DigestSnapshotMetadataAccounting => {
                f.write_str("digest snapshot metadata accounting")
            }
            Self::DigestSnapshotPartCount => f.write_str("digest snapshot part count"),
            Self::DigestSnapshotStorageAccounting => {
                f.write_str("digest snapshot storage accounting")
            }
            Self::DigestStorageSize => f.write_str("digest storage size"),
            Self::DuplicateOperationCompletion => f.write_str("duplicate operation completion"),
            Self::ExtensionDigestAsynchronousModeUnavailable => {
                f.write_str("extension digest native asynchronous mode is unsupported")
            }
            Self::ExtensionDigestFacadeIncomplete => {
                f.write_str("extension digest facade incomplete")
            }
            Self::ExtensionDigestFacadeRoute => f.write_str("extension digest facade route"),
            Self::ExtensionDigestRequiresParameterOutputOwner => {
                f.write_str("extension digest requires parameter output owner")
            }
            Self::ExtensionDigestResultOwner => f.write_str("extension digest result owner"),
            Self::NativeDigestInputChanged => f.write_str("native digest input changed"),
            Self::NativeDigestResultOwner => f.write_str("native digest result owner"),
            Self::OperationFailedExplicitCleanupRequired => {
                f.write_str("operation failed; explicit cleanup required")
            }
            Self::OperationMetadataLength => f.write_str("operation metadata length"),
            Self::OperationNotActive => f.write_str("operation not active"),
            Self::ReconstructionDigestMessageAbsent => {
                f.write_str("reconstruction digest message absent")
            }
            Self::ReconstructionDigestPhase => f.write_str("reconstruction digest phase"),
            Self::RecordDigestMechanism => f.write_str("record digest mechanism"),
            Self::RecordDigestParameterMechanism => {
                f.write_str("record digest parameter mechanism")
            }
            Self::RecordDigestParameterWidth => f.write_str("record digest parameter width"),
            Self::RecordDigestProfile => f.write_str("record digest profile"),
            Self::RecordDigestWidth => f.write_str("record digest width"),
            Self::RecordNativeDigestMechanism => f.write_str("record native digest mechanism"),
            Self::RecordParameterizedDigestProfile => {
                f.write_str("record parameterized digest profile")
            }
            Self::SingleDigestInputCount => f.write_str("single digest input count"),
            Self::StaleDigestFacadeTicket => f.write_str("stale digest facade ticket"),
            Self::UncopiedDigestSnapshot => f.write_str("uncopied digest snapshot"),
        }
    }
}
