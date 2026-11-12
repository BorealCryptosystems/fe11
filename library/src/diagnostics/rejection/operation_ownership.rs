// SPDX-License-Identifier: Apache-2.0
//! OperationOwnership causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to operation ownership.
#[doc = include_str!("../../../docs/diagnostics/rejection-operation_ownership.md")]
pub enum OperationOwnershipRejection {
    /// AEAD message ticket required. [Detection, owner and recovery](#cause-AeadMessageTicketRequired).
    AeadMessageTicketRequired,
    /// Admission result owner. [Detection, owner and recovery](#cause-AdmissionResultOwner).
    AdmissionResultOwner,
    /// Asynchronous join session mode. [Detection, owner and recovery](#cause-AsynchronousJoinSessionMode).
    AsynchronousJoinSessionMode,
    /// Asynchronous legacy conversion. [Detection, owner and recovery](#cause-AsynchronousLegacyConversion).
    AsynchronousLegacyConversion,
    /// Cancelled operation cannot continue. [Detection, owner and recovery](#cause-CancelledOperationCannotContinue).
    CancelledOperationCannotContinue,
    /// Captured key candidate already occupied. [Detection, owner and recovery](#cause-CapturedKeyCandidateAlreadyOccupied).
    CapturedKeyCandidateAlreadyOccupied,
    /// Checkpoint family not serializable. [Detection, owner and recovery](#cause-CheckpointFamilyNotSerializable).
    CheckpointFamilyNotSerializable,
    /// Cipher ticket required. [Detection, owner and recovery](#cause-CipherTicketRequired).
    CipherTicketRequired,
    /// Consumed operation ticket. [Detection, owner and recovery](#cause-ConsumedOperationTicket).
    ConsumedOperationTicket,
    /// Continuation buffer capacity. [Detection, owner and recovery](#cause-ContinuationBufferCapacity).
    ContinuationBufferCapacity,
    /// Control has no cryptographic result. [Detection, owner and recovery](#cause-ControlHasNoCryptographicResult).
    ControlHasNoCryptographicResult,
    /// Digest checkpoint result length. [Detection, owner and recovery](#cause-DigestCheckpointResultLength).
    DigestCheckpointResultLength,
    /// Digest checkpoint unavailable. [Detection, owner and recovery](#cause-DigestCheckpointUnavailable).
    DigestCheckpointUnavailable,
    /// Digest ticket required. [Detection, owner and recovery](#cause-DigestTicketRequired).
    DigestTicketRequired,
    /// Empty message buffer shape. [Detection, owner and recovery](#cause-EmptyMessageBufferShape).
    EmptyMessageBufferShape,
    /// Empty validation report. [Detection, owner and recovery](#cause-EmptyValidationReport).
    EmptyValidationReport,
    /// Finalization operation identity. [Detection, owner and recovery](#cause-FinalizationOperationIdentity).
    FinalizationOperationIdentity,
    /// Finalization operation population. [Detection, owner and recovery](#cause-FinalizationOperationPopulation).
    FinalizationOperationPopulation,
    /// Finalization operation snapshot. [Detection, owner and recovery](#cause-FinalizationOperationSnapshot).
    FinalizationOperationSnapshot,
    /// Finalization operation ticket. [Detection, owner and recovery](#cause-FinalizationOperationTicket).
    FinalizationOperationTicket,
    /// Foreign diagnostic preparation budget. [Detection, owner and recovery](#cause-ForeignDiagnosticPreparationBudget).
    ForeignDiagnosticPreparationBudget,
    /// Foreign operation driver access. [Detection, owner and recovery](#cause-ForeignOperationDriverAccess).
    ForeignOperationDriverAccess,
    /// Foreign operation lease identity. [Detection, owner and recovery](#cause-ForeignOperationLeaseIdentity).
    ForeignOperationLeaseIdentity,
    /// Foreign or consumed AEAD message ticket. [Detection, owner and recovery](#cause-ForeignOrConsumedAeadMessageTicket).
    ForeignOrConsumedAeadMessageTicket,
    /// Foreign or consumed cipher ticket. [Detection, owner and recovery](#cause-ForeignOrConsumedCipherTicket).
    ForeignOrConsumedCipherTicket,
    /// Foreign or consumed digest ticket. [Detection, owner and recovery](#cause-ForeignOrConsumedDigestTicket).
    ForeignOrConsumedDigestTicket,
    /// Foreign or consumed recovery ticket. [Detection, owner and recovery](#cause-ForeignOrConsumedRecoveryTicket).
    ForeignOrConsumedRecoveryTicket,
    /// Foreign or consumed signature ticket. [Detection, owner and recovery](#cause-ForeignOrConsumedSignatureTicket).
    ForeignOrConsumedSignatureTicket,
    /// Foreign preparation budget. [Detection, owner and recovery](#cause-ForeignPreparationBudget).
    ForeignPreparationBudget,
    /// Fragment boundary overflow. [Detection, owner and recovery](#cause-FragmentBoundaryOverflow).
    FragmentBoundaryOverflow,
    /// Fragment boundary range. [Detection, owner and recovery](#cause-FragmentBoundaryRange).
    FragmentBoundaryRange,
    /// Fragment metadata overflow. [Detection, owner and recovery](#cause-FragmentMetadataOverflow).
    FragmentMetadataOverflow,
    /// Fragment retirement accounting. [Detection, owner and recovery](#cause-FragmentRetirementAccounting).
    FragmentRetirementAccounting,
    /// Fragment retirement allocation. [Detection, owner and recovery](#cause-FragmentRetirementAllocation).
    FragmentRetirementAllocation,
    /// Fragment retirement cursor. [Detection, owner and recovery](#cause-FragmentRetirementCursor).
    FragmentRetirementCursor,
    /// Fragment retirement metadata overflow. [Detection, owner and recovery](#cause-FragmentRetirementMetadataOverflow).
    FragmentRetirementMetadataOverflow,
    /// Fragment retirement slot absent. [Detection, owner and recovery](#cause-FragmentRetirementSlotAbsent).
    FragmentRetirementSlotAbsent,
    /// Fragment total mismatch. [Detection, owner and recovery](#cause-FragmentTotalMismatch).
    FragmentTotalMismatch,
    /// Generation descriptive result kind. [Detection, owner and recovery](#cause-GenerationDescriptiveResultKind).
    GenerationDescriptiveResultKind,
    /// Intermediate validation detachment deferred. [Detection, owner and recovery](#cause-IntermediateValidationDetachmentDeferred).
    IntermediateValidationDetachmentDeferred,
    /// Joined cryptographic owner unavailable. [Detection, owner and recovery](#cause-JoinedCryptographicOwnerUnavailable).
    JoinedCryptographicOwnerUnavailable,
    /// Joined result requires its specific owner. [Detection, owner and recovery](#cause-JoinedResultRequiresItsSpecificOwner).
    JoinedResultRequiresItsSpecificOwner,
    /// Multipart boundary mismatch. [Detection, owner and recovery](#cause-MultipartBoundaryMismatch).
    MultipartBoundaryMismatch,
    /// Multipart buffer count. [Detection, owner and recovery](#cause-MultipartBufferCount).
    MultipartBufferCount,
    /// Native asynchronous execution unavailable. [Detection, owner and recovery](#cause-NativeAsynchronousExecutionUnavailable).
    NativeAsynchronousExecutionUnavailable,
    /// Open complete-input stream. [Detection, owner and recovery](#cause-OpenCompleteInputStream).
    OpenCompleteInputStream,
    /// Operation absent. [Detection, owner and recovery](#cause-OperationAbsent).
    OperationAbsent,
    /// Operation candidate absent. [Detection, owner and recovery](#cause-OperationCandidateAbsent).
    OperationCandidateAbsent,
    /// Operation continuation transferred. [Detection, owner and recovery](#cause-OperationContinuationTransferred).
    OperationContinuationTransferred,
    /// Operation has no saved continuation. [Detection, owner and recovery](#cause-OperationHasNoSavedContinuation).
    OperationHasNoSavedContinuation,
    /// Operation identity absent. [Detection, owner and recovery](#cause-OperationIdentityAbsent).
    OperationIdentityAbsent,
    /// Operation not capturable. [Detection, owner and recovery](#cause-OperationNotCapturable).
    OperationNotCapturable,
    /// Operation progress identity. [Detection, owner and recovery](#cause-OperationProgressIdentity).
    OperationProgressIdentity,
    /// Operation progress revision exhausted. [Detection, owner and recovery](#cause-OperationProgressRevisionExhausted).
    OperationProgressRevisionExhausted,
    /// Operation publication storage size. [Detection, owner and recovery](#cause-OperationPublicationStorageSize).
    OperationPublicationStorageSize,
    /// Operation registry allocation. [Detection, owner and recovery](#cause-OperationRegistryAllocation).
    OperationRegistryAllocation,
    /// Operation shell absent. [Detection, owner and recovery](#cause-OperationShellAbsent).
    OperationShellAbsent,
    /// Operation storage already initialized. [Detection, owner and recovery](#cause-OperationStorageAlreadyInitialized).
    OperationStorageAlreadyInitialized,
    /// Operation ticket exhausted. [Detection, owner and recovery](#cause-OperationTicketExhausted).
    OperationTicketExhausted,
    /// Operation waiter count. [Detection, owner and recovery](#cause-OperationWaiterCount).
    OperationWaiterCount,
    /// Poll diagnostic byte count. [Detection, owner and recovery](#cause-PollDiagnosticByteCount).
    PollDiagnosticByteCount,
    /// Prepared operation storage absent. [Detection, owner and recovery](#cause-PreparedOperationStorageAbsent).
    PreparedOperationStorageAbsent,
    /// Recovery ticket required. [Detection, owner and recovery](#cause-RecoveryTicketRequired).
    RecoveryTicketRequired,
    /// Restoration IO absent. [Detection, owner and recovery](#cause-RestorationIoAbsent).
    RestorationIoAbsent,
    /// Restoration absent. [Detection, owner and recovery](#cause-RestorationAbsent).
    RestorationAbsent,
    /// Restoration key roles. [Detection, owner and recovery](#cause-RestorationKeyRoles).
    RestorationKeyRoles,
    /// Restoration owner absent. [Detection, owner and recovery](#cause-RestorationOwnerAbsent).
    RestorationOwnerAbsent,
    /// Retired operation count. [Detection, owner and recovery](#cause-RetiredOperationCount).
    RetiredOperationCount,
    /// Retired operation lease identity. [Detection, owner and recovery](#cause-RetiredOperationLeaseIdentity).
    RetiredOperationLeaseIdentity,
    /// Retired stranded count. [Detection, owner and recovery](#cause-RetiredStrandedCount).
    RetiredStrandedCount,
    /// Retirement owner snapshot. [Detection, owner and recovery](#cause-RetirementOwnerSnapshot).
    RetirementOwnerSnapshot,
    /// Shared unbound operation identity. [Detection, owner and recovery](#cause-SharedUnboundOperationIdentity).
    SharedUnboundOperationIdentity,
    /// Shared unbound operation storage. [Detection, owner and recovery](#cause-SharedUnboundOperationStorage).
    SharedUnboundOperationStorage,
    /// Signature ticket required. [Detection, owner and recovery](#cause-SignatureTicketRequired).
    SignatureTicketRequired,
    /// Single message buffer count. [Detection, owner and recovery](#cause-SingleMessageBufferCount).
    SingleMessageBufferCount,
    /// Stale AEAD message ticket. [Detection, owner and recovery](#cause-StaleAeadMessageTicket).
    StaleAeadMessageTicket,
    /// Stale cipher ticket. [Detection, owner and recovery](#cause-StaleCipherTicket).
    StaleCipherTicket,
    /// Stale digest ticket. [Detection, owner and recovery](#cause-StaleDigestTicket).
    StaleDigestTicket,
    /// Stale operation ticket. [Detection, owner and recovery](#cause-StaleOperationTicket).
    StaleOperationTicket,
    /// Stale recovery ticket. [Detection, owner and recovery](#cause-StaleRecoveryTicket).
    StaleRecoveryTicket,
    /// Stale signature ticket. [Detection, owner and recovery](#cause-StaleSignatureTicket).
    StaleSignatureTicket,
    /// Stream incremental route. [Detection, owner and recovery](#cause-StreamIncrementalRoute).
    StreamIncrementalRoute,
    /// Stream input closure encoding. [Detection, owner and recovery](#cause-StreamInputClosureEncoding).
    StreamInputClosureEncoding,
    /// Stream input counter exhausted. [Detection, owner and recovery](#cause-StreamInputCounterExhausted).
    StreamInputCounterExhausted,
    /// Stream key counter exhausted. [Detection, owner and recovery](#cause-StreamKeyCounterExhausted).
    StreamKeyCounterExhausted,
    /// Stream output counter exhausted. [Detection, owner and recovery](#cause-StreamOutputCounterExhausted).
    StreamOutputCounterExhausted,
    /// Stream output delivery position. [Detection, owner and recovery](#cause-StreamOutputDeliveryPosition).
    StreamOutputDeliveryPosition,
    /// Stream progress encoding. [Detection, owner and recovery](#cause-StreamProgressEncoding).
    StreamProgressEncoding,
    /// Stream retained input. [Detection, owner and recovery](#cause-StreamRetainedInput).
    StreamRetainedInput,
    /// Stream submission counter exhausted. [Detection, owner and recovery](#cause-StreamSubmissionCounterExhausted).
    StreamSubmissionCounterExhausted,
    /// Terminal crypto not complete. [Detection, owner and recovery](#cause-TerminalCryptoNotComplete).
    TerminalCryptoNotComplete,
    /// Terminal validation association. [Detection, owner and recovery](#cause-TerminalValidationAssociation).
    TerminalValidationAssociation,
    /// Token operation count. [Detection, owner and recovery](#cause-TokenOperationCount).
    TokenOperationCount,
    /// Unchanging preparation was invalidated. [Detection, owner and recovery](#cause-UnchangingPreparationWasInvalidated).
    UnchangingPreparationWasInvalidated,
    /// Validation already published. [Detection, owner and recovery](#cause-ValidationAlreadyPublished).
    ValidationAlreadyPublished,
    /// Validation asynchronous version. [Detection, owner and recovery](#cause-ValidationAsynchronousVersion).
    ValidationAsynchronousVersion,
    /// Validation collector absent. [Detection, owner and recovery](#cause-ValidationCollectorAbsent).
    ValidationCollectorAbsent,
    /// Validation control not pending. [Detection, owner and recovery](#cause-ValidationControlNotPending).
    ValidationControlNotPending,
    /// Validation failed. [Detection, owner and recovery](#cause-ValidationFailed).
    ValidationFailed,
    /// Validation incomplete. [Detection, owner and recovery](#cause-ValidationIncomplete).
    ValidationIncomplete,
    /// Validation message index. [Detection, owner and recovery](#cause-ValidationMessageIndex).
    ValidationMessageIndex,
    /// Validation observation absent. [Detection, owner and recovery](#cause-ValidationObservationAbsent).
    ValidationObservationAbsent,
    /// Validation observation sequence. [Detection, owner and recovery](#cause-ValidationObservationSequence).
    ValidationObservationSequence,
    /// Validation point absent. [Detection, owner and recovery](#cause-ValidationPointAbsent).
    ValidationPointAbsent,
    /// Validation reconstruction shape. [Detection, owner and recovery](#cause-ValidationReconstructionShape).
    ValidationReconstructionShape,
    /// Validation report allocation. [Detection, owner and recovery](#cause-ValidationReportAllocation).
    ValidationReportAllocation,
    /// Validation report capacity accounting. [Detection, owner and recovery](#cause-ValidationReportCapacityAccounting).
    ValidationReportCapacityAccounting,
    /// Validation report capacity decreased. [Detection, owner and recovery](#cause-ValidationReportCapacityDecreased).
    ValidationReportCapacityDecreased,
    /// Validation report growth absent. [Detection, owner and recovery](#cause-ValidationReportGrowthAbsent).
    ValidationReportGrowthAbsent,
    /// Validation report growth shape changed. [Detection, owner and recovery](#cause-ValidationReportGrowthShapeChanged).
    ValidationReportGrowthShapeChanged,
    /// Validation report limit. [Detection, owner and recovery](#cause-ValidationReportLimit).
    ValidationReportLimit,
    /// Validation snapshot capacity changed. [Detection, owner and recovery](#cause-ValidationSnapshotCapacityChanged).
    ValidationSnapshotCapacityChanged,
    /// Validation snapshot shape changed. [Detection, owner and recovery](#cause-ValidationSnapshotShapeChanged).
    ValidationSnapshotShapeChanged,


}

impl std::fmt::Display for OperationOwnershipRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {


            Self::AeadMessageTicketRequired => f.write_str("AEAD message ticket required"),
            Self::AdmissionResultOwner => f.write_str("admission result owner"),
            Self::AsynchronousJoinSessionMode => f.write_str("asynchronous join session mode"),
            Self::AsynchronousLegacyConversion => f.write_str("asynchronous legacy conversion"),
            Self::CancelledOperationCannotContinue => {
                f.write_str("cancelled operation cannot continue")
            }
            Self::CapturedKeyCandidateAlreadyOccupied => {
                f.write_str("captured key candidate already occupied")
            }
            Self::CheckpointFamilyNotSerializable => {
                f.write_str("checkpoint family not serializable")
            }
            Self::CipherTicketRequired => f.write_str("cipher ticket required"),
            Self::ConsumedOperationTicket => f.write_str("consumed operation ticket"),
            Self::ContinuationBufferCapacity => f.write_str("continuation buffer capacity"),
            Self::ControlHasNoCryptographicResult => {
                f.write_str("control has no cryptographic result")
            }
            Self::DigestCheckpointResultLength => f.write_str("digest checkpoint result length"),
            Self::DigestCheckpointUnavailable => f.write_str("digest checkpoint unavailable"),
            Self::DigestTicketRequired => f.write_str("digest ticket required"),
            Self::EmptyMessageBufferShape => f.write_str("empty message buffer shape"),
            Self::EmptyValidationReport => f.write_str("empty validation report"),
            Self::FinalizationOperationIdentity => f.write_str("finalization operation identity"),
            Self::FinalizationOperationPopulation => {
                f.write_str("finalization operation population")
            }
            Self::FinalizationOperationSnapshot => f.write_str("finalization operation snapshot"),
            Self::FinalizationOperationTicket => f.write_str("finalization operation ticket"),
            Self::ForeignDiagnosticPreparationBudget => {
                f.write_str("foreign diagnostic preparation budget")
            }
            Self::ForeignOperationDriverAccess => f.write_str("foreign operation driver access"),
            Self::ForeignOperationLeaseIdentity => f.write_str("foreign operation lease identity"),
            Self::ForeignOrConsumedAeadMessageTicket => {
                f.write_str("foreign or consumed AEAD message ticket")
            }
            Self::ForeignOrConsumedCipherTicket => f.write_str("foreign or consumed cipher ticket"),
            Self::ForeignOrConsumedDigestTicket => f.write_str("foreign or consumed digest ticket"),
            Self::ForeignOrConsumedRecoveryTicket => {
                f.write_str("foreign or consumed recovery ticket")
            }
            Self::ForeignOrConsumedSignatureTicket => {
                f.write_str("foreign or consumed signature ticket")
            }
            Self::ForeignPreparationBudget => f.write_str("foreign preparation budget"),
            Self::FragmentBoundaryOverflow => f.write_str("fragment boundary overflow"),
            Self::FragmentBoundaryRange => f.write_str("fragment boundary range"),
            Self::FragmentMetadataOverflow => f.write_str("fragment metadata overflow"),
            Self::FragmentRetirementAccounting => f.write_str("fragment retirement accounting"),
            Self::FragmentRetirementAllocation => f.write_str("fragment retirement allocation"),
            Self::FragmentRetirementCursor => f.write_str("fragment retirement cursor"),
            Self::FragmentRetirementMetadataOverflow => {
                f.write_str("fragment retirement metadata overflow")
            }
            Self::FragmentRetirementSlotAbsent => f.write_str("fragment retirement slot absent"),
            Self::FragmentTotalMismatch => f.write_str("fragment total mismatch"),
            Self::GenerationDescriptiveResultKind => {
                f.write_str("generation descriptive result kind")
            }
            Self::IntermediateValidationDetachmentDeferred => {
                f.write_str("intermediate validation detachment deferred")
            }
            Self::JoinedCryptographicOwnerUnavailable => {
                f.write_str("joined cryptographic owner unavailable")
            }
            Self::JoinedResultRequiresItsSpecificOwner => {
                f.write_str("joined result requires its specific owner")
            }
            Self::MultipartBoundaryMismatch => f.write_str("multipart boundary mismatch"),
            Self::MultipartBufferCount => f.write_str("multipart buffer count"),
            Self::NativeAsynchronousExecutionUnavailable => {
                f.write_str("native asynchronous execution unavailable")
            }
            Self::OpenCompleteInputStream => f.write_str("open complete-input stream"),
            Self::OperationAbsent => f.write_str("operation absent"),
            Self::OperationCandidateAbsent => f.write_str("operation candidate absent"),
            Self::OperationContinuationTransferred => {
                f.write_str("operation continuation transferred")
            }
            Self::OperationHasNoSavedContinuation => {
                f.write_str("operation has no saved continuation")
            }
            Self::OperationIdentityAbsent => f.write_str("operation identity absent"),
            Self::OperationNotCapturable => f.write_str("operation not capturable"),
            Self::OperationProgressIdentity => f.write_str("operation progress identity"),
            Self::OperationProgressRevisionExhausted => {
                f.write_str("operation progress revision exhausted")
            }
            Self::OperationPublicationStorageSize => {
                f.write_str("operation publication storage size")
            }
            Self::OperationRegistryAllocation => f.write_str("operation registry allocation"),
            Self::OperationShellAbsent => f.write_str("operation shell absent"),
            Self::OperationStorageAlreadyInitialized => {
                f.write_str("operation storage already initialized")
            }
            Self::OperationTicketExhausted => f.write_str("operation ticket exhausted"),
            Self::OperationWaiterCount => f.write_str("operation waiter count"),
            Self::PollDiagnosticByteCount => f.write_str("poll diagnostic byte count"),
            Self::PreparedOperationStorageAbsent => {
                f.write_str("prepared operation storage absent")
            }
            Self::RecoveryTicketRequired => f.write_str("recovery ticket required"),
            Self::RestorationIoAbsent => f.write_str("restoration IO absent"),
            Self::RestorationAbsent => f.write_str("restoration absent"),
            Self::RestorationKeyRoles => f.write_str("restoration key roles"),
            Self::RestorationOwnerAbsent => f.write_str("restoration owner absent"),
            Self::RetiredOperationCount => f.write_str("retired operation count"),
            Self::RetiredOperationLeaseIdentity => f.write_str("retired operation lease identity"),
            Self::RetiredStrandedCount => f.write_str("retired stranded count"),
            Self::RetirementOwnerSnapshot => f.write_str("retirement owner snapshot"),
            Self::SharedUnboundOperationIdentity => {
                f.write_str("shared unbound operation identity")
            }
            Self::SharedUnboundOperationStorage => f.write_str("shared unbound operation storage"),
            Self::SignatureTicketRequired => f.write_str("signature ticket required"),
            Self::SingleMessageBufferCount => f.write_str("single message buffer count"),
            Self::StaleAeadMessageTicket => f.write_str("stale AEAD message ticket"),
            Self::StaleCipherTicket => f.write_str("stale cipher ticket"),
            Self::StaleDigestTicket => f.write_str("stale digest ticket"),
            Self::StaleOperationTicket => f.write_str("stale operation ticket"),
            Self::StaleRecoveryTicket => f.write_str("stale recovery ticket"),
            Self::StaleSignatureTicket => f.write_str("stale signature ticket"),
            Self::StreamIncrementalRoute => f.write_str("stream incremental route"),
            Self::StreamInputClosureEncoding => f.write_str("stream input closure encoding"),
            Self::StreamInputCounterExhausted => f.write_str("stream input counter exhausted"),
            Self::StreamKeyCounterExhausted => f.write_str("stream key counter exhausted"),
            Self::StreamOutputCounterExhausted => f.write_str("stream output counter exhausted"),
            Self::StreamOutputDeliveryPosition => f.write_str("stream output delivery position"),
            Self::StreamProgressEncoding => f.write_str("stream progress encoding"),
            Self::StreamRetainedInput => f.write_str("stream retained input"),
            Self::StreamSubmissionCounterExhausted => {
                f.write_str("stream submission counter exhausted")
            }
            Self::TerminalCryptoNotComplete => f.write_str("terminal crypto not complete"),
            Self::TerminalValidationAssociation => f.write_str("terminal validation association"),
            Self::TokenOperationCount => f.write_str("token operation count"),
            Self::UnchangingPreparationWasInvalidated => {
                f.write_str("unchanging preparation was invalidated")
            }
            Self::ValidationAlreadyPublished => f.write_str("validation already published"),
            Self::ValidationAsynchronousVersion => f.write_str("validation asynchronous version"),
            Self::ValidationCollectorAbsent => f.write_str("validation collector absent"),
            Self::ValidationControlNotPending => f.write_str("validation control not pending"),
            Self::ValidationFailed => f.write_str("validation failed"),
            Self::ValidationIncomplete => f.write_str("validation incomplete"),
            Self::ValidationMessageIndex => f.write_str("validation message index"),
            Self::ValidationObservationAbsent => f.write_str("validation observation absent"),
            Self::ValidationObservationSequence => f.write_str("validation observation sequence"),
            Self::ValidationPointAbsent => f.write_str("validation point absent"),
            Self::ValidationReconstructionShape => f.write_str("validation reconstruction shape"),
            Self::ValidationReportAllocation => f.write_str("validation report allocation"),
            Self::ValidationReportCapacityAccounting => {
                f.write_str("validation report capacity accounting")
            }
            Self::ValidationReportCapacityDecreased => {
                f.write_str("validation report capacity decreased")
            }
            Self::ValidationReportGrowthAbsent => f.write_str("validation report growth absent"),
            Self::ValidationReportGrowthShapeChanged => {
                f.write_str("validation report growth shape changed")
            }
            Self::ValidationReportLimit => f.write_str("validation report limit"),
            Self::ValidationSnapshotCapacityChanged => {
                f.write_str("validation snapshot capacity changed")
            }
            Self::ValidationSnapshotShapeChanged => {
                f.write_str("validation snapshot shape changed")
            }
        }
    }
}
