// SPDX-License-Identifier: Apache-2.0
//! ObjectPublication causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to object publication.
#[doc = include_str!("../../../docs/diagnostics/rejection-object_publication.md")]
pub enum ObjectPublicationRejection {
    /// SP800 output slot. [Detection, owner and recovery](#cause-Sp800OutputSlot).
    Sp800OutputSlot,
    /// SP800 publication capacity. [Detection, owner and recovery](#cause-Sp800PublicationCapacity).
    Sp800PublicationCapacity,
    /// TLS output slot. [Detection, owner and recovery](#cause-TlsOutputSlot).
    TlsOutputSlot,
    /// TLS publication capacity. [Detection, owner and recovery](#cause-TlsPublicationCapacity).
    TlsPublicationCapacity,
    /// TLS publication role. [Detection, owner and recovery](#cause-TlsPublicationRole).
    TlsPublicationRole,
    /// Destination byte accounting. [Detection, owner and recovery](#cause-DestinationByteAccounting).
    DestinationByteAccounting,
    /// Destination tuple accounting. [Detection, owner and recovery](#cause-DestinationTupleAccounting).
    DestinationTupleAccounting,
    /// Generation output consumed. [Detection, owner and recovery](#cause-GenerationOutputConsumed).
    GenerationOutputConsumed,
    /// Native auxiliary output absent. [Detection, owner and recovery](#cause-NativeAuxiliaryOutputAbsent).
    NativeAuxiliaryOutputAbsent,
    /// Native creation already dispatched. [Detection, owner and recovery](#cause-NativeCreationAlreadyDispatched).
    NativeCreationAlreadyDispatched,
    /// Native destination owner. [Detection, owner and recovery](#cause-NativeDestinationOwner).
    NativeDestinationOwner,
    /// Native effect is not a resource request. [Detection, owner and recovery](#cause-NativeEffectIsNotAResourceRequest).
    NativeEffectIsNotAResourceRequest,
    /// Native object lifetime absent. [Detection, owner and recovery](#cause-NativeObjectLifetimeAbsent).
    NativeObjectLifetimeAbsent,
    /// Native objects not registered. [Detection, owner and recovery](#cause-NativeObjectsNotRegistered).
    NativeObjectsNotRegistered,
    /// Native output admission owner. [Detection, owner and recovery](#cause-NativeOutputAdmissionOwner).
    NativeOutputAdmissionOwner,
    /// Native output admission state. [Detection, owner and recovery](#cause-NativeOutputAdmissionState).
    NativeOutputAdmissionState,
    /// Native output candidate kind. [Detection, owner and recovery](#cause-NativeOutputCandidateKind).
    NativeOutputCandidateKind,
    /// Native output completion unknown. [Detection, owner and recovery](#cause-NativeOutputCompletionUnknown).
    NativeOutputCompletionUnknown,
    /// Native output content layout. [Detection, owner and recovery](#cause-NativeOutputContentLayout).
    NativeOutputContentLayout,
    /// Native output content owner. [Detection, owner and recovery](#cause-NativeOutputContentOwner).
    NativeOutputContentOwner,
    /// Native output continuation changed. [Detection, owner and recovery](#cause-NativeOutputContinuationChanged).
    NativeOutputContinuationChanged,
    /// Native output destination incomplete. [Detection, owner and recovery](#cause-NativeOutputDestinationIncomplete).
    NativeOutputDestinationIncomplete,
    /// Native output destination phase. [Detection, owner and recovery](#cause-NativeOutputDestinationPhase).
    NativeOutputDestinationPhase,
    /// Native output destination preparation. [Detection, owner and recovery](#cause-NativeOutputDestinationPreparation).
    NativeOutputDestinationPreparation,
    /// Native output destination state. [Detection, owner and recovery](#cause-NativeOutputDestinationState).
    NativeOutputDestinationState,
    /// Native output dispatch phase. [Detection, owner and recovery](#cause-NativeOutputDispatchPhase).
    NativeOutputDispatchPhase,
    /// Native output graph size. [Detection, owner and recovery](#cause-NativeOutputGraphSize).
    NativeOutputGraphSize,
    /// Native output lifetime absent. [Detection, owner and recovery](#cause-NativeOutputLifetimeAbsent).
    NativeOutputLifetimeAbsent,
    /// Native output list empty. [Detection, owner and recovery](#cause-NativeOutputListEmpty).
    NativeOutputListEmpty,
    /// Native output need absent. [Detection, owner and recovery](#cause-NativeOutputNeedAbsent).
    NativeOutputNeedAbsent,
    /// Native output operation stopped. [Detection, owner and recovery](#cause-NativeOutputOperationStopped).
    NativeOutputOperationStopped,
    /// Native output owner absent. [Detection, owner and recovery](#cause-NativeOutputOwnerAbsent).
    NativeOutputOwnerAbsent,
    /// Native output possession absent. [Detection, owner and recovery](#cause-NativeOutputPossessionAbsent).
    NativeOutputPossessionAbsent,
    /// Native output preparation absent. [Detection, owner and recovery](#cause-NativeOutputPreparationAbsent).
    NativeOutputPreparationAbsent,
    /// Native output preparation state. [Detection, owner and recovery](#cause-NativeOutputPreparationState).
    NativeOutputPreparationState,
    /// Native output publication state. [Detection, owner and recovery](#cause-NativeOutputPublicationState).
    NativeOutputPublicationState,
    /// Native output quota absent. [Detection, owner and recovery](#cause-NativeOutputQuotaAbsent).
    NativeOutputQuotaAbsent,
    /// Native output reference index. [Detection, owner and recovery](#cause-NativeOutputReferenceIndex).
    NativeOutputReferenceIndex,
    /// Native output reference owner. [Detection, owner and recovery](#cause-NativeOutputReferenceOwner).
    NativeOutputReferenceOwner,
    /// Native output reference preparation. [Detection, owner and recovery](#cause-NativeOutputReferencePreparation).
    NativeOutputReferencePreparation,
    /// Native output reference unavailable. [Detection, owner and recovery](#cause-NativeOutputReferenceUnavailable).
    NativeOutputReferenceUnavailable,
    /// Native output restoration state. [Detection, owner and recovery](#cause-NativeOutputRestorationState).
    NativeOutputRestorationState,
    /// Native output return phase. [Detection, owner and recovery](#cause-NativeOutputReturnPhase).
    NativeOutputReturnPhase,
    /// Native output search owner. [Detection, owner and recovery](#cause-NativeOutputSearchOwner).
    NativeOutputSearchOwner,
    /// Native output search phase. [Detection, owner and recovery](#cause-NativeOutputSearchPhase).
    NativeOutputSearchPhase,
    /// Native output slot. [Detection, owner and recovery](#cause-NativeOutputSlot).
    NativeOutputSlot,
    /// Native output slot allocation. [Detection, owner and recovery](#cause-NativeOutputSlotAllocation).
    NativeOutputSlotAllocation,
    /// Native output slot size. [Detection, owner and recovery](#cause-NativeOutputSlotSize).
    NativeOutputSlotSize,
    /// Native output vector kind. [Detection, owner and recovery](#cause-NativeOutputVectorKind).
    NativeOutputVectorKind,
    /// Native outputs incomplete. [Detection, owner and recovery](#cause-NativeOutputsIncomplete).
    NativeOutputsIncomplete,
    /// Native publication accounting. [Detection, owner and recovery](#cause-NativePublicationAccounting).
    NativePublicationAccounting,
    /// Native publication allocation. [Detection, owner and recovery](#cause-NativePublicationAllocation).
    NativePublicationAllocation,
    /// Native publication capacity. [Detection, owner and recovery](#cause-NativePublicationCapacity).
    NativePublicationCapacity,
    /// Output cleanup count. [Detection, owner and recovery](#cause-OutputCleanupCount).
    OutputCleanupCount,
    /// Pair output slot. [Detection, owner and recovery](#cause-PairOutputSlot).
    PairOutputSlot,
    /// Requested observation preparation absent. [Detection, owner and recovery](#cause-RequestedObservationPreparationAbsent).
    RequestedObservationPreparationAbsent,
    /// Requested observation selection absent. [Detection, owner and recovery](#cause-RequestedObservationSelectionAbsent).
    RequestedObservationSelectionAbsent,
    /// Transport output consumed. [Detection, owner and recovery](#cause-TransportOutputConsumed).
    TransportOutputConsumed,
    /// Unobserved native identity absent. [Detection, owner and recovery](#cause-UnobservedNativeIdentityAbsent).
    UnobservedNativeIdentityAbsent,
}

impl std::fmt::Display for ObjectPublicationRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sp800OutputSlot => f.write_str("SP800 output slot"),
            Self::Sp800PublicationCapacity => f.write_str("SP800 publication capacity"),
            Self::TlsOutputSlot => f.write_str("TLS output slot"),
            Self::TlsPublicationCapacity => f.write_str("TLS publication capacity"),
            Self::TlsPublicationRole => f.write_str("TLS publication role"),
            Self::DestinationByteAccounting => f.write_str("destination byte accounting"),
            Self::DestinationTupleAccounting => f.write_str("destination tuple accounting"),
            Self::GenerationOutputConsumed => f.write_str("generation output consumed"),
            Self::NativeAuxiliaryOutputAbsent => f.write_str("native auxiliary output absent"),
            Self::NativeCreationAlreadyDispatched => {
                f.write_str("native creation already dispatched")
            }
            Self::NativeDestinationOwner => f.write_str("native destination owner"),
            Self::NativeEffectIsNotAResourceRequest => {
                f.write_str("native effect is not a resource request")
            }
            Self::NativeObjectLifetimeAbsent => f.write_str("native object lifetime absent"),
            Self::NativeObjectsNotRegistered => f.write_str("native objects not registered"),
            Self::NativeOutputAdmissionOwner => f.write_str("native output admission owner"),
            Self::NativeOutputAdmissionState => f.write_str("native output admission state"),
            Self::NativeOutputCandidateKind => f.write_str("native output candidate kind"),
            Self::NativeOutputCompletionUnknown => f.write_str("native output completion unknown"),
            Self::NativeOutputContentLayout => f.write_str("native output content layout"),
            Self::NativeOutputContentOwner => f.write_str("native output content owner"),
            Self::NativeOutputContinuationChanged => {
                f.write_str("native output continuation changed")
            }
            Self::NativeOutputDestinationIncomplete => {
                f.write_str("native output destination incomplete")
            }
            Self::NativeOutputDestinationPhase => f.write_str("native output destination phase"),
            Self::NativeOutputDestinationPreparation => {
                f.write_str("native output destination preparation")
            }
            Self::NativeOutputDestinationState => f.write_str("native output destination state"),
            Self::NativeOutputDispatchPhase => f.write_str("native output dispatch phase"),
            Self::NativeOutputGraphSize => f.write_str("native output graph size"),
            Self::NativeOutputLifetimeAbsent => f.write_str("native output lifetime absent"),
            Self::NativeOutputListEmpty => f.write_str("native output list empty"),
            Self::NativeOutputNeedAbsent => f.write_str("native output need absent"),
            Self::NativeOutputOperationStopped => f.write_str("native output operation stopped"),
            Self::NativeOutputOwnerAbsent => f.write_str("native output owner absent"),
            Self::NativeOutputPossessionAbsent => f.write_str("native output possession absent"),
            Self::NativeOutputPreparationAbsent => f.write_str("native output preparation absent"),
            Self::NativeOutputPreparationState => f.write_str("native output preparation state"),
            Self::NativeOutputPublicationState => f.write_str("native output publication state"),
            Self::NativeOutputQuotaAbsent => f.write_str("native output quota absent"),
            Self::NativeOutputReferenceIndex => f.write_str("native output reference index"),
            Self::NativeOutputReferenceOwner => f.write_str("native output reference owner"),
            Self::NativeOutputReferencePreparation => {
                f.write_str("native output reference preparation")
            }
            Self::NativeOutputReferenceUnavailable => {
                f.write_str("native output reference unavailable")
            }
            Self::NativeOutputRestorationState => f.write_str("native output restoration state"),
            Self::NativeOutputReturnPhase => f.write_str("native output return phase"),
            Self::NativeOutputSearchOwner => f.write_str("native output search owner"),
            Self::NativeOutputSearchPhase => f.write_str("native output search phase"),
            Self::NativeOutputSlot => f.write_str("native output slot"),
            Self::NativeOutputSlotAllocation => f.write_str("native output slot allocation"),
            Self::NativeOutputSlotSize => f.write_str("native output slot size"),
            Self::NativeOutputVectorKind => f.write_str("native output vector kind"),
            Self::NativeOutputsIncomplete => f.write_str("native outputs incomplete"),
            Self::NativePublicationAccounting => f.write_str("native publication accounting"),
            Self::NativePublicationAllocation => f.write_str("native publication allocation"),
            Self::NativePublicationCapacity => f.write_str("native publication capacity"),
            Self::OutputCleanupCount => f.write_str("output cleanup count"),
            Self::PairOutputSlot => f.write_str("pair output slot"),
            Self::RequestedObservationPreparationAbsent => {
                f.write_str("requested observation preparation absent")
            }
            Self::RequestedObservationSelectionAbsent => {
                f.write_str("requested observation selection absent")
            }
            Self::TransportOutputConsumed => f.write_str("transport output consumed"),
            Self::UnobservedNativeIdentityAbsent => {
                f.write_str("unobserved native identity absent")
            }
        }
    }
}
