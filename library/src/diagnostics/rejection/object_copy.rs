// SPDX-License-Identifier: Apache-2.0
//! ObjectCopy causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to object copy.
#[doc = include_str!("../../../docs/diagnostics/rejection-object_copy.md")]
pub enum ObjectCopyRejection {
    /// C_CopyObject unavailable. [Detection, owner and recovery](#cause-CCopyObjectUnavailable).
    CCopyObjectUnavailable,
    /// Copy admission phase. [Detection, owner and recovery](#cause-CopyAdmissionPhase).
    CopyAdmissionPhase,
    /// Copy admission preparation absent. [Detection, owner and recovery](#cause-CopyAdmissionPreparationAbsent).
    CopyAdmissionPreparationAbsent,
    /// Copy already dispatched. [Detection, owner and recovery](#cause-CopyAlreadyDispatched).
    CopyAlreadyDispatched,
    /// Copy candidate kind. [Detection, owner and recovery](#cause-CopyCandidateKind).
    CopyCandidateKind,
    /// Copy completion phase. [Detection, owner and recovery](#cause-CopyCompletionPhase).
    CopyCompletionPhase,
    /// Copy continuation changed. [Detection, owner and recovery](#cause-CopyContinuationChanged).
    CopyContinuationChanged,
    /// Copy destination class. [Detection, owner and recovery](#cause-CopyDestinationClass).
    CopyDestinationClass,
    /// Copy destination phase. [Detection, owner and recovery](#cause-CopyDestinationPhase).
    CopyDestinationPhase,
    /// Copy destination preparation absent. [Detection, owner and recovery](#cause-CopyDestinationPreparationAbsent).
    CopyDestinationPreparationAbsent,
    /// Copy diagnostics already consumed. [Detection, owner and recovery](#cause-CopyDiagnosticsAlreadyConsumed).
    CopyDiagnosticsAlreadyConsumed,
    /// Copy incomplete. [Detection, owner and recovery](#cause-CopyIncomplete).
    CopyIncomplete,
    /// Copy input changed. [Detection, owner and recovery](#cause-CopyInputChanged).
    CopyInputChanged,
    /// Copy metadata phase. [Detection, owner and recovery](#cause-CopyMetadataPhase).
    CopyMetadataPhase,
    /// Copy native lifetime absent. [Detection, owner and recovery](#cause-CopyNativeLifetimeAbsent).
    CopyNativeLifetimeAbsent,
    /// Copy output absent. [Detection, owner and recovery](#cause-CopyOutputAbsent).
    CopyOutputAbsent,
    /// Copy owner absent. [Detection, owner and recovery](#cause-CopyOwnerAbsent).
    CopyOwnerAbsent,
    /// Copy possession absent. [Detection, owner and recovery](#cause-CopyPossessionAbsent).
    CopyPossessionAbsent,
    /// Copy publication quota absent. [Detection, owner and recovery](#cause-CopyPublicationQuotaAbsent).
    CopyPublicationQuotaAbsent,
    /// Copy publication quota transferred. [Detection, owner and recovery](#cause-CopyPublicationQuotaTransferred).
    CopyPublicationQuotaTransferred,
    /// Copy reference phase. [Detection, owner and recovery](#cause-CopyReferencePhase).
    CopyReferencePhase,
    /// Copy resource need absent. [Detection, owner and recovery](#cause-CopyResourceNeedAbsent).
    CopyResourceNeedAbsent,
    /// Copy returned invalid identity. [Detection, owner and recovery](#cause-CopyReturnedInvalidIdentity).
    CopyReturnedInvalidIdentity,
    /// Copy stopped. [Detection, owner and recovery](#cause-CopyStopped).
    CopyStopped,
    /// Copy storage size. [Detection, owner and recovery](#cause-CopyStorageSize).
    CopyStorageSize,
    /// Copy template recipe kind. [Detection, owner and recovery](#cause-CopyTemplateRecipeKind).
    CopyTemplateRecipeKind,
}

impl std::fmt::Display for ObjectCopyRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CCopyObjectUnavailable => f.write_str("C_CopyObject unavailable"),
            Self::CopyAdmissionPhase => f.write_str("copy admission phase"),
            Self::CopyAdmissionPreparationAbsent => {
                f.write_str("copy admission preparation absent")
            }
            Self::CopyAlreadyDispatched => f.write_str("copy already dispatched"),
            Self::CopyCandidateKind => f.write_str("copy candidate kind"),
            Self::CopyCompletionPhase => f.write_str("copy completion phase"),
            Self::CopyContinuationChanged => f.write_str("copy continuation changed"),
            Self::CopyDestinationClass => f.write_str("copy destination class"),
            Self::CopyDestinationPhase => f.write_str("copy destination phase"),
            Self::CopyDestinationPreparationAbsent => {
                f.write_str("copy destination preparation absent")
            }
            Self::CopyDiagnosticsAlreadyConsumed => {
                f.write_str("copy diagnostics already consumed")
            }
            Self::CopyIncomplete => f.write_str("copy incomplete"),
            Self::CopyInputChanged => f.write_str("copy input changed"),
            Self::CopyMetadataPhase => f.write_str("copy metadata phase"),
            Self::CopyNativeLifetimeAbsent => f.write_str("copy native lifetime absent"),
            Self::CopyOutputAbsent => f.write_str("copy output absent"),
            Self::CopyOwnerAbsent => f.write_str("copy owner absent"),
            Self::CopyPossessionAbsent => f.write_str("copy possession absent"),
            Self::CopyPublicationQuotaAbsent => f.write_str("copy publication quota absent"),
            Self::CopyPublicationQuotaTransferred => {
                f.write_str("copy publication quota transferred")
            }
            Self::CopyReferencePhase => f.write_str("copy reference phase"),
            Self::CopyResourceNeedAbsent => f.write_str("copy resource need absent"),
            Self::CopyReturnedInvalidIdentity => f.write_str("copy returned invalid identity"),
            Self::CopyStopped => f.write_str("copy stopped"),
            Self::CopyStorageSize => f.write_str("copy storage size"),
            Self::CopyTemplateRecipeKind => f.write_str("copy template recipe kind"),
        }
    }
}
