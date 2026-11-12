// SPDX-License-Identifier: Apache-2.0
//! ObjectContent causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to object content.
#[doc = include_str!("../../../docs/diagnostics/rejection-object_content.md")]
pub enum ObjectContentRejection {
    /// Content continuation phase. [Detection, owner and recovery](#cause-ContentContinuationPhase).
    ContentContinuationPhase,
    /// Content native descriptor or capacity changed. [Detection, owner and recovery](#cause-ContentNativeDescriptorOrCapacityChanged).
    ContentNativeDescriptorOrCapacityChanged,
    /// Content observation incomplete. [Detection, owner and recovery](#cause-ContentObservationIncomplete).
    ContentObservationIncomplete,
    /// Content observation requires prepared owner. [Detection, owner and recovery](#cause-ContentObservationRequiresPreparedOwner).
    ContentObservationRequiresPreparedOwner,
    /// Content observation storage size. [Detection, owner and recovery](#cause-ContentObservationStorageSize).
    ContentObservationStorageSize,
    /// Content owner absent. [Detection, owner and recovery](#cause-ContentOwnerAbsent).
    ContentOwnerAbsent,
    /// Content possession absent. [Detection, owner and recovery](#cause-ContentPossessionAbsent).
    ContentPossessionAbsent,
    /// Content preparation changed. [Detection, owner and recovery](#cause-ContentPreparationChanged).
    ContentPreparationChanged,
    /// Content read phase. [Detection, owner and recovery](#cause-ContentReadPhase).
    ContentReadPhase,
    /// Content source changed. [Detection, owner and recovery](#cause-ContentSourceChanged).
    ContentSourceChanged,
    /// Content value need absent. [Detection, owner and recovery](#cause-ContentValueNeedAbsent).
    ContentValueNeedAbsent,
    /// Fingerprint already finished. [Detection, owner and recovery](#cause-FingerprintAlreadyFinished).
    FingerprintAlreadyFinished,
    /// Fingerprint byte budget. [Detection, owner and recovery](#cause-FingerprintByteBudget).
    FingerprintByteBudget,
    /// Fingerprint candidate kind. [Detection, owner and recovery](#cause-FingerprintCandidateKind).
    FingerprintCandidateKind,
    /// Fingerprint completion phase. [Detection, owner and recovery](#cause-FingerprintCompletionPhase).
    FingerprintCompletionPhase,
    /// Fingerprint continuation stopped. [Detection, owner and recovery](#cause-FingerprintContinuationStopped).
    FingerprintContinuationStopped,
    /// Fingerprint digest preparation. [Detection, owner and recovery](#cause-FingerprintDigestPreparation).
    FingerprintDigestPreparation,
    /// Fingerprint hash accounting. [Detection, owner and recovery](#cause-FingerprintHashAccounting).
    FingerprintHashAccounting,
    /// Fingerprint header count. [Detection, owner and recovery](#cause-FingerprintHeaderCount).
    FingerprintHeaderCount,
    /// Fingerprint material count. [Detection, owner and recovery](#cause-FingerprintMaterialCount).
    FingerprintMaterialCount,
    /// Fingerprint metadata need. [Detection, owner and recovery](#cause-FingerprintMetadataNeed).
    FingerprintMetadataNeed,
    /// Fingerprint metadata phase. [Detection, owner and recovery](#cause-FingerprintMetadataPhase).
    FingerprintMetadataPhase,
    /// Fingerprint owner absent. [Detection, owner and recovery](#cause-FingerprintOwnerAbsent).
    FingerprintOwnerAbsent,
    /// Fingerprint owner storage size. [Detection, owner and recovery](#cause-FingerprintOwnerStorageSize).
    FingerprintOwnerStorageSize,
    /// Fingerprint possession absent. [Detection, owner and recovery](#cause-FingerprintPossessionAbsent).
    FingerprintPossessionAbsent,
    /// Fingerprint preparation accounting. [Detection, owner and recovery](#cause-FingerprintPreparationAccounting).
    FingerprintPreparationAccounting,
    /// Fingerprint preparation changed. [Detection, owner and recovery](#cause-FingerprintPreparationChanged).
    FingerprintPreparationChanged,
    /// Fingerprint preparation need absent. [Detection, owner and recovery](#cause-FingerprintPreparationNeedAbsent).
    FingerprintPreparationNeedAbsent,
    /// Fingerprint protected call phase. [Detection, owner and recovery](#cause-FingerprintProtectedCallPhase).
    FingerprintProtectedCallPhase,
    /// Fingerprint protected value phase. [Detection, owner and recovery](#cause-FingerprintProtectedValuePhase).
    FingerprintProtectedValuePhase,
    /// Fingerprint public value phase. [Detection, owner and recovery](#cause-FingerprintPublicValuePhase).
    FingerprintPublicValuePhase,
    /// Fingerprint source changed. [Detection, owner and recovery](#cause-FingerprintSourceChanged).
    FingerprintSourceChanged,
    /// Fingerprint state allocation. [Detection, owner and recovery](#cause-FingerprintStateAllocation).
    FingerprintStateAllocation,

}

impl std::fmt::Display for ObjectContentRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {

            Self::ContentContinuationPhase => f.write_str("content continuation phase"),
            Self::ContentNativeDescriptorOrCapacityChanged => {
                f.write_str("content native descriptor or capacity changed")
            }
            Self::ContentObservationIncomplete => f.write_str("content observation incomplete"),
            Self::ContentObservationRequiresPreparedOwner => {
                f.write_str("content observation requires prepared owner")
            }
            Self::ContentObservationStorageSize => f.write_str("content observation storage size"),
            Self::ContentOwnerAbsent => f.write_str("content owner absent"),
            Self::ContentPossessionAbsent => f.write_str("content possession absent"),
            Self::ContentPreparationChanged => f.write_str("content preparation changed"),
            Self::ContentReadPhase => f.write_str("content read phase"),
            Self::ContentSourceChanged => f.write_str("content source changed"),
            Self::ContentValueNeedAbsent => f.write_str("content value need absent"),
            Self::FingerprintAlreadyFinished => f.write_str("fingerprint already finished"),
            Self::FingerprintByteBudget => f.write_str("fingerprint byte budget"),
            Self::FingerprintCandidateKind => f.write_str("fingerprint candidate kind"),
            Self::FingerprintCompletionPhase => f.write_str("fingerprint completion phase"),
            Self::FingerprintContinuationStopped => f.write_str("fingerprint continuation stopped"),
            Self::FingerprintDigestPreparation => f.write_str("fingerprint digest preparation"),
            Self::FingerprintHashAccounting => f.write_str("fingerprint hash accounting"),
            Self::FingerprintHeaderCount => f.write_str("fingerprint header count"),
            Self::FingerprintMaterialCount => f.write_str("fingerprint material count"),
            Self::FingerprintMetadataNeed => f.write_str("fingerprint metadata need"),
            Self::FingerprintMetadataPhase => f.write_str("fingerprint metadata phase"),
            Self::FingerprintOwnerAbsent => f.write_str("fingerprint owner absent"),
            Self::FingerprintOwnerStorageSize => f.write_str("fingerprint owner storage size"),
            Self::FingerprintPossessionAbsent => f.write_str("fingerprint possession absent"),
            Self::FingerprintPreparationAccounting => {
                f.write_str("fingerprint preparation accounting")
            }
            Self::FingerprintPreparationChanged => f.write_str("fingerprint preparation changed"),
            Self::FingerprintPreparationNeedAbsent => {
                f.write_str("fingerprint preparation need absent")
            }
            Self::FingerprintProtectedCallPhase => f.write_str("fingerprint protected call phase"),
            Self::FingerprintProtectedValuePhase => {
                f.write_str("fingerprint protected value phase")
            }
            Self::FingerprintPublicValuePhase => f.write_str("fingerprint public value phase"),
            Self::FingerprintSourceChanged => f.write_str("fingerprint source changed"),
            Self::FingerprintStateAllocation => f.write_str("fingerprint state allocation"),
        }
    }
}
