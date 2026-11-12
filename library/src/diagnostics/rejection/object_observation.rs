// SPDX-License-Identifier: Apache-2.0
//! ObjectObservation causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to object observation.
#[doc = include_str!("../../../docs/diagnostics/rejection-object_observation.md")]
pub enum ObjectObservationRejection {
    /// C_DestroyObject unavailable. [Detection, owner and recovery](#cause-CDestroyObjectUnavailable).
    CDestroyObjectUnavailable,
    /// RSA creation reservation absent. [Detection, owner and recovery](#cause-RsaCreationReservationAbsent).
    RsaCreationReservationAbsent,
    /// RSA diagnostic accounting. [Detection, owner and recovery](#cause-RsaDiagnosticAccounting).
    RsaDiagnosticAccounting,
    /// RSA generation completion unknown. [Detection, owner and recovery](#cause-RsaGenerationCompletionUnknown).
    RsaGenerationCompletionUnknown,
    /// RSA generation diagnostic absent. [Detection, owner and recovery](#cause-RsaGenerationDiagnosticAbsent).
    RsaGenerationDiagnosticAbsent,
    /// RSA generation dispatch phase. [Detection, owner and recovery](#cause-RsaGenerationDispatchPhase).
    RsaGenerationDispatchPhase,
    /// RSA generation result kind. [Detection, owner and recovery](#cause-RsaGenerationResultKind).
    RsaGenerationResultKind,
    /// RSA generation return phase. [Detection, owner and recovery](#cause-RsaGenerationReturnPhase).
    RsaGenerationReturnPhase,
    /// RSA native effect is not a storage request. [Detection, owner and recovery](#cause-RsaNativeEffectIsNotAStorageRequest).
    RsaNativeEffectIsNotAStorageRequest,
    /// RSA object activation phase. [Detection, owner and recovery](#cause-RsaObjectActivationPhase).
    RsaObjectActivationPhase,
    /// RSA object aggregate accounting. [Detection, owner and recovery](#cause-RsaObjectAggregateAccounting).
    RsaObjectAggregateAccounting,
    /// RSA object candidate kind. [Detection, owner and recovery](#cause-RsaObjectCandidateKind).
    RsaObjectCandidateKind,
    /// RSA object continuation changed. [Detection, owner and recovery](#cause-RsaObjectContinuationChanged).
    RsaObjectContinuationChanged,
    /// RSA object graph size. [Detection, owner and recovery](#cause-RsaObjectGraphSize).
    RsaObjectGraphSize,
    /// RSA object need absent. [Detection, owner and recovery](#cause-RsaObjectNeedAbsent).
    RsaObjectNeedAbsent,
    /// RSA object operation stopped. [Detection, owner and recovery](#cause-RsaObjectOperationStopped).
    RsaObjectOperationStopped,
    /// RSA object owner absent. [Detection, owner and recovery](#cause-RsaObjectOwnerAbsent).
    RsaObjectOwnerAbsent,
    /// RSA object possession absent. [Detection, owner and recovery](#cause-RsaObjectPossessionAbsent).
    RsaObjectPossessionAbsent,
    /// RSA object publication phase. [Detection, owner and recovery](#cause-RsaObjectPublicationPhase).
    RsaObjectPublicationPhase,
    /// RSA object result incomplete. [Detection, owner and recovery](#cause-RsaObjectResultIncomplete).
    RsaObjectResultIncomplete,
    /// RSA object result kind. [Detection, owner and recovery](#cause-RsaObjectResultKind).
    RsaObjectResultKind,
    /// RSA object search request. [Detection, owner and recovery](#cause-RsaObjectSearchRequest).
    RsaObjectSearchRequest,
    /// RSA object transition. [Detection, owner and recovery](#cause-RsaObjectTransition).
    RsaObjectTransition,
    /// RSA pair candidate kind. [Detection, owner and recovery](#cause-RsaPairCandidateKind).
    RsaPairCandidateKind,
    /// RSA pair completion phase. [Detection, owner and recovery](#cause-RsaPairCompletionPhase).
    RsaPairCompletionPhase,
    /// RSA pair continuation changed. [Detection, owner and recovery](#cause-RsaPairContinuationChanged).
    RsaPairContinuationChanged,
    /// RSA pair observation incomplete. [Detection, owner and recovery](#cause-RsaPairObservationIncomplete).
    RsaPairObservationIncomplete,
    /// RSA pair observation stopped. [Detection, owner and recovery](#cause-RsaPairObservationStopped).
    RsaPairObservationStopped,
    /// RSA pair observation storage. [Detection, owner and recovery](#cause-RsaPairObservationStorage).
    RsaPairObservationStorage,
    /// RSA pair preparation absent. [Detection, owner and recovery](#cause-RsaPairPreparationAbsent).
    RsaPairPreparationAbsent,
    /// RSA private snapshot preparation absent. [Detection, owner and recovery](#cause-RsaPrivateSnapshotPreparationAbsent).
    RsaPrivateSnapshotPreparationAbsent,
    /// RSA property preparation absent. [Detection, owner and recovery](#cause-RsaPropertyPreparationAbsent).
    RsaPropertyPreparationAbsent,
    /// RSA public encoding absent. [Detection, owner and recovery](#cause-RsaPublicEncodingAbsent).
    RsaPublicEncodingAbsent,
    /// RSA publication preparation absent. [Detection, owner and recovery](#cause-RsaPublicationPreparationAbsent).
    RsaPublicationPreparationAbsent,
    /// RSA selection preparation absent. [Detection, owner and recovery](#cause-RsaSelectionPreparationAbsent).
    RsaSelectionPreparationAbsent,
    /// RSA selection result kind. [Detection, owner and recovery](#cause-RsaSelectionResultKind).
    RsaSelectionResultKind,
    /// Foreign or stale object. [Detection, owner and recovery](#cause-ForeignOrStaleObject).
    ForeignOrStaleObject,
    /// Object context or class. [Detection, owner and recovery](#cause-ObjectContextOrClass).
    ObjectContextOrClass,
    /// Public attribute selection size overflow. [Detection, owner and recovery](#cause-PublicAttributeSelectionSizeOverflow).
    PublicAttributeSelectionSizeOverflow,

}

impl std::fmt::Display for ObjectObservationRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {

            Self::CDestroyObjectUnavailable => f.write_str("C_DestroyObject unavailable"),
            Self::RsaCreationReservationAbsent => f.write_str("RSA creation reservation absent"),
            Self::RsaDiagnosticAccounting => f.write_str("RSA diagnostic accounting"),
            Self::RsaGenerationCompletionUnknown => {
                f.write_str("RSA generation completion unknown")
            }
            Self::RsaGenerationDiagnosticAbsent => f.write_str("RSA generation diagnostic absent"),
            Self::RsaGenerationDispatchPhase => f.write_str("RSA generation dispatch phase"),
            Self::RsaGenerationResultKind => f.write_str("RSA generation result kind"),
            Self::RsaGenerationReturnPhase => f.write_str("RSA generation return phase"),
            Self::RsaNativeEffectIsNotAStorageRequest => {
                f.write_str("RSA native effect is not a storage request")
            }
            Self::RsaObjectActivationPhase => f.write_str("RSA object activation phase"),
            Self::RsaObjectAggregateAccounting => f.write_str("RSA object aggregate accounting"),
            Self::RsaObjectCandidateKind => f.write_str("RSA object candidate kind"),
            Self::RsaObjectContinuationChanged => f.write_str("RSA object continuation changed"),
            Self::RsaObjectGraphSize => f.write_str("RSA object graph size"),
            Self::RsaObjectNeedAbsent => f.write_str("RSA object need absent"),
            Self::RsaObjectOperationStopped => f.write_str("RSA object operation stopped"),
            Self::RsaObjectOwnerAbsent => f.write_str("RSA object owner absent"),
            Self::RsaObjectPossessionAbsent => f.write_str("RSA object possession absent"),
            Self::RsaObjectPublicationPhase => f.write_str("RSA object publication phase"),
            Self::RsaObjectResultIncomplete => f.write_str("RSA object result incomplete"),
            Self::RsaObjectResultKind => f.write_str("RSA object result kind"),
            Self::RsaObjectSearchRequest => f.write_str("RSA object search request"),
            Self::RsaObjectTransition => f.write_str("RSA object transition"),
            Self::RsaPairCandidateKind => f.write_str("RSA pair candidate kind"),
            Self::RsaPairCompletionPhase => f.write_str("RSA pair completion phase"),
            Self::RsaPairContinuationChanged => f.write_str("RSA pair continuation changed"),
            Self::RsaPairObservationIncomplete => f.write_str("RSA pair observation incomplete"),
            Self::RsaPairObservationStopped => f.write_str("RSA pair observation stopped"),
            Self::RsaPairObservationStorage => f.write_str("RSA pair observation storage"),
            Self::RsaPairPreparationAbsent => f.write_str("RSA pair preparation absent"),
            Self::RsaPrivateSnapshotPreparationAbsent => {
                f.write_str("RSA private snapshot preparation absent")
            }
            Self::RsaPropertyPreparationAbsent => f.write_str("RSA property preparation absent"),
            Self::RsaPublicEncodingAbsent => f.write_str("RSA public encoding absent"),
            Self::RsaPublicationPreparationAbsent => {
                f.write_str("RSA publication preparation absent")
            }
            Self::RsaSelectionPreparationAbsent => f.write_str("RSA selection preparation absent"),
            Self::RsaSelectionResultKind => f.write_str("RSA selection result kind"),
            Self::ForeignOrStaleObject => f.write_str("foreign or stale object"),
            Self::ObjectContextOrClass => f.write_str("object context or class"),
            Self::PublicAttributeSelectionSizeOverflow => {
                f.write_str("public attribute selection size overflow")
            }
        }
    }
}
