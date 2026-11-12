// SPDX-License-Identifier: Apache-2.0
//! ObjectCleanup causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to object cleanup.
#[doc = include_str!("../../../docs/diagnostics/rejection-object_cleanup.md")]
pub enum ObjectCleanupRejection {
    /// Abandoned reader snapshot allocation. [Detection, owner and recovery](#cause-AbandonedReaderSnapshotAllocation).
    AbandonedReaderSnapshotAllocation,
    /// Coordination vector storage accounting. [Detection, owner and recovery](#cause-CoordinationVectorStorageAccounting).
    CoordinationVectorStorageAccounting,
    /// Creator activity count. [Detection, owner and recovery](#cause-CreatorActivityCount).
    CreatorActivityCount,
    /// Creator close budget owner. [Detection, owner and recovery](#cause-CreatorCloseBudgetOwner).
    CreatorCloseBudgetOwner,
    /// Creator close capacity not prepared. [Detection, owner and recovery](#cause-CreatorCloseCapacityNotPrepared).
    CreatorCloseCapacityNotPrepared,
    /// Creator close preparation already present. [Detection, owner and recovery](#cause-CreatorClosePreparationAlreadyPresent).
    CreatorClosePreparationAlreadyPresent,
    /// Creator close ticket exhausted. [Detection, owner and recovery](#cause-CreatorCloseTicketExhausted).
    CreatorCloseTicketExhausted,
    /// Creator participant count. [Detection, owner and recovery](#cause-CreatorParticipantCount).
    CreatorParticipantCount,
    /// Creator participant reservation exhausted. [Detection, owner and recovery](#cause-CreatorParticipantReservationExhausted).
    CreatorParticipantReservationExhausted,
    /// Creator reservation count. [Detection, owner and recovery](#cause-CreatorReservationCount).
    CreatorReservationCount,
    /// Creator snapshot allocation. [Detection, owner and recovery](#cause-CreatorSnapshotAllocation).
    CreatorSnapshotAllocation,
    /// Foreign creator close credit. [Detection, owner and recovery](#cause-ForeignCreatorCloseCredit).
    ForeignCreatorCloseCredit,
    /// Foreign creator close preparation. [Detection, owner and recovery](#cause-ForeignCreatorClosePreparation).
    ForeignCreatorClosePreparation,
    /// Mutation cleanup owner absent. [Detection, owner and recovery](#cause-MutationCleanupOwnerAbsent).
    MutationCleanupOwnerAbsent,
    /// Reference close storage accounting. [Detection, owner and recovery](#cause-ReferenceCloseStorageAccounting).
    ReferenceCloseStorageAccounting,
    /// Unknown creator close absent. [Detection, owner and recovery](#cause-UnknownCreatorCloseAbsent).
    UnknownCreatorCloseAbsent,
    /// Unknown creator close allocation. [Detection, owner and recovery](#cause-UnknownCreatorCloseAllocation).
    UnknownCreatorCloseAllocation,
    /// Unknown creator close count. [Detection, owner and recovery](#cause-UnknownCreatorCloseCount).
    UnknownCreatorCloseCount,
}

impl std::fmt::Display for ObjectCleanupRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AbandonedReaderSnapshotAllocation => {
                f.write_str("abandoned reader snapshot allocation")
            }
            Self::CoordinationVectorStorageAccounting => {
                f.write_str("coordination vector storage accounting")
            }
            Self::CreatorActivityCount => f.write_str("creator activity count"),
            Self::CreatorCloseBudgetOwner => f.write_str("creator close budget owner"),
            Self::CreatorCloseCapacityNotPrepared => {
                f.write_str("creator close capacity not prepared")
            }
            Self::CreatorClosePreparationAlreadyPresent => {
                f.write_str("creator close preparation already present")
            }
            Self::CreatorCloseTicketExhausted => f.write_str("creator close ticket exhausted"),
            Self::CreatorParticipantCount => f.write_str("creator participant count"),
            Self::CreatorParticipantReservationExhausted => {
                f.write_str("creator participant reservation exhausted")
            }
            Self::CreatorReservationCount => f.write_str("creator reservation count"),
            Self::CreatorSnapshotAllocation => f.write_str("creator snapshot allocation"),
            Self::ForeignCreatorCloseCredit => f.write_str("foreign creator close credit"),
            Self::ForeignCreatorClosePreparation => {
                f.write_str("foreign creator close preparation")
            }
            Self::MutationCleanupOwnerAbsent => f.write_str("mutation cleanup owner absent"),
            Self::ReferenceCloseStorageAccounting => {
                f.write_str("reference close storage accounting")
            }
            Self::UnknownCreatorCloseAbsent => f.write_str("unknown creator close absent"),
            Self::UnknownCreatorCloseAllocation => f.write_str("unknown creator close allocation"),
            Self::UnknownCreatorCloseCount => f.write_str("unknown creator close count"),
        }
    }
}
