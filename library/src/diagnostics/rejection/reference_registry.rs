// SPDX-License-Identifier: Apache-2.0
//! ReferenceRegistry causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to reference registry.
#[doc = include_str!("../../../docs/diagnostics/rejection-reference_registry.md")]
pub enum ReferenceRegistryRejection {
    /// Activity context notifier absent. [Detection, owner and recovery](#cause-ActivityContextNotifierAbsent).
    ActivityContextNotifierAbsent,
    /// Activity context notifier mismatch. [Detection, owner and recovery](#cause-ActivityContextNotifierMismatch).
    ActivityContextNotifierMismatch,
    /// Activity owner storage accounting. [Detection, owner and recovery](#cause-ActivityOwnerStorageAccounting).
    ActivityOwnerStorageAccounting,
    /// Activity storage accounting. [Detection, owner and recovery](#cause-ActivityStorageAccounting).
    ActivityStorageAccounting,
    /// Foreign or borrowed object writer. [Detection, owner and recovery](#cause-ForeignOrBorrowedObjectWriter).
    ForeignOrBorrowedObjectWriter,
    /// Foreign or exhausted reference reservation. [Detection, owner and recovery](#cause-ForeignOrExhaustedReferenceReservation).
    ForeignOrExhaustedReferenceReservation,
    /// Foreign writer transfer activity. [Detection, owner and recovery](#cause-ForeignWriterTransferActivity).
    ForeignWriterTransferActivity,
    /// Live reference allocation. [Detection, owner and recovery](#cause-LiveReferenceAllocation).
    LiveReferenceAllocation,
    /// Live registry boundary absent. [Detection, owner and recovery](#cause-LiveRegistryBoundaryAbsent).
    LiveRegistryBoundaryAbsent,
    /// Live registry cursor absent. [Detection, owner and recovery](#cause-LiveRegistryCursorAbsent).
    LiveRegistryCursorAbsent,
    /// Object activity allocation. [Detection, owner and recovery](#cause-ObjectActivityAllocation).
    ObjectActivityAllocation,
    /// Object activity count. [Detection, owner and recovery](#cause-ObjectActivityCount).
    ObjectActivityCount,
    /// Object activity owner. [Detection, owner and recovery](#cause-ObjectActivityOwner).
    ObjectActivityOwner,
    /// Object reader slot already occupied. [Detection, owner and recovery](#cause-ObjectReaderSlotAlreadyOccupied).
    ObjectReaderSlotAlreadyOccupied,
    /// Object write ownership state. [Detection, owner and recovery](#cause-ObjectWriteOwnershipState).
    ObjectWriteOwnershipState,
    /// Object writer count. [Detection, owner and recovery](#cause-ObjectWriterCount).
    ObjectWriterCount,
    /// Prepared key reader absent. [Detection, owner and recovery](#cause-PreparedKeyReaderAbsent).
    PreparedKeyReaderAbsent,
    /// Prepared key reader attribution lost. [Detection, owner and recovery](#cause-PreparedKeyReaderAttributionLost).
    PreparedKeyReaderAttributionLost,
    /// Reference activity preparation absent. [Detection, owner and recovery](#cause-ReferenceActivityPreparationAbsent).
    ReferenceActivityPreparationAbsent,
    /// Reference activity preparation already present. [Detection, owner and recovery](#cause-ReferenceActivityPreparationAlreadyPresent).
    ReferenceActivityPreparationAlreadyPresent,
    /// Reference allocation. [Detection, owner and recovery](#cause-ReferenceAllocation).
    ReferenceAllocation,
    /// Reference count overflow. [Detection, owner and recovery](#cause-ReferenceCountOverflow).
    ReferenceCountOverflow,
    /// Reference quota exceeded. [Detection, owner and recovery](#cause-ReferenceQuotaExceeded).
    ReferenceQuotaExceeded,
    /// Revocation snapshot already populated. [Detection, owner and recovery](#cause-RevocationSnapshotAlreadyPopulated).
    RevocationSnapshotAlreadyPopulated,
    /// Transferred writer attribution. [Detection, owner and recovery](#cause-TransferredWriterAttribution).
    TransferredWriterAttribution,
    /// Unknown creator capacity not prepared. [Detection, owner and recovery](#cause-UnknownCreatorCapacityNotPrepared).
    UnknownCreatorCapacityNotPrepared,
    /// Writer transfer attribution absent. [Detection, owner and recovery](#cause-WriterTransferAttributionAbsent).
    WriterTransferAttributionAbsent,
    /// Writer transfer count. [Detection, owner and recovery](#cause-WriterTransferCount).
    WriterTransferCount,
    /// Writer transfer state. [Detection, owner and recovery](#cause-WriterTransferState).
    WriterTransferState,
}

impl std::fmt::Display for ReferenceRegistryRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ActivityContextNotifierAbsent => f.write_str("activity context notifier absent"),
            Self::ActivityContextNotifierMismatch => {
                f.write_str("activity context notifier mismatch")
            }
            Self::ActivityOwnerStorageAccounting => {
                f.write_str("activity owner storage accounting")
            }
            Self::ActivityStorageAccounting => f.write_str("activity storage accounting"),
            Self::ForeignOrBorrowedObjectWriter => f.write_str("foreign or borrowed object writer"),
            Self::ForeignOrExhaustedReferenceReservation => {
                f.write_str("foreign or exhausted reference reservation")
            }
            Self::ForeignWriterTransferActivity => f.write_str("foreign writer transfer activity"),
            Self::LiveReferenceAllocation => f.write_str("live reference allocation"),
            Self::LiveRegistryBoundaryAbsent => f.write_str("live registry boundary absent"),
            Self::LiveRegistryCursorAbsent => f.write_str("live registry cursor absent"),
            Self::ObjectActivityAllocation => f.write_str("object activity allocation"),
            Self::ObjectActivityCount => f.write_str("object activity count"),
            Self::ObjectActivityOwner => f.write_str("object activity owner"),
            Self::ObjectReaderSlotAlreadyOccupied => {
                f.write_str("object reader slot already occupied")
            }
            Self::ObjectWriteOwnershipState => f.write_str("object write ownership state"),
            Self::ObjectWriterCount => f.write_str("object writer count"),
            Self::PreparedKeyReaderAbsent => f.write_str("prepared key reader absent"),
            Self::PreparedKeyReaderAttributionLost => {
                f.write_str("prepared key reader attribution lost")
            }
            Self::ReferenceActivityPreparationAbsent => {
                f.write_str("reference activity preparation absent")
            }
            Self::ReferenceActivityPreparationAlreadyPresent => {
                f.write_str("reference activity preparation already present")
            }
            Self::ReferenceAllocation => f.write_str("reference allocation"),
            Self::ReferenceCountOverflow => f.write_str("reference count overflow"),
            Self::ReferenceQuotaExceeded => f.write_str("reference quota exceeded"),
            Self::RevocationSnapshotAlreadyPopulated => {
                f.write_str("revocation snapshot already populated")
            }
            Self::TransferredWriterAttribution => f.write_str("transferred writer attribution"),
            Self::UnknownCreatorCapacityNotPrepared => {
                f.write_str("unknown creator capacity not prepared")
            }
            Self::WriterTransferAttributionAbsent => {
                f.write_str("writer transfer attribution absent")
            }
            Self::WriterTransferCount => f.write_str("writer transfer count"),
            Self::WriterTransferState => f.write_str("writer transfer state"),
        }
    }
}
