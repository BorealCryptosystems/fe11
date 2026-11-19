// SPDX-License-Identifier: Apache-2.0
//! Public ReferenceRegistryRejection values retain identity through category conversion.
use fe11::{Error, ReferenceRegistryRejection, RejectionReason};

#[test]
fn variants_preserve_category_and_payload() {
    let cases = [
        ReferenceRegistryRejection::ActivityContextNotifierAbsent,
        ReferenceRegistryRejection::ActivityContextNotifierMismatch,
        ReferenceRegistryRejection::ActivityOwnerStorageAccounting,
        ReferenceRegistryRejection::ActivityStorageAccounting,
        ReferenceRegistryRejection::ForeignOrBorrowedObjectWriter,
        ReferenceRegistryRejection::ForeignOrExhaustedReferenceReservation,
        ReferenceRegistryRejection::ForeignWriterTransferActivity,
        ReferenceRegistryRejection::LiveReferenceAllocation,
        ReferenceRegistryRejection::LiveRegistryBoundaryAbsent,
        ReferenceRegistryRejection::LiveRegistryCursorAbsent,
        ReferenceRegistryRejection::ObjectActivityAllocation,
        ReferenceRegistryRejection::ObjectActivityCount,
        ReferenceRegistryRejection::ObjectActivityOwner,
        ReferenceRegistryRejection::ObjectReaderSlotAlreadyOccupied,
        ReferenceRegistryRejection::ObjectWriteOwnershipState,
        ReferenceRegistryRejection::ObjectWriterCount,
        ReferenceRegistryRejection::PreparedKeyReaderAbsent,
        ReferenceRegistryRejection::PreparedKeyReaderAttributionLost,
        ReferenceRegistryRejection::ReferenceActivityPreparationAbsent,
        ReferenceRegistryRejection::ReferenceActivityPreparationAlreadyPresent,
        ReferenceRegistryRejection::ReferenceAllocation,
        ReferenceRegistryRejection::ReferenceCountOverflow,
        ReferenceRegistryRejection::ReferenceQuotaExceeded,
        ReferenceRegistryRejection::RevocationSnapshotAlreadyPopulated,
        ReferenceRegistryRejection::TransferredWriterAttribution,
        ReferenceRegistryRejection::UnknownCreatorCapacityNotPrepared,
        ReferenceRegistryRejection::WriterTransferAttributionAbsent,
        ReferenceRegistryRejection::WriterTransferCount,
        ReferenceRegistryRejection::WriterTransferState,
    ];
    for value in cases {
        let category: RejectionReason = value.into();
        assert!(matches!(category, RejectionReason::ReferenceRegistry(actual) if actual == value));
        let error = Error::Rejected(category);
        assert_eq!(error.clone(), error);
        assert!(
            matches!(&error, Error::Rejected(RejectionReason::ReferenceRegistry(actual)) if *actual == value)
        );
        assert!(!value.to_string().is_empty());
        assert!(!category.to_string().is_empty());
        assert!(!error.to_string().is_empty());
        assert!(!format!("{value:?}").is_empty());
    }
}
