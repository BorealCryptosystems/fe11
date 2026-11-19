// SPDX-License-Identifier: Apache-2.0
//! Public ObjectSearchRejection values retain identity through category conversion.
use fe11::{Error, ObjectSearchRejection, RejectionReason};

#[test]
fn variants_preserve_category_and_payload() {
    let cases = [
        ObjectSearchRejection::DiscoveryContentPublicationIncomplete,
        ObjectSearchRejection::DiscoveryPublicationIncomplete,
        ObjectSearchRejection::DiscoveryQuotaAlreadyTransferred,
        ObjectSearchRejection::DiscoveryQuotaTransferred,
        ObjectSearchRejection::EmptySearchBatchRequiresFinalization,
        ObjectSearchRejection::IntegerAttributeWidth,
        ObjectSearchRejection::InvalidSearchResultHandle,
        ObjectSearchRejection::InventoryByteQuota,
        ObjectSearchRejection::InventoryCandidateKind,
        ObjectSearchRejection::InventoryContinuationChanged,
        ObjectSearchRejection::InventoryIncomplete,
        ObjectSearchRejection::InventoryMetadataAllocation,
        ObjectSearchRejection::InventoryMetadataPhase,
        ObjectSearchRejection::InventoryMetadataSize,
        ObjectSearchRejection::InventoryOwnerAbsent,
        ObjectSearchRejection::InventoryPhase,
        ObjectSearchRejection::InventoryPossessionAbsent,
        ObjectSearchRejection::InventoryReadNeed,
        ObjectSearchRejection::InventoryReadPhase,
        ObjectSearchRejection::InventoryResourceNeedAbsent,
        ObjectSearchRejection::InventoryRowsCapacity,
        ObjectSearchRejection::InventoryRowsNeed,
        ObjectSearchRejection::InventorySortAllocation,
        ObjectSearchRejection::InventoryStorageSize,
        ObjectSearchRejection::InventoryValueNeed,
        ObjectSearchRejection::ManagedClassUnsupported,
        ObjectSearchRejection::ManagedDiscoveryCandidateKind,
        ObjectSearchRejection::ManagedDiscoveryCompletionPhase,
        ObjectSearchRejection::ManagedDiscoveryContentPhase,
        ObjectSearchRejection::ManagedDiscoveryContinuationChanged,
        ObjectSearchRejection::ManagedDiscoveryFingerprintPhase,
        ObjectSearchRejection::ManagedDiscoveryFingerprintSelection,
        ObjectSearchRejection::ManagedDiscoveryIncomplete,
        ObjectSearchRejection::ManagedDiscoveryMetadataPhase,
        ObjectSearchRejection::ManagedDiscoveryNeedAbsent,
        ObjectSearchRejection::ManagedDiscoveryOwnerAbsent,
        ObjectSearchRejection::ManagedDiscoveryPossessionAbsent,
        ObjectSearchRejection::ManagedDiscoverySearchPhase,
        ObjectSearchRejection::ManagedDiscoveryStopped,
        ObjectSearchRejection::ManagedDiscoveryStorageSize,
        ObjectSearchRejection::ManagedKeySelector,
        ObjectSearchRejection::NativeObservationStorageSize,
        ObjectSearchRejection::NativeSearchBatchAllocation,
        ObjectSearchRejection::NativeSearchOwnerAbsent,
        ObjectSearchRejection::NativeSearchPossessionAbsent,
        ObjectSearchRejection::NativeSearchResourceNeedAbsent,
        ObjectSearchRejection::NativeSearchStillPending,
        ObjectSearchRejection::NativeSearchStorageAccounting,
        ObjectSearchRejection::NativeSearchStorageSize,
        ObjectSearchRejection::NativeSearchStreamOwnerAbsent,
        ObjectSearchRejection::ObjectSearchCountOverflow,
        ObjectSearchRejection::ObjectSearchLimitExceeded,
        ObjectSearchRejection::SearchAccessOwner,
        ObjectSearchRejection::SearchBatchAllocation,
        ObjectSearchRejection::SearchCapacityOverflow,
        ObjectSearchRejection::SearchCardinalityWidth,
        ObjectSearchRejection::SearchCleanupOwnerAbsent,
        ObjectSearchRejection::SearchContinuationChanged,
        ObjectSearchRejection::SearchDispatchPhase,
        ObjectSearchRejection::SearchIdentityAllocation,
        ObjectSearchRejection::SearchIdentityStorageAccounting,
        ObjectSearchRejection::SearchIncomplete,
        ObjectSearchRejection::SearchOutcomeUncertain,
        ObjectSearchRejection::SearchPreparationAbsent,
        ObjectSearchRejection::SearchPreparationAlreadyConsumed,
        ObjectSearchRejection::SearchPreparationKindMismatch,
        ObjectSearchRejection::SearchPreparationUnexpectedlyInvalidated,
        ObjectSearchRejection::SearchPreparationWithoutByteOwner,
        ObjectSearchRejection::SearchPublicationChanged,
        ObjectSearchRejection::SearchPublicationIncomplete,
        ObjectSearchRejection::SearchPublicationIndexAbsent,
        ObjectSearchRejection::SearchPublicationNotPrepared,
        ObjectSearchRejection::SearchResultAllocation,
        ObjectSearchRejection::SearchResultKindMismatch,
        ObjectSearchRejection::SearchResultStorageAccounting,
        ObjectSearchRejection::SearchStorageSize,
        ObjectSearchRejection::SearchStreamAlreadyInitialized,
        ObjectSearchRejection::SearchStreamBatchAlreadyOwned,
        ObjectSearchRejection::SearchStreamBatchUnavailable,
        ObjectSearchRejection::SearchStreamIndexOutsideBatch,
        ObjectSearchRejection::SearchStreamPublicationAbsent,
        ObjectSearchRejection::SearchStreamPublicationChanged,
        ObjectSearchRejection::SearchStreamPublicationIndexAbsent,
        ObjectSearchRejection::SearchStreamStillPending,
        ObjectSearchRejection::SearchStreamStorageAccounting,
        ObjectSearchRejection::SearchTemplateOrCapacityChanged,
        ObjectSearchRejection::SelectedAdmissionStorageSize,
        ObjectSearchRejection::SelectedSearchResultAbsent,
        ObjectSearchRejection::UnknownObjectClassRequiresAnExtensionContract,
        ObjectSearchRejection::UnselectedManagedContent,
    ];
    for value in cases {
        let category: RejectionReason = value.into();
        assert!(matches!(category, RejectionReason::ObjectSearch(actual) if actual == value));
        let error = Error::Rejected(category);
        assert_eq!(error.clone(), error);
        assert!(
            matches!(&error, Error::Rejected(RejectionReason::ObjectSearch(actual)) if *actual == value)
        );
        assert!(!value.to_string().is_empty());
        assert!(!category.to_string().is_empty());
        assert!(!error.to_string().is_empty());
        assert!(!format!("{value:?}").is_empty());
    }
}
