// SPDX-License-Identifier: Apache-2.0
//! ObjectSearch causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to object search.
#[doc = include_str!("../../../docs/diagnostics/rejection-object_search.md")]
pub enum ObjectSearchRejection {
    /// Discovery content publication incomplete. [Detection, owner and recovery](#cause-DiscoveryContentPublicationIncomplete).
    DiscoveryContentPublicationIncomplete,
    /// Discovery publication incomplete. [Detection, owner and recovery](#cause-DiscoveryPublicationIncomplete).
    DiscoveryPublicationIncomplete,
    /// Discovery quota already transferred. [Detection, owner and recovery](#cause-DiscoveryQuotaAlreadyTransferred).
    DiscoveryQuotaAlreadyTransferred,
    /// Discovery quota transferred. [Detection, owner and recovery](#cause-DiscoveryQuotaTransferred).
    DiscoveryQuotaTransferred,
    /// Empty search batch requires finalization. [Detection, owner and recovery](#cause-EmptySearchBatchRequiresFinalization).
    EmptySearchBatchRequiresFinalization,
    /// Integer attribute width. [Detection, owner and recovery](#cause-IntegerAttributeWidth).
    IntegerAttributeWidth,
    /// Invalid search result handle. [Detection, owner and recovery](#cause-InvalidSearchResultHandle).
    InvalidSearchResultHandle,
    /// Inventory byte quota. [Detection, owner and recovery](#cause-InventoryByteQuota).
    InventoryByteQuota,
    /// Inventory candidate kind. [Detection, owner and recovery](#cause-InventoryCandidateKind).
    InventoryCandidateKind,
    /// Inventory continuation changed. [Detection, owner and recovery](#cause-InventoryContinuationChanged).
    InventoryContinuationChanged,
    /// Inventory incomplete. [Detection, owner and recovery](#cause-InventoryIncomplete).
    InventoryIncomplete,
    /// Inventory metadata allocation. [Detection, owner and recovery](#cause-InventoryMetadataAllocation).
    InventoryMetadataAllocation,
    /// Inventory metadata phase. [Detection, owner and recovery](#cause-InventoryMetadataPhase).
    InventoryMetadataPhase,
    /// Inventory metadata size. [Detection, owner and recovery](#cause-InventoryMetadataSize).
    InventoryMetadataSize,
    /// Inventory owner absent. [Detection, owner and recovery](#cause-InventoryOwnerAbsent).
    InventoryOwnerAbsent,
    /// Inventory phase. [Detection, owner and recovery](#cause-InventoryPhase).
    InventoryPhase,
    /// Inventory possession absent. [Detection, owner and recovery](#cause-InventoryPossessionAbsent).
    InventoryPossessionAbsent,
    /// Inventory read need. [Detection, owner and recovery](#cause-InventoryReadNeed).
    InventoryReadNeed,
    /// Inventory read phase. [Detection, owner and recovery](#cause-InventoryReadPhase).
    InventoryReadPhase,
    /// Inventory resource need absent. [Detection, owner and recovery](#cause-InventoryResourceNeedAbsent).
    InventoryResourceNeedAbsent,
    /// Inventory rows capacity. [Detection, owner and recovery](#cause-InventoryRowsCapacity).
    InventoryRowsCapacity,
    /// Inventory rows need. [Detection, owner and recovery](#cause-InventoryRowsNeed).
    InventoryRowsNeed,
    /// Inventory sort allocation. [Detection, owner and recovery](#cause-InventorySortAllocation).
    InventorySortAllocation,
    /// Inventory storage size. [Detection, owner and recovery](#cause-InventoryStorageSize).
    InventoryStorageSize,
    /// Inventory value need. [Detection, owner and recovery](#cause-InventoryValueNeed).
    InventoryValueNeed,
    /// Managed class unsupported. [Detection, owner and recovery](#cause-ManagedClassUnsupported).
    ManagedClassUnsupported,
    /// Managed discovery candidate kind. [Detection, owner and recovery](#cause-ManagedDiscoveryCandidateKind).
    ManagedDiscoveryCandidateKind,
    /// Managed discovery completion phase. [Detection, owner and recovery](#cause-ManagedDiscoveryCompletionPhase).
    ManagedDiscoveryCompletionPhase,
    /// Managed discovery content phase. [Detection, owner and recovery](#cause-ManagedDiscoveryContentPhase).
    ManagedDiscoveryContentPhase,
    /// Managed discovery continuation changed. [Detection, owner and recovery](#cause-ManagedDiscoveryContinuationChanged).
    ManagedDiscoveryContinuationChanged,
    /// Managed discovery fingerprint phase. [Detection, owner and recovery](#cause-ManagedDiscoveryFingerprintPhase).
    ManagedDiscoveryFingerprintPhase,
    /// Managed discovery fingerprint selection. [Detection, owner and recovery](#cause-ManagedDiscoveryFingerprintSelection).
    ManagedDiscoveryFingerprintSelection,
    /// Managed discovery incomplete. [Detection, owner and recovery](#cause-ManagedDiscoveryIncomplete).
    ManagedDiscoveryIncomplete,
    /// Managed discovery metadata phase. [Detection, owner and recovery](#cause-ManagedDiscoveryMetadataPhase).
    ManagedDiscoveryMetadataPhase,
    /// Managed discovery need absent. [Detection, owner and recovery](#cause-ManagedDiscoveryNeedAbsent).
    ManagedDiscoveryNeedAbsent,
    /// Managed discovery owner absent. [Detection, owner and recovery](#cause-ManagedDiscoveryOwnerAbsent).
    ManagedDiscoveryOwnerAbsent,
    /// Managed discovery possession absent. [Detection, owner and recovery](#cause-ManagedDiscoveryPossessionAbsent).
    ManagedDiscoveryPossessionAbsent,
    /// Managed discovery search phase. [Detection, owner and recovery](#cause-ManagedDiscoverySearchPhase).
    ManagedDiscoverySearchPhase,
    /// Managed discovery stopped. [Detection, owner and recovery](#cause-ManagedDiscoveryStopped).
    ManagedDiscoveryStopped,
    /// Managed discovery storage size. [Detection, owner and recovery](#cause-ManagedDiscoveryStorageSize).
    ManagedDiscoveryStorageSize,
    /// Managed key selector. [Detection, owner and recovery](#cause-ManagedKeySelector).
    ManagedKeySelector,
    /// Native observation storage size. [Detection, owner and recovery](#cause-NativeObservationStorageSize).
    NativeObservationStorageSize,
    /// Native search batch allocation. [Detection, owner and recovery](#cause-NativeSearchBatchAllocation).
    NativeSearchBatchAllocation,
    /// Native search owner absent. [Detection, owner and recovery](#cause-NativeSearchOwnerAbsent).
    NativeSearchOwnerAbsent,
    /// Native search possession absent. [Detection, owner and recovery](#cause-NativeSearchPossessionAbsent).
    NativeSearchPossessionAbsent,
    /// Native search resource need absent. [Detection, owner and recovery](#cause-NativeSearchResourceNeedAbsent).
    NativeSearchResourceNeedAbsent,
    /// Native search still pending. [Detection, owner and recovery](#cause-NativeSearchStillPending).
    NativeSearchStillPending,
    /// Native search storage accounting. [Detection, owner and recovery](#cause-NativeSearchStorageAccounting).
    NativeSearchStorageAccounting,
    /// Native search storage size. [Detection, owner and recovery](#cause-NativeSearchStorageSize).
    NativeSearchStorageSize,
    /// Native search stream owner absent. [Detection, owner and recovery](#cause-NativeSearchStreamOwnerAbsent).
    NativeSearchStreamOwnerAbsent,
    /// Object search count overflow. [Detection, owner and recovery](#cause-ObjectSearchCountOverflow).
    ObjectSearchCountOverflow,
    /// Object search limit exceeded. [Detection, owner and recovery](#cause-ObjectSearchLimitExceeded).
    ObjectSearchLimitExceeded,
    /// Search access owner. [Detection, owner and recovery](#cause-SearchAccessOwner).
    SearchAccessOwner,
    /// Search batch allocation. [Detection, owner and recovery](#cause-SearchBatchAllocation).
    SearchBatchAllocation,
    /// Search capacity overflow. [Detection, owner and recovery](#cause-SearchCapacityOverflow).
    SearchCapacityOverflow,
    /// Search cardinality width. [Detection, owner and recovery](#cause-SearchCardinalityWidth).
    SearchCardinalityWidth,
    /// Search cleanup owner absent. [Detection, owner and recovery](#cause-SearchCleanupOwnerAbsent).
    SearchCleanupOwnerAbsent,
    /// Search continuation changed. [Detection, owner and recovery](#cause-SearchContinuationChanged).
    SearchContinuationChanged,
    /// Search dispatch phase. [Detection, owner and recovery](#cause-SearchDispatchPhase).
    SearchDispatchPhase,
    /// Search identity allocation. [Detection, owner and recovery](#cause-SearchIdentityAllocation).
    SearchIdentityAllocation,
    /// Search identity storage accounting. [Detection, owner and recovery](#cause-SearchIdentityStorageAccounting).
    SearchIdentityStorageAccounting,
    /// Search incomplete. [Detection, owner and recovery](#cause-SearchIncomplete).
    SearchIncomplete,
    /// Search outcome uncertain. [Detection, owner and recovery](#cause-SearchOutcomeUncertain).
    SearchOutcomeUncertain,
    /// Search preparation absent. [Detection, owner and recovery](#cause-SearchPreparationAbsent).
    SearchPreparationAbsent,
    /// Search preparation already consumed. [Detection, owner and recovery](#cause-SearchPreparationAlreadyConsumed).
    SearchPreparationAlreadyConsumed,
    /// Search preparation kind mismatch. [Detection, owner and recovery](#cause-SearchPreparationKindMismatch).
    SearchPreparationKindMismatch,
    /// Search preparation unexpectedly invalidated. [Detection, owner and recovery](#cause-SearchPreparationUnexpectedlyInvalidated).
    SearchPreparationUnexpectedlyInvalidated,
    /// Search preparation without byte owner. [Detection, owner and recovery](#cause-SearchPreparationWithoutByteOwner).
    SearchPreparationWithoutByteOwner,
    /// Search publication changed. [Detection, owner and recovery](#cause-SearchPublicationChanged).
    SearchPublicationChanged,
    /// Search publication incomplete. [Detection, owner and recovery](#cause-SearchPublicationIncomplete).
    SearchPublicationIncomplete,
    /// Search publication index absent. [Detection, owner and recovery](#cause-SearchPublicationIndexAbsent).
    SearchPublicationIndexAbsent,
    /// Search publication not prepared. [Detection, owner and recovery](#cause-SearchPublicationNotPrepared).
    SearchPublicationNotPrepared,
    /// Search result allocation. [Detection, owner and recovery](#cause-SearchResultAllocation).
    SearchResultAllocation,
    /// Search result kind mismatch. [Detection, owner and recovery](#cause-SearchResultKindMismatch).
    SearchResultKindMismatch,
    /// Search result storage accounting. [Detection, owner and recovery](#cause-SearchResultStorageAccounting).
    SearchResultStorageAccounting,
    /// Search storage size. [Detection, owner and recovery](#cause-SearchStorageSize).
    SearchStorageSize,
    /// Search stream already initialized. [Detection, owner and recovery](#cause-SearchStreamAlreadyInitialized).
    SearchStreamAlreadyInitialized,
    /// Search stream batch already owned. [Detection, owner and recovery](#cause-SearchStreamBatchAlreadyOwned).
    SearchStreamBatchAlreadyOwned,
    /// Search stream batch unavailable. [Detection, owner and recovery](#cause-SearchStreamBatchUnavailable).
    SearchStreamBatchUnavailable,
    /// Search stream index outside batch. [Detection, owner and recovery](#cause-SearchStreamIndexOutsideBatch).
    SearchStreamIndexOutsideBatch,
    /// Search stream publication absent. [Detection, owner and recovery](#cause-SearchStreamPublicationAbsent).
    SearchStreamPublicationAbsent,
    /// Search stream publication changed. [Detection, owner and recovery](#cause-SearchStreamPublicationChanged).
    SearchStreamPublicationChanged,
    /// Search stream publication index absent. [Detection, owner and recovery](#cause-SearchStreamPublicationIndexAbsent).
    SearchStreamPublicationIndexAbsent,
    /// Search stream still pending. [Detection, owner and recovery](#cause-SearchStreamStillPending).
    SearchStreamStillPending,
    /// Search stream storage accounting. [Detection, owner and recovery](#cause-SearchStreamStorageAccounting).
    SearchStreamStorageAccounting,
    /// Search template or capacity changed. [Detection, owner and recovery](#cause-SearchTemplateOrCapacityChanged).
    SearchTemplateOrCapacityChanged,
    /// Selected admission storage size. [Detection, owner and recovery](#cause-SelectedAdmissionStorageSize).
    SelectedAdmissionStorageSize,
    /// Selected search result absent. [Detection, owner and recovery](#cause-SelectedSearchResultAbsent).
    SelectedSearchResultAbsent,
    /// Unknown object class requires an extension contract. [Detection, owner and recovery](#cause-UnknownObjectClassRequiresAnExtensionContract).
    UnknownObjectClassRequiresAnExtensionContract,
    /// Unselected managed content. [Detection, owner and recovery](#cause-UnselectedManagedContent).
    UnselectedManagedContent,
}

impl std::fmt::Display for ObjectSearchRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DiscoveryContentPublicationIncomplete => {
                f.write_str("discovery content publication incomplete")
            }
            Self::DiscoveryPublicationIncomplete => f.write_str("discovery publication incomplete"),
            Self::DiscoveryQuotaAlreadyTransferred => {
                f.write_str("discovery quota already transferred")
            }
            Self::DiscoveryQuotaTransferred => f.write_str("discovery quota transferred"),
            Self::EmptySearchBatchRequiresFinalization => {
                f.write_str("empty search batch requires finalization")
            }
            Self::IntegerAttributeWidth => f.write_str("integer attribute width"),
            Self::InvalidSearchResultHandle => f.write_str("invalid search result handle"),
            Self::InventoryByteQuota => f.write_str("inventory byte quota"),
            Self::InventoryCandidateKind => f.write_str("inventory candidate kind"),
            Self::InventoryContinuationChanged => f.write_str("inventory continuation changed"),
            Self::InventoryIncomplete => f.write_str("inventory incomplete"),
            Self::InventoryMetadataAllocation => f.write_str("inventory metadata allocation"),
            Self::InventoryMetadataPhase => f.write_str("inventory metadata phase"),
            Self::InventoryMetadataSize => f.write_str("inventory metadata size"),
            Self::InventoryOwnerAbsent => f.write_str("inventory owner absent"),
            Self::InventoryPhase => f.write_str("inventory phase"),
            Self::InventoryPossessionAbsent => f.write_str("inventory possession absent"),
            Self::InventoryReadNeed => f.write_str("inventory read need"),
            Self::InventoryReadPhase => f.write_str("inventory read phase"),
            Self::InventoryResourceNeedAbsent => f.write_str("inventory resource need absent"),
            Self::InventoryRowsCapacity => f.write_str("inventory rows capacity"),
            Self::InventoryRowsNeed => f.write_str("inventory rows need"),
            Self::InventorySortAllocation => f.write_str("inventory sort allocation"),
            Self::InventoryStorageSize => f.write_str("inventory storage size"),
            Self::InventoryValueNeed => f.write_str("inventory value need"),
            Self::ManagedClassUnsupported => f.write_str("managed class unsupported"),
            Self::ManagedDiscoveryCandidateKind => f.write_str("managed discovery candidate kind"),
            Self::ManagedDiscoveryCompletionPhase => {
                f.write_str("managed discovery completion phase")
            }
            Self::ManagedDiscoveryContentPhase => f.write_str("managed discovery content phase"),
            Self::ManagedDiscoveryContinuationChanged => {
                f.write_str("managed discovery continuation changed")
            }
            Self::ManagedDiscoveryFingerprintPhase => {
                f.write_str("managed discovery fingerprint phase")
            }
            Self::ManagedDiscoveryFingerprintSelection => {
                f.write_str("managed discovery fingerprint selection")
            }
            Self::ManagedDiscoveryIncomplete => f.write_str("managed discovery incomplete"),
            Self::ManagedDiscoveryMetadataPhase => f.write_str("managed discovery metadata phase"),
            Self::ManagedDiscoveryNeedAbsent => f.write_str("managed discovery need absent"),
            Self::ManagedDiscoveryOwnerAbsent => f.write_str("managed discovery owner absent"),
            Self::ManagedDiscoveryPossessionAbsent => {
                f.write_str("managed discovery possession absent")
            }
            Self::ManagedDiscoverySearchPhase => f.write_str("managed discovery search phase"),
            Self::ManagedDiscoveryStopped => f.write_str("managed discovery stopped"),
            Self::ManagedDiscoveryStorageSize => f.write_str("managed discovery storage size"),
            Self::ManagedKeySelector => f.write_str("managed key selector"),
            Self::NativeObservationStorageSize => f.write_str("native observation storage size"),
            Self::NativeSearchBatchAllocation => f.write_str("native search batch allocation"),
            Self::NativeSearchOwnerAbsent => f.write_str("native search owner absent"),
            Self::NativeSearchPossessionAbsent => f.write_str("native search possession absent"),
            Self::NativeSearchResourceNeedAbsent => {
                f.write_str("native search resource need absent")
            }
            Self::NativeSearchStillPending => f.write_str("native search still pending"),
            Self::NativeSearchStorageAccounting => f.write_str("native search storage accounting"),
            Self::NativeSearchStorageSize => f.write_str("native search storage size"),
            Self::NativeSearchStreamOwnerAbsent => f.write_str("native search stream owner absent"),
            Self::ObjectSearchCountOverflow => f.write_str("object search count overflow"),
            Self::ObjectSearchLimitExceeded => f.write_str("object search limit exceeded"),
            Self::SearchAccessOwner => f.write_str("search access owner"),
            Self::SearchBatchAllocation => f.write_str("search batch allocation"),
            Self::SearchCapacityOverflow => f.write_str("search capacity overflow"),
            Self::SearchCardinalityWidth => f.write_str("search cardinality width"),
            Self::SearchCleanupOwnerAbsent => f.write_str("search cleanup owner absent"),
            Self::SearchContinuationChanged => f.write_str("search continuation changed"),
            Self::SearchDispatchPhase => f.write_str("search dispatch phase"),
            Self::SearchIdentityAllocation => f.write_str("search identity allocation"),
            Self::SearchIdentityStorageAccounting => {
                f.write_str("search identity storage accounting")
            }
            Self::SearchIncomplete => f.write_str("search incomplete"),
            Self::SearchOutcomeUncertain => f.write_str("search outcome uncertain"),
            Self::SearchPreparationAbsent => f.write_str("search preparation absent"),
            Self::SearchPreparationAlreadyConsumed => {
                f.write_str("search preparation already consumed")
            }
            Self::SearchPreparationKindMismatch => f.write_str("search preparation kind mismatch"),
            Self::SearchPreparationUnexpectedlyInvalidated => {
                f.write_str("search preparation unexpectedly invalidated")
            }
            Self::SearchPreparationWithoutByteOwner => {
                f.write_str("search preparation without byte owner")
            }
            Self::SearchPublicationChanged => f.write_str("search publication changed"),
            Self::SearchPublicationIncomplete => f.write_str("search publication incomplete"),
            Self::SearchPublicationIndexAbsent => f.write_str("search publication index absent"),
            Self::SearchPublicationNotPrepared => f.write_str("search publication not prepared"),
            Self::SearchResultAllocation => f.write_str("search result allocation"),
            Self::SearchResultKindMismatch => f.write_str("search result kind mismatch"),
            Self::SearchResultStorageAccounting => f.write_str("search result storage accounting"),
            Self::SearchStorageSize => f.write_str("search storage size"),
            Self::SearchStreamAlreadyInitialized => {
                f.write_str("search stream already initialized")
            }
            Self::SearchStreamBatchAlreadyOwned => f.write_str("search stream batch already owned"),
            Self::SearchStreamBatchUnavailable => f.write_str("search stream batch unavailable"),
            Self::SearchStreamIndexOutsideBatch => f.write_str("search stream index outside batch"),
            Self::SearchStreamPublicationAbsent => f.write_str("search stream publication absent"),
            Self::SearchStreamPublicationChanged => {
                f.write_str("search stream publication changed")
            }
            Self::SearchStreamPublicationIndexAbsent => {
                f.write_str("search stream publication index absent")
            }
            Self::SearchStreamStillPending => f.write_str("search stream still pending"),
            Self::SearchStreamStorageAccounting => f.write_str("search stream storage accounting"),
            Self::SearchTemplateOrCapacityChanged => {
                f.write_str("search template or capacity changed")
            }
            Self::SelectedAdmissionStorageSize => f.write_str("selected admission storage size"),
            Self::SelectedSearchResultAbsent => f.write_str("selected search result absent"),
            Self::UnknownObjectClassRequiresAnExtensionContract => {
                f.write_str("unknown object class requires an extension contract")
            }
            Self::UnselectedManagedContent => f.write_str("unselected managed content"),
        }
    }
}
