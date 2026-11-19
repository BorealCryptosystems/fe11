// SPDX-License-Identifier: Apache-2.0
//! Public ModuleLifecycleRejection values retain identity through category conversion.
use fe11::{Error, ModuleLifecycleRejection, RejectionReason};

#[test]
fn variants_preserve_category_and_payload() {
    let cases = [
        ModuleLifecycleRejection::CCloseAllSessionsUnavailable,
        ModuleLifecycleRejection::CGetInfoUnavailable,
        ModuleLifecycleRejection::CGetMechanismInfoUnavailable,
        ModuleLifecycleRejection::CGetMechanismListUnavailable,
        ModuleLifecycleRejection::CGetSlotInfoUnavailable,
        ModuleLifecycleRejection::CGetSlotListUnavailable,
        ModuleLifecycleRejection::CLoginUnavailable,
        ModuleLifecycleRejection::CLogoutUnavailable,
        ModuleLifecycleRejection::AbsoluteModulePathRequired,
        ModuleLifecycleRejection::AsynchronousSessionCapability,
        ModuleLifecycleRejection::CollectiveCloseDiagnosticAbsent,
        ModuleLifecycleRejection::DiscoveryAllocation,
        ModuleLifecycleRejection::DiscoveryAllocationRepresentation,
        ModuleLifecycleRejection::DiscoveryAttemptBudgetExhausted,
        ModuleLifecycleRejection::DiscoveryFailureAllocation,
        ModuleLifecycleRejection::DiscoveryItemBudgetAfterSizing,
        ModuleLifecycleRejection::DiscoveryLengthConversion,
        ModuleLifecycleRejection::DiscoverySnapshotAllocation,
        ModuleLifecycleRejection::DuplicateSlot,
        ModuleLifecycleRejection::ExternalInitializationIdentityMismatch,
        ModuleLifecycleRejection::ForeignDrainingSession,
        ModuleLifecycleRejection::InitializationArgumentGraphChanged,
        ModuleLifecycleRejection::InvalidOrDuplicateProviderSession,
        ModuleLifecycleRejection::LoginRoleIdentifierConversion,
        ModuleLifecycleRejection::LogoutDiagnosticAbsent,
        ModuleLifecycleRejection::MechanismIdentifierConversion,
        ModuleLifecycleRejection::ModuleClosed,
        ModuleLifecycleRejection::ModuleIsNotRegularFile,
        ModuleLifecycleRejection::ModuleMetadata,
        ModuleLifecycleRejection::NativeAuthenticationInputChanged,
        ModuleLifecycleRejection::NativeIdentifierAllocation,
        ModuleLifecycleRejection::NativeStateUncertain,
        ModuleLifecycleRejection::ProcessObservationOwnerAbsent,
        ModuleLifecycleRejection::RecoveryOwnerMismatch,
        ModuleLifecycleRejection::RecoverySnapshotAllocation,
        ModuleLifecycleRejection::RecoveryTokenIdentityChanged,
        ModuleLifecycleRejection::ReplacementSlotMismatch,
        ModuleLifecycleRejection::RuntimeClientIdentityExhausted,
        ModuleLifecycleRejection::RuntimeOwnerRequired,
        ModuleLifecycleRejection::SelectedSlotAllocation,
        ModuleLifecycleRejection::SelectedSlotBudget,
        ModuleLifecycleRejection::SessionCloseEpochExhausted,
        ModuleLifecycleRejection::SessionCloseResultAbsent,
        ModuleLifecycleRejection::SessionOpeningStorageAccounting,
        ModuleLifecycleRejection::SlotCloseCount,
        ModuleLifecycleRejection::SlotIdentifierConversion,
        ModuleLifecycleRejection::StandardLoginRoleRequiresDedicatedVariant,
        ModuleLifecycleRejection::TokenAdmissionOwnerMismatch,
        ModuleLifecycleRejection::TokenContextRetired,
        ModuleLifecycleRejection::TokenContextStale,
        ModuleLifecycleRejection::TokenRegistryRevisionExhausted,
        ModuleLifecycleRejection::TokenRetirementAllocation,
        ModuleLifecycleRejection::TokenSelectorNotUnique,
        ModuleLifecycleRejection::UnavailableDiscoveryCount,
    ];
    for value in cases {
        let category: RejectionReason = value.into();
        assert!(matches!(category, RejectionReason::ModuleLifecycle(actual) if actual == value));
        let error = Error::Rejected(category);
        assert_eq!(error.clone(), error);
        assert!(
            matches!(&error, Error::Rejected(RejectionReason::ModuleLifecycle(actual)) if *actual == value)
        );
        assert!(!value.to_string().is_empty());
        assert!(!category.to_string().is_empty());
        assert!(!error.to_string().is_empty());
        assert!(!format!("{value:?}").is_empty());
    }
}
