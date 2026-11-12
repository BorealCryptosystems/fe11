// SPDX-License-Identifier: Apache-2.0
//! ModuleLifecycle causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to module lifecycle.
#[doc = include_str!("../../../docs/diagnostics/rejection-module_lifecycle.md")]
pub enum ModuleLifecycleRejection {
    /// C_CloseAllSessions unavailable. [Detection, owner and recovery](#cause-CCloseAllSessionsUnavailable).
    CCloseAllSessionsUnavailable,
    /// C_GetInfo unavailable. [Detection, owner and recovery](#cause-CGetInfoUnavailable).
    CGetInfoUnavailable,
    /// C_GetMechanismInfo unavailable. [Detection, owner and recovery](#cause-CGetMechanismInfoUnavailable).
    CGetMechanismInfoUnavailable,
    /// C_GetMechanismList unavailable. [Detection, owner and recovery](#cause-CGetMechanismListUnavailable).
    CGetMechanismListUnavailable,
    /// C_GetSlotInfo unavailable. [Detection, owner and recovery](#cause-CGetSlotInfoUnavailable).
    CGetSlotInfoUnavailable,
    /// C_GetSlotList unavailable. [Detection, owner and recovery](#cause-CGetSlotListUnavailable).
    CGetSlotListUnavailable,
    /// C_Login unavailable. [Detection, owner and recovery](#cause-CLoginUnavailable).
    CLoginUnavailable,
    /// C_Logout unavailable. [Detection, owner and recovery](#cause-CLogoutUnavailable).
    CLogoutUnavailable,
    /// Absolute module path required. [Detection, owner and recovery](#cause-AbsoluteModulePathRequired).
    AbsoluteModulePathRequired,
    /// Asynchronous session capability. [Detection, owner and recovery](#cause-AsynchronousSessionCapability).
    AsynchronousSessionCapability,
    /// Collective close diagnostic absent. [Detection, owner and recovery](#cause-CollectiveCloseDiagnosticAbsent).
    CollectiveCloseDiagnosticAbsent,
    /// Discovery allocation. [Detection, owner and recovery](#cause-DiscoveryAllocation).
    DiscoveryAllocation,
    /// Discovery allocation representation. [Detection, owner and recovery](#cause-DiscoveryAllocationRepresentation).
    DiscoveryAllocationRepresentation,
    /// Discovery attempt budget exhausted. [Detection, owner and recovery](#cause-DiscoveryAttemptBudgetExhausted).
    DiscoveryAttemptBudgetExhausted,
    /// Discovery failure allocation. [Detection, owner and recovery](#cause-DiscoveryFailureAllocation).
    DiscoveryFailureAllocation,
    /// Discovery item budget after sizing. [Detection, owner and recovery](#cause-DiscoveryItemBudgetAfterSizing).
    DiscoveryItemBudgetAfterSizing,
    /// Discovery length conversion. [Detection, owner and recovery](#cause-DiscoveryLengthConversion).
    DiscoveryLengthConversion,
    /// Discovery snapshot allocation. [Detection, owner and recovery](#cause-DiscoverySnapshotAllocation).
    DiscoverySnapshotAllocation,
    /// Duplicate slot. [Detection, owner and recovery](#cause-DuplicateSlot).
    DuplicateSlot,
    /// External initialization identity mismatch. [Detection, owner and recovery](#cause-ExternalInitializationIdentityMismatch).
    ExternalInitializationIdentityMismatch,
    /// Foreign draining session. [Detection, owner and recovery](#cause-ForeignDrainingSession).
    ForeignDrainingSession,
    /// Initialization argument graph changed. [Detection, owner and recovery](#cause-InitializationArgumentGraphChanged).
    InitializationArgumentGraphChanged,
    /// Invalid or duplicate provider session. [Detection, owner and recovery](#cause-InvalidOrDuplicateProviderSession).
    InvalidOrDuplicateProviderSession,
    /// Login role identifier conversion. [Detection, owner and recovery](#cause-LoginRoleIdentifierConversion).
    LoginRoleIdentifierConversion,
    /// Logout diagnostic absent. [Detection, owner and recovery](#cause-LogoutDiagnosticAbsent).
    LogoutDiagnosticAbsent,
    /// Mechanism identifier conversion. [Detection, owner and recovery](#cause-MechanismIdentifierConversion).
    MechanismIdentifierConversion,
    /// Module closed. [Detection, owner and recovery](#cause-ModuleClosed).
    ModuleClosed,
    /// Module is not regular file. [Detection, owner and recovery](#cause-ModuleIsNotRegularFile).
    ModuleIsNotRegularFile,
    /// Module metadata. [Detection, owner and recovery](#cause-ModuleMetadata).
    ModuleMetadata,
    /// Native authentication input changed. [Detection, owner and recovery](#cause-NativeAuthenticationInputChanged).
    NativeAuthenticationInputChanged,
    /// Native identifier allocation. [Detection, owner and recovery](#cause-NativeIdentifierAllocation).
    NativeIdentifierAllocation,
    /// Native state uncertain. [Detection, owner and recovery](#cause-NativeStateUncertain).
    NativeStateUncertain,
    /// Process observation owner absent. [Detection, owner and recovery](#cause-ProcessObservationOwnerAbsent).
    ProcessObservationOwnerAbsent,
    /// Recovery owner mismatch. [Detection, owner and recovery](#cause-RecoveryOwnerMismatch).
    RecoveryOwnerMismatch,
    /// Recovery snapshot allocation. [Detection, owner and recovery](#cause-RecoverySnapshotAllocation).
    RecoverySnapshotAllocation,
    /// Recovery token identity changed. [Detection, owner and recovery](#cause-RecoveryTokenIdentityChanged).
    RecoveryTokenIdentityChanged,
    /// Replacement slot mismatch. [Detection, owner and recovery](#cause-ReplacementSlotMismatch).
    ReplacementSlotMismatch,
    /// Runtime client identity exhausted. [Detection, owner and recovery](#cause-RuntimeClientIdentityExhausted).
    RuntimeClientIdentityExhausted,
    /// Runtime owner required. [Detection, owner and recovery](#cause-RuntimeOwnerRequired).
    RuntimeOwnerRequired,
    /// Selected slot allocation. [Detection, owner and recovery](#cause-SelectedSlotAllocation).
    SelectedSlotAllocation,
    /// Selected slot budget. [Detection, owner and recovery](#cause-SelectedSlotBudget).
    SelectedSlotBudget,
    /// Session close epoch exhausted. [Detection, owner and recovery](#cause-SessionCloseEpochExhausted).
    SessionCloseEpochExhausted,
    /// Session close result absent. [Detection, owner and recovery](#cause-SessionCloseResultAbsent).
    SessionCloseResultAbsent,
    /// Session opening storage accounting. [Detection, owner and recovery](#cause-SessionOpeningStorageAccounting).
    SessionOpeningStorageAccounting,
    /// Slot close count. [Detection, owner and recovery](#cause-SlotCloseCount).
    SlotCloseCount,
    /// Slot identifier conversion. [Detection, owner and recovery](#cause-SlotIdentifierConversion).
    SlotIdentifierConversion,
    /// Standard login role requires dedicated variant. [Detection, owner and recovery](#cause-StandardLoginRoleRequiresDedicatedVariant).
    StandardLoginRoleRequiresDedicatedVariant,
    /// Token admission owner mismatch. [Detection, owner and recovery](#cause-TokenAdmissionOwnerMismatch).
    TokenAdmissionOwnerMismatch,
    /// Token context retired. [Detection, owner and recovery](#cause-TokenContextRetired).
    TokenContextRetired,
    /// Token context stale. [Detection, owner and recovery](#cause-TokenContextStale).
    TokenContextStale,
    /// Token registry revision exhausted. [Detection, owner and recovery](#cause-TokenRegistryRevisionExhausted).
    TokenRegistryRevisionExhausted,
    /// Token retirement allocation. [Detection, owner and recovery](#cause-TokenRetirementAllocation).
    TokenRetirementAllocation,
    /// Token selector not unique. [Detection, owner and recovery](#cause-TokenSelectorNotUnique).
    TokenSelectorNotUnique,
    /// Unavailable discovery count. [Detection, owner and recovery](#cause-UnavailableDiscoveryCount).
    UnavailableDiscoveryCount,
}

impl std::fmt::Display for ModuleLifecycleRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CCloseAllSessionsUnavailable => f.write_str("C_CloseAllSessions unavailable"),
            Self::CGetInfoUnavailable => f.write_str("C_GetInfo unavailable"),
            Self::CGetMechanismInfoUnavailable => f.write_str("C_GetMechanismInfo unavailable"),
            Self::CGetMechanismListUnavailable => f.write_str("C_GetMechanismList unavailable"),
            Self::CGetSlotInfoUnavailable => f.write_str("C_GetSlotInfo unavailable"),
            Self::CGetSlotListUnavailable => f.write_str("C_GetSlotList unavailable"),
            Self::CLoginUnavailable => f.write_str("C_Login unavailable"),
            Self::CLogoutUnavailable => f.write_str("C_Logout unavailable"),
            Self::AbsoluteModulePathRequired => f.write_str("absolute module path required"),
            Self::AsynchronousSessionCapability => f.write_str("asynchronous session capability"),
            Self::CollectiveCloseDiagnosticAbsent => {
                f.write_str("collective close diagnostic absent")
            }
            Self::DiscoveryAllocation => f.write_str("discovery allocation"),
            Self::DiscoveryAllocationRepresentation => {
                f.write_str("discovery allocation representation")
            }
            Self::DiscoveryAttemptBudgetExhausted => {
                f.write_str("discovery attempt budget exhausted")
            }
            Self::DiscoveryFailureAllocation => f.write_str("discovery failure allocation"),
            Self::DiscoveryItemBudgetAfterSizing => {
                f.write_str("discovery item budget after sizing")
            }
            Self::DiscoveryLengthConversion => f.write_str("discovery length conversion"),
            Self::DiscoverySnapshotAllocation => f.write_str("discovery snapshot allocation"),
            Self::DuplicateSlot => f.write_str("duplicate slot"),
            Self::ExternalInitializationIdentityMismatch => {
                f.write_str("external initialization identity mismatch")
            }
            Self::ForeignDrainingSession => f.write_str("foreign draining session"),
            Self::InitializationArgumentGraphChanged => {
                f.write_str("initialization argument graph changed")
            }
            Self::InvalidOrDuplicateProviderSession => {
                f.write_str("invalid or duplicate provider session")
            }
            Self::LoginRoleIdentifierConversion => f.write_str("login role identifier conversion"),
            Self::LogoutDiagnosticAbsent => f.write_str("logout diagnostic absent"),
            Self::MechanismIdentifierConversion => f.write_str("mechanism identifier conversion"),
            Self::ModuleClosed => f.write_str("module closed"),
            Self::ModuleIsNotRegularFile => f.write_str("module is not regular file"),
            Self::ModuleMetadata => f.write_str("module metadata"),
            Self::NativeAuthenticationInputChanged => {
                f.write_str("native authentication input changed")
            }
            Self::NativeIdentifierAllocation => f.write_str("native identifier allocation"),
            Self::NativeStateUncertain => f.write_str("native state uncertain"),
            Self::ProcessObservationOwnerAbsent => f.write_str("process observation owner absent"),
            Self::RecoveryOwnerMismatch => f.write_str("recovery owner mismatch"),
            Self::RecoverySnapshotAllocation => f.write_str("recovery snapshot allocation"),
            Self::RecoveryTokenIdentityChanged => f.write_str("recovery token identity changed"),
            Self::ReplacementSlotMismatch => f.write_str("replacement slot mismatch"),
            Self::RuntimeClientIdentityExhausted => {
                f.write_str("runtime client identity exhausted")
            }
            Self::RuntimeOwnerRequired => f.write_str("runtime owner required"),
            Self::SelectedSlotAllocation => f.write_str("selected slot allocation"),
            Self::SelectedSlotBudget => f.write_str("selected slot budget"),
            Self::SessionCloseEpochExhausted => f.write_str("session close epoch exhausted"),
            Self::SessionCloseResultAbsent => f.write_str("session close result absent"),
            Self::SessionOpeningStorageAccounting => {
                f.write_str("session opening storage accounting")
            }
            Self::SlotCloseCount => f.write_str("slot close count"),
            Self::SlotIdentifierConversion => f.write_str("slot identifier conversion"),
            Self::StandardLoginRoleRequiresDedicatedVariant => {
                f.write_str("standard login role requires dedicated variant")
            }
            Self::TokenAdmissionOwnerMismatch => f.write_str("token admission owner mismatch"),
            Self::TokenContextRetired => f.write_str("token context retired"),
            Self::TokenContextStale => f.write_str("token context stale"),
            Self::TokenRegistryRevisionExhausted => {
                f.write_str("token registry revision exhausted")
            }
            Self::TokenRetirementAllocation => f.write_str("token retirement allocation"),
            Self::TokenSelectorNotUnique => f.write_str("token selector not unique"),
            Self::UnavailableDiscoveryCount => f.write_str("unavailable discovery count"),
        }
    }
}
