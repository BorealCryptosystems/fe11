// SPDX-License-Identifier: Apache-2.0
//! SessionLifecycle causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to session lifecycle.
#[doc = include_str!("../../../docs/diagnostics/rejection-session_lifecycle.md")]
pub enum SessionLifecycleRejection {
    /// C_AsyncComplete unavailable. [Detection, owner and recovery](#cause-CAsyncCompleteUnavailable).
    CAsyncCompleteUnavailable,
    /// C_FindObjects unavailable. [Detection, owner and recovery](#cause-CFindObjectsUnavailable).
    CFindObjectsUnavailable,
    /// C_FindObjectsFinal unavailable. [Detection, owner and recovery](#cause-CFindObjectsFinalUnavailable).
    CFindObjectsFinalUnavailable,
    /// C_FindObjectsInit unavailable. [Detection, owner and recovery](#cause-CFindObjectsInitUnavailable).
    CFindObjectsInitUnavailable,
    /// C_GetSessionValidationFlags unavailable. [Detection, owner and recovery](#cause-CGetSessionValidationFlagsUnavailable).
    CGetSessionValidationFlagsUnavailable,
    /// C_Sign unavailable. [Detection, owner and recovery](#cause-CSignUnavailable).
    CSignUnavailable,
    /// C_SignInit unavailable. [Detection, owner and recovery](#cause-CSignInitUnavailable).
    CSignInitUnavailable,
    /// C_Verify unavailable. [Detection, owner and recovery](#cause-CVerifyUnavailable).
    CVerifyUnavailable,
    /// C_VerifyInit unavailable. [Detection, owner and recovery](#cause-CVerifyInitUnavailable).
    CVerifyInitUnavailable,
    /// Digest32 requires SHA256. [Detection, owner and recovery](#cause-Digest32RequiresSha256).
    Digest32RequiresSha256,
    /// PQC export owner kind. [Detection, owner and recovery](#cause-PqcExportOwnerKind).
    PqcExportOwnerKind,
    /// PSS input changed. [Detection, owner and recovery](#cause-PssInputChanged).
    PssInputChanged,
    /// PSS input changed during context authentication. [Detection, owner and recovery](#cause-PssInputChangedDuringContextAuthentication).
    PssInputChangedDuringContextAuthentication,
    /// PSS input descriptor changed. [Detection, owner and recovery](#cause-PssInputDescriptorChanged).
    PssInputDescriptorChanged,
    /// PSS storage accounting. [Detection, owner and recovery](#cause-PssStorageAccounting).
    PssStorageAccounting,
    /// PSS verification input changed. [Detection, owner and recovery](#cause-PssVerificationInputChanged).
    PssVerificationInputChanged,
    /// RSA objects owner kind. [Detection, owner and recovery](#cause-RsaObjectsOwnerKind).
    RsaObjectsOwnerKind,
    /// RSA signature allocation. [Detection, owner and recovery](#cause-RsaSignatureAllocation).
    RsaSignatureAllocation,
    /// RSA signature capacity. [Detection, owner and recovery](#cause-RsaSignatureCapacity).
    RsaSignatureCapacity,
    /// RSA signature length. [Detection, owner and recovery](#cause-RsaSignatureLength).
    RsaSignatureLength,
    /// SHA256 digest length. [Detection, owner and recovery](#cause-Sha256DigestLength).
    Sha256DigestLength,
    /// Asynchronous session requires owned dispatch. [Detection, owner and recovery](#cause-AsynchronousSessionRequiresOwnedDispatch).
    AsynchronousSessionRequiresOwnedDispatch,
    /// Attribute observation absent. [Detection, owner and recovery](#cause-AttributeObservationAbsent).
    AttributeObservationAbsent,
    /// Attribute observation retired. [Detection, owner and recovery](#cause-AttributeObservationRetired).
    AttributeObservationRetired,
    /// Attribute owner kind. [Detection, owner and recovery](#cause-AttributeOwnerKind).
    AttributeOwnerKind,
    /// Context authentication preparation mismatch. [Detection, owner and recovery](#cause-ContextAuthenticationPreparationMismatch).
    ContextAuthenticationPreparationMismatch,
    /// Context authentication requires token writer. [Detection, owner and recovery](#cause-ContextAuthenticationRequiresTokenWriter).
    ContextAuthenticationRequiresTokenWriter,
    /// Context authentication storage accounting. [Detection, owner and recovery](#cause-ContextAuthenticationStorageAccounting).
    ContextAuthenticationStorageAccounting,
    /// Context login already performed. [Detection, owner and recovery](#cause-ContextLoginAlreadyPerformed).
    ContextLoginAlreadyPerformed,
    /// Control frame accounting. [Detection, owner and recovery](#cause-ControlFrameAccounting).
    ControlFrameAccounting,
    /// Creation owner kind. [Detection, owner and recovery](#cause-CreationOwnerKind).
    CreationOwnerKind,
    /// Creation protection in cryptographic continuation. [Detection, owner and recovery](#cause-CreationProtectionInCryptographicContinuation).
    CreationProtectionInCryptographicContinuation,
    /// Derivation owner kind. [Detection, owner and recovery](#cause-DerivationOwnerKind).
    DerivationOwnerKind,
    /// Foreign contextual authentication session. [Detection, owner and recovery](#cause-ForeignContextualAuthenticationSession).
    ForeignContextualAuthenticationSession,
    /// Foreign inventory protection. [Detection, owner and recovery](#cause-ForeignInventoryProtection).
    ForeignInventoryProtection,
    /// Foreign mutation possession. [Detection, owner and recovery](#cause-ForeignMutationPossession).
    ForeignMutationPossession,
    /// Foreign mutation protection. [Detection, owner and recovery](#cause-ForeignMutationProtection).
    ForeignMutationProtection,
    /// Foreign observation credit. [Detection, owner and recovery](#cause-ForeignObservationCredit).
    ForeignObservationCredit,
    /// Foreign observation selection. [Detection, owner and recovery](#cause-ForeignObservationSelection).
    ForeignObservationSelection,
    /// Foreign reference observation budget. [Detection, owner and recovery](#cause-ForeignReferenceObservationBudget).
    ForeignReferenceObservationBudget,
    /// Inventory owner kind. [Detection, owner and recovery](#cause-InventoryOwnerKind).
    InventoryOwnerKind,
    /// Legacy parallel function unavailable. [Detection, owner and recovery](#cause-LegacyParallelFunctionUnavailable).
    LegacyParallelFunctionUnavailable,
    /// Lifecycle diagnostic already consumed. [Detection, owner and recovery](#cause-LifecycleDiagnosticAlreadyConsumed).
    LifecycleDiagnosticAlreadyConsumed,
    /// Lifecycle secondary diagnostic already consumed. [Detection, owner and recovery](#cause-LifecycleSecondaryDiagnosticAlreadyConsumed).
    LifecycleSecondaryDiagnosticAlreadyConsumed,
    /// Managed copy owner kind. [Detection, owner and recovery](#cause-ManagedCopyOwnerKind).
    ManagedCopyOwnerKind,
    /// Managed destruction owner kind. [Detection, owner and recovery](#cause-ManagedDestructionOwnerKind).
    ManagedDestructionOwnerKind,
    /// Managed discovery owner kind. [Detection, owner and recovery](#cause-ManagedDiscoveryOwnerKind).
    ManagedDiscoveryOwnerKind,
    /// Managed label owner kind. [Detection, owner and recovery](#cause-ManagedLabelOwnerKind).
    ManagedLabelOwnerKind,
    /// Managed set_attributes owner kind. [Detection, owner and recovery](#cause-ManagedSetAttributesOwnerKind).
    ManagedSetAttributesOwnerKind,
    /// Module accepted a competing object search. [Detection, owner and recovery](#cause-ModuleAcceptedACompetingObjectSearch).
    ModuleAcceptedACompetingObjectSearch,
    /// Mutation protection absent. [Detection, owner and recovery](#cause-MutationProtectionAbsent).
    MutationProtectionAbsent,
    /// Native outputs owner kind. [Detection, owner and recovery](#cause-NativeOutputsOwnerKind).
    NativeOutputsOwnerKind,
    /// Native search owner kind. [Detection, owner and recovery](#cause-NativeSearchOwnerKind).
    NativeSearchOwnerKind,
    /// Native search ownership changed. [Detection, owner and recovery](#cause-NativeSearchOwnershipChanged).
    NativeSearchOwnershipChanged,
    /// Native search stream owner kind. [Detection, owner and recovery](#cause-NativeSearchStreamOwnerKind).
    NativeSearchStreamOwnerKind,
    /// Native session handle retired. [Detection, owner and recovery](#cause-NativeSessionHandleRetired).
    NativeSessionHandleRetired,
    /// Object activity owners allocation. [Detection, owner and recovery](#cause-ObjectActivityOwnersAllocation).
    ObjectActivityOwnersAllocation,
    /// Object activity storage accounting. [Detection, owner and recovery](#cause-ObjectActivityStorageAccounting).
    ObjectActivityStorageAccounting,
    /// Object activity storage shape changed. [Detection, owner and recovery](#cause-ObjectActivityStorageShapeChanged).
    ObjectActivityStorageShapeChanged,
    /// Object permission storage accounting. [Detection, owner and recovery](#cause-ObjectPermissionStorageAccounting).
    ObjectPermissionStorageAccounting,
    /// Object permission storage allocation. [Detection, owner and recovery](#cause-ObjectPermissionStorageAllocation).
    ObjectPermissionStorageAllocation,
    /// Object permission storage shape. [Detection, owner and recovery](#cause-ObjectPermissionStorageShape).
    ObjectPermissionStorageShape,
    /// Object protections already retained. [Detection, owner and recovery](#cause-ObjectProtectionsAlreadyRetained).
    ObjectProtectionsAlreadyRetained,
    /// Object resource roles already retained. [Detection, owner and recovery](#cause-ObjectResourceRolesAlreadyRetained).
    ObjectResourceRolesAlreadyRetained,
    /// Observation preparation absent. [Detection, owner and recovery](#cause-ObservationPreparationAbsent).
    ObservationPreparationAbsent,
    /// Observation selection absent. [Detection, owner and recovery](#cause-ObservationSelectionAbsent).
    ObservationSelectionAbsent,
    /// Operation destinations already retained. [Detection, owner and recovery](#cause-OperationDestinationsAlreadyRetained).
    OperationDestinationsAlreadyRetained,
    /// Operation lease requires ordinary admission. [Detection, owner and recovery](#cause-OperationLeaseRequiresOrdinaryAdmission).
    OperationLeaseRequiresOrdinaryAdmission,
    /// Policy observation owner kind. [Detection, owner and recovery](#cause-PolicyObservationOwnerKind).
    PolicyObservationOwnerKind,
    /// Public fingerprint owner kind. [Detection, owner and recovery](#cause-PublicFingerprintOwnerKind).
    PublicFingerprintOwnerKind,
    /// Reference admission absent. [Detection, owner and recovery](#cause-ReferenceAdmissionAbsent).
    ReferenceAdmissionAbsent,
    /// Reference owner kind. [Detection, owner and recovery](#cause-ReferenceOwnerKind).
    ReferenceOwnerKind,
    /// Reference reservation absent. [Detection, owner and recovery](#cause-ReferenceReservationAbsent).
    ReferenceReservationAbsent,
    /// Retained role protections absent. [Detection, owner and recovery](#cause-RetainedRoleProtectionsAbsent).
    RetainedRoleProtectionsAbsent,
    /// Retained source absent. [Detection, owner and recovery](#cause-RetainedSourceAbsent).
    RetainedSourceAbsent,
    /// Retained source already attached. [Detection, owner and recovery](#cause-RetainedSourceAlreadyAttached).
    RetainedSourceAlreadyAttached,
    /// Search retirement owner kind. [Detection, owner and recovery](#cause-SearchRetirementOwnerKind).
    SearchRetirementOwnerKind,
    /// Sequence context unavailable. [Detection, owner and recovery](#cause-SequenceContextUnavailable).
    SequenceContextUnavailable,
    /// Sequence outcome uncertain. [Detection, owner and recovery](#cause-SequenceOutcomeUncertain).
    SequenceOutcomeUncertain,
    /// Session close already attempted. [Detection, owner and recovery](#cause-SessionCloseAlreadyAttempted).
    SessionCloseAlreadyAttempted,
    /// Session closed. [Detection, owner and recovery](#cause-SessionClosed).
    SessionClosed,
    /// Session closing or close failed. [Detection, owner and recovery](#cause-SessionClosingOrCloseFailed).
    SessionClosingOrCloseFailed,
    /// Session generation mismatch. [Detection, owner and recovery](#cause-SessionGenerationMismatch).
    SessionGenerationMismatch,
    /// Session lifecycle diagnostic absent. [Detection, owner and recovery](#cause-SessionLifecycleDiagnosticAbsent).
    SessionLifecycleDiagnosticAbsent,
    /// Session lifecycle storage accounting. [Detection, owner and recovery](#cause-SessionLifecycleStorageAccounting).
    SessionLifecycleStorageAccounting,
    /// Session state uncertain. [Detection, owner and recovery](#cause-SessionStateUncertain).
    SessionStateUncertain,
    /// Signature writer capability absent. [Detection, owner and recovery](#cause-SignatureWriterCapabilityAbsent).
    SignatureWriterCapabilityAbsent,
    /// Signature writer not installed. [Detection, owner and recovery](#cause-SignatureWriterNotInstalled).
    SignatureWriterNotInstalled,
    /// Signing selection owner kind. [Detection, owner and recovery](#cause-SigningSelectionOwnerKind).
    SigningSelectionOwnerKind,
    /// Source-free roles already retained. [Detection, owner and recovery](#cause-SourceFreeRolesAlreadyRetained).
    SourceFreeRolesAlreadyRetained,
    /// Synchronous admission requires a synchronous session. [Detection, owner and recovery](#cause-SynchronousAdmissionRequiresASynchronousSession).
    SynchronousAdmissionRequiresASynchronousSession,
    /// Unplanned protection in cryptographic continuation. [Detection, owner and recovery](#cause-UnplannedProtectionInCryptographicContinuation).
    UnplannedProtectionInCryptographicContinuation,
    /// Validation flags type conversion. [Detection, owner and recovery](#cause-ValidationFlagsTypeConversion).
    ValidationFlagsTypeConversion,
}

impl std::fmt::Display for SessionLifecycleRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CAsyncCompleteUnavailable => f.write_str("C_AsyncComplete unavailable"),
            Self::CFindObjectsUnavailable => f.write_str("C_FindObjects unavailable"),
            Self::CFindObjectsFinalUnavailable => f.write_str("C_FindObjectsFinal unavailable"),
            Self::CFindObjectsInitUnavailable => f.write_str("C_FindObjectsInit unavailable"),
            Self::CGetSessionValidationFlagsUnavailable => {
                f.write_str("C_GetSessionValidationFlags unavailable")
            }
            Self::CSignUnavailable => f.write_str("C_Sign unavailable"),
            Self::CSignInitUnavailable => f.write_str("C_SignInit unavailable"),
            Self::CVerifyUnavailable => f.write_str("C_Verify unavailable"),
            Self::CVerifyInitUnavailable => f.write_str("C_VerifyInit unavailable"),
            Self::Digest32RequiresSha256 => f.write_str("Digest32 requires SHA256"),
            Self::PqcExportOwnerKind => f.write_str("PQC export owner kind"),
            Self::PssInputChanged => f.write_str("PSS input changed"),
            Self::PssInputChangedDuringContextAuthentication => {
                f.write_str("PSS input changed during context authentication")
            }
            Self::PssInputDescriptorChanged => f.write_str("PSS input descriptor changed"),
            Self::PssStorageAccounting => f.write_str("PSS storage accounting"),
            Self::PssVerificationInputChanged => f.write_str("PSS verification input changed"),
            Self::RsaObjectsOwnerKind => f.write_str("RSA objects owner kind"),
            Self::RsaSignatureAllocation => f.write_str("RSA signature allocation"),
            Self::RsaSignatureCapacity => f.write_str("RSA signature capacity"),
            Self::RsaSignatureLength => f.write_str("RSA signature length"),
            Self::Sha256DigestLength => f.write_str("SHA256 digest length"),
            Self::AsynchronousSessionRequiresOwnedDispatch => {
                f.write_str("asynchronous session requires owned dispatch")
            }
            Self::AttributeObservationAbsent => f.write_str("attribute observation absent"),
            Self::AttributeObservationRetired => f.write_str("attribute observation retired"),
            Self::AttributeOwnerKind => f.write_str("attribute owner kind"),
            Self::ContextAuthenticationPreparationMismatch => {
                f.write_str("context authentication preparation mismatch")
            }
            Self::ContextAuthenticationRequiresTokenWriter => {
                f.write_str("context authentication requires token writer")
            }
            Self::ContextAuthenticationStorageAccounting => {
                f.write_str("context authentication storage accounting")
            }
            Self::ContextLoginAlreadyPerformed => f.write_str("context login already performed"),
            Self::ControlFrameAccounting => f.write_str("control frame accounting"),
            Self::CreationOwnerKind => f.write_str("creation owner kind"),
            Self::CreationProtectionInCryptographicContinuation => {
                f.write_str("creation protection in cryptographic continuation")
            }
            Self::DerivationOwnerKind => f.write_str("derivation owner kind"),
            Self::ForeignContextualAuthenticationSession => {
                f.write_str("foreign contextual authentication session")
            }
            Self::ForeignInventoryProtection => f.write_str("foreign inventory protection"),
            Self::ForeignMutationPossession => f.write_str("foreign mutation possession"),
            Self::ForeignMutationProtection => f.write_str("foreign mutation protection"),
            Self::ForeignObservationCredit => f.write_str("foreign observation credit"),
            Self::ForeignObservationSelection => f.write_str("foreign observation selection"),
            Self::ForeignReferenceObservationBudget => {
                f.write_str("foreign reference observation budget")
            }
            Self::InventoryOwnerKind => f.write_str("inventory owner kind"),
            Self::LegacyParallelFunctionUnavailable => {
                f.write_str("legacy parallel function unavailable")
            }
            Self::LifecycleDiagnosticAlreadyConsumed => {
                f.write_str("lifecycle diagnostic already consumed")
            }
            Self::LifecycleSecondaryDiagnosticAlreadyConsumed => {
                f.write_str("lifecycle secondary diagnostic already consumed")
            }
            Self::ManagedCopyOwnerKind => f.write_str("managed copy owner kind"),
            Self::ManagedDestructionOwnerKind => f.write_str("managed destruction owner kind"),
            Self::ManagedDiscoveryOwnerKind => f.write_str("managed discovery owner kind"),
            Self::ManagedLabelOwnerKind => f.write_str("managed label owner kind"),
            Self::ManagedSetAttributesOwnerKind => f.write_str("managed set_attributes owner kind"),
            Self::ModuleAcceptedACompetingObjectSearch => {
                f.write_str("module accepted a competing object search")
            }
            Self::MutationProtectionAbsent => f.write_str("mutation protection absent"),
            Self::NativeOutputsOwnerKind => f.write_str("native outputs owner kind"),
            Self::NativeSearchOwnerKind => f.write_str("native search owner kind"),
            Self::NativeSearchOwnershipChanged => f.write_str("native search ownership changed"),
            Self::NativeSearchStreamOwnerKind => f.write_str("native search stream owner kind"),
            Self::NativeSessionHandleRetired => f.write_str("native session handle retired"),
            Self::ObjectActivityOwnersAllocation => {
                f.write_str("object activity owners allocation")
            }
            Self::ObjectActivityStorageAccounting => {
                f.write_str("object activity storage accounting")
            }
            Self::ObjectActivityStorageShapeChanged => {
                f.write_str("object activity storage shape changed")
            }
            Self::ObjectPermissionStorageAccounting => {
                f.write_str("object permission storage accounting")
            }
            Self::ObjectPermissionStorageAllocation => {
                f.write_str("object permission storage allocation")
            }
            Self::ObjectPermissionStorageShape => f.write_str("object permission storage shape"),
            Self::ObjectProtectionsAlreadyRetained => {
                f.write_str("object protections already retained")
            }
            Self::ObjectResourceRolesAlreadyRetained => {
                f.write_str("object resource roles already retained")
            }
            Self::ObservationPreparationAbsent => f.write_str("observation preparation absent"),
            Self::ObservationSelectionAbsent => f.write_str("observation selection absent"),
            Self::OperationDestinationsAlreadyRetained => {
                f.write_str("operation destinations already retained")
            }
            Self::OperationLeaseRequiresOrdinaryAdmission => {
                f.write_str("operation lease requires ordinary admission")
            }
            Self::PolicyObservationOwnerKind => f.write_str("policy observation owner kind"),
            Self::PublicFingerprintOwnerKind => f.write_str("public fingerprint owner kind"),
            Self::ReferenceAdmissionAbsent => f.write_str("reference admission absent"),
            Self::ReferenceOwnerKind => f.write_str("reference owner kind"),
            Self::ReferenceReservationAbsent => f.write_str("reference reservation absent"),
            Self::RetainedRoleProtectionsAbsent => f.write_str("retained role protections absent"),
            Self::RetainedSourceAbsent => f.write_str("retained source absent"),
            Self::RetainedSourceAlreadyAttached => f.write_str("retained source already attached"),
            Self::SearchRetirementOwnerKind => f.write_str("search retirement owner kind"),
            Self::SequenceContextUnavailable => f.write_str("sequence context unavailable"),
            Self::SequenceOutcomeUncertain => f.write_str("sequence outcome uncertain"),
            Self::SessionCloseAlreadyAttempted => f.write_str("session close already attempted"),
            Self::SessionClosed => f.write_str("session closed"),
            Self::SessionClosingOrCloseFailed => f.write_str("session closing or close failed"),
            Self::SessionGenerationMismatch => f.write_str("session generation mismatch"),
            Self::SessionLifecycleDiagnosticAbsent => {
                f.write_str("session lifecycle diagnostic absent")
            }
            Self::SessionLifecycleStorageAccounting => {
                f.write_str("session lifecycle storage accounting")
            }
            Self::SessionStateUncertain => f.write_str("session state uncertain"),
            Self::SignatureWriterCapabilityAbsent => {
                f.write_str("signature writer capability absent")
            }
            Self::SignatureWriterNotInstalled => f.write_str("signature writer not installed"),
            Self::SigningSelectionOwnerKind => f.write_str("signing selection owner kind"),
            Self::SourceFreeRolesAlreadyRetained => {
                f.write_str("source-free roles already retained")
            }
            Self::SynchronousAdmissionRequiresASynchronousSession => {
                f.write_str("synchronous admission requires a synchronous session")
            }
            Self::UnplannedProtectionInCryptographicContinuation => {
                f.write_str("unplanned protection in cryptographic continuation")
            }
            Self::ValidationFlagsTypeConversion => f.write_str("validation flags type conversion"),
        }
    }
}
