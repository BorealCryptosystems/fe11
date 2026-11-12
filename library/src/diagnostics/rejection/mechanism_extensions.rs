// SPDX-License-Identifier: Apache-2.0
//! MechanismExtensions causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to mechanism extensions.
#[doc = include_str!("../../../docs/diagnostics/rejection-mechanism_extensions.md")]
pub enum MechanismExtensionsRejection {
    /// NULL extension parameter cannot own unreachable blocks. [Detection, owner and recovery](#cause-NullExtensionParameterCannotOwnUnreachableBlocks).
    NullExtensionParameterCannotOwnUnreachableBlocks,
    /// Ratchet mechanism/function mismatch. [Detection, owner and recovery](#cause-RatchetMechanismFunctionMismatch).
    RatchetMechanismFunctionMismatch,
    /// Changed graph cannot be captured. [Detection, owner and recovery](#cause-ChangedGraphCannotBeCaptured).
    ChangedGraphCannotBeCaptured,
    /// Changed message initialization. [Detection, owner and recovery](#cause-ChangedMessageInitialization).
    ChangedMessageInitialization,
    /// Changed parameter graph cannot be rebound. [Detection, owner and recovery](#cause-ChangedParameterGraphCannotBeRebound).
    ChangedParameterGraphCannotBeRebound,
    /// Changed retained extension graph. [Detection, owner and recovery](#cause-ChangedRetainedExtensionGraph).
    ChangedRetainedExtensionGraph,
    /// Digest extension has no contextual key authentication. [Detection, owner and recovery](#cause-DigestExtensionHasNoContextualKeyAuthentication).
    DigestExtensionHasNoContextualKeyAuthentication,
    /// Digest extension has no key. [Detection, owner and recovery](#cause-DigestExtensionHasNoKey).
    DigestExtensionHasNoKey,
    /// Extension aligned allocation. [Detection, owner and recovery](#cause-ExtensionAlignedAllocation).
    ExtensionAlignedAllocation,
    /// Extension allocation layout. [Detection, owner and recovery](#cause-ExtensionAllocationLayout).
    ExtensionAllocationLayout,
    /// Extension block alignment. [Detection, owner and recovery](#cause-ExtensionBlockAlignment).
    ExtensionBlockAlignment,
    /// Extension call allocation accounting. [Detection, owner and recovery](#cause-ExtensionCallAllocationAccounting).
    ExtensionCallAllocationAccounting,
    /// Extension diagnostic route changed. [Detection, owner and recovery](#cause-ExtensionDiagnosticRouteChanged).
    ExtensionDiagnosticRouteChanged,
    /// Extension graph metadata allocation. [Detection, owner and recovery](#cause-ExtensionGraphMetadataAllocation).
    ExtensionGraphMetadataAllocation,
    /// Extension graph range or overlap. [Detection, owner and recovery](#cause-ExtensionGraphRangeOrOverlap).
    ExtensionGraphRangeOrOverlap,
    /// Extension initialization input mutation. [Detection, owner and recovery](#cause-ExtensionInitializationInputMutation).
    ExtensionInitializationInputMutation,
    /// Extension input length overflow. [Detection, owner and recovery](#cause-ExtensionInputLengthOverflow).
    ExtensionInputLengthOverflow,
    /// Extension input mutation during authentication. [Detection, owner and recovery](#cause-ExtensionInputMutationDuringAuthentication).
    ExtensionInputMutationDuringAuthentication,
    /// Extension input route changed. [Detection, owner and recovery](#cause-ExtensionInputRouteChanged).
    ExtensionInputRouteChanged,
    /// Extension mechanism ABI width. [Detection, owner and recovery](#cause-ExtensionMechanismAbiWidth).
    ExtensionMechanismAbiWidth,
    /// Extension native input mutation. [Detection, owner and recovery](#cause-ExtensionNativeInputMutation).
    ExtensionNativeInputMutation,
    /// Extension output exceeds capacity. [Detection, owner and recovery](#cause-ExtensionOutputExceedsCapacity).
    ExtensionOutputExceedsCapacity,
    /// Extension pointer placeholder must be zero. [Detection, owner and recovery](#cause-ExtensionPointerPlaceholderMustBeZero).
    ExtensionPointerPlaceholderMustBeZero,
    /// Extension update input mutation. [Detection, owner and recovery](#cause-ExtensionUpdateInputMutation).
    ExtensionUpdateInputMutation,
    /// Graph snapshot ABI or version. [Detection, owner and recovery](#cause-GraphSnapshotAbiOrVersion).
    GraphSnapshotAbiOrVersion,
    /// Graph validation index allocation. [Detection, owner and recovery](#cause-GraphValidationIndexAllocation).
    GraphValidationIndexAllocation,
    /// Graph validation index capacity. [Detection, owner and recovery](#cause-GraphValidationIndexCapacity).
    GraphValidationIndexCapacity,
    /// Key transport native input or output capacity violation. [Detection, owner and recovery](#cause-KeyTransportNativeInputOrOutputCapacityViolation).
    KeyTransportNativeInputOrOutputCapacityViolation,
    /// Key transport returned auxiliary source handle. [Detection, owner and recovery](#cause-KeyTransportReturnedAuxiliarySourceHandle).
    KeyTransportReturnedAuxiliarySourceHandle,
    /// Key transport returned source handle. [Detection, owner and recovery](#cause-KeyTransportReturnedSourceHandle).
    KeyTransportReturnedSourceHandle,
    /// Key transport storage accounting. [Detection, owner and recovery](#cause-KeyTransportStorageAccounting).
    KeyTransportStorageAccounting,
    /// Mechanism extension module/function mismatch. [Detection, owner and recovery](#cause-MechanismExtensionModuleFunctionMismatch).
    MechanismExtensionModuleFunctionMismatch,
    /// Native aligned output accounting. [Detection, owner and recovery](#cause-NativeAlignedOutputAccounting).
    NativeAlignedOutputAccounting,
    /// Native output alignment. [Detection, owner and recovery](#cause-NativeOutputAlignment).
    NativeOutputAlignment,
    /// Native output alignment unavailable. [Detection, owner and recovery](#cause-NativeOutputAlignmentUnavailable).
    NativeOutputAlignmentUnavailable,
    /// Nested mechanism graph accounting. [Detection, owner and recovery](#cause-NestedMechanismGraphAccounting).
    NestedMechanismGraphAccounting,
    /// Nested mechanism parent has no root. [Detection, owner and recovery](#cause-NestedMechanismParentHasNoRoot).
    NestedMechanismParentHasNoRoot,
    /// Single message facade result shape. [Detection, owner and recovery](#cause-SingleMessageFacadeResultShape).
    SingleMessageFacadeResultShape,
    /// Transport input accounting. [Detection, owner and recovery](#cause-TransportInputAccounting).
    TransportInputAccounting,
    /// Typed parameter key binding. [Detection, owner and recovery](#cause-TypedParameterKeyBinding).
    TypedParameterKeyBinding,
    /// Typed signature publication route. [Detection, owner and recovery](#cause-TypedSignaturePublicationRoute).
    TypedSignaturePublicationRoute,
    /// Wrap aggregate storage accounting. [Detection, owner and recovery](#cause-WrapAggregateStorageAccounting).
    WrapAggregateStorageAccounting,
    /// Wrap frame storage accounting. [Detection, owner and recovery](#cause-WrapFrameStorageAccounting).
    WrapFrameStorageAccounting,
    /// Wrap native input changed. [Detection, owner and recovery](#cause-WrapNativeInputChanged).
    WrapNativeInputChanged,
    /// Wrap revocation storage accounting. [Detection, owner and recovery](#cause-WrapRevocationStorageAccounting).
    WrapRevocationStorageAccounting,
    /// Wrap storage accounting. [Detection, owner and recovery](#cause-WrapStorageAccounting).
    WrapStorageAccounting,
}

impl std::fmt::Display for MechanismExtensionsRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NullExtensionParameterCannotOwnUnreachableBlocks => {
                f.write_str("NULL extension parameter cannot own unreachable blocks")
            }
            Self::RatchetMechanismFunctionMismatch => {
                f.write_str("Ratchet mechanism/function mismatch")
            }
            Self::ChangedGraphCannotBeCaptured => f.write_str("changed graph cannot be captured"),
            Self::ChangedMessageInitialization => f.write_str("changed message initialization"),
            Self::ChangedParameterGraphCannotBeRebound => {
                f.write_str("changed parameter graph cannot be rebound")
            }
            Self::ChangedRetainedExtensionGraph => f.write_str("changed retained extension graph"),
            Self::DigestExtensionHasNoContextualKeyAuthentication => {
                f.write_str("digest extension has no contextual key authentication")
            }
            Self::DigestExtensionHasNoKey => f.write_str("digest extension has no key"),
            Self::ExtensionAlignedAllocation => f.write_str("extension aligned allocation"),
            Self::ExtensionAllocationLayout => f.write_str("extension allocation layout"),
            Self::ExtensionBlockAlignment => f.write_str("extension block alignment"),
            Self::ExtensionCallAllocationAccounting => {
                f.write_str("extension call allocation accounting")
            }
            Self::ExtensionDiagnosticRouteChanged => {
                f.write_str("extension diagnostic route changed")
            }
            Self::ExtensionGraphMetadataAllocation => {
                f.write_str("extension graph metadata allocation")
            }
            Self::ExtensionGraphRangeOrOverlap => f.write_str("extension graph range or overlap"),
            Self::ExtensionInitializationInputMutation => {
                f.write_str("extension initialization input mutation")
            }
            Self::ExtensionInputLengthOverflow => f.write_str("extension input length overflow"),
            Self::ExtensionInputMutationDuringAuthentication => {
                f.write_str("extension input mutation during authentication")
            }
            Self::ExtensionInputRouteChanged => f.write_str("extension input route changed"),
            Self::ExtensionMechanismAbiWidth => f.write_str("extension mechanism ABI width"),
            Self::ExtensionNativeInputMutation => f.write_str("extension native input mutation"),
            Self::ExtensionOutputExceedsCapacity => {
                f.write_str("extension output exceeds capacity")
            }
            Self::ExtensionPointerPlaceholderMustBeZero => {
                f.write_str("extension pointer placeholder must be zero")
            }
            Self::ExtensionUpdateInputMutation => f.write_str("extension update input mutation"),
            Self::GraphSnapshotAbiOrVersion => f.write_str("graph snapshot ABI or version"),
            Self::GraphValidationIndexAllocation => {
                f.write_str("graph validation index allocation")
            }
            Self::GraphValidationIndexCapacity => f.write_str("graph validation index capacity"),
            Self::KeyTransportNativeInputOrOutputCapacityViolation => {
                f.write_str("key transport native input or output capacity violation")
            }
            Self::KeyTransportReturnedAuxiliarySourceHandle => {
                f.write_str("key transport returned auxiliary source handle")
            }
            Self::KeyTransportReturnedSourceHandle => {
                f.write_str("key transport returned source handle")
            }
            Self::KeyTransportStorageAccounting => f.write_str("key transport storage accounting"),
            Self::MechanismExtensionModuleFunctionMismatch => {
                f.write_str("mechanism extension module/function mismatch")
            }
            Self::NativeAlignedOutputAccounting => f.write_str("native aligned output accounting"),
            Self::NativeOutputAlignment => f.write_str("native output alignment"),
            Self::NativeOutputAlignmentUnavailable => {
                f.write_str("native output alignment unavailable")
            }
            Self::NestedMechanismGraphAccounting => {
                f.write_str("nested mechanism graph accounting")
            }
            Self::NestedMechanismParentHasNoRoot => {
                f.write_str("nested mechanism parent has no root")
            }
            Self::SingleMessageFacadeResultShape => {
                f.write_str("single message facade result shape")
            }
            Self::TransportInputAccounting => f.write_str("transport input accounting"),
            Self::TypedParameterKeyBinding => f.write_str("typed parameter key binding"),
            Self::TypedSignaturePublicationRoute => {
                f.write_str("typed signature publication route")
            }
            Self::WrapAggregateStorageAccounting => {
                f.write_str("wrap aggregate storage accounting")
            }
            Self::WrapFrameStorageAccounting => f.write_str("wrap frame storage accounting"),
            Self::WrapNativeInputChanged => f.write_str("wrap native input changed"),
            Self::WrapRevocationStorageAccounting => {
                f.write_str("wrap revocation storage accounting")
            }
            Self::WrapStorageAccounting => f.write_str("wrap storage accounting"),
        }
    }
}
