// SPDX-License-Identifier: Apache-2.0
//! NativeExecution causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to native execution.
#[doc = include_str!("../../../docs/diagnostics/rejection-native_execution.md")]
pub enum NativeExecutionRejection {
    /// C_GenerateKey unavailable. [Detection, owner and recovery](#cause-CGenerateKeyUnavailable).
    CGenerateKeyUnavailable,
    /// C_GenerateKeyPair unavailable. [Detection, owner and recovery](#cause-CGenerateKeyPairUnavailable).
    CGenerateKeyPairUnavailable,
    /// DSA seed returned length. [Detection, owner and recovery](#cause-DsaSeedReturnedLength).
    DsaSeedReturnedLength,
    /// Blocking event without module possession. [Detection, owner and recovery](#cause-BlockingEventWithoutModulePossession).
    BlockingEventWithoutModulePossession,
    /// Different slot event source selected. [Detection, owner and recovery](#cause-DifferentSlotEventSourceSelected).
    DifferentSlotEventSourceSelected,
    /// File reservation allocation. [Detection, owner and recovery](#cause-FileReservationAllocation).
    FileReservationAllocation,
    /// File reservation count exhausted. [Detection, owner and recovery](#cause-FileReservationCountExhausted).
    FileReservationCountExhausted,
    /// Function table export. [Detection, owner and recovery](#cause-FunctionTableExport).
    FunctionTableExport,
    /// Generation extension output taken. [Detection, owner and recovery](#cause-GenerationExtensionOutputTaken).
    GenerationExtensionOutputTaken,
    /// Generation parameter accounting. [Detection, owner and recovery](#cause-GenerationParameterAccounting).
    GenerationParameterAccounting,
    /// Generation preparation changed. [Detection, owner and recovery](#cause-GenerationPreparationChanged).
    GenerationPreparationChanged,
    /// Generation scalar ABI width. [Detection, owner and recovery](#cause-GenerationScalarAbiWidth).
    GenerationScalarAbiWidth,
    /// Initialization outcome expected. [Detection, owner and recovery](#cause-InitializationOutcomeExpected).
    InitializationOutcomeExpected,
    /// Key generation input changed. [Detection, owner and recovery](#cause-KeyGenerationInputChanged).
    KeyGenerationInputChanged,
    /// Key-pair generation input changed. [Detection, owner and recovery](#cause-KeyPairGenerationInputChanged).
    KeyPairGenerationInputChanged,
    /// Module finalization abort state. [Detection, owner and recovery](#cause-ModuleFinalizationAbortState).
    ModuleFinalizationAbortState,
    /// Module finalization dispatch state. [Detection, owner and recovery](#cause-ModuleFinalizationDispatchState).
    ModuleFinalizationDispatchState,
    /// Module finalization return state. [Detection, owner and recovery](#cause-ModuleFinalizationReturnState).
    ModuleFinalizationReturnState,
    /// Module finalization state. [Detection, owner and recovery](#cause-ModuleFinalizationState).
    ModuleFinalizationState,
    /// Module identity reservation absent. [Detection, owner and recovery](#cause-ModuleIdentityReservationAbsent).
    ModuleIdentityReservationAbsent,
    /// Native admission already bound. [Detection, owner and recovery](#cause-NativeAdmissionAlreadyBound).
    NativeAdmissionAlreadyBound,
    /// Native admission lifecycle. [Detection, owner and recovery](#cause-NativeAdmissionLifecycle).
    NativeAdmissionLifecycle,
    /// Native call counters incomplete. [Detection, owner and recovery](#cause-NativeCallCountersIncomplete).
    NativeCallCountersIncomplete,
    /// Native data allocation. [Detection, owner and recovery](#cause-NativeDataAllocation).
    NativeDataAllocation,
    /// Native finalization success absent. [Detection, owner and recovery](#cause-NativeFinalizationSuccessAbsent).
    NativeFinalizationSuccessAbsent,
    /// Native frame allocation. [Detection, owner and recovery](#cause-NativeFrameAllocation).
    NativeFrameAllocation,
    /// Native frame completion unproven. [Detection, owner and recovery](#cause-NativeFrameCompletionUnproven).
    NativeFrameCompletionUnproven,
    /// Native initialization retired. [Detection, owner and recovery](#cause-NativeInitializationRetired).
    NativeInitializationRetired,
    /// Notification retirement owner occupied. [Detection, owner and recovery](#cause-NotificationRetirementOwnerOccupied).
    NotificationRetirementOwnerOccupied,
    /// Null function table. [Detection, owner and recovery](#cause-NullFunctionTable).
    NullFunctionTable,
    /// Object creation input changed. [Detection, owner and recovery](#cause-ObjectCreationInputChanged).
    ObjectCreationInputChanged,
    /// Predecessor file reservation absent. [Detection, owner and recovery](#cause-PredecessorFileReservationAbsent).
    PredecessorFileReservationAbsent,
    /// Process export allocation. [Detection, owner and recovery](#cause-ProcessExportAllocation).
    ProcessExportAllocation,
    /// Retired runtime has no Finalize authority. [Detection, owner and recovery](#cause-RetiredRuntimeHasNoFinalizeAuthority).
    RetiredRuntimeHasNoFinalizeAuthority,
    /// Runtime owner withdrawn. [Detection, owner and recovery](#cause-RuntimeOwnerWithdrawn).
    RuntimeOwnerWithdrawn,
    /// Runtime retirement not established. [Detection, owner and recovery](#cause-RuntimeRetirementNotEstablished).
    RuntimeRetirementNotEstablished,
    /// Runtime successor already published. [Detection, owner and recovery](#cause-RuntimeSuccessorAlreadyPublished).
    RuntimeSuccessorAlreadyPublished,
    /// Serialized callback depth. [Detection, owner and recovery](#cause-SerializedCallbackDepth).
    SerializedCallbackDepth,
    /// Serialized dispatch depth. [Detection, owner and recovery](#cause-SerializedDispatchDepth).
    SerializedDispatchDepth,
    /// Serialized module callback reentry. [Detection, owner and recovery](#cause-SerializedModuleCallbackReentry).
    SerializedModuleCallbackReentry,
    /// Slot event admission already bound. [Detection, owner and recovery](#cause-SlotEventAdmissionAlreadyBound).
    SlotEventAdmissionAlreadyBound,
    /// Slot event admission closed. [Detection, owner and recovery](#cause-SlotEventAdmissionClosed).
    SlotEventAdmissionClosed,
    /// Slot event completion unproven. [Detection, owner and recovery](#cause-SlotEventCompletionUnproven).
    SlotEventCompletionUnproven,
    /// Slot event native return unproven. [Detection, owner and recovery](#cause-SlotEventNativeReturnUnproven).
    SlotEventNativeReturnUnproven,
    /// Slot event owner state. [Detection, owner and recovery](#cause-SlotEventOwnerState).
    SlotEventOwnerState,
    /// Table observation expected. [Detection, owner and recovery](#cause-TableObservationExpected).
    TableObservationExpected,
    /// Unqualified interface version. [Detection, owner and recovery](#cause-UnqualifiedInterfaceVersion).
    UnqualifiedInterfaceVersion,
}

impl std::fmt::Display for NativeExecutionRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CGenerateKeyUnavailable => f.write_str("C_GenerateKey unavailable"),
            Self::CGenerateKeyPairUnavailable => f.write_str("C_GenerateKeyPair unavailable"),
            Self::DsaSeedReturnedLength => f.write_str("DSA seed returned length"),
            Self::BlockingEventWithoutModulePossession => {
                f.write_str("blocking event without module possession")
            }
            Self::DifferentSlotEventSourceSelected => {
                f.write_str("different slot event source selected")
            }
            Self::FileReservationAllocation => f.write_str("file reservation allocation"),
            Self::FileReservationCountExhausted => f.write_str("file reservation count exhausted"),
            Self::FunctionTableExport => f.write_str("function table export"),
            Self::GenerationExtensionOutputTaken => {
                f.write_str("generation extension output taken")
            }
            Self::GenerationParameterAccounting => f.write_str("generation parameter accounting"),
            Self::GenerationPreparationChanged => f.write_str("generation preparation changed"),
            Self::GenerationScalarAbiWidth => f.write_str("generation scalar ABI width"),
            Self::InitializationOutcomeExpected => f.write_str("initialization outcome expected"),
            Self::KeyGenerationInputChanged => f.write_str("key generation input changed"),
            Self::KeyPairGenerationInputChanged => f.write_str("key-pair generation input changed"),
            Self::ModuleFinalizationAbortState => f.write_str("module finalization abort state"),
            Self::ModuleFinalizationDispatchState => {
                f.write_str("module finalization dispatch state")
            }
            Self::ModuleFinalizationReturnState => f.write_str("module finalization return state"),
            Self::ModuleFinalizationState => f.write_str("module finalization state"),
            Self::ModuleIdentityReservationAbsent => {
                f.write_str("module identity reservation absent")
            }
            Self::NativeAdmissionAlreadyBound => f.write_str("native admission already bound"),
            Self::NativeAdmissionLifecycle => f.write_str("native admission lifecycle"),
            Self::NativeCallCountersIncomplete => f.write_str("native call counters incomplete"),
            Self::NativeDataAllocation => f.write_str("native data allocation"),
            Self::NativeFinalizationSuccessAbsent => {
                f.write_str("native finalization success absent")
            }
            Self::NativeFrameAllocation => f.write_str("native frame allocation"),
            Self::NativeFrameCompletionUnproven => f.write_str("native frame completion unproven"),
            Self::NativeInitializationRetired => f.write_str("native initialization retired"),
            Self::NotificationRetirementOwnerOccupied => {
                f.write_str("notification retirement owner occupied")
            }
            Self::NullFunctionTable => f.write_str("null function table"),
            Self::ObjectCreationInputChanged => f.write_str("object creation input changed"),
            Self::PredecessorFileReservationAbsent => {
                f.write_str("predecessor file reservation absent")
            }
            Self::ProcessExportAllocation => f.write_str("process export allocation"),
            Self::RetiredRuntimeHasNoFinalizeAuthority => {
                f.write_str("retired runtime has no Finalize authority")
            }
            Self::RuntimeOwnerWithdrawn => f.write_str("runtime owner withdrawn"),
            Self::RuntimeRetirementNotEstablished => {
                f.write_str("runtime retirement not established")
            }
            Self::RuntimeSuccessorAlreadyPublished => {
                f.write_str("runtime successor already published")
            }
            Self::SerializedCallbackDepth => f.write_str("serialized callback depth"),
            Self::SerializedDispatchDepth => f.write_str("serialized dispatch depth"),
            Self::SerializedModuleCallbackReentry => {
                f.write_str("serialized module callback reentry")
            }
            Self::SlotEventAdmissionAlreadyBound => {
                f.write_str("slot event admission already bound")
            }
            Self::SlotEventAdmissionClosed => f.write_str("slot event admission closed"),
            Self::SlotEventCompletionUnproven => f.write_str("slot event completion unproven"),
            Self::SlotEventNativeReturnUnproven => f.write_str("slot event native return unproven"),
            Self::SlotEventOwnerState => f.write_str("slot event owner state"),
            Self::TableObservationExpected => f.write_str("table observation expected"),
            Self::UnqualifiedInterfaceVersion => f.write_str("unqualified interface version"),
        }
    }
}
