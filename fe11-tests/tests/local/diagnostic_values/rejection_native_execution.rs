// SPDX-License-Identifier: Apache-2.0
//! Public NativeExecutionRejection values retain identity through category conversion.
use fe11::{Error, NativeExecutionRejection, RejectionReason};

#[test]
fn variants_preserve_category_and_payload() {
    let cases = [
        NativeExecutionRejection::CGenerateKeyUnavailable,
        NativeExecutionRejection::CGenerateKeyPairUnavailable,
        NativeExecutionRejection::DsaSeedReturnedLength,
        NativeExecutionRejection::BlockingEventWithoutModulePossession,
        NativeExecutionRejection::DifferentSlotEventSourceSelected,
        NativeExecutionRejection::FileReservationAllocation,
        NativeExecutionRejection::FileReservationCountExhausted,
        NativeExecutionRejection::FunctionTableExport,
        NativeExecutionRejection::GenerationExtensionOutputTaken,
        NativeExecutionRejection::GenerationParameterAccounting,
        NativeExecutionRejection::GenerationPreparationChanged,
        NativeExecutionRejection::GenerationScalarAbiWidth,
        NativeExecutionRejection::InitializationOutcomeExpected,
        NativeExecutionRejection::KeyGenerationInputChanged,
        NativeExecutionRejection::KeyPairGenerationInputChanged,
        NativeExecutionRejection::ModuleFinalizationAbortState,
        NativeExecutionRejection::ModuleFinalizationDispatchState,
        NativeExecutionRejection::ModuleFinalizationReturnState,
        NativeExecutionRejection::ModuleFinalizationState,
        NativeExecutionRejection::ModuleIdentityReservationAbsent,
        NativeExecutionRejection::NativeAdmissionAlreadyBound,
        NativeExecutionRejection::NativeAdmissionLifecycle,
        NativeExecutionRejection::NativeCallCountersIncomplete,
        NativeExecutionRejection::NativeDataAllocation,
        NativeExecutionRejection::NativeFinalizationSuccessAbsent,
        NativeExecutionRejection::NativeFrameAllocation,
        NativeExecutionRejection::NativeFrameCompletionUnproven,
        NativeExecutionRejection::NativeInitializationRetired,
        NativeExecutionRejection::NotificationRetirementOwnerOccupied,
        NativeExecutionRejection::NullFunctionTable,
        NativeExecutionRejection::ObjectCreationInputChanged,
        NativeExecutionRejection::PredecessorFileReservationAbsent,
        NativeExecutionRejection::ProcessExportAllocation,
        NativeExecutionRejection::RetiredRuntimeHasNoFinalizeAuthority,
        NativeExecutionRejection::RuntimeOwnerWithdrawn,
        NativeExecutionRejection::RuntimeRetirementNotEstablished,
        NativeExecutionRejection::RuntimeSuccessorAlreadyPublished,
        NativeExecutionRejection::SerializedCallbackDepth,
        NativeExecutionRejection::SerializedDispatchDepth,
        NativeExecutionRejection::SerializedModuleCallbackReentry,
        NativeExecutionRejection::SlotEventAdmissionAlreadyBound,
        NativeExecutionRejection::SlotEventAdmissionClosed,
        NativeExecutionRejection::SlotEventCompletionUnproven,
        NativeExecutionRejection::SlotEventNativeReturnUnproven,
        NativeExecutionRejection::SlotEventOwnerState,
        NativeExecutionRejection::TableObservationExpected,
        NativeExecutionRejection::UnqualifiedInterfaceVersion,
    ];
    for value in cases {
        let category: RejectionReason = value.into();
        assert!(matches!(category, RejectionReason::NativeExecution(actual) if actual == value));
        let error = Error::Rejected(category);
        assert_eq!(error.clone(), error);
        assert!(
            matches!(&error, Error::Rejected(RejectionReason::NativeExecution(actual)) if *actual == value)
        );
        assert!(!value.to_string().is_empty());
        assert!(!category.to_string().is_empty());
        assert!(!error.to_string().is_empty());
        assert!(!format!("{value:?}").is_empty());
    }
}
