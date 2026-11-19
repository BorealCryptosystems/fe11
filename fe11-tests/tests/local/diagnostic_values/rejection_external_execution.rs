// SPDX-License-Identifier: Apache-2.0
//! Public ExternalExecutionRejection values retain identity through category conversion.
use fe11::{Error, ExternalExecutionRejection, RejectionReason};

#[test]
fn variants_preserve_category_and_payload() {
    let cases = [
        ExternalExecutionRejection::ForeignJoinOwnerMismatch,
        ExternalExecutionRejection::ForeignJoinSourceMissing,
        ExternalExecutionRejection::ForeignJoinSourceNotDetached,
        ExternalExecutionRejection::ForeignAdoptedProgressMismatch,
        ExternalExecutionRejection::ForeignCallAlreadyDispatched,
        ExternalExecutionRejection::ForeignCallReservationChanged,
        ExternalExecutionRejection::ForeignCallScopeAllocation,
        ExternalExecutionRejection::ForeignCallbackCount,
        ExternalExecutionRejection::ForeignCallbackCountExhausted,
        ExternalExecutionRejection::ForeignCallbackGraphRetired,
        ExternalExecutionRejection::ForeignCallbackScopeAllocation,
        ExternalExecutionRejection::ForeignCloseSessionOwner,
        ExternalExecutionRejection::ForeignCloseSessionOwnerRequired,
        ExternalExecutionRejection::ForeignCollectionAllocation,
        ExternalExecutionRejection::ForeignDrainingRuntime,
        ExternalExecutionRejection::ForeignDrainingSlot,
        ExternalExecutionRejection::ForeignEventAlreadyIssued,
        ExternalExecutionRejection::ForeignEventCodeConversion,
        ExternalExecutionRejection::ForeignEventCompletionUnproven,
        ExternalExecutionRejection::ForeignEventNotDispatched,
        ExternalExecutionRejection::ForeignEventRuntimeMismatch,
        ExternalExecutionRejection::ForeignEventSlotConversion,
        ExternalExecutionRejection::ForeignGraphRetired,
        ExternalExecutionRejection::ForeignInitializationFinalized,
        ExternalExecutionRejection::ForeignNativeContextRetired,
        ExternalExecutionRejection::ForeignNativeReturnWithoutMatchingDispatch,
        ExternalExecutionRejection::ForeignNativeSessionHandleReused,
        ExternalExecutionRejection::ForeignOpenSessionOwnerRequired,
        ExternalExecutionRejection::ForeignOpenSessionReceiptRequired,
        ExternalExecutionRejection::ForeignOpenWithoutDispatch,
        ExternalExecutionRejection::ForeignOperationSessionMismatch,
        ExternalExecutionRejection::ForeignParticipantAllocation,
        ExternalExecutionRejection::ForeignParticipantRetired,
        ExternalExecutionRejection::ForeignRetirementAllocation,
        ExternalExecutionRejection::ForeignRetirementCapacityChanged,
        ExternalExecutionRejection::ForeignReturnCodeConversion,
        ExternalExecutionRejection::ForeignReturnDoesNotProveDeclaredCompletion,
        ExternalExecutionRejection::ForeignRuntimeRetired,
        ExternalExecutionRejection::ForeignSessionAlreadyRegistered,
        ExternalExecutionRejection::ForeignSessionHandleConversion,
        ExternalExecutionRejection::ForeignSessionHandleInvalid,
        ExternalExecutionRejection::ForeignSessionOwnerRequired,
        ExternalExecutionRejection::ForeignSessionRetired,
        ExternalExecutionRejection::ForeignSessionsActive,
        ExternalExecutionRejection::ForeignSlotConversion,
        ExternalExecutionRejection::ForeignSlotRegistryAllocation,
        ExternalExecutionRejection::ForeignWorkRegistryAllocation,
        ExternalExecutionRejection::ForeignWorkStepNotAdmitted,
    ];
    for value in cases {
        let category: RejectionReason = value.into();
        assert!(matches!(category, RejectionReason::ExternalExecution(actual) if actual == value));
        let error = Error::Rejected(category);
        assert_eq!(error.clone(), error);
        assert!(
            matches!(&error, Error::Rejected(RejectionReason::ExternalExecution(actual)) if *actual == value)
        );
        assert!(!value.to_string().is_empty());
        assert!(!category.to_string().is_empty());
        assert!(!error.to_string().is_empty());
        assert!(!format!("{value:?}").is_empty());
    }
}
