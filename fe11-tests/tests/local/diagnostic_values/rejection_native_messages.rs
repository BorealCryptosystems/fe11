// SPDX-License-Identifier: Apache-2.0
//! Public NativeMessagesRejection values retain identity through category conversion.
use fe11::{Error, NativeMessagesRejection, RejectionReason};

#[test]
fn variants_preserve_category_and_payload() {
    let cases = [
        NativeMessagesRejection::CapturedGenericMessageRequiresDestinationBinding,
        NativeMessagesRejection::ChangedGenericMessageSnapshotInput,
        NativeMessagesRejection::ForeignMessagePreparationBudget,
        NativeMessagesRejection::ForeignOrConsumedGenericMessageTicket,
        NativeMessagesRejection::GenericMessageContinuationTicketUnavailable,
        NativeMessagesRejection::GenericMessageDestinationBinding,
        NativeMessagesRejection::GenericMessageDiagnosticNotUsed,
        NativeMessagesRejection::GenericMessageFacadeIncomplete,
        NativeMessagesRejection::GenericMessageInitializationBinding,
        NativeMessagesRejection::GenericMessageInputBoundaryNotEstablished,
        NativeMessagesRejection::GenericMessageInputBoundaryUnavailable,
        NativeMessagesRejection::GenericMessageInputMutation,
        NativeMessagesRejection::GenericMessageIsNotWaitingForOutput,
        NativeMessagesRejection::GenericMessageNotAtACapturableBoundary,
        NativeMessagesRejection::GenericMessageOutputRowAbsent,
        NativeMessagesRejection::GenericMessageOwnerAccounting,
        NativeMessagesRejection::GenericMessageOwnerShape,
        NativeMessagesRejection::GenericMessageParameterDeclarationMismatch,
        NativeMessagesRejection::GenericMessagePreparedOutputWidth,
        NativeMessagesRejection::GenericMessageReconstruction,
        NativeMessagesRejection::GenericMessageRequiresExplicitCleanup,
        NativeMessagesRejection::GenericMessageResultAbsent,
        NativeMessagesRejection::GenericMessageResultNotAvailable,
        NativeMessagesRejection::GenericMessageResultShape,
        NativeMessagesRejection::GenericMessageRetainedInputMutation,
        NativeMessagesRejection::GenericMessageSigningOutputAbsent,
        NativeMessagesRejection::GenericMessageSnapshotShape,
        NativeMessagesRejection::GenericMessageStartAccounting,
        NativeMessagesRejection::GenericMessageStreamIsNotAwaitingInput,
        NativeMessagesRejection::GenericMessageSubmissionAccounting,
        NativeMessagesRejection::GenericMessageSubmissionRoute,
        NativeMessagesRejection::GenericMessageTerminalOperands,
        NativeMessagesRejection::GenericMessageTicketAlreadyTransferred,
        NativeMessagesRejection::GenericMessageTicketRequired,
        NativeMessagesRejection::GenericResultAccounting,
        NativeMessagesRejection::MessageAsynchronousModeUnavailable,
        NativeMessagesRejection::MessageOutputAlreadySubmitted,
        NativeMessagesRejection::MessageParameterMechanismMismatch,
        NativeMessagesRejection::MessagePartCountOverflow,
        NativeMessagesRejection::MessagePrimaryBindingAbsent,
        NativeMessagesRejection::MessageSignatureNotCompleted,
        NativeMessagesRejection::MessageSignatureOutputOffset,
        NativeMessagesRejection::MessageSignatureResultExtent,
        NativeMessagesRejection::MessageWriteRequiresItsDeclaredWriter,
        NativeMessagesRejection::RevokedMessageAuxiliaryKey,
        NativeMessagesRejection::StaleGenericMessageTicket,
    ];
    for value in cases {
        let category: RejectionReason = value.into();
        assert!(matches!(category, RejectionReason::NativeMessages(actual) if actual == value));
        let error = Error::Rejected(category);
        assert_eq!(error.clone(), error);
        assert!(
            matches!(&error, Error::Rejected(RejectionReason::NativeMessages(actual)) if *actual == value)
        );
        assert!(!value.to_string().is_empty());
        assert!(!category.to_string().is_empty());
        assert!(!error.to_string().is_empty());
        assert!(!format!("{value:?}").is_empty());
    }
}
