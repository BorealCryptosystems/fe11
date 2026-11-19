// SPDX-License-Identifier: Apache-2.0
//! Public SessionAccountingRejection values retain identity through category conversion.
use fe11::{Error, RejectionReason, SessionAccountingRejection};

#[test]
fn variants_preserve_category_and_payload() {
    let cases = [
        SessionAccountingRejection::AmbiguousSessionOwner,
        SessionAccountingRejection::AuthenticationRequiresSession,
        SessionAccountingRejection::DuplicateSessionPolicyToken,
        SessionAccountingRejection::FinalizationOwnersNotSealed,
        SessionAccountingRejection::FinalizationOwnershipChanged,
        SessionAccountingRejection::FinalizationPopulationChanged,
        SessionAccountingRejection::FinalizationSnapshotAllocation,
        SessionAccountingRejection::LiveProviderSessionCollision,
        SessionAccountingRejection::ModuleSessionAdmissionClosed,
        SessionAccountingRejection::PendingCloseHandleCollision,
        SessionAccountingRejection::PredecessorSessionAdmissionNotSealed,
        SessionAccountingRejection::PredecessorSessionAdmissionReopened,
        SessionAccountingRejection::RecoveryAlreadyStarted,
        SessionAccountingRejection::RecoveryOwnerAbsent,
        SessionAccountingRejection::RecoveryStateMismatch,
        SessionAccountingRejection::RecoveryTicketExhausted,
        SessionAccountingRejection::RecoveryTicketMismatch,
        SessionAccountingRejection::SessionCloseState,
        SessionAccountingRejection::SessionClosingOwnership,
        SessionAccountingRejection::SessionCountInvariant,
        SessionAccountingRejection::SessionCountOverflow,
        SessionAccountingRejection::SessionDispatchReservation,
        SessionAccountingRejection::SessionGenerationExhausted,
        SessionAccountingRejection::SessionLedgerEntryInvariant,
        SessionAccountingRejection::SessionLedgerIdentityInvariant,
        SessionAccountingRejection::SessionLimit,
        SessionAccountingRejection::SessionLossOwnerMismatch,
        SessionAccountingRejection::SessionOwnerAbsent,
        SessionAccountingRejection::SessionOwnerMismatch,
        SessionAccountingRejection::SessionOwnerReleased,
        SessionAccountingRejection::SessionPublicationState,
        SessionAccountingRejection::SessionRegistryAllocation,
        SessionAccountingRejection::SessionReservationAbsent,
        SessionAccountingRejection::SessionReservationAlreadyReleased,
        SessionAccountingRejection::SessionSnapshotAllocation,
        SessionAccountingRejection::SessionStatusOverflow,
        SessionAccountingRejection::SessionTokenCountInvariant,
        SessionAccountingRejection::SessionsActive,
        SessionAccountingRejection::StaleClosingTicket,
        SessionAccountingRejection::StaleRecoveryCompletion,
    ];
    for value in cases {
        let category: RejectionReason = value.into();
        assert!(matches!(category, RejectionReason::SessionAccounting(actual) if actual == value));
        let error = Error::Rejected(category);
        assert_eq!(error.clone(), error);
        assert!(
            matches!(&error, Error::Rejected(RejectionReason::SessionAccounting(actual)) if *actual == value)
        );
        assert!(!value.to_string().is_empty());
        assert!(!category.to_string().is_empty());
        assert!(!error.to_string().is_empty());
        assert!(!format!("{value:?}").is_empty());
    }
}
