// SPDX-License-Identifier: Apache-2.0
//! SessionAccounting causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to session accounting.
#[doc = include_str!("../../../docs/diagnostics/rejection-session_accounting.md")]
pub enum SessionAccountingRejection {
    /// Ambiguous session owner. [Detection, owner and recovery](#cause-AmbiguousSessionOwner).
    AmbiguousSessionOwner,
    /// Authentication requires session. [Detection, owner and recovery](#cause-AuthenticationRequiresSession).
    AuthenticationRequiresSession,
    /// Duplicate session policy token. [Detection, owner and recovery](#cause-DuplicateSessionPolicyToken).
    DuplicateSessionPolicyToken,
    /// Finalization owners not sealed. [Detection, owner and recovery](#cause-FinalizationOwnersNotSealed).
    FinalizationOwnersNotSealed,
    /// Finalization ownership changed. [Detection, owner and recovery](#cause-FinalizationOwnershipChanged).
    FinalizationOwnershipChanged,
    /// Finalization population changed. [Detection, owner and recovery](#cause-FinalizationPopulationChanged).
    FinalizationPopulationChanged,
    /// Finalization snapshot allocation. [Detection, owner and recovery](#cause-FinalizationSnapshotAllocation).
    FinalizationSnapshotAllocation,
    /// Live provider session collision. [Detection, owner and recovery](#cause-LiveProviderSessionCollision).
    LiveProviderSessionCollision,
    /// Module session admission closed. [Detection, owner and recovery](#cause-ModuleSessionAdmissionClosed).
    ModuleSessionAdmissionClosed,
    /// Pending close handle collision. [Detection, owner and recovery](#cause-PendingCloseHandleCollision).
    PendingCloseHandleCollision,
    /// Predecessor session admission not sealed. [Detection, owner and recovery](#cause-PredecessorSessionAdmissionNotSealed).
    PredecessorSessionAdmissionNotSealed,
    /// Predecessor session admission reopened. [Detection, owner and recovery](#cause-PredecessorSessionAdmissionReopened).
    PredecessorSessionAdmissionReopened,
    /// Recovery already started. [Detection, owner and recovery](#cause-RecoveryAlreadyStarted).
    RecoveryAlreadyStarted,
    /// Recovery owner absent. [Detection, owner and recovery](#cause-RecoveryOwnerAbsent).
    RecoveryOwnerAbsent,
    /// Recovery state mismatch. [Detection, owner and recovery](#cause-RecoveryStateMismatch).
    RecoveryStateMismatch,
    /// Recovery ticket exhausted. [Detection, owner and recovery](#cause-RecoveryTicketExhausted).
    RecoveryTicketExhausted,
    /// Recovery ticket mismatch. [Detection, owner and recovery](#cause-RecoveryTicketMismatch).
    RecoveryTicketMismatch,
    /// Session close state. [Detection, owner and recovery](#cause-SessionCloseState).
    SessionCloseState,
    /// Session closing ownership. [Detection, owner and recovery](#cause-SessionClosingOwnership).
    SessionClosingOwnership,
    /// Session count invariant. [Detection, owner and recovery](#cause-SessionCountInvariant).
    SessionCountInvariant,
    /// Session count overflow. [Detection, owner and recovery](#cause-SessionCountOverflow).
    SessionCountOverflow,
    /// Session dispatch reservation. [Detection, owner and recovery](#cause-SessionDispatchReservation).
    SessionDispatchReservation,
    /// Session generation exhausted. [Detection, owner and recovery](#cause-SessionGenerationExhausted).
    SessionGenerationExhausted,
    /// Session ledger entry invariant. [Detection, owner and recovery](#cause-SessionLedgerEntryInvariant).
    SessionLedgerEntryInvariant,
    /// Session ledger identity invariant. [Detection, owner and recovery](#cause-SessionLedgerIdentityInvariant).
    SessionLedgerIdentityInvariant,
    /// Session limit. [Detection, owner and recovery](#cause-SessionLimit).
    SessionLimit,
    /// Session loss owner mismatch. [Detection, owner and recovery](#cause-SessionLossOwnerMismatch).
    SessionLossOwnerMismatch,
    /// Session owner absent. [Detection, owner and recovery](#cause-SessionOwnerAbsent).
    SessionOwnerAbsent,
    /// Session owner mismatch. [Detection, owner and recovery](#cause-SessionOwnerMismatch).
    SessionOwnerMismatch,
    /// Session owner released. [Detection, owner and recovery](#cause-SessionOwnerReleased).
    SessionOwnerReleased,
    /// Session publication state. [Detection, owner and recovery](#cause-SessionPublicationState).
    SessionPublicationState,
    /// Session registry allocation. [Detection, owner and recovery](#cause-SessionRegistryAllocation).
    SessionRegistryAllocation,
    /// Session reservation absent. [Detection, owner and recovery](#cause-SessionReservationAbsent).
    SessionReservationAbsent,
    /// Session reservation already released. [Detection, owner and recovery](#cause-SessionReservationAlreadyReleased).
    SessionReservationAlreadyReleased,
    /// Session snapshot allocation. [Detection, owner and recovery](#cause-SessionSnapshotAllocation).
    SessionSnapshotAllocation,
    /// Session status overflow. [Detection, owner and recovery](#cause-SessionStatusOverflow).
    SessionStatusOverflow,
    /// Session token count invariant. [Detection, owner and recovery](#cause-SessionTokenCountInvariant).
    SessionTokenCountInvariant,
    /// Sessions active. [Detection, owner and recovery](#cause-SessionsActive).
    SessionsActive,
    /// Stale closing ticket. [Detection, owner and recovery](#cause-StaleClosingTicket).
    StaleClosingTicket,
    /// Stale recovery completion. [Detection, owner and recovery](#cause-StaleRecoveryCompletion).
    StaleRecoveryCompletion,
}

impl std::fmt::Display for SessionAccountingRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AmbiguousSessionOwner => f.write_str("ambiguous session owner"),
            Self::AuthenticationRequiresSession => f.write_str("authentication requires session"),
            Self::DuplicateSessionPolicyToken => f.write_str("duplicate session policy token"),
            Self::FinalizationOwnersNotSealed => f.write_str("finalization owners not sealed"),
            Self::FinalizationOwnershipChanged => f.write_str("finalization ownership changed"),
            Self::FinalizationPopulationChanged => f.write_str("finalization population changed"),
            Self::FinalizationSnapshotAllocation => f.write_str("finalization snapshot allocation"),
            Self::LiveProviderSessionCollision => f.write_str("live provider session collision"),
            Self::ModuleSessionAdmissionClosed => f.write_str("module session admission closed"),
            Self::PendingCloseHandleCollision => f.write_str("pending close handle collision"),
            Self::PredecessorSessionAdmissionNotSealed => {
                f.write_str("predecessor session admission not sealed")
            }
            Self::PredecessorSessionAdmissionReopened => {
                f.write_str("predecessor session admission reopened")
            }
            Self::RecoveryAlreadyStarted => f.write_str("recovery already started"),
            Self::RecoveryOwnerAbsent => f.write_str("recovery owner absent"),
            Self::RecoveryStateMismatch => f.write_str("recovery state mismatch"),
            Self::RecoveryTicketExhausted => f.write_str("recovery ticket exhausted"),
            Self::RecoveryTicketMismatch => f.write_str("recovery ticket mismatch"),
            Self::SessionCloseState => f.write_str("session close state"),
            Self::SessionClosingOwnership => f.write_str("session closing ownership"),
            Self::SessionCountInvariant => f.write_str("session count invariant"),
            Self::SessionCountOverflow => f.write_str("session count overflow"),
            Self::SessionDispatchReservation => f.write_str("session dispatch reservation"),
            Self::SessionGenerationExhausted => f.write_str("session generation exhausted"),
            Self::SessionLedgerEntryInvariant => f.write_str("session ledger entry invariant"),
            Self::SessionLedgerIdentityInvariant => {
                f.write_str("session ledger identity invariant")
            }
            Self::SessionLimit => f.write_str("session limit"),
            Self::SessionLossOwnerMismatch => f.write_str("session loss owner mismatch"),
            Self::SessionOwnerAbsent => f.write_str("session owner absent"),
            Self::SessionOwnerMismatch => f.write_str("session owner mismatch"),
            Self::SessionOwnerReleased => f.write_str("session owner released"),
            Self::SessionPublicationState => f.write_str("session publication state"),
            Self::SessionRegistryAllocation => f.write_str("session registry allocation"),
            Self::SessionReservationAbsent => f.write_str("session reservation absent"),
            Self::SessionReservationAlreadyReleased => {
                f.write_str("session reservation already released")
            }
            Self::SessionSnapshotAllocation => f.write_str("session snapshot allocation"),
            Self::SessionStatusOverflow => f.write_str("session status overflow"),
            Self::SessionTokenCountInvariant => f.write_str("session token count invariant"),
            Self::SessionsActive => f.write_str("sessions active"),
            Self::StaleClosingTicket => f.write_str("stale closing ticket"),
            Self::StaleRecoveryCompletion => f.write_str("stale recovery completion"),
        }
    }
}
