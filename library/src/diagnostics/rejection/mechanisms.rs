// SPDX-License-Identifier: Apache-2.0
//! Mechanisms causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to mechanisms.
#[doc = include_str!("../../../docs/diagnostics/rejection-mechanisms.md")]
pub enum MechanismsRejection {
    /// Conflicting mechanism properties. [Detection, owner and recovery](#cause-ConflictingMechanismProperties).
    ConflictingMechanismProperties,
    /// Mechanism catalogue allocation. [Detection, owner and recovery](#cause-MechanismCatalogueAllocation).
    MechanismCatalogueAllocation,
    /// Mechanism not announced. [Detection, owner and recovery](#cause-MechanismNotAnnounced).
    MechanismNotAnnounced,
    /// Mechanism request allocation. [Detection, owner and recovery](#cause-MechanismRequestAllocation).
    MechanismRequestAllocation,
    /// Mechanism request budget. [Detection, owner and recovery](#cause-MechanismRequestBudget).
    MechanismRequestBudget,
    /// Mechanism request byte count. [Detection, owner and recovery](#cause-MechanismRequestByteCount).
    MechanismRequestByteCount,
    /// Mechanism request width. [Detection, owner and recovery](#cause-MechanismRequestWidth).
    MechanismRequestWidth,
    /// Policy mechanism recipe absent. [Detection, owner and recovery](#cause-PolicyMechanismRecipeAbsent).
    PolicyMechanismRecipeAbsent,
    /// Policy observation completion phase. [Detection, owner and recovery](#cause-PolicyObservationCompletionPhase).
    PolicyObservationCompletionPhase,
    /// Policy observation incomplete. [Detection, owner and recovery](#cause-PolicyObservationIncomplete).
    PolicyObservationIncomplete,
    /// Policy observation need absent. [Detection, owner and recovery](#cause-PolicyObservationNeedAbsent).
    PolicyObservationNeedAbsent,
    /// Policy observation owner absent. [Detection, owner and recovery](#cause-PolicyObservationOwnerAbsent).
    PolicyObservationOwnerAbsent,
    /// Policy observation phase. [Detection, owner and recovery](#cause-PolicyObservationPhase).
    PolicyObservationPhase,
    /// Policy observation possession absent. [Detection, owner and recovery](#cause-PolicyObservationPossessionAbsent).
    PolicyObservationPossessionAbsent,
    /// Policy observation source changed. [Detection, owner and recovery](#cause-PolicyObservationSourceChanged).
    PolicyObservationSourceChanged,
    /// Policy observation stopped. [Detection, owner and recovery](#cause-PolicyObservationStopped).
    PolicyObservationStopped,
    /// Policy observation storage size. [Detection, owner and recovery](#cause-PolicyObservationStorageSize).
    PolicyObservationStorageSize,
    /// Retained mechanism request size. [Detection, owner and recovery](#cause-RetainedMechanismRequestSize).
    RetainedMechanismRequestSize,

}

impl std::fmt::Display for MechanismsRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {

            Self::ConflictingMechanismProperties => f.write_str("conflicting mechanism properties"),
            Self::MechanismCatalogueAllocation => f.write_str("mechanism catalogue allocation"),
            Self::MechanismNotAnnounced => f.write_str("mechanism not announced"),
            Self::MechanismRequestAllocation => f.write_str("mechanism request allocation"),
            Self::MechanismRequestBudget => f.write_str("mechanism request budget"),
            Self::MechanismRequestByteCount => f.write_str("mechanism request byte count"),
            Self::MechanismRequestWidth => f.write_str("mechanism request width"),
            Self::PolicyMechanismRecipeAbsent => f.write_str("policy mechanism recipe absent"),
            Self::PolicyObservationCompletionPhase => {
                f.write_str("policy observation completion phase")
            }
            Self::PolicyObservationIncomplete => f.write_str("policy observation incomplete"),
            Self::PolicyObservationNeedAbsent => f.write_str("policy observation need absent"),
            Self::PolicyObservationOwnerAbsent => f.write_str("policy observation owner absent"),
            Self::PolicyObservationPhase => f.write_str("policy observation phase"),
            Self::PolicyObservationPossessionAbsent => {
                f.write_str("policy observation possession absent")
            }
            Self::PolicyObservationSourceChanged => {
                f.write_str("policy observation source changed")
            }
            Self::PolicyObservationStopped => f.write_str("policy observation stopped"),
            Self::PolicyObservationStorageSize => f.write_str("policy observation storage size"),
            Self::RetainedMechanismRequestSize => f.write_str("retained mechanism request size"),
        }
    }
}
