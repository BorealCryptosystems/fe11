// SPDX-License-Identifier: Apache-2.0
//! ObjectDestination causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to object destination.
#[doc = include_str!("../../../docs/diagnostics/rejection-object_destination.md")]
pub enum ObjectDestinationRejection {
    /// Destination cardinality width. [Detection, owner and recovery](#cause-DestinationCardinalityWidth).
    DestinationCardinalityWidth,
    /// Destination completion phase. [Detection, owner and recovery](#cause-DestinationCompletionPhase).
    DestinationCompletionPhase,
    /// Destination continuation phase. [Detection, owner and recovery](#cause-DestinationContinuationPhase).
    DestinationContinuationPhase,
    /// Destination incomplete. [Detection, owner and recovery](#cause-DestinationIncomplete).
    DestinationIncomplete,
    /// Destination observation requires prepared owner. [Detection, owner and recovery](#cause-DestinationObservationRequiresPreparedOwner).
    DestinationObservationRequiresPreparedOwner,
    /// Destination preparation already bound. [Detection, owner and recovery](#cause-DestinationPreparationAlreadyBound).
    DestinationPreparationAlreadyBound,
    /// Destination preparation already consumed. [Detection, owner and recovery](#cause-DestinationPreparationAlreadyConsumed).
    DestinationPreparationAlreadyConsumed,
    /// Destination protection absent. [Detection, owner and recovery](#cause-DestinationProtectionAbsent).
    DestinationProtectionAbsent,
    /// Destination query reached local report. [Detection, owner and recovery](#cause-DestinationQueryReachedLocalReport).
    DestinationQueryReachedLocalReport,
    /// Destination search preparation absent. [Detection, owner and recovery](#cause-DestinationSearchPreparationAbsent).
    DestinationSearchPreparationAbsent,
    /// Destination storage size. [Detection, owner and recovery](#cause-DestinationStorageSize).
    DestinationStorageSize,
    /// Unrequested destination count. [Detection, owner and recovery](#cause-UnrequestedDestinationCount).
    UnrequestedDestinationCount,
}

impl std::fmt::Display for ObjectDestinationRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DestinationCardinalityWidth => f.write_str("destination cardinality width"),
            Self::DestinationCompletionPhase => f.write_str("destination completion phase"),
            Self::DestinationContinuationPhase => f.write_str("destination continuation phase"),
            Self::DestinationIncomplete => f.write_str("destination incomplete"),
            Self::DestinationObservationRequiresPreparedOwner => {
                f.write_str("destination observation requires prepared owner")
            }
            Self::DestinationPreparationAlreadyBound => {
                f.write_str("destination preparation already bound")
            }
            Self::DestinationPreparationAlreadyConsumed => {
                f.write_str("destination preparation already consumed")
            }
            Self::DestinationProtectionAbsent => f.write_str("destination protection absent"),
            Self::DestinationQueryReachedLocalReport => {
                f.write_str("destination query reached local report")
            }
            Self::DestinationSearchPreparationAbsent => {
                f.write_str("destination search preparation absent")
            }
            Self::DestinationStorageSize => f.write_str("destination storage size"),
            Self::UnrequestedDestinationCount => f.write_str("unrequested destination count"),
        }
    }
}
