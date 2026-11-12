// SPDX-License-Identifier: Apache-2.0
//! Restoration causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to restoration.
#[doc = include_str!("../../../docs/diagnostics/busy-restoration.md")]
pub enum RestorationBusy {
    /// Destination operation control active. [Detection, owner and recovery](#cause-DestinationOperationControlActive).
    DestinationOperationControlActive,
    /// Restoration control active. [Detection, owner and recovery](#cause-RestorationControlActive).
    RestorationControlActive,
    /// Restoration transfer active. [Detection, owner and recovery](#cause-RestorationTransferActive).
    RestorationTransferActive,
}

impl std::fmt::Display for RestorationBusy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DestinationOperationControlActive => {
                f.write_str("destination operation control active")
            }
            Self::RestorationControlActive => f.write_str("restoration control active"),
            Self::RestorationTransferActive => f.write_str("restoration transfer active"),
        }
    }
}
