// SPDX-License-Identifier: Apache-2.0
//! CheckpointCapture causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to checkpoint capture.
#[doc = include_str!("../../../docs/diagnostics/busy-checkpoint_capture.md")]
pub enum CheckpointCaptureBusy {
    /// State capture active. [Detection, owner and recovery](#cause-StateCaptureActive).
    StateCaptureActive,
}

impl std::fmt::Display for CheckpointCaptureBusy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StateCaptureActive => f.write_str("state capture active"),
        }
    }
}
