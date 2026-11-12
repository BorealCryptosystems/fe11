// SPDX-License-Identifier: Apache-2.0
//! Detachment causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to detachment.
#[doc = include_str!("../../../docs/diagnostics/busy-detachment.md")]
pub enum DetachmentBusy {
    /// Restoration requires its transfer ticket. [Detection, owner and recovery](#cause-RestorationRequiresItsTransferTicket).
    RestorationRequiresItsTransferTicket,
}

impl std::fmt::Display for DetachmentBusy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RestorationRequiresItsTransferTicket => {
                f.write_str("restoration requires its transfer ticket")
            }
        }
    }
}
