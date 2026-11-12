// SPDX-License-Identifier: Apache-2.0
//! MemoryAccounting causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to memory accounting.
#[doc = include_str!("../../../docs/diagnostics/busy-memory_accounting.md")]
pub enum MemoryAccountingBusy {
    /// Symmetric byte budget. [Detection, owner and recovery](#cause-SymmetricByteBudget).
    SymmetricByteBudget,
}

impl std::fmt::Display for MemoryAccountingBusy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SymmetricByteBudget => f.write_str("symmetric byte budget"),
        }
    }
}
