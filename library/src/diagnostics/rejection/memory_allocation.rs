// SPDX-License-Identifier: Apache-2.0
//! MemoryAllocation causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to memory allocation.
#[doc = include_str!("../../../docs/diagnostics/rejection-memory_allocation.md")]
pub enum MemoryAllocationRejection {
    /// Stable owner allocation. [Detection, owner and recovery](#cause-StableOwnerAllocation).
    StableOwnerAllocation,
}

impl std::fmt::Display for MemoryAllocationRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StableOwnerAllocation => f.write_str("stable owner allocation"),
        }
    }
}
