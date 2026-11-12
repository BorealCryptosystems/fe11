// SPDX-License-Identifier: Apache-2.0
//! MemoryAccounting causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to memory accounting.
#[doc = include_str!("../../../docs/diagnostics/rejection-memory_accounting.md")]
pub enum MemoryAccountingRejection {
    /// Credit transfer exceeds ownership. [Detection, owner and recovery](#cause-CreditTransferExceedsOwnership).
    CreditTransferExceedsOwnership,
    /// Foreign byte credit. [Detection, owner and recovery](#cause-ForeignByteCredit).
    ForeignByteCredit,
    /// Module storage requires global credit. [Detection, owner and recovery](#cause-ModuleStorageRequiresGlobalCredit).
    ModuleStorageRequiresGlobalCredit,
    /// Private account requires complete source measurement. [Detection, owner and recovery](#cause-PrivateAccountRequiresCompleteSourceMeasurement).
    PrivateAccountRequiresCompleteSourceMeasurement,
    /// Resident byte accounting overflow. [Detection, owner and recovery](#cause-ResidentByteAccountingOverflow).
    ResidentByteAccountingOverflow,
    /// Retained source credit overflow. [Detection, owner and recovery](#cause-RetainedSourceCreditOverflow).
    RetainedSourceCreditOverflow,
    /// Retained source destination changed. [Detection, owner and recovery](#cause-RetainedSourceDestinationChanged).
    RetainedSourceDestinationChanged,
    /// Retained source observation exhausted. [Detection, owner and recovery](#cause-RetainedSourceObservationExhausted).
    RetainedSourceObservationExhausted,
    /// Successor must preserve retained byte credit domain. [Detection, owner and recovery](#cause-SuccessorMustPreserveRetainedByteCreditDomain).
    SuccessorMustPreserveRetainedByteCreditDomain,
    /// Symmetric allocation. [Detection, owner and recovery](#cause-SymmetricAllocation).
    SymmetricAllocation,
    /// Symmetric allocation accounting. [Detection, owner and recovery](#cause-SymmetricAllocationAccounting).
    SymmetricAllocationAccounting,
    /// Symmetric allocator capacity. [Detection, owner and recovery](#cause-SymmetricAllocatorCapacity).
    SymmetricAllocatorCapacity,
    /// Symmetric budget counter overflow. [Detection, owner and recovery](#cause-SymmetricBudgetCounterOverflow).
    SymmetricBudgetCounterOverflow,
    /// Symmetric credit overflow. [Detection, owner and recovery](#cause-SymmetricCreditOverflow).
    SymmetricCreditOverflow,
    /// Symmetric output length. [Detection, owner and recovery](#cause-SymmetricOutputLength).
    SymmetricOutputLength,
}

impl std::fmt::Display for MemoryAccountingRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CreditTransferExceedsOwnership => {
                f.write_str("credit transfer exceeds ownership")
            }
            Self::ForeignByteCredit => f.write_str("foreign byte credit"),
            Self::ModuleStorageRequiresGlobalCredit => {
                f.write_str("module storage requires global credit")
            }
            Self::PrivateAccountRequiresCompleteSourceMeasurement => {
                f.write_str("private account requires complete source measurement")
            }
            Self::ResidentByteAccountingOverflow => {
                f.write_str("resident byte accounting overflow")
            }
            Self::RetainedSourceCreditOverflow => f.write_str("retained source credit overflow"),
            Self::RetainedSourceDestinationChanged => {
                f.write_str("retained source destination changed")
            }
            Self::RetainedSourceObservationExhausted => {
                f.write_str("retained source observation exhausted")
            }
            Self::SuccessorMustPreserveRetainedByteCreditDomain => {
                f.write_str("successor must preserve retained byte credit domain")
            }
            Self::SymmetricAllocation => f.write_str("symmetric allocation"),
            Self::SymmetricAllocationAccounting => f.write_str("symmetric allocation accounting"),
            Self::SymmetricAllocatorCapacity => f.write_str("symmetric allocator capacity"),
            Self::SymmetricBudgetCounterOverflow => {
                f.write_str("symmetric budget counter overflow")
            }
            Self::SymmetricCreditOverflow => f.write_str("symmetric credit overflow"),
            Self::SymmetricOutputLength => f.write_str("symmetric output length"),
        }
    }
}
