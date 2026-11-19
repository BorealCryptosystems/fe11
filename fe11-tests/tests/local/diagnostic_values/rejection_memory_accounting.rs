// SPDX-License-Identifier: Apache-2.0
//! Public MemoryAccountingRejection values retain identity through category conversion.
use fe11::{Error, MemoryAccountingRejection, RejectionReason};

#[test]
fn variants_preserve_category_and_payload() {
    let cases = [
        MemoryAccountingRejection::CreditTransferExceedsOwnership,
        MemoryAccountingRejection::ForeignByteCredit,
        MemoryAccountingRejection::ModuleStorageRequiresGlobalCredit,
        MemoryAccountingRejection::PrivateAccountRequiresCompleteSourceMeasurement,
        MemoryAccountingRejection::ResidentByteAccountingOverflow,
        MemoryAccountingRejection::RetainedSourceCreditOverflow,
        MemoryAccountingRejection::RetainedSourceDestinationChanged,
        MemoryAccountingRejection::RetainedSourceObservationExhausted,
        MemoryAccountingRejection::SuccessorMustPreserveRetainedByteCreditDomain,
        MemoryAccountingRejection::SymmetricAllocation,
        MemoryAccountingRejection::SymmetricAllocationAccounting,
        MemoryAccountingRejection::SymmetricAllocatorCapacity,
        MemoryAccountingRejection::SymmetricBudgetCounterOverflow,
        MemoryAccountingRejection::SymmetricCreditOverflow,
        MemoryAccountingRejection::SymmetricOutputLength,
    ];
    for value in cases {
        let category: RejectionReason = value.into();
        assert!(matches!(category, RejectionReason::MemoryAccounting(actual) if actual == value));
        let error = Error::Rejected(category);
        assert_eq!(error.clone(), error);
        assert!(
            matches!(&error, Error::Rejected(RejectionReason::MemoryAccounting(actual)) if *actual == value)
        );
        assert!(!value.to_string().is_empty());
        assert!(!category.to_string().is_empty());
        assert!(!error.to_string().is_empty());
        assert!(!format!("{value:?}").is_empty());
    }
}
