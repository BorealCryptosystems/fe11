// SPDX-License-Identifier: Apache-2.0
//! Public RandomGenerationRejection values retain identity through category conversion.
use fe11::{Error, RandomGenerationRejection, RejectionReason};

#[test]
fn variants_preserve_category_and_payload() {
    let cases = [
        RandomGenerationRejection::CGenerateRandomUnavailable,
        RandomGenerationRejection::CSeedRandomUnavailable,
        RandomGenerationRejection::CWaitForSlotEventUnavailable,
        RandomGenerationRejection::NativeSeedInputChanged,
        RandomGenerationRejection::RandomOutputAccounting,
        RandomGenerationRejection::SecretBufferAccounting,
        RandomGenerationRejection::SecretBufferAllocation,
        RandomGenerationRejection::SecretBufferAlreadyCredited,
        RandomGenerationRejection::SecretLengthExceedsCapacity,
        RandomGenerationRejection::SeedOwnershipAccounting,
        RandomGenerationRejection::SlotEventGenerationAllocation,
    ];
    for value in cases {
        let category: RejectionReason = value.into();
        assert!(matches!(category, RejectionReason::RandomGeneration(actual) if actual == value));
        let error = Error::Rejected(category);
        assert_eq!(error.clone(), error);
        assert!(
            matches!(&error, Error::Rejected(RejectionReason::RandomGeneration(actual)) if *actual == value)
        );
        assert!(!value.to_string().is_empty());
        assert!(!category.to_string().is_empty());
        assert!(!error.to_string().is_empty());
        assert!(!format!("{value:?}").is_empty());
    }
}
