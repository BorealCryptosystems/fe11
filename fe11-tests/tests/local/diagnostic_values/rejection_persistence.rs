// SPDX-License-Identifier: Apache-2.0
//! Public PersistenceRejection values retain identity through category conversion.
use fe11::{Error, PersistenceRejection, RejectionReason};

#[test]
fn variants_preserve_category_and_payload() {
    let cases = [
        PersistenceRejection::AsynchronousRejoinSessionMode,
        PersistenceRejection::CapturedModuleNoLongerOwned,
        PersistenceRejection::CapturedNativeStateAbsent,
        PersistenceRejection::DetachedRecordKind,
        PersistenceRejection::ImportNativeStorageAbsent,
        PersistenceRejection::NativeMessageDestinationRequired,
        PersistenceRejection::UnsupportedAuthenticatedRecordKind,
    ];
    for value in cases {
        let category: RejectionReason = value.into();
        assert!(matches!(category, RejectionReason::Persistence(actual) if actual == value));
        let error = Error::Rejected(category);
        assert_eq!(error.clone(), error);
        assert!(
            matches!(&error, Error::Rejected(RejectionReason::Persistence(actual)) if *actual == value)
        );
        assert!(!value.to_string().is_empty());
        assert!(!category.to_string().is_empty());
        assert!(!error.to_string().is_empty());
        assert!(!format!("{value:?}").is_empty());
    }
}
