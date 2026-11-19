// SPDX-License-Identifier: Apache-2.0
//! Public NativeInterfacesRejection values retain identity through category conversion.
use fe11::{Error, NativeInterfacesRejection, RejectionReason};

#[test]
fn variants_preserve_category_and_payload() {
    let cases = [
        NativeInterfacesRejection::CounterExhausted,
        NativeInterfacesRejection::InterfaceNameLimit { index: 0, limit: 1 },
        NativeInterfacesRejection::InterfaceNameLimit {
            index: 1,
            limit: usize::MAX,
        },
        NativeInterfacesRejection::InterfaceNameLimit {
            index: usize::MAX,
            limit: 0,
        },
        NativeInterfacesRejection::InterfaceNamesTotalLimit { index: 0, limit: 1 },
        NativeInterfacesRejection::InterfaceNamesTotalLimit {
            index: 1,
            limit: usize::MAX,
        },
        NativeInterfacesRejection::InterfaceNamesTotalLimit {
            index: usize::MAX,
            limit: 0,
        },
        NativeInterfacesRejection::IncoherentSelectedInterface,
        NativeInterfacesRejection::InterfaceAllocation,
        NativeInterfacesRejection::InterfaceDiscoveryAttemptsExhausted,
        NativeInterfacesRejection::InterfaceListExport,
        NativeInterfacesRejection::InterfaceSelectionExport,
        NativeInterfacesRejection::NullInterfaceName,
        NativeInterfacesRejection::NullInterfaceTable,
        NativeInterfacesRejection::NullSelectedInterface,
        NativeInterfacesRejection::RequestedInterfaceAbsent,
        NativeInterfacesRejection::UnsupportedInterfaceSelection,
    ];
    for value in cases {
        let category: RejectionReason = value.into();
        assert!(matches!(category, RejectionReason::NativeInterfaces(actual) if actual == value));
        let error = Error::Rejected(category);
        assert_eq!(error.clone(), error);
        assert!(
            matches!(&error, Error::Rejected(RejectionReason::NativeInterfaces(actual)) if *actual == value)
        );
        assert!(!value.to_string().is_empty());
        assert!(!category.to_string().is_empty());
        assert!(!error.to_string().is_empty());
        assert!(!format!("{value:?}").is_empty());
    }
}
