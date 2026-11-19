// SPDX-License-Identifier: Apache-2.0
use super::super::fixtures;
use fe11::*;

#[test]
fn destination_search_plan() {
    let values: [DestinationSearchPlan; 2] = [
        DestinationSearchPlan::NotRequested,
        DestinationSearchPlan::Observe {
            resources: fixtures::search_plan(false),
            source: DestinationSource::Exclude,
            template: ReferenceTemplate::Fields(std::sync::Arc::new(
                std::collections::BTreeSet::new(),
            )),
        },
    ];
    for item in &values {
        fn require_eq<T: Eq>(_: &T) {}
        require_eq(item);
        assert_eq!(item, item);
        assert!(!format!("{item:?}").is_empty());
        let cloned = (*item).clone();
        assert_eq!(&cloned, item);
    }
    for (index, item) in values.iter().enumerate() {
        for different_variant in &values[index + 1..] {
            assert_ne!(item, different_variant);
        }
    }
}

#[test]
fn destination_user_observation() {
    let values: [DestinationUserObservation; 2] = [
        DestinationUserObservation::NotRequested,
        DestinationUserObservation::Read,
    ];
    for item in &values {
        fn require_eq<T: Eq>(_: &T) {}
        require_eq(item);
        assert_eq!(item, item);
        assert!(!format!("{item:?}").is_empty());
        let cloned = (*item).clone();
        assert_eq!(&cloned, item);
    }
    for (index, item) in values.iter().enumerate() {
        for different_variant in &values[index + 1..] {
            assert_ne!(item, different_variant);
        }
    }
}

#[test]
fn discovery_selection() {
    let values: [DiscoverySelection; 3] = [
        DiscoverySelection::AllPresentSlots,
        DiscoverySelection::Deferred,
        DiscoverySelection::Slots(vec![]),
    ];
    for item in &values {
        fn require_eq<T: Eq>(_: &T) {}
        require_eq(item);
        assert_eq!(item, item);
        assert!(!format!("{item:?}").is_empty());
        let cloned = (*item).clone();
        assert_eq!(&cloned, item);
    }
    for (index, item) in values.iter().enumerate() {
        for different_variant in &values[index + 1..] {
            assert_ne!(item, different_variant);
        }
    }
}

#[test]
fn extension_output_length() {
    let values: [ExtensionOutputLength; 2] = [
        ExtensionOutputLength::Fixed,
        ExtensionOutputLength::NativeUnsigned {
            block: 4,
            offset: 5,
        },
    ];
    for item in &values {
        fn require_eq<T: Eq>(_: &T) {}
        require_eq(item);
        assert_eq!(item, item);
        assert!(!format!("{item:?}").is_empty());
        let copied = *item;
        assert_eq!(&copied, item);
        let cloned = (*item).clone();
        assert_eq!(&cloned, item);
    }
    for (index, item) in values.iter().enumerate() {
        for different_variant in &values[index + 1..] {
            assert_ne!(item, different_variant);
        }
    }
}

#[test]
fn extension_output_region() {
    let values: [ExtensionOutputRegion; 2] = [
        fixtures::extension_output_region(false),
        fixtures::extension_output_region(true),
    ];
    for item in &values {
        fn require_eq<T: Eq>(_: &T) {}
        require_eq(item);
        assert_eq!(item, item);
        assert!(!format!("{item:?}").is_empty());
        let copied = *item;
        assert_eq!(&copied, item);
        let cloned = (*item).clone();
        assert_eq!(&cloned, item);
    }
}

#[test]
fn extension_pointer() {
    let values: [ExtensionPointer; 2] = [
        fixtures::extension_pointer(false),
        fixtures::extension_pointer(true),
    ];
    for item in &values {
        fn require_eq<T: Eq>(_: &T) {}
        require_eq(item);
        assert_eq!(item, item);
        assert!(!format!("{item:?}").is_empty());
        let copied = *item;
        assert_eq!(&copied, item);
        let cloned = (*item).clone();
        assert_eq!(&cloned, item);
    }
}

#[test]
fn extension_pointer_target() {
    let values: [ExtensionPointerTarget; 2] = [
        ExtensionPointerTarget::Block {
            block: 4,
            offset: 5,
        },
        ExtensionPointerTarget::Null,
    ];
    for item in &values {
        fn require_eq<T: Eq>(_: &T) {}
        require_eq(item);
        assert_eq!(item, item);
        assert!(!format!("{item:?}").is_empty());
        let copied = *item;
        assert_eq!(&copied, item);
        let cloned = (*item).clone();
        assert_eq!(&cloned, item);
    }
    for (index, item) in values.iter().enumerate() {
        for different_variant in &values[index + 1..] {
            assert_ne!(item, different_variant);
        }
    }
}

#[test]
fn flat_attribute_read_plan() {
    let values: [FlatAttributeReadPlan; 3] = [
        FlatAttributeReadPlan::Buffer { capacity: 4 },
        FlatAttributeReadPlan::LengthOnly,
        FlatAttributeReadPlan::Value { maximum_bytes: 4 },
    ];
    for item in &values {
        fn require_eq<T: Eq>(_: &T) {}
        require_eq(item);
        assert_eq!(item, item);
        assert!(!format!("{item:?}").is_empty());
        let copied = *item;
        assert_eq!(&copied, item);
        let cloned = (*item).clone();
        assert_eq!(&cloned, item);
    }
    for (index, item) in values.iter().enumerate() {
        for different_variant in &values[index + 1..] {
            assert_ne!(item, different_variant);
        }
    }
}

#[test]
fn foreign_scope() {
    let values: [ForeignScope; 3] = [
        ForeignScope::Module,
        ForeignScope::Session { handle: 4, slot: 5 },
        ForeignScope::Slot(4),
    ];
    for item in &values {
        fn require_eq<T: Eq>(_: &T) {}
        require_eq(item);
        assert_eq!(item, item);
        assert!(!format!("{item:?}").is_empty());
        let copied = *item;
        assert_eq!(&copied, item);
        let cloned = (*item).clone();
        assert_eq!(&cloned, item);
    }
    for (index, item) in values.iter().enumerate() {
        for different_variant in &values[index + 1..] {
            assert_ne!(item, different_variant);
        }
    }
}
