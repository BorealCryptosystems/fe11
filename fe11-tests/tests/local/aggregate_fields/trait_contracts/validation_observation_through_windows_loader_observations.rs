// SPDX-License-Identifier: Apache-2.0
use super::super::fixtures;
use fe11::*;

#[test]
fn validation_observation() {
    let values: [ValidationObservation; 2] = [
        fixtures::validation_observation(false),
        fixtures::validation_observation(true),
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
fn windows_dependency_search() {
    let values: [WindowsDependencySearch; 2] = [
        WindowsDependencySearch::ApplicationConfigured,
        WindowsDependencySearch::Directories {
            application_added_directories: true,
            application_directory: true,
            module_directory: true,
            system32: true,
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
fn windows_file_pinning() {
    let values: [WindowsFilePinning; 2] = [
        WindowsFilePinning::NotRequested,
        WindowsFilePinning::Pin {
            maximum_ancestors: None,
            maximum_path_code_units: std::num::NonZeroUsize::new(1).unwrap(),
            reparse: WindowsReparseHandling::Reject,
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
fn windows_image_consistency() {
    let values: [WindowsImageConsistency; 2] = [
        WindowsImageConsistency::CompareToPinnedFile {
            maximum_mapped_path_code_units: std::num::NonZeroUsize::new(1).unwrap(),
        },
        WindowsImageConsistency::NotRequested,
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
fn windows_loader_observations() {
    let values: [WindowsLoaderObservations; 2] = [
        WindowsLoaderObservations::NotRequested,
        WindowsLoaderObservations::Selected {
            limits: fixtures::windows_loader_observation_limits(false),
            requests: fixtures::windows_loader_requests(false),
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
