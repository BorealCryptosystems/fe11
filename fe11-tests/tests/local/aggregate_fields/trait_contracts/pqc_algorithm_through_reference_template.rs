// SPDX-License-Identifier: Apache-2.0
use super::super::fixtures;
use fe11::*;

#[test]
fn pqc_algorithm() {
    let values: [PqcAlgorithm; 2] = [
        PqcAlgorithm::MlDsa(MlDsaParameterSet::MlDsa44),
        PqcAlgorithm::SlhDsa(SlhDsaParameterSet::Sha2_128f),
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
fn pqc_private_key_algorithm() {
    let values: [PqcPrivateKeyAlgorithm; 2] = [
        PqcPrivateKeyAlgorithm::MlDsa(MlDsaParameterSet::MlDsa44),
        PqcPrivateKeyAlgorithm::MlKem(MlKemParameterSet::MlKem1024),
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
fn pqc_signature_mode() {
    let values: [PqcSignatureMode; 3] = [
        PqcSignatureMode::HashMessage(PqcHash::Sha224),
        PqcSignatureMode::Prehashed(PqcHash::Sha224),
        PqcSignatureMode::Pure,
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
fn public_import_metadata() {
    let values: [PublicImportMetadata; 2] = [
        PublicImportMetadata::Exact {
            id: vec![],
            label: vec![],
        },
        PublicImportMetadata::SpkiSha256 {
            label: vec![],
            prefix: vec![],
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
fn public_key_import_options() {
    let values: [PublicKeyImportOptions; 2] = [
        fixtures::public_key_import_options(false),
        fixtures::public_key_import_options(true),
    ];
    for item in &values {
        fn require_eq<T: Eq>(_: &T) {}
        require_eq(item);
        assert_eq!(item, item);
        assert!(!format!("{item:?}").is_empty());
        let cloned = (*item).clone();
        assert_eq!(&cloned, item);
    }
}

#[test]
fn recover_output_plan() {
    let values: [RecoverOutputPlan; 2] = [
        RecoverOutputPlan::Buffer { capacity: 4 },
        RecoverOutputPlan::LengthOnly,
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
fn reference_search_plan() {
    let values: [ReferenceSearchPlan; 2] = [
        ReferenceSearchPlan::NotRequested,
        ReferenceSearchPlan::Observe {
            resources: fixtures::search_plan(false),
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
fn reference_template() {
    let values: [ReferenceTemplate; 2] = [
        ReferenceTemplate::Fields(std::sync::Arc::new(std::collections::BTreeSet::new())),
        ReferenceTemplate::Selector,
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
