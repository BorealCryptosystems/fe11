// SPDX-License-Identifier: Apache-2.0
use super::super::fixtures;
use fe11::*;

#[test]
fn generation_invocation() {
    let values: [GenerationInvocation; 2] = [
        GenerationInvocation::GeneratedByThisCall { mechanism: 4 },
        GenerationInvocation::NotGeneratedByThisCall,
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
fn hash_provenance() {
    let values: [HashProvenance; 2] = [
        HashProvenance::ConsumerAttested,
        HashProvenance::Executed(HashExecution::Pkcs11Combined),
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
fn historical_profile() {
    let values: [HistoricalProfile; 4] = [
        HistoricalProfile::Dsa(DsaVerificationHash::Sha1),
        HistoricalProfile::EcdsaSha1,
        HistoricalProfile::RsaPkcs1(HistoricalHash::Md5),
        HistoricalProfile::RsaPss(fixtures::historical_pss_parameters(false)),
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
fn mechanism_observation() {
    let values: [MechanismObservation; 3] = [
        MechanismObservation::Available(fixtures::mechanism_info(false)),
        MechanismObservation::Refused { code: 4 },
        MechanismObservation::Unavailable,
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
fn mechanism_observation_plan() {
    let values: [MechanismObservationPlan; 2] = [
        MechanismObservationPlan::NotRequested,
        MechanismObservationPlan::Read { maximum_bytes: 4 },
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
fn module_integrity() {
    let values: [ModuleIntegrity; 2] = [
        ModuleIntegrity::NotRequested,
        ModuleIntegrity::Sha256 {
            expected: [3; 32],
            on_mismatch: ModuleDigestMismatch::Refuse,
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
fn notification() {
    let values: [Notification; 2] = [Notification::Other(4), Notification::Surrender];
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
fn object_admission() {
    let values: [ObjectAdmission; 2] = [
        fixtures::object_admission(false),
        fixtures::object_admission(true),
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
