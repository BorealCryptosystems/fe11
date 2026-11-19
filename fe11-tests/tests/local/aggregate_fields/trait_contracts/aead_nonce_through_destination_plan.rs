// SPDX-License-Identifier: Apache-2.0
use super::super::fixtures;
use fe11::*;

#[test]
fn aead_nonce() {
    let values: [AeadNonce; 3] = [
        AeadNonce::BackendRandom,
        AeadNonce::Gcm {
            fixed_bits: 4,
            generator: 5,
            iv: std::sync::Arc::from(&[][..]),
            tag_bits: 7,
        },
        AeadNonce::Provided([3; 12]),
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
fn aes_cipher_parameters() {
    let values: [AesCipherParameters; 8] = [
        AesCipherParameters::Cbc { iv: [3; 16] },
        AesCipherParameters::CbcPad { iv: [3; 16] },
        AesCipherParameters::Cfb128 { iv: [3; 16] },
        AesCipherParameters::Cfb64 { iv: [3; 16] },
        AesCipherParameters::Cfb8 { iv: [3; 16] },
        AesCipherParameters::Ctr {
            counter_bits: 4,
            counter_block: [4; 16],
        },
        AesCipherParameters::Ecb,
        AesCipherParameters::Ofb { iv: [3; 16] },
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
fn attribute_batch_calls() {
    let values: [AttributeBatchCalls; 3] = [
        AttributeBatchCalls::None,
        AttributeBatchCalls::One(fixtures::attribute_batch_call(false)),
        AttributeBatchCalls::Two {
            first: fixtures::attribute_batch_call(false),
            second: fixtures::attribute_batch_call(false),
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
fn attribute_read_calls() {
    let values: [AttributeReadCalls; 3] = [
        AttributeReadCalls::Direct { code: 4 },
        AttributeReadCalls::Size { code: 4 },
        AttributeReadCalls::Value {
            code: 4,
            size_code: 5,
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
fn attribute_value() {
    let values: [AttributeValue; 5] = [
        AttributeValue::Available(vec![]),
        AttributeValue::Indeterminate,
        AttributeValue::NotRequested,
        AttributeValue::Sensitive,
        AttributeValue::Unsupported,
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
fn content_observation() {
    let values: [ContentObservation; 2] = [
        ContentObservation::NotRequested,
        ContentObservation::Observe(ContentReadPlan::PublicFingerprintV1 {
            read: fixtures::attribute_read_plan(false),
        }),
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
fn content_read_plan() {
    let values: [ContentReadPlan; 2] = [
        ContentReadPlan::PublicFingerprintV1 {
            read: fixtures::attribute_read_plan(false),
        },
        ContentReadPlan::Value { maximum_bytes: 4 },
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
fn destination_plan() {
    let values: [DestinationPlan; 2] = [
        fixtures::destination_plan(false),
        fixtures::destination_plan(true),
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
