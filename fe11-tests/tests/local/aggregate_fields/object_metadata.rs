// SPDX-License-Identifier: Apache-2.0
use fe11::*;

#[test]
fn object_metadata() {
    let base = || ObjectMetadata {
        ambiguous: true,
        application: AttributeValue::Available(vec![]),
        class: ManagedClass::Certificate,
        id: AttributeValue::Available(vec![]),
        key_type: AttributeValue::Available(vec![]),
        label: AttributeValue::Available(vec![]),
        object_type: AttributeValue::Available(vec![]),
        persistent: AttributeValue::Available(vec![]),
        private: AttributeValue::Available(vec![]),
        unique_id: AttributeValue::Available(vec![]),
    };
    let samples: [bool; 2] = [true, false];
    for expected in samples {
        let instance = ObjectMetadata {
            ambiguous: expected.clone(),
            ..base()
        };
        assert_eq!(instance.ambiguous, expected);
    }
    let samples: [AttributeValue; 5] = [
        AttributeValue::Available(vec![]),
        AttributeValue::Indeterminate,
        AttributeValue::NotRequested,
        AttributeValue::Sensitive,
        AttributeValue::Unsupported,
    ];
    for expected in samples {
        let instance = ObjectMetadata {
            application: expected.clone(),
            ..base()
        };
        assert_eq!(instance.application, expected);
    }
    let samples: [ManagedClass; 13] = [
        ManagedClass::Certificate,
        ManagedClass::Data,
        ManagedClass::DomainParameters,
        ManagedClass::HardwareFeature,
        ManagedClass::Mechanism,
        ManagedClass::Other(6),
        ManagedClass::OtpKey,
        ManagedClass::PrivateKey,
        ManagedClass::Profile,
        ManagedClass::PublicKey,
        ManagedClass::SecretKey,
        ManagedClass::Trust,
        ManagedClass::Validation,
    ];
    for expected in samples {
        let instance = ObjectMetadata {
            class: expected.clone(),
            ..base()
        };
        assert_eq!(instance.class, expected);
    }
    let samples: [AttributeValue; 5] = [
        AttributeValue::Available(vec![]),
        AttributeValue::Indeterminate,
        AttributeValue::NotRequested,
        AttributeValue::Sensitive,
        AttributeValue::Unsupported,
    ];
    for expected in samples {
        let instance = ObjectMetadata {
            id: expected.clone(),
            ..base()
        };
        assert_eq!(instance.id, expected);
    }
    let samples: [AttributeValue; 5] = [
        AttributeValue::Available(vec![]),
        AttributeValue::Indeterminate,
        AttributeValue::NotRequested,
        AttributeValue::Sensitive,
        AttributeValue::Unsupported,
    ];
    for expected in samples {
        let instance = ObjectMetadata {
            key_type: expected.clone(),
            ..base()
        };
        assert_eq!(instance.key_type, expected);
    }
    let samples: [AttributeValue; 5] = [
        AttributeValue::Available(vec![]),
        AttributeValue::Indeterminate,
        AttributeValue::NotRequested,
        AttributeValue::Sensitive,
        AttributeValue::Unsupported,
    ];
    for expected in samples {
        let instance = ObjectMetadata {
            label: expected.clone(),
            ..base()
        };
        assert_eq!(instance.label, expected);
    }
    let samples: [AttributeValue; 5] = [
        AttributeValue::Available(vec![]),
        AttributeValue::Indeterminate,
        AttributeValue::NotRequested,
        AttributeValue::Sensitive,
        AttributeValue::Unsupported,
    ];
    for expected in samples {
        let instance = ObjectMetadata {
            object_type: expected.clone(),
            ..base()
        };
        assert_eq!(instance.object_type, expected);
    }
    let samples: [AttributeValue; 5] = [
        AttributeValue::Available(vec![]),
        AttributeValue::Indeterminate,
        AttributeValue::NotRequested,
        AttributeValue::Sensitive,
        AttributeValue::Unsupported,
    ];
    for expected in samples {
        let instance = ObjectMetadata {
            persistent: expected.clone(),
            ..base()
        };
        assert_eq!(instance.persistent, expected);
    }
    let samples: [AttributeValue; 5] = [
        AttributeValue::Available(vec![]),
        AttributeValue::Indeterminate,
        AttributeValue::NotRequested,
        AttributeValue::Sensitive,
        AttributeValue::Unsupported,
    ];
    for expected in samples {
        let instance = ObjectMetadata {
            private: expected.clone(),
            ..base()
        };
        assert_eq!(instance.private, expected);
    }
    let samples: [AttributeValue; 5] = [
        AttributeValue::Available(vec![]),
        AttributeValue::Indeterminate,
        AttributeValue::NotRequested,
        AttributeValue::Sensitive,
        AttributeValue::Unsupported,
    ];
    for expected in samples {
        let instance = ObjectMetadata {
            unique_id: expected.clone(),
            ..base()
        };
        assert_eq!(instance.unique_id, expected);
    }
}
