// SPDX-License-Identifier: Apache-2.0
use fe11::*;

use super::fixtures;

#[test]
fn rsa_key_encryption_spec() {
    let base = || RsaKeyEncryptionSpec {
        bits: 3,
        history_observation: fixtures::history_observation_plan(false),
        id: vec![],
        label: "".to_owned(),
        native_protection: fixtures::current_key_protection(false),
        persistent: true,
        private_admission: fixtures::object_admission(false),
        private_usages: fixtures::key_usage_request(false),
        private_visibility: ObjectVisibility::Private,
        public_admission: fixtures::object_admission(false),
        public_exponent: None,
        public_usages: fixtures::key_usage_request(false),
        public_visibility: ObjectVisibility::Private,
    };
    let samples: [usize; 4] = [3, 0, 1, usize::MAX];
    for expected in samples {
        let instance = RsaKeyEncryptionSpec {
            bits: expected.clone(),
            ..base()
        };
        assert_eq!(instance.bits, expected);
    }
    let samples: [HistoryObservationPlan; 2] = [
        fixtures::history_observation_plan(false),
        fixtures::history_observation_plan(true),
    ];
    for expected in samples {
        let instance = RsaKeyEncryptionSpec {
            history_observation: expected.clone(),
            ..base()
        };
        assert_eq!(instance.history_observation, expected);
    }
    let samples: [Vec<u8>; 5] = [
        vec![],
        vec![0],
        vec![0xff],
        vec![0, 1, 0xfe, 0xff],
        vec![44],
    ];
    for expected in samples {
        let instance = RsaKeyEncryptionSpec {
            id: expected.clone(),
            ..base()
        };
        assert_eq!(instance.id, expected);
    }
    let samples: [String; 5] = [
        "".to_owned(),
        "abc".to_owned(),
        "é".to_owned(),
        "a\0b".to_owned(),
        "field3".to_owned(),
    ];
    for expected in samples {
        let instance = RsaKeyEncryptionSpec {
            label: expected.clone(),
            ..base()
        };
        assert_eq!(instance.label, expected);
    }
    let samples: [CurrentKeyProtection; 2] = [
        fixtures::current_key_protection(false),
        fixtures::current_key_protection(true),
    ];
    for expected in samples {
        let instance = RsaKeyEncryptionSpec {
            native_protection: expected.clone(),
            ..base()
        };
        assert_eq!(instance.native_protection, expected);
    }
    let samples: [bool; 2] = [true, false];
    for expected in samples {
        let instance = RsaKeyEncryptionSpec {
            persistent: expected.clone(),
            ..base()
        };
        assert_eq!(instance.persistent, expected);
    }
    let samples: [ObjectAdmission; 2] = [
        fixtures::object_admission(false),
        fixtures::object_admission(true),
    ];
    for expected in samples {
        let instance = RsaKeyEncryptionSpec {
            private_admission: expected.clone(),
            ..base()
        };
        assert_eq!(instance.private_admission, expected);
    }
    let samples: [KeyUsageRequest; 2] = [
        fixtures::key_usage_request(false),
        fixtures::key_usage_request(true),
    ];
    for expected in samples {
        let instance = RsaKeyEncryptionSpec {
            private_usages: expected.clone(),
            ..base()
        };
        assert_eq!(instance.private_usages, expected);
    }
    let samples: [ObjectVisibility; 2] = [ObjectVisibility::Private, ObjectVisibility::Public];
    for expected in samples {
        let instance = RsaKeyEncryptionSpec {
            private_visibility: expected.clone(),
            ..base()
        };
        assert_eq!(instance.private_visibility, expected);
    }
    let samples: [ObjectAdmission; 2] = [
        fixtures::object_admission(false),
        fixtures::object_admission(true),
    ];
    for expected in samples {
        let instance = RsaKeyEncryptionSpec {
            public_admission: expected.clone(),
            ..base()
        };
        assert_eq!(instance.public_admission, expected);
    }
    let samples: [Option<Vec<u8>>; 6] = [
        None,
        Some(vec![]),
        Some(vec![0]),
        Some(vec![0xff]),
        Some(vec![0, 1, 0xfe, 0xff]),
        Some(vec![52]),
    ];
    for expected in samples {
        let instance = RsaKeyEncryptionSpec {
            public_exponent: expected.clone(),
            ..base()
        };
        assert_eq!(instance.public_exponent, expected);
    }
    let samples: [KeyUsageRequest; 2] = [
        fixtures::key_usage_request(false),
        fixtures::key_usage_request(true),
    ];
    for expected in samples {
        let instance = RsaKeyEncryptionSpec {
            public_usages: expected.clone(),
            ..base()
        };
        assert_eq!(instance.public_usages, expected);
    }
    let samples: [ObjectVisibility; 2] = [ObjectVisibility::Private, ObjectVisibility::Public];
    for expected in samples {
        let instance = RsaKeyEncryptionSpec {
            public_visibility: expected.clone(),
            ..base()
        };
        assert_eq!(instance.public_visibility, expected);
    }
}
