// SPDX-License-Identifier: Apache-2.0
use fe11::*;

use super::fixtures;

#[test]
fn oaep_key_spec() {
    let base = || OaepKeySpec {
        bits: 3,
        exponent: 4,
        id: vec![],
        label: "".to_owned(),
        persistent: true,
        private_admission: fixtures::object_admission(false),
        private_protection: fixtures::current_key_protection(false),
        private_usages: fixtures::key_usage_request(false),
        private_visibility: ObjectVisibility::Private,
        public_admission: fixtures::object_admission(false),
        public_usages: fixtures::key_usage_request(false),
        public_visibility: ObjectVisibility::Private,
    };
    let samples: [u32; 4] = [3, 0, 1, u32::MAX];
    for expected in samples {
        let instance = OaepKeySpec {
            bits: expected.clone(),
            ..base()
        };
        assert_eq!(instance.bits, expected);
    }
    let samples: [u64; 4] = [4, 0, 1, u64::MAX];
    for expected in samples {
        let instance = OaepKeySpec {
            exponent: expected.clone(),
            ..base()
        };
        assert_eq!(instance.exponent, expected);
    }
    let samples: [Vec<u8>; 5] = [
        vec![],
        vec![0],
        vec![0xff],
        vec![0, 1, 0xfe, 0xff],
        vec![44],
    ];
    for expected in samples {
        let instance = OaepKeySpec {
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
        let instance = OaepKeySpec {
            label: expected.clone(),
            ..base()
        };
        assert_eq!(instance.label, expected);
    }
    let samples: [bool; 2] = [true, false];
    for expected in samples {
        let instance = OaepKeySpec {
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
        let instance = OaepKeySpec {
            private_admission: expected.clone(),
            ..base()
        };
        assert_eq!(instance.private_admission, expected);
    }
    let samples: [CurrentKeyProtection; 2] = [
        fixtures::current_key_protection(false),
        fixtures::current_key_protection(true),
    ];
    for expected in samples {
        let instance = OaepKeySpec {
            private_protection: expected.clone(),
            ..base()
        };
        assert_eq!(instance.private_protection, expected);
    }
    let samples: [KeyUsageRequest; 2] = [
        fixtures::key_usage_request(false),
        fixtures::key_usage_request(true),
    ];
    for expected in samples {
        let instance = OaepKeySpec {
            private_usages: expected.clone(),
            ..base()
        };
        assert_eq!(instance.private_usages, expected);
    }
    let samples: [ObjectVisibility; 2] = [ObjectVisibility::Private, ObjectVisibility::Public];
    for expected in samples {
        let instance = OaepKeySpec {
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
        let instance = OaepKeySpec {
            public_admission: expected.clone(),
            ..base()
        };
        assert_eq!(instance.public_admission, expected);
    }
    let samples: [KeyUsageRequest; 2] = [
        fixtures::key_usage_request(false),
        fixtures::key_usage_request(true),
    ];
    for expected in samples {
        let instance = OaepKeySpec {
            public_usages: expected.clone(),
            ..base()
        };
        assert_eq!(instance.public_usages, expected);
    }
    let samples: [ObjectVisibility; 2] = [ObjectVisibility::Private, ObjectVisibility::Public];
    for expected in samples {
        let instance = OaepKeySpec {
            public_visibility: expected.clone(),
            ..base()
        };
        assert_eq!(instance.public_visibility, expected);
    }
}
