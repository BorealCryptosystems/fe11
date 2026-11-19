// SPDX-License-Identifier: Apache-2.0
use fe11::*;

use super::fixtures;

#[test]
fn kem_key_spec() {
    let base = || KemKeySpec {
        id: vec![],
        label: "".to_owned(),
        parameter_set: MlKemParameterSet::MlKem1024,
        persistent: true,
        private_admission: fixtures::object_admission(false),
        private_usages: fixtures::key_usage_request(false),
        private_visibility: ObjectVisibility::Private,
        public_admission: fixtures::object_admission(false),
        public_usages: fixtures::key_usage_request(false),
    };
    let samples: [Vec<u8>; 5] = [
        vec![],
        vec![0],
        vec![0xff],
        vec![0, 1, 0xfe, 0xff],
        vec![42],
    ];
    for expected in samples {
        let instance = KemKeySpec {
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
        "field1".to_owned(),
    ];
    for expected in samples {
        let instance = KemKeySpec {
            label: expected.clone(),
            ..base()
        };
        assert_eq!(instance.label, expected);
    }
    let samples: [MlKemParameterSet; 3] = [
        MlKemParameterSet::MlKem1024,
        MlKemParameterSet::MlKem512,
        MlKemParameterSet::MlKem768,
    ];
    for expected in samples {
        let instance = KemKeySpec {
            parameter_set: expected.clone(),
            ..base()
        };
        assert_eq!(instance.parameter_set, expected);
    }
    let samples: [bool; 2] = [true, false];
    for expected in samples {
        let instance = KemKeySpec {
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
        let instance = KemKeySpec {
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
        let instance = KemKeySpec {
            private_usages: expected.clone(),
            ..base()
        };
        assert_eq!(instance.private_usages, expected);
    }
    let samples: [ObjectVisibility; 2] = [ObjectVisibility::Private, ObjectVisibility::Public];
    for expected in samples {
        let instance = KemKeySpec {
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
        let instance = KemKeySpec {
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
        let instance = KemKeySpec {
            public_usages: expected.clone(),
            ..base()
        };
        assert_eq!(instance.public_usages, expected);
    }
}
