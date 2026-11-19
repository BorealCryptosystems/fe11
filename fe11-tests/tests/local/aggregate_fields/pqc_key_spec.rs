// SPDX-License-Identifier: Apache-2.0
use fe11::*;

use super::fixtures;

#[test]
fn pqc_key_spec() {
    let base = || PqcKeySpec {
        algorithm: PqcAlgorithm::MlDsa(MlDsaParameterSet::MlDsa44),
        id: vec![],
        label: "".to_owned(),
        persistent: true,
        private_admission: fixtures::object_admission(false),
        private_usages: fixtures::key_usage_request(false),
        private_visibility: ObjectVisibility::Private,
        public_admission: fixtures::object_admission(false),
        public_usages: fixtures::key_usage_request(false),
    };
    let samples: [PqcAlgorithm; 2] = [
        PqcAlgorithm::MlDsa(MlDsaParameterSet::MlDsa44),
        PqcAlgorithm::SlhDsa(SlhDsaParameterSet::Sha2_128f),
    ];
    for expected in samples {
        let instance = PqcKeySpec {
            algorithm: expected.clone(),
            ..base()
        };
        assert_eq!(instance.algorithm, expected);
    }
    let samples: [Vec<u8>; 5] = [
        vec![],
        vec![0],
        vec![0xff],
        vec![0, 1, 0xfe, 0xff],
        vec![43],
    ];
    for expected in samples {
        let instance = PqcKeySpec {
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
        "field2".to_owned(),
    ];
    for expected in samples {
        let instance = PqcKeySpec {
            label: expected.clone(),
            ..base()
        };
        assert_eq!(instance.label, expected);
    }
    let samples: [bool; 2] = [true, false];
    for expected in samples {
        let instance = PqcKeySpec {
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
        let instance = PqcKeySpec {
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
        let instance = PqcKeySpec {
            private_usages: expected.clone(),
            ..base()
        };
        assert_eq!(instance.private_usages, expected);
    }
    let samples: [ObjectVisibility; 2] = [ObjectVisibility::Private, ObjectVisibility::Public];
    for expected in samples {
        let instance = PqcKeySpec {
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
        let instance = PqcKeySpec {
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
        let instance = PqcKeySpec {
            public_usages: expected.clone(),
            ..base()
        };
        assert_eq!(instance.public_usages, expected);
    }
}
