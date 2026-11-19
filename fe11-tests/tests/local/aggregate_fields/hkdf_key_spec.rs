// SPDX-License-Identifier: Apache-2.0
use fe11::*;

use super::fixtures;

#[test]
fn hkdf_key_spec() {
    let base = || HkdfKeySpec {
        admission: fixtures::object_admission(false),
        id: vec![],
        kind: HkdfKeyType::Dedicated,
        label: "".to_owned(),
        length: 7,
        mechanisms: MechanismObservationPlan::NotRequested,
        persistent: true,
        usages: fixtures::key_usage_request(false),
        visibility: ObjectVisibility::Private,
    };
    let samples: [ObjectAdmission; 2] = [
        fixtures::object_admission(false),
        fixtures::object_admission(true),
    ];
    for expected in samples {
        let instance = HkdfKeySpec {
            admission: expected.clone(),
            ..base()
        };
        assert_eq!(instance.admission, expected);
    }
    let samples: [Vec<u8>; 5] = [
        vec![],
        vec![0],
        vec![0xff],
        vec![0, 1, 0xfe, 0xff],
        vec![43],
    ];
    for expected in samples {
        let instance = HkdfKeySpec {
            id: expected.clone(),
            ..base()
        };
        assert_eq!(instance.id, expected);
    }
    let samples: [HkdfKeyType; 2] = [HkdfKeyType::Dedicated, HkdfKeyType::Generic];
    for expected in samples {
        let instance = HkdfKeySpec {
            kind: expected.clone(),
            ..base()
        };
        assert_eq!(instance.kind, expected);
    }
    let samples: [String; 5] = [
        "".to_owned(),
        "abc".to_owned(),
        "é".to_owned(),
        "a\0b".to_owned(),
        "field3".to_owned(),
    ];
    for expected in samples {
        let instance = HkdfKeySpec {
            label: expected.clone(),
            ..base()
        };
        assert_eq!(instance.label, expected);
    }
    let samples: [usize; 4] = [7, 0, 1, usize::MAX];
    for expected in samples {
        let instance = HkdfKeySpec {
            length: expected.clone(),
            ..base()
        };
        assert_eq!(instance.length, expected);
    }
    let samples: [MechanismObservationPlan; 2] = [
        MechanismObservationPlan::NotRequested,
        MechanismObservationPlan::Read { maximum_bytes: 9 },
    ];
    for expected in samples {
        let instance = HkdfKeySpec {
            mechanisms: expected.clone(),
            ..base()
        };
        assert_eq!(instance.mechanisms, expected);
    }
    let samples: [bool; 2] = [true, false];
    for expected in samples {
        let instance = HkdfKeySpec {
            persistent: expected.clone(),
            ..base()
        };
        assert_eq!(instance.persistent, expected);
    }
    let samples: [KeyUsageRequest; 2] = [
        fixtures::key_usage_request(false),
        fixtures::key_usage_request(true),
    ];
    for expected in samples {
        let instance = HkdfKeySpec {
            usages: expected.clone(),
            ..base()
        };
        assert_eq!(instance.usages, expected);
    }
    let samples: [ObjectVisibility; 2] = [ObjectVisibility::Private, ObjectVisibility::Public];
    for expected in samples {
        let instance = HkdfKeySpec {
            visibility: expected.clone(),
            ..base()
        };
        assert_eq!(instance.visibility, expected);
    }
}
