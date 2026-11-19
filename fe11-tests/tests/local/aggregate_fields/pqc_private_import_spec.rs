// SPDX-License-Identifier: Apache-2.0
use fe11::*;

use super::fixtures;

#[test]
fn pqc_private_import_spec() {
    let base = || PqcPrivateImportSpec {
        admission: fixtures::object_admission(false),
        history_observation: fixtures::history_observation_plan(false),
        id: vec![],
        label: "".to_owned(),
        persistent: true,
        protection: fixtures::current_key_protection(false),
        usages: fixtures::key_usage_request(false),
        visibility: ObjectVisibility::Private,
    };
    let samples: [ObjectAdmission; 2] = [
        fixtures::object_admission(false),
        fixtures::object_admission(true),
    ];
    for expected in samples {
        let instance = PqcPrivateImportSpec {
            admission: expected.clone(),
            ..base()
        };
        assert_eq!(instance.admission, expected);
    }
    let samples: [HistoryObservationPlan; 2] = [
        fixtures::history_observation_plan(false),
        fixtures::history_observation_plan(true),
    ];
    for expected in samples {
        let instance = PqcPrivateImportSpec {
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
        let instance = PqcPrivateImportSpec {
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
        let instance = PqcPrivateImportSpec {
            label: expected.clone(),
            ..base()
        };
        assert_eq!(instance.label, expected);
    }
    let samples: [bool; 2] = [true, false];
    for expected in samples {
        let instance = PqcPrivateImportSpec {
            persistent: expected.clone(),
            ..base()
        };
        assert_eq!(instance.persistent, expected);
    }
    let samples: [CurrentKeyProtection; 2] = [
        fixtures::current_key_protection(false),
        fixtures::current_key_protection(true),
    ];
    for expected in samples {
        let instance = PqcPrivateImportSpec {
            protection: expected.clone(),
            ..base()
        };
        assert_eq!(instance.protection, expected);
    }
    let samples: [KeyUsageRequest; 2] = [
        fixtures::key_usage_request(false),
        fixtures::key_usage_request(true),
    ];
    for expected in samples {
        let instance = PqcPrivateImportSpec {
            usages: expected.clone(),
            ..base()
        };
        assert_eq!(instance.usages, expected);
    }
    let samples: [ObjectVisibility; 2] = [ObjectVisibility::Private, ObjectVisibility::Public];
    for expected in samples {
        let instance = PqcPrivateImportSpec {
            visibility: expected.clone(),
            ..base()
        };
        assert_eq!(instance.visibility, expected);
    }
}
