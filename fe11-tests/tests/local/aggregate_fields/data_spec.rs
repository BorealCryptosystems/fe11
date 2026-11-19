// SPDX-License-Identifier: Apache-2.0
use fe11::*;

use super::fixtures;

#[test]
fn data_spec() {
    let base = || DataSpec {
        admission: fixtures::object_admission(false),
        application: "".to_owned(),
        content: ContentObservation::NotRequested,
        copyable: true,
        destination: fixtures::destination_plan(false),
        destroyable: true,
        label: "".to_owned(),
        modifiable: true,
        object_type: vec![],
        persistent: true,
        private: true,
    };
    let samples: [ObjectAdmission; 2] = [
        fixtures::object_admission(false),
        fixtures::object_admission(true),
    ];
    for expected in samples {
        let instance = DataSpec {
            admission: expected.clone(),
            ..base()
        };
        assert_eq!(instance.admission, expected);
    }
    let samples: [String; 5] = [
        "".to_owned(),
        "abc".to_owned(),
        "é".to_owned(),
        "a\0b".to_owned(),
        "field1".to_owned(),
    ];
    for expected in samples {
        let instance = DataSpec {
            application: expected.clone(),
            ..base()
        };
        assert_eq!(instance.application, expected);
    }
    let samples: [ContentObservation; 2] = [
        ContentObservation::NotRequested,
        ContentObservation::Observe(ContentReadPlan::PublicFingerprintV1 {
            read: fixtures::attribute_read_plan(false),
        }),
    ];
    for expected in samples {
        let instance = DataSpec {
            content: expected.clone(),
            ..base()
        };
        assert_eq!(instance.content, expected);
    }
    let samples: [bool; 2] = [true, false];
    for expected in samples {
        let instance = DataSpec {
            copyable: expected.clone(),
            ..base()
        };
        assert_eq!(instance.copyable, expected);
    }
    let samples: [DestinationPlan; 2] = [
        fixtures::destination_plan(false),
        fixtures::destination_plan(true),
    ];
    for expected in samples {
        let instance = DataSpec {
            destination: expected.clone(),
            ..base()
        };
        assert_eq!(instance.destination, expected);
    }
    let samples: [bool; 2] = [true, false];
    for expected in samples {
        let instance = DataSpec {
            destroyable: expected.clone(),
            ..base()
        };
        assert_eq!(instance.destroyable, expected);
    }
    let samples: [String; 5] = [
        "".to_owned(),
        "abc".to_owned(),
        "é".to_owned(),
        "a\0b".to_owned(),
        "field6".to_owned(),
    ];
    for expected in samples {
        let instance = DataSpec {
            label: expected.clone(),
            ..base()
        };
        assert_eq!(instance.label, expected);
    }
    let samples: [bool; 2] = [true, false];
    for expected in samples {
        let instance = DataSpec {
            modifiable: expected.clone(),
            ..base()
        };
        assert_eq!(instance.modifiable, expected);
    }
    let samples: [Vec<u8>; 5] = [
        vec![],
        vec![0],
        vec![0xff],
        vec![0, 1, 0xfe, 0xff],
        vec![50],
    ];
    for expected in samples {
        let instance = DataSpec {
            object_type: expected.clone(),
            ..base()
        };
        assert_eq!(instance.object_type, expected);
    }
    let samples: [bool; 2] = [true, false];
    for expected in samples {
        let instance = DataSpec {
            persistent: expected.clone(),
            ..base()
        };
        assert_eq!(instance.persistent, expected);
    }
    let samples: [bool; 2] = [true, false];
    for expected in samples {
        let instance = DataSpec {
            private: expected.clone(),
            ..base()
        };
        assert_eq!(instance.private, expected);
    }
}
