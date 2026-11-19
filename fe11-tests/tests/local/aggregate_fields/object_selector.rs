// SPDX-License-Identifier: Apache-2.0
use fe11::*;

use super::fixtures;

#[test]
fn object_selector() {
    let base = || ObjectSelector {
        admission: fixtures::object_admission(false),
        class: ObjectClass::PrivateKey,
        companion_selection: fixtures::object_search_selection(false),
        id: vec![],
    };
    let samples: [ObjectAdmission; 2] = [
        fixtures::object_admission(false),
        fixtures::object_admission(true),
    ];
    for expected in samples {
        let instance = ObjectSelector {
            admission: expected.clone(),
            ..base()
        };
        assert_eq!(instance.admission, expected);
    }
    let samples: [ObjectClass; 2] = [ObjectClass::PrivateKey, ObjectClass::PublicKey];
    for expected in samples {
        let instance = ObjectSelector {
            class: expected.clone(),
            ..base()
        };
        assert_eq!(instance.class, expected);
    }
    let samples: [ObjectSearchSelection; 2] = [
        fixtures::object_search_selection(false),
        fixtures::object_search_selection(true),
    ];
    for expected in samples {
        let instance = ObjectSelector {
            companion_selection: expected.clone(),
            ..base()
        };
        assert_eq!(instance.companion_selection, expected);
    }
    let samples: [Vec<u8>; 5] = [
        vec![],
        vec![0],
        vec![0xff],
        vec![0, 1, 0xfe, 0xff],
        vec![45],
    ];
    for expected in samples {
        let instance = ObjectSelector {
            id: expected.clone(),
            ..base()
        };
        assert_eq!(instance.id, expected);
    }
}
