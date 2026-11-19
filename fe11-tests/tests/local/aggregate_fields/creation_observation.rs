// SPDX-License-Identifier: Apache-2.0
use fe11::*;

use super::fixtures;

#[test]
fn creation_observation() {
    let base = || CreationObservation {
        admission: fixtures::object_admission(false),
        content: ContentObservation::NotRequested,
    };
    let samples: [ObjectAdmission; 2] = [
        fixtures::object_admission(false),
        fixtures::object_admission(true),
    ];
    for expected in samples {
        let instance = CreationObservation {
            admission: expected.clone(),
            ..base()
        };
        assert_eq!(instance.admission, expected);
    }
    let samples: [ContentObservation; 2] = [
        ContentObservation::NotRequested,
        ContentObservation::Observe(ContentReadPlan::PublicFingerprintV1 {
            read: fixtures::attribute_read_plan(false),
        }),
    ];
    for expected in samples {
        let instance = CreationObservation {
            content: expected.clone(),
            ..base()
        };
        assert_eq!(instance.content, expected);
    }
}
