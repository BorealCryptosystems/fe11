// SPDX-License-Identifier: Apache-2.0
use fe11::*;

use super::fixtures;

#[test]
fn content_mutation_plan() {
    let base = || ContentMutationPlan {
        after: ContentObservation::NotRequested,
        before: ContentObservation::NotRequested,
    };
    let samples: [ContentObservation; 2] = [
        ContentObservation::NotRequested,
        ContentObservation::Observe(ContentReadPlan::PublicFingerprintV1 {
            read: fixtures::attribute_read_plan(false),
        }),
    ];
    for expected in samples {
        let instance = ContentMutationPlan {
            after: expected.clone(),
            ..base()
        };
        assert_eq!(instance.after, expected);
    }
    let samples: [ContentObservation; 2] = [
        ContentObservation::NotRequested,
        ContentObservation::Observe(ContentReadPlan::PublicFingerprintV1 {
            read: fixtures::attribute_read_plan(false),
        }),
    ];
    for expected in samples {
        let instance = ContentMutationPlan {
            before: expected.clone(),
            ..base()
        };
        assert_eq!(instance.before, expected);
    }
}
