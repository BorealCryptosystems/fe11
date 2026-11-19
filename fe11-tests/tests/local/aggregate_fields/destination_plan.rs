// SPDX-License-Identifier: Apache-2.0
use fe11::*;

use super::fixtures;

#[test]
fn destination_plan() {
    let base = || DestinationPlan {
        search: DestinationSearchPlan::NotRequested,
        user: DestinationUserObservation::NotRequested,
    };
    let samples: [DestinationSearchPlan; 2] = [
        DestinationSearchPlan::NotRequested,
        DestinationSearchPlan::Observe {
            resources: fixtures::search_plan(false),
            source: DestinationSource::Exclude,
            template: ReferenceTemplate::Fields(std::sync::Arc::new(
                std::collections::BTreeSet::new(),
            )),
        },
    ];
    for expected in samples {
        let instance = DestinationPlan {
            search: expected.clone(),
            ..base()
        };
        assert_eq!(instance.search, expected);
    }
    let samples: [DestinationUserObservation; 2] = [
        DestinationUserObservation::NotRequested,
        DestinationUserObservation::Read,
    ];
    for expected in samples {
        let instance = DestinationPlan {
            user: expected.clone(),
            ..base()
        };
        assert_eq!(instance.user, expected);
    }
}
