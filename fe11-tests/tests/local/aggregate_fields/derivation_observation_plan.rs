// SPDX-License-Identifier: Apache-2.0
use fe11::*;

use super::fixtures;

#[test]
fn derivation_observation_plan() {
    let base = || DerivationObservationPlan {
        child: fixtures::history_observation_plan(false),
        parent: fixtures::history_observation_plan(false),
    };
    let samples: [HistoryObservationPlan; 2] = [
        fixtures::history_observation_plan(false),
        fixtures::history_observation_plan(true),
    ];
    for expected in samples {
        let instance = DerivationObservationPlan {
            child: expected.clone(),
            ..base()
        };
        assert_eq!(instance.child, expected);
    }
    let samples: [HistoryObservationPlan; 2] = [
        fixtures::history_observation_plan(false),
        fixtures::history_observation_plan(true),
    ];
    for expected in samples {
        let instance = DerivationObservationPlan {
            parent: expected.clone(),
            ..base()
        };
        assert_eq!(instance.parent, expected);
    }
}
