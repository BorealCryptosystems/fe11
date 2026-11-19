// SPDX-License-Identifier: Apache-2.0
use fe11::*;

use super::fixtures;

#[test]
fn object_admission() {
    let base = || ObjectAdmission {
        destination: fixtures::destination_plan(false),
        metadata: fixtures::attribute_read_plan(false),
        observation: fixtures::object_observation_plan(false),
        public_attributes: std::sync::Arc::new(vec![]),
        search: fixtures::search_plan(false),
        selection: fixtures::object_search_selection(false),
    };
    let samples: [DestinationPlan; 2] = [
        fixtures::destination_plan(false),
        fixtures::destination_plan(true),
    ];
    for expected in samples {
        let instance = ObjectAdmission {
            destination: expected.clone(),
            ..base()
        };
        assert_eq!(instance.destination, expected);
    }
    let samples: [AttributeReadPlan; 2] = [
        fixtures::attribute_read_plan(false),
        fixtures::attribute_read_plan(true),
    ];
    for expected in samples {
        let instance = ObjectAdmission {
            metadata: expected.clone(),
            ..base()
        };
        assert_eq!(instance.metadata, expected);
    }
    let samples: [ObjectObservationPlan; 2] = [
        fixtures::object_observation_plan(false),
        fixtures::object_observation_plan(true),
    ];
    for expected in samples {
        let instance = ObjectAdmission {
            observation: expected.clone(),
            ..base()
        };
        assert_eq!(instance.observation, expected);
    }
    let samples: [std::sync::Arc<Vec<Attribute>>; 2] = [
        std::sync::Arc::new(vec![]),
        std::sync::Arc::new(vec![Attribute::Label, Attribute::Id]),
    ];
    for expected in samples {
        let instance = ObjectAdmission {
            public_attributes: expected.clone(),
            ..base()
        };
        assert_eq!(instance.public_attributes, expected);
    }
    let samples: [SearchPlan; 2] = [fixtures::search_plan(false), fixtures::search_plan(true)];
    for expected in samples {
        let instance = ObjectAdmission {
            search: expected.clone(),
            ..base()
        };
        assert_eq!(instance.search, expected);
    }
    let samples: [ObjectSearchSelection; 2] = [
        fixtures::object_search_selection(false),
        fixtures::object_search_selection(true),
    ];
    for expected in samples {
        let instance = ObjectAdmission {
            selection: expected.clone(),
            ..base()
        };
        assert_eq!(instance.selection, expected);
    }
}
