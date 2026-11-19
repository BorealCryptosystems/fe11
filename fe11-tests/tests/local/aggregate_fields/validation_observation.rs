// SPDX-License-Identifier: Apache-2.0
use fe11::*;

#[test]
fn validation_observation() {
    let base = || ValidationObservation {
        function: "",
        message_index: None,
        validation: SessionValidation::Reported(6),
    };
    let samples: [&'static str; 5] = ["", "abc", "é", "a\0b", "field0"];
    for expected in samples {
        let instance = ValidationObservation {
            function: expected,
            ..base()
        };
        assert_eq!(instance.function, expected);
    }
    let samples: [Option<usize>; 4] = [None, Some(0), Some(1), Some(usize::MAX)];
    for expected in samples {
        let instance = ValidationObservation {
            message_index: expected.clone(),
            ..base()
        };
        assert_eq!(instance.message_index, expected);
    }
    let samples: [SessionValidation; 2] = [
        SessionValidation::Reported(6),
        SessionValidation::Unavailable,
    ];
    for expected in samples {
        let instance = ValidationObservation {
            validation: expected.clone(),
            ..base()
        };
        assert_eq!(instance.validation, expected);
    }
}
