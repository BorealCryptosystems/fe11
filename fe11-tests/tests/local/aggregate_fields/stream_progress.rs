// SPDX-License-Identifier: Apache-2.0
use fe11::*;

#[test]
fn stream_progress() {
    let base = || StreamProgress {
        delivered_bytes: 0,
        input_bytes: 0,
        key_inputs: 5,
        output_bytes: 0,
        submissions: 7,
    };
    let samples: [u128; 4] = [0, 1, u128::MAX, 7];
    for expected in samples {
        let instance = StreamProgress {
            delivered_bytes: expected.clone(),
            ..base()
        };
        assert_eq!(instance.delivered_bytes, expected);
    }
    let samples: [u128; 4] = [0, 1, u128::MAX, 8];
    for expected in samples {
        let instance = StreamProgress {
            input_bytes: expected.clone(),
            ..base()
        };
        assert_eq!(instance.input_bytes, expected);
    }
    let samples: [u64; 4] = [5, 0, 1, u64::MAX];
    for expected in samples {
        let instance = StreamProgress {
            key_inputs: expected.clone(),
            ..base()
        };
        assert_eq!(instance.key_inputs, expected);
    }
    let samples: [u128; 4] = [0, 1, u128::MAX, 10];
    for expected in samples {
        let instance = StreamProgress {
            output_bytes: expected.clone(),
            ..base()
        };
        assert_eq!(instance.output_bytes, expected);
    }
    let samples: [u64; 4] = [7, 0, 1, u64::MAX];
    for expected in samples {
        let instance = StreamProgress {
            submissions: expected.clone(),
            ..base()
        };
        assert_eq!(instance.submissions, expected);
    }
}
