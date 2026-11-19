// SPDX-License-Identifier: Apache-2.0
use fe11::*;

use super::fixtures;

#[test]
fn token_resource_status() {
    let base = || TokenResourceStatus {
        generation: 3,
        identity: fixtures::token_identity(false),
        usage: fixtures::session_usage(false),
    };
    let samples: [u64; 4] = [3, 0, 1, u64::MAX];
    for expected in samples {
        let instance = TokenResourceStatus {
            generation: expected.clone(),
            ..base()
        };
        assert_eq!(instance.generation, expected);
    }
    let samples: [TokenIdentity; 2] = [
        fixtures::token_identity(false),
        fixtures::token_identity(true),
    ];
    for expected in samples {
        let instance = TokenResourceStatus {
            identity: expected.clone(),
            ..base()
        };
        assert_eq!(instance.identity, expected);
    }
    let samples: [SessionUsage; 2] = [
        fixtures::session_usage(false),
        fixtures::session_usage(true),
    ];
    for expected in samples {
        let instance = TokenResourceStatus {
            usage: expected.clone(),
            ..base()
        };
        assert_eq!(instance.usage, expected);
    }
}
