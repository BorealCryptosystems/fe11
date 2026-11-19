// SPDX-License-Identifier: Apache-2.0
use fe11::*;

use super::fixtures;

#[test]
fn token_session_limit() {
    let base = || TokenSessionLimit {
        identity: fixtures::token_identity(false),
        limit: fixtures::session_limit(false),
    };
    let samples: [TokenIdentity; 2] = [
        fixtures::token_identity(false),
        fixtures::token_identity(true),
    ];
    for expected in samples {
        let instance = TokenSessionLimit {
            identity: expected.clone(),
            ..base()
        };
        assert_eq!(instance.identity, expected);
    }
    let samples: [SessionLimit; 2] = [
        fixtures::session_limit(false),
        fixtures::session_limit(true),
    ];
    for expected in samples {
        let instance = TokenSessionLimit {
            limit: expected.clone(),
            ..base()
        };
        assert_eq!(instance.limit, expected);
    }
}
