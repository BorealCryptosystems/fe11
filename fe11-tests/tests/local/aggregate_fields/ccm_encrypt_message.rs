// SPDX-License-Identifier: Apache-2.0
use fe11::*;

use super::fixtures;

#[test]
fn ccm_encrypt_message() {
    let base = || CcmEncryptMessage {
        aad: &[],
        mac_length: 4,
        nonce: fixtures::ccm_nonce(false),
        parts: &[],
    };
    let samples: [&[u8]; 5] = [&[], &[0], &[0xff], &[0, 1, 0xfe, 0xff], &[42]];
    for expected in samples {
        let instance = CcmEncryptMessage {
            aad: expected,
            ..base()
        };
        assert_eq!(instance.aad, expected);
    }
    let samples: [u64; 4] = [4, 0, 1, u64::MAX];
    for expected in samples {
        let instance = CcmEncryptMessage {
            mac_length: expected.clone(),
            ..base()
        };
        assert_eq!(instance.mac_length, expected);
    }
    let samples: [CcmNonce; 2] = [fixtures::ccm_nonce(false), fixtures::ccm_nonce(true)];
    for expected in samples {
        let instance = CcmEncryptMessage {
            nonce: expected.clone(),
            ..base()
        };
        assert_eq!(instance.nonce, expected);
    }
    let samples: [&'static [&'static [u8]]; 3] = [&[], &[&[]], &[&[0], &[255]]];
    for expected in samples {
        let instance = CcmEncryptMessage {
            parts: expected,
            ..base()
        };
        assert_eq!(instance.parts, expected);
    }
}
