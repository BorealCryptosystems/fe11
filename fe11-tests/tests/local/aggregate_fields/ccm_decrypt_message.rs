// SPDX-License-Identifier: Apache-2.0
use fe11::*;

use super::fixtures;

#[test]
fn ccm_decrypt_message() {
    let base = || CcmDecryptMessage {
        aad: &[],
        mac: &[],
        nonce: fixtures::ccm_nonce(false),
        parts: &[],
    };
    let samples: [&[u8]; 5] = [&[], &[0], &[0xff], &[0, 1, 0xfe, 0xff], &[42]];
    for expected in samples {
        let instance = CcmDecryptMessage {
            aad: expected,
            ..base()
        };
        assert_eq!(instance.aad, expected);
    }
    let samples: [&[u8]; 5] = [&[], &[0], &[0xff], &[0, 1, 0xfe, 0xff], &[43]];
    for expected in samples {
        let instance = CcmDecryptMessage {
            mac: expected,
            ..base()
        };
        assert_eq!(instance.mac, expected);
    }
    let samples: [CcmNonce; 2] = [fixtures::ccm_nonce(false), fixtures::ccm_nonce(true)];
    for expected in samples {
        let instance = CcmDecryptMessage {
            nonce: expected.clone(),
            ..base()
        };
        assert_eq!(instance.nonce, expected);
    }
    let samples: [&'static [&'static [u8]]; 3] = [&[], &[&[]], &[&[0], &[255]]];
    for expected in samples {
        let instance = CcmDecryptMessage {
            parts: expected,
            ..base()
        };
        assert_eq!(instance.parts, expected);
    }
}
