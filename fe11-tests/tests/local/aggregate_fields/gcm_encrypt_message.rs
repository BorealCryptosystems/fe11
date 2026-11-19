// SPDX-License-Identifier: Apache-2.0
use fe11::*;

#[test]
fn gcm_encrypt_message() {
    let base = || GcmEncryptMessage {
        aad: &[],
        nonce: AeadNonce::BackendRandom,
        parts: &[],
    };
    let samples: [&[u8]; 5] = [&[], &[0], &[0xff], &[0, 1, 0xfe, 0xff], &[42]];
    for expected in samples {
        let instance = GcmEncryptMessage {
            aad: expected,
            ..base()
        };
        assert_eq!(instance.aad, expected);
    }
    let samples: [AeadNonce; 3] = [
        AeadNonce::BackendRandom,
        AeadNonce::Gcm {
            fixed_bits: 5,
            generator: 6,
            iv: std::sync::Arc::from(&[][..]),
            tag_bits: 8,
        },
        AeadNonce::Provided([4; 12]),
    ];
    for expected in samples {
        let instance = GcmEncryptMessage {
            nonce: expected.clone(),
            ..base()
        };
        assert_eq!(instance.nonce, expected);
    }
    let samples: [&'static [&'static [u8]]; 3] = [&[], &[&[]], &[&[0], &[255]]];
    for expected in samples {
        let instance = GcmEncryptMessage {
            parts: expected,
            ..base()
        };
        assert_eq!(instance.parts, expected);
    }
}
