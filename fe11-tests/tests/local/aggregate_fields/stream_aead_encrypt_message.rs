// SPDX-License-Identifier: Apache-2.0
use fe11::*;

#[test]
fn stream_aead_encrypt_message() {
    let base = || StreamAeadEncryptMessage {
        aad: &[],
        nonce: StreamAeadNonce::ChaCha20([4; 8]),
        parts: &[],
    };
    let samples: [&[u8]; 5] = [&[], &[0], &[0xff], &[0, 1, 0xfe, 0xff], &[42]];
    for expected in samples {
        let instance = StreamAeadEncryptMessage {
            aad: expected,
            ..base()
        };
        assert_eq!(instance.aad, expected);
    }
    let samples: [StreamAeadNonce; 5] = [
        StreamAeadNonce::ChaCha20([4; 8]),
        StreamAeadNonce::ChaCha20Ietf([4; 12]),
        StreamAeadNonce::Salsa20([4; 8]),
        StreamAeadNonce::XChaCha20([4; 24]),
        StreamAeadNonce::XSalsa20([4; 24]),
    ];
    for expected in samples {
        let instance = StreamAeadEncryptMessage {
            nonce: expected.clone(),
            ..base()
        };
        assert_eq!(instance.nonce, expected);
    }
    let samples: [&'static [&'static [u8]]; 3] = [&[], &[&[]], &[&[0], &[255]]];
    for expected in samples {
        let instance = StreamAeadEncryptMessage {
            parts: expected,
            ..base()
        };
        assert_eq!(instance.parts, expected);
    }
}
