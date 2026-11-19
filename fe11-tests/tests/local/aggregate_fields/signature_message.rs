// SPDX-License-Identifier: Apache-2.0
use fe11::*;

#[test]
fn signature_message() {
    let base = || SignatureMessage { parts: &[] };
    let samples: [&'static [&'static [u8]]; 3] = [&[], &[&[]], &[&[0], &[255]]];
    for expected in samples {
        let instance = SignatureMessage {
            parts: expected,
            ..base()
        };
        assert_eq!(instance.parts, expected);
    }
}
