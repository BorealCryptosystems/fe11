// SPDX-License-Identifier: Apache-2.0
use fe11::*;

#[test]
fn tls_prf_request() {
    let base = || TlsPrfRequest {
        label: &[],
        mechanism: TlsPrfMechanism::Tls,
        output_bytes: 5,
        seed: &[],
    };
    let samples: [&[u8]; 5] = [&[], &[0], &[0xff], &[0, 1, 0xfe, 0xff], &[42]];
    for expected in samples {
        let instance = TlsPrfRequest {
            label: expected,
            ..base()
        };
        assert_eq!(instance.label, expected);
    }
    let samples: [TlsPrfMechanism; 2] = [TlsPrfMechanism::Tls, TlsPrfMechanism::Wtls { digest: 5 }];
    for expected in samples {
        let instance = TlsPrfRequest {
            mechanism: expected.clone(),
            ..base()
        };
        assert_eq!(instance.mechanism, expected);
    }
    let samples: [usize; 4] = [5, 0, 1, usize::MAX];
    for expected in samples {
        let instance = TlsPrfRequest {
            output_bytes: expected.clone(),
            ..base()
        };
        assert_eq!(instance.output_bytes, expected);
    }
    let samples: [&[u8]; 5] = [&[], &[0], &[0xff], &[0, 1, 0xfe, 0xff], &[45]];
    for expected in samples {
        let instance = TlsPrfRequest {
            seed: expected,
            ..base()
        };
        assert_eq!(instance.seed, expected);
    }
}
