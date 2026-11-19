// SPDX-License-Identifier: Apache-2.0
use fe11::*;

#[test]
fn interface_descriptor() {
    let base = || InterfaceDescriptor {
        flags: 3,
        name: vec![],
        standard_version: None,
    };
    let samples: [u64; 4] = [3, 0, 1, u64::MAX];
    for expected in samples {
        let instance = InterfaceDescriptor {
            flags: expected.clone(),
            ..base()
        };
        assert_eq!(instance.flags, expected);
    }
    let samples: [Vec<u8>; 5] = [
        vec![],
        vec![0],
        vec![0xff],
        vec![0, 1, 0xfe, 0xff],
        vec![43],
    ];
    for expected in samples {
        let instance = InterfaceDescriptor {
            name: expected.clone(),
            ..base()
        };
        assert_eq!(instance.name, expected);
    }
    let samples: [Option<(u8, u8)>; 5] = [
        None,
        Some((4, 10)),
        Some((0, 0)),
        Some((1, 255)),
        Some((255, 1)),
    ];
    for expected in samples {
        let instance = InterfaceDescriptor {
            standard_version: expected.clone(),
            ..base()
        };
        assert_eq!(instance.standard_version, expected);
    }
}
