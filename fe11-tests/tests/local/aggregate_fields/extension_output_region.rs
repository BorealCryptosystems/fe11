// SPDX-License-Identifier: Apache-2.0
use fe11::*;

#[test]
fn extension_output_region() {
    let base = || ExtensionOutputRegion {
        block: 3,
        capacity: 4,
        length: ExtensionOutputLength::Fixed,
        offset: 6,
    };
    let samples: [usize; 4] = [3, 0, 1, usize::MAX];
    for expected in samples {
        let instance = ExtensionOutputRegion {
            block: expected.clone(),
            ..base()
        };
        assert_eq!(instance.block, expected);
    }
    let samples: [usize; 4] = [4, 0, 1, usize::MAX];
    for expected in samples {
        let instance = ExtensionOutputRegion {
            capacity: expected.clone(),
            ..base()
        };
        assert_eq!(instance.capacity, expected);
    }
    let samples: [ExtensionOutputLength; 2] = [
        ExtensionOutputLength::Fixed,
        ExtensionOutputLength::NativeUnsigned {
            block: 6,
            offset: 7,
        },
    ];
    for expected in samples {
        let instance = ExtensionOutputRegion {
            length: expected.clone(),
            ..base()
        };
        assert_eq!(instance.length, expected);
    }
    let samples: [usize; 4] = [6, 0, 1, usize::MAX];
    for expected in samples {
        let instance = ExtensionOutputRegion {
            offset: expected.clone(),
            ..base()
        };
        assert_eq!(instance.offset, expected);
    }
}
