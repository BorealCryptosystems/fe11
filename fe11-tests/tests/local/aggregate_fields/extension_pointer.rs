// SPDX-License-Identifier: Apache-2.0
use fe11::*;

#[test]
fn extension_pointer() {
    let base = || ExtensionPointer {
        block: 3,
        offset: 4,
        target: ExtensionPointerTarget::Block {
            block: 6,
            offset: 7,
        },
    };
    let samples: [usize; 4] = [3, 0, 1, usize::MAX];
    for expected in samples {
        let instance = ExtensionPointer {
            block: expected.clone(),
            ..base()
        };
        assert_eq!(instance.block, expected);
    }
    let samples: [usize; 4] = [4, 0, 1, usize::MAX];
    for expected in samples {
        let instance = ExtensionPointer {
            offset: expected.clone(),
            ..base()
        };
        assert_eq!(instance.offset, expected);
    }
    let samples: [ExtensionPointerTarget; 2] = [
        ExtensionPointerTarget::Block {
            block: 6,
            offset: 7,
        },
        ExtensionPointerTarget::Null,
    ];
    for expected in samples {
        let instance = ExtensionPointer {
            target: expected.clone(),
            ..base()
        };
        assert_eq!(instance.target, expected);
    }
}
