// SPDX-License-Identifier: Apache-2.0
use fe11::*;

use super::fixtures;

#[test]
fn public_key_import_options() {
    let base = || PublicKeyImportOptions {
        admission: fixtures::object_admission(false),
        copyable: true,
        destroyable: true,
        metadata: PublicImportMetadata::Exact {
            id: vec![],
            label: vec![],
        },
        modifiable: true,
        persistent: true,
        usages: fixtures::key_usage_request(false),
        visibility: ObjectVisibility::Private,
    };
    let samples: [ObjectAdmission; 2] = [
        fixtures::object_admission(false),
        fixtures::object_admission(true),
    ];
    for expected in samples {
        let instance = PublicKeyImportOptions {
            admission: expected.clone(),
            ..base()
        };
        assert_eq!(instance.admission, expected);
    }
    let samples: [bool; 2] = [true, false];
    for expected in samples {
        let instance = PublicKeyImportOptions {
            copyable: expected.clone(),
            ..base()
        };
        assert_eq!(instance.copyable, expected);
    }
    let samples: [bool; 2] = [true, false];
    for expected in samples {
        let instance = PublicKeyImportOptions {
            destroyable: expected.clone(),
            ..base()
        };
        assert_eq!(instance.destroyable, expected);
    }
    let samples: [PublicImportMetadata; 2] = [
        PublicImportMetadata::Exact {
            id: vec![],
            label: vec![],
        },
        PublicImportMetadata::SpkiSha256 {
            label: vec![],
            prefix: vec![],
        },
    ];
    for expected in samples {
        let instance = PublicKeyImportOptions {
            metadata: expected.clone(),
            ..base()
        };
        assert_eq!(instance.metadata, expected);
    }
    let samples: [bool; 2] = [true, false];
    for expected in samples {
        let instance = PublicKeyImportOptions {
            modifiable: expected.clone(),
            ..base()
        };
        assert_eq!(instance.modifiable, expected);
    }
    let samples: [bool; 2] = [true, false];
    for expected in samples {
        let instance = PublicKeyImportOptions {
            persistent: expected.clone(),
            ..base()
        };
        assert_eq!(instance.persistent, expected);
    }
    let samples: [KeyUsageRequest; 2] = [
        fixtures::key_usage_request(false),
        fixtures::key_usage_request(true),
    ];
    for expected in samples {
        let instance = PublicKeyImportOptions {
            usages: expected.clone(),
            ..base()
        };
        assert_eq!(instance.usages, expected);
    }
    let samples: [ObjectVisibility; 2] = [ObjectVisibility::Private, ObjectVisibility::Public];
    for expected in samples {
        let instance = PublicKeyImportOptions {
            visibility: expected.clone(),
            ..base()
        };
        assert_eq!(instance.visibility, expected);
    }
}
