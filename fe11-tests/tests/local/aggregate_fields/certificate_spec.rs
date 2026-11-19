// SPDX-License-Identifier: Apache-2.0
use fe11::*;

use super::fixtures;

#[test]
fn certificate_spec() {
    let base = || CertificateSpec {
        admission: fixtures::object_admission(false),
        category: 4,
        content: ContentObservation::NotRequested,
        copyable: true,
        destination: fixtures::destination_plan(false),
        destroyable: true,
        id: vec![],
        label: "".to_owned(),
        modifiable: true,
        persistent: true,
        private: true,
        trusted: true,
    };
    let samples: [ObjectAdmission; 2] = [
        fixtures::object_admission(false),
        fixtures::object_admission(true),
    ];
    for expected in samples {
        let instance = CertificateSpec {
            admission: expected.clone(),
            ..base()
        };
        assert_eq!(instance.admission, expected);
    }
    let samples: [u64; 4] = [4, 0, 1, u64::MAX];
    for expected in samples {
        let instance = CertificateSpec {
            category: expected.clone(),
            ..base()
        };
        assert_eq!(instance.category, expected);
    }
    let samples: [ContentObservation; 2] = [
        ContentObservation::NotRequested,
        ContentObservation::Observe(ContentReadPlan::PublicFingerprintV1 {
            read: fixtures::attribute_read_plan(false),
        }),
    ];
    for expected in samples {
        let instance = CertificateSpec {
            content: expected.clone(),
            ..base()
        };
        assert_eq!(instance.content, expected);
    }
    let samples: [bool; 2] = [true, false];
    for expected in samples {
        let instance = CertificateSpec {
            copyable: expected.clone(),
            ..base()
        };
        assert_eq!(instance.copyable, expected);
    }
    let samples: [DestinationPlan; 2] = [
        fixtures::destination_plan(false),
        fixtures::destination_plan(true),
    ];
    for expected in samples {
        let instance = CertificateSpec {
            destination: expected.clone(),
            ..base()
        };
        assert_eq!(instance.destination, expected);
    }
    let samples: [bool; 2] = [true, false];
    for expected in samples {
        let instance = CertificateSpec {
            destroyable: expected.clone(),
            ..base()
        };
        assert_eq!(instance.destroyable, expected);
    }
    let samples: [Vec<u8>; 5] = [
        vec![],
        vec![0],
        vec![0xff],
        vec![0, 1, 0xfe, 0xff],
        vec![48],
    ];
    for expected in samples {
        let instance = CertificateSpec {
            id: expected.clone(),
            ..base()
        };
        assert_eq!(instance.id, expected);
    }
    let samples: [String; 5] = [
        "".to_owned(),
        "abc".to_owned(),
        "é".to_owned(),
        "a\0b".to_owned(),
        "field7".to_owned(),
    ];
    for expected in samples {
        let instance = CertificateSpec {
            label: expected.clone(),
            ..base()
        };
        assert_eq!(instance.label, expected);
    }
    let samples: [bool; 2] = [true, false];
    for expected in samples {
        let instance = CertificateSpec {
            modifiable: expected.clone(),
            ..base()
        };
        assert_eq!(instance.modifiable, expected);
    }
    let samples: [bool; 2] = [true, false];
    for expected in samples {
        let instance = CertificateSpec {
            persistent: expected.clone(),
            ..base()
        };
        assert_eq!(instance.persistent, expected);
    }
    let samples: [bool; 2] = [true, false];
    for expected in samples {
        let instance = CertificateSpec {
            private: expected.clone(),
            ..base()
        };
        assert_eq!(instance.private, expected);
    }
    let samples: [bool; 2] = [true, false];
    for expected in samples {
        let instance = CertificateSpec {
            trusted: expected.clone(),
            ..base()
        };
        assert_eq!(instance.trusted, expected);
    }
}
