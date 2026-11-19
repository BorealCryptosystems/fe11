// SPDX-License-Identifier: Apache-2.0
use fe11::*;

use super::fixtures;

#[test]
fn agreement_key_spec() {
    let base = || AgreementKeySpec {
        curve: AgreementCurve::BrainpoolP256,
        id: vec![],
        label: "".to_owned(),
        mechanisms: MechanismObservationPlan::NotRequested,
        persistent: true,
        private_admission: fixtures::object_admission(false),
        private_usages: fixtures::key_usage_request(false),
        private_visibility: ObjectVisibility::Private,
        public_admission: fixtures::object_admission(false),
        public_usages: fixtures::key_usage_request(false),
        public_visibility: ObjectVisibility::Private,
    };
    let samples: [AgreementCurve; 4] = [
        AgreementCurve::BrainpoolP256,
        AgreementCurve::BrainpoolP384,
        AgreementCurve::P256,
        AgreementCurve::P384,
    ];
    for expected in samples {
        let instance = AgreementKeySpec {
            curve: expected.clone(),
            ..base()
        };
        assert_eq!(instance.curve, expected);
    }
    let samples: [Vec<u8>; 5] = [
        vec![],
        vec![0],
        vec![0xff],
        vec![0, 1, 0xfe, 0xff],
        vec![43],
    ];
    for expected in samples {
        let instance = AgreementKeySpec {
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
        "field2".to_owned(),
    ];
    for expected in samples {
        let instance = AgreementKeySpec {
            label: expected.clone(),
            ..base()
        };
        assert_eq!(instance.label, expected);
    }
    let samples: [MechanismObservationPlan; 2] = [
        MechanismObservationPlan::NotRequested,
        MechanismObservationPlan::Read { maximum_bytes: 7 },
    ];
    for expected in samples {
        let instance = AgreementKeySpec {
            mechanisms: expected.clone(),
            ..base()
        };
        assert_eq!(instance.mechanisms, expected);
    }
    let samples: [bool; 2] = [true, false];
    for expected in samples {
        let instance = AgreementKeySpec {
            persistent: expected.clone(),
            ..base()
        };
        assert_eq!(instance.persistent, expected);
    }
    let samples: [ObjectAdmission; 2] = [
        fixtures::object_admission(false),
        fixtures::object_admission(true),
    ];
    for expected in samples {
        let instance = AgreementKeySpec {
            private_admission: expected.clone(),
            ..base()
        };
        assert_eq!(instance.private_admission, expected);
    }
    let samples: [KeyUsageRequest; 2] = [
        fixtures::key_usage_request(false),
        fixtures::key_usage_request(true),
    ];
    for expected in samples {
        let instance = AgreementKeySpec {
            private_usages: expected.clone(),
            ..base()
        };
        assert_eq!(instance.private_usages, expected);
    }
    let samples: [ObjectVisibility; 2] = [ObjectVisibility::Private, ObjectVisibility::Public];
    for expected in samples {
        let instance = AgreementKeySpec {
            private_visibility: expected.clone(),
            ..base()
        };
        assert_eq!(instance.private_visibility, expected);
    }
    let samples: [ObjectAdmission; 2] = [
        fixtures::object_admission(false),
        fixtures::object_admission(true),
    ];
    for expected in samples {
        let instance = AgreementKeySpec {
            public_admission: expected.clone(),
            ..base()
        };
        assert_eq!(instance.public_admission, expected);
    }
    let samples: [KeyUsageRequest; 2] = [
        fixtures::key_usage_request(false),
        fixtures::key_usage_request(true),
    ];
    for expected in samples {
        let instance = AgreementKeySpec {
            public_usages: expected.clone(),
            ..base()
        };
        assert_eq!(instance.public_usages, expected);
    }
    let samples: [ObjectVisibility; 2] = [ObjectVisibility::Private, ObjectVisibility::Public];
    for expected in samples {
        let instance = AgreementKeySpec {
            public_visibility: expected.clone(),
            ..base()
        };
        assert_eq!(instance.public_visibility, expected);
    }
}
