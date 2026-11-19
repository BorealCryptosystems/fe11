// SPDX-License-Identifier: Apache-2.0
use fe11::*;

use super::fixtures;

#[test]
fn symmetric_key_spec() {
    let base = || SymmetricKeySpec {
        admission: fixtures::object_admission(false),
        algorithm: SymmetricAlgorithm::Aes128,
        history: fixtures::history_observation_plan(false),
        hmac_key_type: None,
        id: vec![],
        label: "".to_owned(),
        mechanisms: MechanismObservationPlan::NotRequested,
        persistent: true,
        protection_request: fixtures::current_key_protection(false),
        usages: fixtures::key_usage_request(false),
        visibility: ObjectVisibility::Private,
    };
    let samples: [ObjectAdmission; 2] = [
        fixtures::object_admission(false),
        fixtures::object_admission(true),
    ];
    for expected in samples {
        let instance = SymmetricKeySpec {
            admission: expected.clone(),
            ..base()
        };
        assert_eq!(instance.admission, expected);
    }
    let samples: [SymmetricAlgorithm; 7] = [
        SymmetricAlgorithm::Aes128,
        SymmetricAlgorithm::Aes192,
        SymmetricAlgorithm::Aes256,
        SymmetricAlgorithm::ChaCha20,
        SymmetricAlgorithm::HmacSha256 { key_length: 5 },
        SymmetricAlgorithm::HmacSha384 { key_length: 5 },
        SymmetricAlgorithm::HmacSha512 { key_length: 5 },
    ];
    for expected in samples {
        let instance = SymmetricKeySpec {
            algorithm: expected.clone(),
            ..base()
        };
        assert_eq!(instance.algorithm, expected);
    }
    let samples: [HistoryObservationPlan; 2] = [
        fixtures::history_observation_plan(false),
        fixtures::history_observation_plan(true),
    ];
    for expected in samples {
        let instance = SymmetricKeySpec {
            history: expected.clone(),
            ..base()
        };
        assert_eq!(instance.history, expected);
    }
    let samples: [Option<HmacKeyType>; 3] = [
        None,
        Some(HmacKeyType::Dedicated),
        Some(HmacKeyType::Generic),
    ];
    for expected in samples {
        let instance = SymmetricKeySpec {
            hmac_key_type: expected.clone(),
            ..base()
        };
        assert_eq!(instance.hmac_key_type, expected);
    }
    let samples: [Vec<u8>; 5] = [
        vec![],
        vec![0],
        vec![0xff],
        vec![0, 1, 0xfe, 0xff],
        vec![46],
    ];
    for expected in samples {
        let instance = SymmetricKeySpec {
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
        "field5".to_owned(),
    ];
    for expected in samples {
        let instance = SymmetricKeySpec {
            label: expected.clone(),
            ..base()
        };
        assert_eq!(instance.label, expected);
    }
    let samples: [MechanismObservationPlan; 2] = [
        MechanismObservationPlan::NotRequested,
        MechanismObservationPlan::Read { maximum_bytes: 10 },
    ];
    for expected in samples {
        let instance = SymmetricKeySpec {
            mechanisms: expected.clone(),
            ..base()
        };
        assert_eq!(instance.mechanisms, expected);
    }
    let samples: [bool; 2] = [true, false];
    for expected in samples {
        let instance = SymmetricKeySpec {
            persistent: expected.clone(),
            ..base()
        };
        assert_eq!(instance.persistent, expected);
    }
    let samples: [CurrentKeyProtection; 2] = [
        fixtures::current_key_protection(false),
        fixtures::current_key_protection(true),
    ];
    for expected in samples {
        let instance = SymmetricKeySpec {
            protection_request: expected.clone(),
            ..base()
        };
        assert_eq!(instance.protection_request, expected);
    }
    let samples: [KeyUsageRequest; 2] = [
        fixtures::key_usage_request(false),
        fixtures::key_usage_request(true),
    ];
    for expected in samples {
        let instance = SymmetricKeySpec {
            usages: expected.clone(),
            ..base()
        };
        assert_eq!(instance.usages, expected);
    }
    let samples: [ObjectVisibility; 2] = [ObjectVisibility::Private, ObjectVisibility::Public];
    for expected in samples {
        let instance = SymmetricKeySpec {
            visibility: expected.clone(),
            ..base()
        };
        assert_eq!(instance.visibility, expected);
    }
}
