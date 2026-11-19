// SPDX-License-Identifier: Apache-2.0
//! Small, explicit native requests for each typed generation entry point.
use super::{generation_transition_spec as aes, object_fixture, outcome::Failure};
use fe11::*;

pub fn supported(route: &str) -> bool {
    matches!(
        route,
        "typed_generate_hkdf_key"
            | "typed_generate_agreement_key"
            | "typed_generate_transport_agreement_key"
            | "typed_generate_montgomery_key"
            | "typed_generate_montgomery_key_448"
            | "typed_generate_classical_key_pair"
            | "typed_generate_transport_signing_key_pair"
            | "typed_generate_rsa_key_encryption_pair"
            | "typed_generate_pqc_key_pair"
            | "typed_generate_kem_key_pair"
    )
}
pub fn count(route: &str) -> usize {
    if route == "typed_generate_hkdf_key" {
        1
    } else {
        2
    }
}
pub fn mechanism(route: &str) -> u64 {
    match route {
        "typed_generate_hkdf_key" => fe11_sys::CKM_GENERIC_SECRET_KEY_GEN as u64,
        "typed_generate_montgomery_key" | "typed_generate_montgomery_key_448" => {
            fe11_sys::CKM_EC_MONTGOMERY_KEY_PAIR_GEN as u64
        }
        "typed_generate_rsa_key_encryption_pair" => fe11_sys::CKM_RSA_PKCS_KEY_PAIR_GEN as u64,
        "typed_generate_pqc_key_pair" => fe11_sys::CKM_ML_DSA_KEY_PAIR_GEN as u64,
        "typed_generate_kem_key_pair" => fe11_sys::CKM_ML_KEM_KEY_PAIR_GEN as u64,
        _ => fe11_sys::CKM_EC_KEY_PAIR_GEN as u64,
    }
}
pub fn protection() -> CurrentKeyProtection {
    CurrentKeyProtection {
        sensitive: true,
        extractable: false,
    }
}
fn admission(label: &str) -> ObjectAdmission {
    let mut value = object_fixture::public_key_options(label.as_bytes()).admission;
    value.observation.verify = false;
    value.observation.maximum_bytes = 2;
    value
}
fn agreement(label: &str) -> AgreementKeySpec {
    AgreementKeySpec {
        public_usages: KeyUsageRequest {
            derive: Some(true),
            ..KeyUsageRequest::omitted()
        },
        private_usages: KeyUsageRequest {
            derive: Some(true),
            ..KeyUsageRequest::omitted()
        },
        public_visibility: ObjectVisibility::Public,
        private_visibility: ObjectVisibility::Public,
        public_admission: admission(label),
        private_admission: admission(label),
        mechanisms: MechanismObservationPlan::NotRequested,
        curve: AgreementCurve::P256,
        id: label.as_bytes().to_vec(),
        label: label.into(),
        persistent: true,
    }
}
fn classical(label: &str) -> ClassicalKeySpec {
    ClassicalKeySpec {
        rsa_public_exponent: None,
        public_usages: KeyUsageRequest {
            verify: Some(true),
            ..KeyUsageRequest::omitted()
        },
        private_usages: KeyUsageRequest {
            sign: Some(true),
            ..KeyUsageRequest::omitted()
        },
        public_visibility: ObjectVisibility::Public,
        private_visibility: ObjectVisibility::Public,
        private_protection: protection(),
        public_admission: admission(label),
        private_admission: admission(label),
        mechanisms: MechanismObservationPlan::NotRequested,
        algorithm: ClassicalKeyAlgorithm::Ecdsa(EcCurve::P256),
        id: label.as_bytes().to_vec(),
        label: label.into(),
        persistent: true,
        profiles: Vec::new(),
    }
}
fn policy() -> MechanismAttributes<'static> {
    MechanismAttributes {
        request: MechanismRequest::Omitted,
        admission: MechanismObservationPlan::NotRequested,
    }
}
pub fn invalid_reason(route: &str) -> Option<RejectionReason> {
    match route {
        "typed_generate_pqc_key_pair" => Some(RejectionReason::PostQuantumKeys(
            PostQuantumKeysRejection::PqcPairObservationBudget,
        )),
        "typed_generate_kem_key_pair" => Some(RejectionReason::KeyEncapsulation(
            KeyEncapsulationRejection::MlKemPairObservationBudget,
        )),
        _ => None,
    }
}
pub fn start(
    session: &AdvancedSession,
    route: &str,
    label: &str,
    invalid: bool,
) -> std::result::Result<OperationTicket, Failure> {
    if invalid && invalid_reason(route).is_none() {
        return Err(Failure::Input("generation_local_negative_not_defined"));
    }
    Ok(match route {
        "typed_generate_hkdf_key" => session.generate_hkdf_key(
            HkdfKeySpec {
                usages: KeyUsageRequest {
                    derive: Some(true),
                    ..KeyUsageRequest::omitted()
                },
                visibility: ObjectVisibility::Public,
                length: 32,
                admission: admission(label),
                mechanisms: MechanismObservationPlan::NotRequested,
                kind: HkdfKeyType::Generic,
                id: label.as_bytes().to_vec(),
                label: label.into(),
                persistent: true,
            },
            protection(),
            aes::history(),
        ),
        "typed_generate_agreement_key" => {
            session.generate_agreement_key(agreement(label), protection(), aes::history())
        }
        "typed_generate_transport_agreement_key" => {
            session.generate_transport_agreement_key(AgreementIntroductionSpec {
                native_protection: protection(),
                history_observation: aes::history(),
                key: agreement(label),
            })
        }
        "typed_generate_montgomery_key" | "typed_generate_montgomery_key_448" => {
            let key = agreement(label);
            session.generate_montgomery_key(
                MontgomeryKeySpec {
                    public_usages: key.public_usages,
                    private_usages: key.private_usages,
                    public_visibility: key.public_visibility,
                    private_visibility: key.private_visibility,
                    public_admission: key.public_admission,
                    private_admission: key.private_admission,
                    mechanisms: key.mechanisms,
                    domain: if route == "typed_generate_montgomery_key_448" {
                        MontgomeryDomain::Curve448
                    } else {
                        MontgomeryDomain::Curve25519
                    },
                    id: key.id,
                    label: key.label,
                    persistent: key.persistent,
                },
                protection(),
                aes::history(),
            )
        }
        "typed_generate_classical_key_pair" => session
            .generate_classical_key_pair(classical(label), MechanismObservationPlan::NotRequested),
        "typed_generate_transport_signing_key_pair" => session.generate_transport_signing_key_pair(
            SigningIntroductionSpec {
                history_observation: aes::history(),
                key: classical(label),
            },
            MechanismObservationPlan::NotRequested,
        ),
        "typed_generate_rsa_key_encryption_pair" => session.generate_rsa_key_encryption_pair(
            RsaKeyEncryptionSpec {
                public_exponent: Some(vec![1, 0, 1]),
                native_protection: protection(),
                public_visibility: ObjectVisibility::Public,
                private_visibility: ObjectVisibility::Public,
                public_usages: KeyUsageRequest {
                    wrap: Some(true),
                    ..KeyUsageRequest::omitted()
                },
                private_usages: KeyUsageRequest {
                    unwrap: Some(true),
                    ..KeyUsageRequest::omitted()
                },
                history_observation: aes::history(),
                public_admission: admission(label),
                private_admission: admission(label),
                bits: 2048,
                id: label.as_bytes().to_vec(),
                label: label.into(),
                persistent: true,
            },
            MechanismObservationPlan::NotRequested,
            MechanismObservationPlan::NotRequested,
        ),
        "typed_generate_pqc_key_pair" => {
            let mut public = admission(label);
            if invalid {
                public.metadata.maximum_bytes = 0;
            }
            session.generate_pqc_key_pair(
                PqcKeySpec {
                    public_usages: KeyUsageRequest {
                        verify: Some(true),
                        ..KeyUsageRequest::omitted()
                    },
                    private_usages: KeyUsageRequest {
                        sign: Some(true),
                        ..KeyUsageRequest::omitted()
                    },
                    private_visibility: ObjectVisibility::Public,
                    public_admission: public,
                    private_admission: admission(label),
                    algorithm: PqcAlgorithm::MlDsa(MlDsaParameterSet::MlDsa44),
                    id: label.as_bytes().to_vec(),
                    label: label.into(),
                    persistent: true,
                },
                policy(),
                policy(),
                protection(),
                ObjectVisibility::Public,
            )
        }
        "typed_generate_kem_key_pair" => {
            let mut public = admission(label);
            if invalid {
                public.metadata.maximum_bytes = 0;
            }
            session.generate_kem_key_pair(
                KemKeySpec {
                    public_usages: KeyUsageRequest {
                        encapsulate: Some(true),
                        ..KeyUsageRequest::omitted()
                    },
                    private_usages: KeyUsageRequest {
                        decapsulate: Some(true),
                        ..KeyUsageRequest::omitted()
                    },
                    private_visibility: ObjectVisibility::Public,
                    public_admission: public,
                    private_admission: admission(label),
                    parameter_set: MlKemParameterSet::MlKem512,
                    id: label.as_bytes().to_vec(),
                    label: label.into(),
                    persistent: true,
                },
                policy(),
                policy(),
                protection(),
                ObjectVisibility::Public,
            )
        }
        _ => return Err(Failure::Input("generation_family")),
    }?)
}
pub fn observation(value: GeneratedObjects, route: &str) -> std::result::Result<(), Failure> {
    let correct = matches!(
        (route, value),
        ("typed_generate_hkdf_key", GeneratedObjects::HkdfKey(_))
            | (
                "typed_generate_agreement_key",
                GeneratedObjects::AgreementKeyPair(_)
            )
            | (
                "typed_generate_transport_agreement_key",
                GeneratedObjects::TransportAgreementKeyPair(_)
            )
            | (
                "typed_generate_montgomery_key" | "typed_generate_montgomery_key_448",
                GeneratedObjects::MontgomeryKeyPair(_)
            )
            | (
                "typed_generate_classical_key_pair",
                GeneratedObjects::ClassicalKeyPair(_)
            )
            | (
                "typed_generate_transport_signing_key_pair",
                GeneratedObjects::TransportSigningKeyPair(_)
            )
            | (
                "typed_generate_rsa_key_encryption_pair",
                GeneratedObjects::RsaKeyEncryptionPair(_)
            )
            | (
                "typed_generate_pqc_key_pair",
                GeneratedObjects::PqcKeyPair(_)
            )
            | (
                "typed_generate_kem_key_pair",
                GeneratedObjects::KemKeyPair(_)
            )
    );
    if correct {
        Ok(())
    } else {
        Err(Failure::Oracle("generated_family_descriptive_kind"))
    }
}
