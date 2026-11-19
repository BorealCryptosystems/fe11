// SPDX-License-Identifier: Apache-2.0
//! Typed asymmetric selection observes identity without inferring key possession.
use super::{
    generation_transition_spec::history, object_owner::Owner, outcome::Failure,
    selection_symmetric as symmetric,
};
use der::{
    asn1::{ObjectIdentifier, OctetStringRef},
    Decode, Encode,
};
use fe11::*;
use sha2::{Digest, Sha256};
use x509_cert::spki::SubjectPublicKeyInfoRef;

const P256: &[u8] = &[6, 8, 42, 134, 72, 206, 61, 3, 1, 7];
fn admission() -> ObjectAdmission {
    symmetric::key(false).admission
}
fn protection() -> CurrentKeyProtection {
    CurrentKeyProtection {
        sensitive: false,
        extractable: true,
    }
}
fn policy() -> MechanismAttributes<'static> {
    MechanismAttributes {
        request: MechanismRequest::Omitted,
        admission: MechanismObservationPlan::NotRequested,
    }
}
pub(super) fn agreement() -> AgreementKeySpec {
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
        private_visibility: ObjectVisibility::Private,
        public_admission: admission(),
        private_admission: admission(),
        mechanisms: MechanismObservationPlan::NotRequested,
        curve: AgreementCurve::P256,
        id: symmetric::ID.to_vec(),
        label: symmetric::LABEL.into(),
        persistent: false,
    }
}
fn introduced() -> AgreementIntroductionSpec {
    AgreementIntroductionSpec {
        native_protection: protection(),
        history_observation: history(),
        key: agreement(),
    }
}
pub(super) fn pqc() -> PqcKeySpec {
    PqcKeySpec {
        public_usages: KeyUsageRequest {
            verify: Some(true),
            ..KeyUsageRequest::omitted()
        },
        private_usages: KeyUsageRequest {
            sign: Some(true),
            ..KeyUsageRequest::omitted()
        },
        private_visibility: ObjectVisibility::Private,
        public_admission: admission(),
        private_admission: admission(),
        algorithm: PqcAlgorithm::MlDsa(MlDsaParameterSet::MlDsa44),
        id: symmetric::ID.to_vec(),
        label: symmetric::LABEL.into(),
        persistent: false,
    }
}
fn kem() -> KemKeySpec {
    KemKeySpec {
        public_usages: KeyUsageRequest {
            encapsulate: Some(true),
            ..KeyUsageRequest::omitted()
        },
        private_usages: KeyUsageRequest {
            decapsulate: Some(true),
            ..KeyUsageRequest::omitted()
        },
        private_visibility: ObjectVisibility::Private,
        public_admission: admission(),
        private_admission: admission(),
        parameter_set: MlKemParameterSet::MlKem512,
        id: symmetric::ID.to_vec(),
        label: symmetric::LABEL.into(),
        persistent: false,
    }
}
fn retain<T>(
    created: CreatedObjects<T>,
    sets: &mut Vec<CreatedObjectSet>,
) -> std::result::Result<T, Failure> {
    let count = created.objects.as_slice().len();
    sets.push(created.objects);
    if count != 2 || created.remainder.is_some() {
        return Err(Failure::Oracle("asymmetric_selection_created_count"));
    }
    Ok(created.observation?)
}
fn public_encoding(
    session: &Session,
    key: &ManagedObjectRef,
    spki: &[u8],
    route: &str,
) -> std::result::Result<(), Failure> {
    let decoded = SubjectPublicKeyInfoRef::from_der(spki)
        .map_err(|_| Failure::Oracle("selection_spki_der"))?;
    let raw = decoded
        .subject_public_key
        .as_bytes()
        .ok_or(Failure::Oracle("selection_spki_unused_bits"))?;
    let ec = matches!(route, "agreement" | "agreement-introduced");
    let (oid, length) = match route {
        "agreement" | "agreement-introduced" => ("1.2.840.10045.2.1", 65),
        "pqc" => ("2.16.840.1.101.3.4.3.17", 1312),
        "kem" => ("2.16.840.1.101.3.4.4.1", 800),
        _ => return Err(Failure::Input("selection_public_family")),
    };
    if decoded.algorithm.oid
        != ObjectIdentifier::new(oid).map_err(|_| Failure::Input("selection_oid"))?
        || raw.len() != length
        || decoded
            .to_der()
            .map_err(|_| Failure::Oracle("selection_spki_encoding"))?
            != spki
    {
        return Err(Failure::Oracle("selection_spki_algorithm_or_width"));
    }
    if ec {
        let parameters = decoded
            .algorithm
            .parameters
            .ok_or(Failure::Oracle("selection_ec_parameters_absent"))?;
        if parameters
            .to_der()
            .map_err(|_| Failure::Oracle("selection_ec_parameters_der"))?
            != P256
            || raw[0] != 4
        {
            return Err(Failure::Oracle("selection_ec_domain_or_point_form"));
        }
    } else if decoded.algorithm.parameters.is_some() {
        return Err(Failure::Oracle("selection_pqc_parameters_present"));
    }
    let attribute = if ec {
        StandardAttribute::EC_POINT
    } else {
        StandardAttribute::VALUE
    };
    let observation = session.read_flat_attribute(
        &key.native_object(),
        attribute,
        FlatAttributeReadPlan::Value {
            maximum_bytes: 32768,
        },
    )?;
    let FlatAttributeValue::Available(bytes) = observation.value else {
        return Err(Failure::Oracle("selection_public_unavailable"));
    };
    let point = if ec {
        Some(
            OctetStringRef::from_der(bytes.as_bytes())
                .map_err(|_| Failure::Oracle("selection_native_point_der"))?,
        )
    } else {
        None
    };
    let observed = point
        .as_ref()
        .map_or(bytes.as_bytes(), |value| value.as_bytes());
    if observed != raw {
        return Err(Failure::Oracle("selection_public_native_mismatch"));
    }
    Ok(())
}
pub fn prepare(
    session: &Session,
    route: &str,
    sets: &mut Vec<CreatedObjectSet>,
) -> std::result::Result<Option<Vec<u8>>, Failure> {
    let public = match route {
        "agreement" => {
            let pair = retain(
                session.generate_agreement_key(agreement(), protection(), history())?,
                sets,
            )?;
            public_encoding(session, &pair.public, &pair.public_der, route)?;
            pair.public_der
        }
        "agreement-introduced" => {
            let pair = retain(
                session.generate_transport_agreement_key(introduced())?,
                sets,
            )?;
            public_encoding(session, &pair.public, &pair.public_der, route)?;
            pair.public_der
        }
        "pqc" => {
            let pair = retain(
                session.generate_pqc_key_pair(
                    pqc(),
                    policy(),
                    policy(),
                    protection(),
                    ObjectVisibility::Public,
                )?,
                sets,
            )?;
            let spki = pair.public_key.to_spki()?;
            public_encoding(session, pair.public.management_reference(), &spki, route)?;
            spki
        }
        "kem" => {
            let pair = retain(
                session.generate_kem_key_pair(
                    kem(),
                    policy(),
                    policy(),
                    protection(),
                    ObjectVisibility::Public,
                )?,
                sets,
            )?;
            let spki = pair.public.public_key().to_spki()?;
            public_encoding(session, pair.public.managed(), &spki, route)?;
            spki
        }
        _ => return Ok(None),
    };
    Ok(Some(public))
}
pub enum Selected {
    Agreement(AgreementKey),
    Introduced(IntroducedAgreementKey),
    Pqc(PqcKeyPair),
    Kem(KemKeyPair),
}
pub fn find(owner: &Owner, route: &str, spki: &[u8]) -> std::result::Result<Selected, Failure> {
    let none = || MechanismObservationPlan::NotRequested;
    Ok(match owner {
        Owner::Session(s) => match route {
            "agreement" => Selected::Agreement(s.find_agreement_key(agreement(), history())?),
            "agreement-introduced" => {
                Selected::Introduced(s.find_introduced_agreement_key(introduced())?)
            }
            "pqc" => Selected::Pqc(s.find_pqc_key_pair(
                symmetric::ID,
                spki,
                none(),
                none(),
                admission(),
                admission(),
            )?),
            "kem" => Selected::Kem(s.find_kem_key_pair(
                symmetric::ID,
                spki,
                none(),
                none(),
                admission(),
                admission(),
            )?),
            _ => return Err(Failure::Input("asymmetric_selection_route")),
        },
        Owner::Advanced(s) => {
            let mut ticket = match route {
                "agreement" => s.find_agreement_key(agreement(), history())?,
                "agreement-introduced" => s.find_introduced_agreement_key(introduced())?,
                "pqc" => s.find_pqc_key_pair(
                    symmetric::ID,
                    spki,
                    none(),
                    none(),
                    admission(),
                    admission(),
                )?,
                "kem" => s.find_kem_key_pair(
                    symmetric::ID,
                    spki,
                    none(),
                    none(),
                    admission(),
                    admission(),
                )?,
                _ => return Err(Failure::Input("asymmetric_selection_route")),
            };
            match (route, s.poll(&mut ticket)?) {
                ("agreement", OperationProgress::AgreementKey(k)) => Selected::Agreement(k),
                ("agreement-introduced", OperationProgress::IntroducedAgreementKey(k)) => {
                    Selected::Introduced(k)
                }
                ("pqc", OperationProgress::PqcKeyPair(k)) => Selected::Pqc(k),
                ("kem", OperationProgress::KemKeyPair(k)) => Selected::Kem(k),
                _ => return Err(Failure::Oracle("asymmetric_selection_result_variant")),
            }
        }
    })
}
fn identity(
    key: &ManagedObjectRef,
    private: bool,
    kind: fe11_sys::CK_KEY_TYPE,
) -> std::result::Result<(), Failure> {
    let (class, raw) = if private {
        (ManagedClass::PrivateKey, fe11_sys::CKO_PRIVATE_KEY)
    } else {
        (ManagedClass::PublicKey, fe11_sys::CKO_PUBLIC_KEY)
    };
    if key.class() != class
        || !key
            .search_report()
            .is_some_and(|s| s.cardinality() == 1 && s.selection().index == 0)
    {
        return Err(Failure::Oracle("asymmetric_selection_class_or_cardinality"));
    }
    let class = raw.to_ne_bytes();
    let kind = kind.to_ne_bytes();
    let visibility = [u8::from(private)];
    for (attribute, expected) in [
        (Attribute::Class, class.as_slice()),
        (Attribute::KeyType, kind.as_slice()),
        (Attribute::Id, symmetric::ID),
        (Attribute::Token, &[0][..]),
        (Attribute::Private, visibility.as_slice()),
    ] {
        match key.object_observations().attribute_observation(attribute) {
            AttributeValue::Available(value) if value.as_slice() == expected => (),
            _ => return Err(Failure::Oracle("asymmetric_selection_attribute")),
        }
    }
    Ok(())
}
fn domain(owner: &Owner, key: &ManagedObjectRef) -> std::result::Result<(), Failure> {
    let plan = FlatAttributeReadPlan::Value {
        maximum_bytes: 32768,
    };
    let result = match owner {
        Owner::Session(s) => {
            s.read_flat_attribute(&key.native_object(), StandardAttribute::EC_PARAMS, plan)?
        }
        Owner::Advanced(s) => {
            s.read_flat_attribute(&key.native_object(), StandardAttribute::EC_PARAMS, plan)?
        }
    };
    match result.value {
        FlatAttributeValue::Available(bytes) if bytes.as_bytes() == P256 => Ok(()),
        _ => Err(Failure::Oracle("selected_agreement_domain")),
    }
}
impl Selected {
    pub fn check(&self, owner: &Owner, spki: &[u8]) -> std::result::Result<(), Failure> {
        match self {
            Self::Agreement(key) => {
                identity(key.managed(), true, fe11_sys::CKK_EC)?;
                domain(owner, key.managed())?;
            }
            Self::Introduced(key) => {
                identity(key.managed(), true, fe11_sys::CKK_EC)?;
                domain(owner, key.managed())?;
                if key.curve() != AgreementCurve::P256 {
                    return Err(Failure::Oracle("selected_introduced_curve"));
                }
            }
            Self::Pqc(pair) => {
                identity(
                    pair.public.management_reference(),
                    false,
                    fe11_sys::CKK_ML_DSA,
                )?;
                identity(
                    pair.private.management_reference(),
                    true,
                    fe11_sys::CKK_ML_DSA,
                )?;
                let algorithm = PqcAlgorithm::MlDsa(MlDsaParameterSet::MlDsa44);
                let fingerprint: [u8; 32] = Sha256::digest(spki).into();
                if pair.public_key.to_spki()? != spki
                    || pair.public.algorithm() != algorithm
                    || pair.private.algorithm() != algorithm
                    || pair.public.fingerprint() != fingerprint
                    || pair.private.fingerprint() != fingerprint
                {
                    return Err(Failure::Oracle("selected_pqc_identity"));
                }
            }
            Self::Kem(pair) => {
                identity(pair.public.managed(), false, fe11_sys::CKK_ML_KEM)?;
                identity(pair.private.managed(), true, fe11_sys::CKK_ML_KEM)?;
                if pair.public.public_key().to_spki()? != spki
                    || pair.public.public_key().parameter_set() != MlKemParameterSet::MlKem512
                    || pair.private.parameter_set() != MlKemParameterSet::MlKem512
                {
                    return Err(Failure::Oracle("selected_kem_identity"));
                }
            }
        }
        Ok(())
    }
}
