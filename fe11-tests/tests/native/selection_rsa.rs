// SPDX-License-Identifier: Apache-2.0
//! RSA lookup preserves the public identity read from the exact generated pair.
use super::{
    generation_transition_spec::history, object_owner::Owner, outcome::Failure,
    selection_symmetric as symmetric,
};
use der::{
    asn1::{Null, ObjectIdentifier, UintRef},
    Decode, Encode, Sequence,
};
use fe11::*;
use sha2::{Digest, Sha256};
use x509_cert::spki::SubjectPublicKeyInfoRef;

fn protection() -> CurrentKeyProtection {
    CurrentKeyProtection {
        sensitive: false,
        extractable: true,
    }
}
fn admission() -> ObjectAdmission {
    symmetric::key(false).admission
}
pub(super) fn classical() -> ClassicalKeySpec {
    ClassicalKeySpec {
        rsa_public_exponent: Some(vec![1, 0, 1]),
        public_usages: KeyUsageRequest {
            verify: Some(true),
            ..KeyUsageRequest::omitted()
        },
        private_usages: KeyUsageRequest {
            sign: Some(true),
            ..KeyUsageRequest::omitted()
        },
        public_visibility: ObjectVisibility::Public,
        private_visibility: ObjectVisibility::Private,
        private_protection: protection(),
        public_admission: admission(),
        private_admission: admission(),
        mechanisms: MechanismObservationPlan::NotRequested,
        algorithm: ClassicalKeyAlgorithm::Rsa { bits: 2048 },
        id: symmetric::ID.to_vec(),
        label: symmetric::LABEL.into(),
        persistent: false,
        profiles: vec![SignatureProfile::RsaPkcs1(HashAlgorithm::Sha256)],
    }
}
fn introduced() -> SigningIntroductionSpec {
    SigningIntroductionSpec {
        history_observation: history(),
        key: classical(),
    }
}
pub(super) fn transport() -> RsaKeyEncryptionSpec {
    RsaKeyEncryptionSpec {
        public_exponent: Some(vec![1, 0, 1]),
        native_protection: protection(),
        public_visibility: ObjectVisibility::Public,
        private_visibility: ObjectVisibility::Private,
        public_usages: KeyUsageRequest {
            wrap: Some(true),
            encrypt: Some(true),
            ..KeyUsageRequest::omitted()
        },
        private_usages: KeyUsageRequest {
            unwrap: Some(true),
            decrypt: Some(true),
            ..KeyUsageRequest::omitted()
        },
        history_observation: history(),
        public_admission: admission(),
        private_admission: admission(),
        bits: 2048,
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
        return Err(Failure::Oracle("rsa_selection_created_count"));
    }
    Ok(created.observation?)
}

#[derive(Sequence)]
struct PublicRsa<'a> {
    modulus: UintRef<'a>,
    exponent: UintRef<'a>,
}
fn public_encoding(
    session: &Session,
    key: &ManagedObjectRef,
    bytes: &[u8],
    expected_exponent: &[u8],
) -> std::result::Result<(), Failure> {
    let spki = SubjectPublicKeyInfoRef::from_der(bytes)
        .map_err(|_| Failure::Oracle("rsa_selection_spki_der"))?;
    let rsa_bytes = spki
        .subject_public_key
        .as_bytes()
        .ok_or(Failure::Oracle("rsa_selection_spki_unused_bits"))?;
    let rsa =
        PublicRsa::from_der(rsa_bytes).map_err(|_| Failure::Oracle("rsa_selection_public_der"))?;
    if spki.algorithm.oid != ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1")
        || spki
            .algorithm
            .parameters
            .and_then(|p| p.decode_as::<Null>().ok())
            .is_none()
        || spki
            .to_der()
            .map_err(|_| Failure::Oracle("rsa_selection_spki_encoding"))?
            != bytes
        || rsa.modulus.as_bytes().len() != 256
        || rsa.modulus.as_bytes()[0] & 0x80 == 0
        || rsa.exponent.as_bytes() != expected_exponent
    {
        return Err(Failure::Oracle("rsa_selection_public_parameters"));
    }
    // Compare the public DER against separate native attribute reads. No private
    // component or self-generated signature is used as an identity oracle.
    for (attribute, expected) in [
        (StandardAttribute::MODULUS, rsa.modulus.as_bytes()),
        (StandardAttribute::PUBLIC_EXPONENT, rsa.exponent.as_bytes()),
    ] {
        let observed = session.read_flat_attribute(
            &key.native_object(),
            attribute,
            FlatAttributeReadPlan::Value {
                maximum_bytes: 32768,
            },
        )?;
        match observed.value {
            FlatAttributeValue::Available(value) if value.as_bytes() == expected => (),
            _ => return Err(Failure::Oracle("rsa_selection_public_native_readback")),
        }
    }
    Ok(())
}
pub fn prepare(
    session: &Session,
    route: &str,
    sets: &mut Vec<CreatedObjectSet>,
    supplied_spki: Option<&[u8]>,
    generation_exponent: Option<&[u8]>,
) -> std::result::Result<Option<Vec<u8>>, Failure> {
    // A non-default exponent makes a dropped public template field observable.
    let exponent = generation_exponent.unwrap_or(&[1, 0, 1]);
    let public = match route {
        "rsa-verify" => {
            let spki = supplied_spki.ok_or(Failure::Input("rsa_selection_public_fixture"))?;
            let mut options =
                super::object_fixture::public_key_options(symmetric::LABEL.as_bytes());
            options.metadata = PublicImportMetadata::Exact {
                id: symmetric::ID.to_vec(),
                label: symmetric::LABEL.as_bytes().to_vec(),
            };
            options.admission = admission();
            let created = session.create_verification_key(
                spki,
                &[VerificationProfile::RsaPkcs1(HashAlgorithm::Sha256)],
                MechanismObservationPlan::NotRequested,
                options,
            )?;
            let count = created.objects.as_slice().len();
            sets.push(created.objects);
            if count != 1 || created.remainder.is_some() {
                return Err(Failure::Oracle("rsa_selection_public_creation_count"));
            }
            let key = created.observation?;
            public_encoding(session, key.management_reference(), spki, exponent)?;
            spki.to_vec()
        }
        "rsa-pair" => {
            let pair = retain(
                session.generate_classical_key_pair(
                    ClassicalKeySpec {
                        rsa_public_exponent: Some(exponent.to_vec()),
                        ..classical()
                    },
                    MechanismObservationPlan::NotRequested,
                )?,
                sets,
            )?;
            public_encoding(
                session,
                pair.public.management_reference(),
                &pair.public_der,
                exponent,
            )?;
            pair.public_der
        }
        "rsa-introduced" => {
            let pair = retain(
                session.generate_transport_signing_key_pair(
                    introduced(),
                    MechanismObservationPlan::NotRequested,
                )?,
                sets,
            )?;
            public_encoding(session, &pair.public, &pair.public_der, exponent)?;
            pair.public_der
        }
        "rsa-wrap" | "rsa-unwrap" => {
            let pair = retain(
                session.generate_rsa_key_encryption_pair(
                    RsaKeyEncryptionSpec {
                        public_exponent: Some(exponent.to_vec()),
                        ..transport()
                    },
                    MechanismObservationPlan::NotRequested,
                    MechanismObservationPlan::NotRequested,
                )?,
                sets,
            )?;
            public_encoding(
                session,
                pair.public().managed(),
                pair.public().spki_der(),
                exponent,
            )?;
            pair.public().spki_der().to_vec()
        }
        _ => return Ok(None),
    };
    Ok(Some(public))
}
pub enum Selected {
    Verification(VerificationKey),
    Pair(ClassicalKeyPair),
    Introduced(IntroducedSigningKey),
    Wrapping(RsaKeyEncryptionPublic),
    Unwrapping(RsaKeyEncryptionPrivate),
}
pub fn find(owner: &Owner, route: &str, spki: &[u8]) -> std::result::Result<Selected, Failure> {
    let profiles = [SignatureProfile::RsaPkcs1(HashAlgorithm::Sha256)];
    let none = || MechanismObservationPlan::NotRequested;
    Ok(match (owner, route) {
        (Owner::Session(s), "rsa-verify") => {
            Selected::Verification(s.find_classical_verification_key(
                symmetric::ID,
                spki,
                &[VerificationProfile::RsaPkcs1(HashAlgorithm::Sha256)],
                none(),
                admission(),
            )?)
        }
        (Owner::Advanced(s), "rsa-verify") => {
            let mut ticket = s.find_classical_verification_key(
                symmetric::ID,
                spki,
                &[VerificationProfile::RsaPkcs1(HashAlgorithm::Sha256)],
                none(),
                admission(),
            )?;
            match s.poll(&mut ticket)? {
                OperationProgress::VerificationKey(key) => Selected::Verification(key),
                _ => return Err(Failure::Oracle("rsa_selection_public_result_variant")),
            }
        }
        (Owner::Session(s), "rsa-pair") => Selected::Pair(s.find_classical_key_pair(
            symmetric::ID,
            spki,
            &profiles,
            none(),
            none(),
            admission(),
            admission(),
        )?),
        (Owner::Advanced(s), "rsa-pair") => {
            let mut ticket = s.find_classical_key_pair(
                symmetric::ID,
                spki,
                &profiles,
                none(),
                none(),
                admission(),
                admission(),
            )?;
            match s.poll(&mut ticket)? {
                OperationProgress::ClassicalKeyPair(pair) => Selected::Pair(pair),
                _ => return Err(Failure::Oracle("rsa_selection_result_variant")),
            }
        }
        (Owner::Session(s), "rsa-introduced") => {
            Selected::Introduced(s.find_introduced_signing_key(introduced(), spki)?)
        }
        (Owner::Session(s), "rsa-wrap") => {
            Selected::Wrapping(s.find_rsa_wrapping_key(transport(), spki, none())?)
        }
        (Owner::Session(s), "rsa-unwrap") => {
            Selected::Unwrapping(s.find_rsa_unwrapping_key(transport(), none())?)
        }
        _ => return Err(Failure::Input("rsa_selection_owner_route")),
    })
}
fn identity(key: &ManagedObjectRef, private: bool) -> std::result::Result<(), Failure> {
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
        return Err(Failure::Oracle("rsa_selection_class_or_cardinality"));
    }
    let class = raw.to_ne_bytes();
    let kind = fe11_sys::CKK_RSA.to_ne_bytes();
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
            _ => return Err(Failure::Oracle("rsa_selection_attribute")),
        }
    }
    Ok(())
}
impl Selected {
    pub fn check(&self, spki: &[u8]) -> std::result::Result<(), Failure> {
        match self {
            Self::Verification(key) => {
                identity(key.management_reference(), false)?;
                let fingerprint: [u8; 32] = Sha256::digest(spki).into();
                if key.fingerprint() != fingerprint
                    || key.profiles() != [VerificationProfile::RsaPkcs1(HashAlgorithm::Sha256)]
                {
                    return Err(Failure::Oracle("rsa_selection_public_identity_or_profile"));
                }
            }
            Self::Pair(pair) => {
                identity(pair.public.management_reference(), false)?;
                identity(pair.private.management_reference(), true)?;
                let fingerprint: [u8; 32] = Sha256::digest(spki).into();
                if pair.public_der != spki
                    || pair.public.fingerprint() != fingerprint
                    || pair.private.fingerprint() != fingerprint
                {
                    return Err(Failure::Oracle("rsa_selection_pair_spki"));
                }
            }
            Self::Introduced(key) => {
                identity(key.managed(), true)?;
                if key.spki_der() != spki {
                    return Err(Failure::Oracle("rsa_selection_introduced_spki"));
                }
            }
            Self::Wrapping(key) => {
                identity(key.managed(), false)?;
                if key.spki_der() != spki {
                    return Err(Failure::Oracle("rsa_selection_wrapping_spki"));
                }
            }
            Self::Unwrapping(key) => identity(key.managed(), true)?,
        }
        Ok(())
    }
}
