// SPDX-License-Identifier: Apache-2.0
//! Explicit public AES import and selection plans, without implicit usage defaults.
use super::{
    generation_transition_spec::history, object_fixture, object_owner::Owner, outcome::Failure,
};
use fe11::*;
use std::{num::NonZeroUsize, sync::Arc};

pub const LABEL: &str = "public-key-selection";
pub const ID: &[u8] = &[1, 2, 3, 4];

pub fn key(kek: bool) -> SymmetricKeySpec {
    let mut admission = object_fixture::public_key_options(LABEL.as_bytes()).admission;
    admission.public_attributes = Arc::new(vec![
        Attribute::Class,
        Attribute::KeyType,
        Attribute::Id,
        Attribute::Token,
        Attribute::Private,
    ]);
    admission.search = SearchPlan {
        maximum_objects: Some(4),
        batch_size: NonZeroUsize::new(2).unwrap(),
    };
    admission.metadata.maximum_bytes = 32768;
    admission.observation.private = false;
    admission.observation.token = false;
    admission.observation.verify = false;
    admission.observation.maximum_bytes = 32768;
    SymmetricKeySpec {
        usages: if kek {
            KeyUsageRequest {
                wrap: Some(true),
                unwrap: Some(true),
                ..KeyUsageRequest::omitted()
            }
        } else {
            KeyUsageRequest {
                encrypt: Some(true),
                decrypt: Some(true),
                ..KeyUsageRequest::omitted()
            }
        },
        visibility: ObjectVisibility::Public,
        admission,
        protection_request: CurrentKeyProtection {
            sensitive: false,
            extractable: true,
        },
        history: history(),
        mechanisms: MechanismObservationPlan::NotRequested,
        algorithm: SymmetricAlgorithm::Aes128,
        hmac_key_type: None,
        id: ID.to_vec(),
        label: LABEL.into(),
        persistent: false,
    }
}
pub fn introduced() -> SymmetricIntroductionSpec {
    SymmetricIntroductionSpec {
        native_protection: CurrentKeyProtection {
            sensitive: false,
            extractable: true,
        },
        history_observation: history(),
        key: key(false),
    }
}
pub fn kek() -> AesKeyEncryptionSpec {
    AesKeyEncryptionSpec {
        native_protection: CurrentKeyProtection {
            sensitive: false,
            extractable: true,
        },
        history_observation: history(),
        key: key(true),
        usage: KeyTransportUsage::WrapAndUnwrap,
    }
}

pub enum Selected {
    Symmetric(SymmetricKey),
    Introduced(IntroducedSymmetricKey),
    Kek(AesKeyEncryptionKey),
}
impl Selected {
    fn managed(&self) -> &ManagedObjectRef {
        match self {
            Self::Symmetric(k) => k.managed(),
            Self::Introduced(k) => k.managed(),
            Self::Kek(k) => k.managed(),
        }
    }
    pub fn check(&self) -> std::result::Result<(), Failure> {
        let key = self.managed();
        if key.class() != ManagedClass::SecretKey
            || !key
                .search_report()
                .is_some_and(|r| r.cardinality() == 1 && r.selection().index == 0)
        {
            return Err(Failure::Oracle("typed_selection_class_or_cardinality"));
        }
        let class = fe11_sys::CKO_SECRET_KEY.to_ne_bytes();
        let kind = fe11_sys::CKK_AES.to_ne_bytes();
        for (attribute, expected) in [
            (Attribute::Class, class.as_slice()),
            (Attribute::KeyType, kind.as_slice()),
            (Attribute::Id, ID),
            (Attribute::Token, &[0][..]),
            (Attribute::Private, &[0][..]),
        ] {
            match key.object_observations().attribute_observation(attribute) {
                AttributeValue::Available(value) if value == expected => (),
                _ => return Err(Failure::Oracle("typed_selection_observed_attribute")),
            }
        }
        Ok(())
    }
}

pub fn find(owner: &Owner, route: &str) -> std::result::Result<Selected, Failure> {
    Ok(match owner {
        Owner::Session(s) => match route {
            "aes" => Selected::Symmetric(s.find_aes_key(key(false))?),
            "symmetric" => Selected::Symmetric(s.find_symmetric_key(key(false))?),
            "introduced" => Selected::Introduced(s.find_introduced_symmetric_key(introduced())?),
            "kek" => Selected::Kek(s.find_aes_key_encryption_key(kek())?),
            _ => return Err(Failure::Input("typed_selection_route")),
        },
        Owner::Advanced(s) => {
            let mut ticket = match route {
                "aes" => s.find_aes_key(key(false))?,
                "symmetric" => s.find_symmetric_key(key(false))?,
                "introduced" => s.find_introduced_symmetric_key(introduced())?,
                "kek" => s.find_aes_key_encryption_key(kek())?,
                _ => return Err(Failure::Input("typed_selection_route")),
            };
            // Eager native admission reaches publication before the explicit
            // result poll; accepting a different progress value would hide an
            // unfinished operation or a return-type mismatch.
            match (route, s.poll(&mut ticket)?) {
                ("aes" | "symmetric", OperationProgress::SymmetricKey(key)) => {
                    Selected::Symmetric(key)
                }
                ("introduced", OperationProgress::IntroducedSymmetricKey(key)) => {
                    Selected::Introduced(key)
                }
                ("kek", OperationProgress::AesKeyEncryptionKey(key)) => Selected::Kek(key),
                _ => return Err(Failure::Oracle("typed_selection_result_variant")),
            }
        }
    })
}
