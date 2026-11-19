// SPDX-License-Identifier: Apache-2.0
//! Data and HKDF discovery use different identities and observation contracts.
use super::{
    generation_transition_spec::history, object_owner::Owner, outcome::Failure,
    selection_symmetric as symmetric, typed_selection::retain,
};
use fe11::*;
use std::sync::Arc;

const DATA_LABEL: &str = "public-data-selection";
const APPLICATION: &[u8] = b"public-selection";
// CKA_OBJECT_ID is a DER object identifier, here 1.2.3.4, not an arbitrary key ID.
const OBJECT_ID: &[u8] = &[6, 3, 42, 3, 4];

fn admission(data: bool) -> ObjectAdmission {
    let mut plan = symmetric::key(false).admission;
    if data {
        plan.public_attributes = Arc::new(vec![
            Attribute::Class,
            Attribute::ObjectType,
            Attribute::Token,
            Attribute::Private,
        ]);
    }
    plan
}
pub(super) fn hkdf() -> HkdfKeySpec {
    HkdfKeySpec {
        usages: KeyUsageRequest {
            derive: Some(true),
            ..KeyUsageRequest::omitted()
        },
        visibility: ObjectVisibility::Public,
        length: 32,
        admission: admission(false),
        mechanisms: MechanismObservationPlan::NotRequested,
        kind: HkdfKeyType::Generic,
        id: symmetric::ID.to_vec(),
        label: symmetric::LABEL.into(),
        persistent: false,
    }
}
fn attr(attribute: StandardAttribute, value: AttributeInputValue<'_>) -> AttributeInput<'_> {
    AttributeInput {
        attribute: attribute.into(),
        value,
    }
}
fn limits(count: usize) -> AttributeTemplateLimits {
    // All inputs are public fixed fixtures; this includes the native-width scalars.
    AttributeTemplateLimits {
        maximum_attributes: count,
        maximum_depth: 0,
        maximum_value_bytes: 256,
    }
}

pub fn prepare(
    session: &Session,
    route: &str,
    sets: &mut Vec<CreatedObjectSet>,
    native: &mut Vec<NativeObjectRef>,
    expected_spki: &mut Option<Vec<u8>>,
) -> std::result::Result<bool, Failure> {
    if route == "montgomery-empty" {
        return Ok(true);
    }
    if let Some(spki) = super::selection_asymmetric::prepare(session, route, sets)? {
        *expected_spki = Some(spki);
        return Ok(true);
    }
    if route == "managed-data" {
        let plan = admission(true);
        let destination = DestinationPlan {
            search: DestinationSearchPlan::NotRequested,
            user: DestinationUserObservation::NotRequested,
        };
        let spec = DataSpec {
            modifiable: false,
            copyable: false,
            destroyable: true,
            admission: plan,
            content: ContentObservation::NotRequested,
            destination,
            application: "public-selection".into(),
            object_type: OBJECT_ID.to_vec(),
            label: DATA_LABEL.into(),
            private: false,
            persistent: false,
        };
        let mut value = SecretBytes::new(3)?;
        value.as_mut_slice().copy_from_slice(b"abc");
        retain(session.create_data(spec, value)?, sets)?;
    } else if route == "native-data" {
        let template = [
            attr(
                StandardAttribute::CLASS,
                AttributeInputValue::Unsigned(fe11_sys::CKO_DATA as u64),
            ),
            attr(
                StandardAttribute::TOKEN,
                AttributeInputValue::Boolean(false),
            ),
            attr(
                StandardAttribute::PRIVATE,
                AttributeInputValue::Boolean(false),
            ),
            attr(
                StandardAttribute::OBJECT_ID,
                AttributeInputValue::Bytes(OBJECT_ID),
            ),
            attr(
                StandardAttribute::LABEL,
                AttributeInputValue::Bytes(DATA_LABEL.as_bytes()),
            ),
            attr(
                StandardAttribute::APPLICATION,
                AttributeInputValue::Bytes(APPLICATION),
            ),
            attr(StandardAttribute::VALUE, AttributeInputValue::Bytes(b"abc")),
        ];
        native.push(session.create_native_object(&template, limits(template.len()))?);
    } else if route == "hkdf" {
        let template = [
            attr(
                StandardAttribute::CLASS,
                AttributeInputValue::Unsigned(fe11_sys::CKO_SECRET_KEY as u64),
            ),
            attr(
                StandardAttribute::KEY_TYPE,
                AttributeInputValue::Unsigned(fe11_sys::CKK_GENERIC_SECRET as u64),
            ),
            attr(
                StandardAttribute::TOKEN,
                AttributeInputValue::Boolean(false),
            ),
            attr(
                StandardAttribute::PRIVATE,
                AttributeInputValue::Boolean(false),
            ),
            attr(
                StandardAttribute::ID,
                AttributeInputValue::Bytes(symmetric::ID),
            ),
            attr(
                StandardAttribute::LABEL,
                AttributeInputValue::Bytes(symmetric::LABEL.as_bytes()),
            ),
            attr(
                StandardAttribute::DERIVE,
                AttributeInputValue::Boolean(true),
            ),
            attr(
                StandardAttribute::SENSITIVE,
                AttributeInputValue::Boolean(false),
            ),
            attr(
                StandardAttribute::EXTRACTABLE,
                AttributeInputValue::Boolean(true),
            ),
            attr(
                StandardAttribute::VALUE,
                AttributeInputValue::Bytes(&[0; 32]),
            ),
        ];
        native.push(session.create_native_object(&template, limits(template.len()))?);
        let base = session.find_managed(
            ManagedSelector::Key {
                class: ManagedClass::SecretKey,
                id: symmetric::ID.to_vec(),
                content: ContentObservation::NotRequested,
            },
            admission(false),
        )?;
        if base.class() != ManagedClass::SecretKey {
            return Err(Failure::Oracle("hkdf_fixture_class"));
        }
    } else {
        return Ok(false);
    }
    Ok(true)
}

pub enum Selected {
    Exact(ObjectRef),
    Symmetric(symmetric::Selected),
    ExpectedAbsent,
    Asymmetric(super::selection_asymmetric::Selected),
    Rsa(super::selection_rsa::Selected),
    Hkdf(HkdfKey),
    Data(ManagedObjectRef),
    Native(NativeObjectSelection),
}
pub fn find(
    owner: &Owner,
    route: &str,
    expected_spki: Option<&[u8]>,
) -> std::result::Result<Selected, Failure> {
    if matches!(route, "rsa-exact" | "rsa-oaep-exact") {
        return Ok(Selected::Exact(super::selection_exact::find(owner, route)?));
    }
    if route == "montgomery-empty" {
        super::selection_negative::montgomery_absent(owner)?;
        return Ok(Selected::ExpectedAbsent);
    }
    if matches!(route, "agreement" | "agreement-introduced" | "pqc" | "kem") {
        return Ok(Selected::Asymmetric(super::selection_asymmetric::find(
            owner,
            route,
            expected_spki.ok_or(Failure::Input("asymmetric_selection_spki_absent"))?,
        )?));
    }
    if route.starts_with("rsa-") {
        return Ok(Selected::Rsa(super::selection_rsa::find(
            owner,
            route,
            expected_spki.ok_or(Failure::Input("rsa_selection_spki_absent"))?,
        )?));
    }
    let data = || ManagedSelector::Data {
        application: APPLICATION.to_vec(),
        object_type: OBJECT_ID.to_vec(),
        label: DATA_LABEL.as_bytes().to_vec(),
        content: ContentObservation::NotRequested,
    };
    Ok(match (owner, route) {
        (Owner::Session(s), "hkdf") => Selected::Hkdf(s.find_hkdf_key(hkdf(), history())?),
        (Owner::Session(s), "managed-data") => {
            Selected::Data(s.find_managed(data(), admission(true))?)
        }
        (Owner::Session(s), "native-data") => {
            let template = [
                attr(
                    StandardAttribute::CLASS,
                    AttributeInputValue::Unsigned(fe11_sys::CKO_DATA as u64),
                ),
                attr(
                    StandardAttribute::OBJECT_ID,
                    AttributeInputValue::Bytes(OBJECT_ID),
                ),
            ];
            Selected::Native(s.find_native_object_at(
                &template,
                limits(template.len()),
                admission(true).search,
                0,
            )?)
        }
        (Owner::Advanced(s), "managed-data") => {
            Selected::Data(s.find_managed(data(), admission(true))?)
        }
        (Owner::Advanced(s), "hkdf") => {
            let mut ticket = s.find_hkdf_key(hkdf(), history())?;
            match s.poll(&mut ticket)? {
                OperationProgress::HkdfKey(k) => Selected::Hkdf(k),
                _ => return Err(Failure::Oracle("typed_selection_result_variant")),
            }
        }
        _ => Selected::Symmetric(symmetric::find(owner, route)?),
    })
}

fn read(
    owner: &Owner,
    object: &NativeObjectRef,
    attribute: StandardAttribute,
    expected: &[u8],
) -> std::result::Result<(), Failure> {
    let plan = FlatAttributeReadPlan::Value {
        maximum_bytes: 32768,
    };
    let observation = match owner {
        Owner::Session(s) => s.read_flat_attribute(object, attribute, plan)?,
        Owner::Advanced(s) => s.read_flat_attribute(object, attribute, plan)?,
    };
    match observation.value {
        FlatAttributeValue::Available(bytes) if bytes.as_bytes() == expected => Ok(()),
        _ => Err(Failure::Oracle("typed_selection_value_or_metadata")),
    }
}
impl Selected {
    pub fn check(
        &self,
        owner: &Owner,
        expected_spki: Option<&[u8]>,
    ) -> std::result::Result<(), Failure> {
        let (managed, data) = match self {
            Self::Exact(key) => {
                return super::selection_exact::check(
                    owner,
                    key,
                    expected_spki.ok_or(Failure::Input("exact_selection_spki_absent"))?,
                )
            }
            Self::ExpectedAbsent => return Ok(()),
            Self::Asymmetric(key) => {
                return key.check(
                    owner,
                    expected_spki.ok_or(Failure::Input("asymmetric_selection_spki_absent"))?,
                )
            }
            Self::Symmetric(k) => return k.check(),
            Self::Rsa(k) => {
                return k.check(expected_spki.ok_or(Failure::Input("rsa_selection_spki_absent"))?)
            }
            Self::Hkdf(k) => (Some(k.managed()), false),
            Self::Data(k) => (Some(k), true),
            Self::Native(k) => {
                if k.matched != 1 {
                    return Err(Failure::Oracle("typed_selection_native_count"));
                }
                (None, true)
            }
        };
        let class = if data {
            fe11_sys::CKO_DATA
        } else {
            fe11_sys::CKO_SECRET_KEY
        }
        .to_ne_bytes();
        if let Some(key) = managed {
            let expected_class = if data {
                ManagedClass::Data
            } else {
                ManagedClass::SecretKey
            };
            if key.class() != expected_class
                || !key
                    .search_report()
                    .is_some_and(|r| r.cardinality() == 1 && r.selection().index == 0)
            {
                return Err(Failure::Oracle("typed_selection_class_or_cardinality"));
            }
            let id_attribute = if data {
                Attribute::ObjectType
            } else {
                Attribute::Id
            };
            let id = if data { OBJECT_ID } else { symmetric::ID };
            for (attribute, expected) in [
                (Attribute::Class, class.as_slice()),
                (id_attribute, id),
                (Attribute::Token, &[0][..]),
                (Attribute::Private, &[0][..]),
            ] {
                match key.object_observations().attribute_observation(attribute) {
                    AttributeValue::Available(v) if v == expected => (),
                    _ => return Err(Failure::Oracle("typed_selection_observed_attribute")),
                }
            }
            if !data {
                let kind = fe11_sys::CKK_GENERIC_SECRET.to_ne_bytes();
                match key
                    .object_observations()
                    .attribute_observation(Attribute::KeyType)
                {
                    AttributeValue::Available(v) if v.as_slice() == kind => (),
                    _ => return Err(Failure::Oracle("typed_selection_generic_key_type")),
                }
            }
        }
        if data {
            let object = match self {
                Self::Data(k) => k.native_object(),
                Self::Native(k) => k
                    .object
                    .as_ref()
                    .ok_or(Failure::Oracle("typed_selection_native_absent"))?
                    .clone(),
                _ => return Err(Failure::Oracle("typed_selection_data_variant")),
            };
            for (attribute, expected) in [
                (StandardAttribute::CLASS, class.as_slice()),
                (StandardAttribute::OBJECT_ID, OBJECT_ID),
                (StandardAttribute::TOKEN, &[0][..]),
                (StandardAttribute::PRIVATE, &[0][..]),
                (StandardAttribute::LABEL, DATA_LABEL.as_bytes()),
                (StandardAttribute::VALUE, b"abc".as_slice()),
            ] {
                read(owner, &object, attribute, expected)?;
            }
        }
        Ok(())
    }
}
