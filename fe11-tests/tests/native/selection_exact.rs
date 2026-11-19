// SPDX-License-Identifier: Apache-2.0
//! Resident RSA selection requires both classes, even when returning the public key.
use super::{object_owner::Owner, outcome::Failure, selection_symmetric as symmetric};
use der::{asn1::UintRef, Decode, Sequence};
use fe11::*;
use x509_cert::spki::SubjectPublicKeyInfoRef;

fn attr(attribute: StandardAttribute, value: AttributeInputValue<'_>) -> AttributeInput<'_> {
    AttributeInput {
        attribute: attribute.into(),
        value,
    }
}

pub fn prepare(
    session: &Session,
    route: &str,
    key: &[Vec<u8>],
    owned: &mut Vec<NativeObjectRef>,
) -> std::result::Result<(), Failure> {
    if key.len() != 8 || key.iter().any(Vec::is_empty) {
        return Err(Failure::Input("exact_selection_rsa_components"));
    }
    if route == "rsa-empty" {
        return Ok(());
    }
    let components = [
        StandardAttribute::MODULUS,
        StandardAttribute::PUBLIC_EXPONENT,
        StandardAttribute::PRIVATE_EXPONENT,
        StandardAttribute::PRIME_1,
        StandardAttribute::PRIME_2,
        StandardAttribute::EXPONENT_1,
        StandardAttribute::EXPONENT_2,
        StandardAttribute::COEFFICIENT,
    ];
    for private in [false, true] {
        if private && route == "rsa-after-destroy" {
            continue;
        }
        let usage = match (route, private) {
            ("rsa-after-destroy", false) => StandardAttribute::VERIFY,
            ("rsa-exact", false) => StandardAttribute::VERIFY,
            ("rsa-exact", true) => StandardAttribute::SIGN,
            ("rsa-oaep-exact", false) => StandardAttribute::ENCRYPT,
            ("rsa-oaep-exact", true) => StandardAttribute::DECRYPT,
            _ => return Err(Failure::Input("exact_selection_route")),
        };
        let class = if private {
            fe11_sys::CKO_PRIVATE_KEY
        } else {
            fe11_sys::CKO_PUBLIC_KEY
        };
        let mut template = vec![
            attr(
                StandardAttribute::CLASS,
                AttributeInputValue::Unsigned(class as u64),
            ),
            attr(
                StandardAttribute::KEY_TYPE,
                AttributeInputValue::Unsigned(fe11_sys::CKK_RSA as u64),
            ),
            attr(
                StandardAttribute::TOKEN,
                AttributeInputValue::Boolean(false),
            ),
            attr(
                StandardAttribute::PRIVATE,
                AttributeInputValue::Boolean(private),
            ),
            attr(
                StandardAttribute::ID,
                AttributeInputValue::Bytes(symmetric::ID),
            ),
            attr(
                StandardAttribute::LABEL,
                AttributeInputValue::Bytes(symmetric::LABEL.as_bytes()),
            ),
            attr(usage, AttributeInputValue::Boolean(true)),
        ];
        if private {
            template.extend([
                attr(
                    StandardAttribute::SENSITIVE,
                    AttributeInputValue::Boolean(false),
                ),
                attr(
                    StandardAttribute::EXTRACTABLE,
                    AttributeInputValue::Boolean(true),
                ),
            ]);
        }
        let count = if private { 8 } else { 2 };
        for (attribute, value) in components.iter().copied().zip(key).take(count) {
            template.push(attr(attribute, AttributeInputValue::Bytes(value)));
        }
        let limits = AttributeTemplateLimits {
            maximum_attributes: template.len(),
            maximum_depth: 0,
            maximum_value_bytes: 32
                + symmetric::ID.len()
                + symmetric::LABEL.len()
                + key.iter().take(count).map(Vec::len).sum::<usize>(),
        };
        // Retain each creation before the next fallible call, including partial setup.
        owned.push(session.create_native_object(&template, limits)?);
    }
    Ok(())
}

pub fn missing(
    creator: &Session,
    owner: &Owner,
    route: &str,
    objects: &mut Vec<NativeObjectRef>,
) -> std::result::Result<(), Failure> {
    let Owner::Session(session) = owner else {
        return Err(Failure::Input("exact_selection_requires_session"));
    };
    if route == "rsa-after-destroy" {
        if objects.len() != 1 {
            return Err(Failure::Oracle("selection_single_owned_object"));
        }
        // The original reference belongs to the creating session. The peer
        // performs a fresh selection only after the creator destroyed it.
        creator.destroy_native_object(&objects[0])?;
        objects.clear();
    } else if !objects.is_empty() {
        return Err(Failure::Oracle("selection_empty_setup"));
    }
    let admission = symmetric::key(false).admission;
    let result = session.find_exact(ObjectSelector {
        companion_selection: admission.selection.clone(),
        admission,
        class: ObjectClass::PublicKey,
        id: symmetric::ID.to_vec(),
    });
    match result {
        Err(Error::Rejected(RejectionReason::ObjectSearch(
            ObjectSearchRejection::SelectedSearchResultAbsent,
        ))) => Ok(()),
        Err(error) => Err(error.into()),
        Ok(_) => Err(Failure::Oracle("absent_rsa_selection_succeeded")),
    }
}

pub fn find(owner: &Owner, route: &str) -> std::result::Result<ObjectRef, Failure> {
    let Owner::Session(session) = owner else {
        return Err(Failure::Input("exact_selection_requires_session"));
    };
    let admission = symmetric::key(false).admission;
    let selector = ObjectSelector {
        companion_selection: admission.selection.clone(),
        admission,
        class: ObjectClass::PublicKey,
        id: symmetric::ID.to_vec(),
    };
    Ok(match route {
        "rsa-exact" => session.find_exact(selector)?,
        "rsa-oaep-exact" => session.find_oaep_exact(selector)?,
        _ => return Err(Failure::Input("exact_selection_route")),
    })
}

#[derive(Sequence)]
struct PublicRsa<'a> {
    modulus: UintRef<'a>,
    exponent: UintRef<'a>,
}

pub fn check(owner: &Owner, key: &ObjectRef, expected: &[u8]) -> std::result::Result<(), Failure> {
    let Owner::Session(session) = owner else {
        return Err(Failure::Input("exact_selection_requires_session"));
    };
    let reports = key
        .pair_search_reports()
        .ok_or(Failure::Oracle("exact_selection_pair_reports"))?;
    if reports
        .iter()
        .any(|r| r.cardinality() != 1 || r.selection().index != 0)
    {
        return Err(Failure::Oracle("exact_selection_pair_cardinality"));
    }
    let class = fe11_sys::CKO_PUBLIC_KEY.to_ne_bytes();
    let kind = fe11_sys::CKK_RSA.to_ne_bytes();
    for (attribute, expected) in [
        (Attribute::Class, class.as_slice()),
        (Attribute::KeyType, kind.as_slice()),
        (Attribute::Id, symmetric::ID),
        (Attribute::Token, &[0][..]),
        (Attribute::Private, &[0][..]),
    ] {
        match key.object_observations().attribute_observation(attribute) {
            AttributeValue::Available(value) if value == expected => (),
            _ => return Err(Failure::Oracle("exact_selection_public_identity")),
        }
    }
    let spki = SubjectPublicKeyInfoRef::from_der(expected)
        .map_err(|_| Failure::Input("exact_selection_spki"))?;
    let bits = spki
        .subject_public_key
        .as_bytes()
        .ok_or(Failure::Input("exact_selection_spki_bits"))?;
    let rsa =
        PublicRsa::from_der(bits).map_err(|_| Failure::Input("exact_selection_public_key"))?;
    // ObjectRef exposes native identity and observations, not its internal fingerprint.
    // Compare its public components to the independent published-key SPKI instead.
    for (attribute, expected) in [
        (StandardAttribute::MODULUS, rsa.modulus.as_bytes()),
        (StandardAttribute::PUBLIC_EXPONENT, rsa.exponent.as_bytes()),
    ] {
        let value = session.read_flat_attribute(
            &key.native_object(),
            attribute,
            FlatAttributeReadPlan::Value {
                maximum_bytes: 32768,
            },
        )?;
        match value.value {
            FlatAttributeValue::Available(value) if value.as_bytes() == expected => (),
            _ => return Err(Failure::Oracle("exact_selection_public_components")),
        }
    }
    Ok(())
}
