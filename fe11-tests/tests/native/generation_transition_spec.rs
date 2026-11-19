// SPDX-License-Identifier: Apache-2.0
//! Explicit AES generation requests shared by four distinct public entry points.
use super::{
    generation_fixture::{Field, Value},
    object_fixture,
    outcome::Failure,
};
use fe11::*;

pub fn history() -> HistoryObservationPlan {
    HistoryObservationPlan {
        sensitive: true,
        extractable: true,
        always_sensitive: true,
        never_extractable: true,
        local: true,
        generation: true,
        maximum_bytes: 32,
    }
}
pub fn key(label: &str) -> SymmetricKeySpec {
    let mut admission = object_fixture::public_key_options(label.as_bytes()).admission;
    admission.observation.verify = false;
    admission.observation.encrypt = true;
    admission.observation.decrypt = true;
    admission.observation.maximum_bytes = 4;
    SymmetricKeySpec {
        usages: KeyUsageRequest {
            encrypt: Some(true),
            decrypt: Some(true),
            wrap: Some(true),
            unwrap: Some(true),
            ..KeyUsageRequest::omitted()
        },
        visibility: ObjectVisibility::Public,
        admission,
        protection_request: CurrentKeyProtection {
            sensitive: true,
            extractable: false,
        },
        history: history(),
        mechanisms: MechanismObservationPlan::NotRequested,
        algorithm: SymmetricAlgorithm::Aes128,
        hmac_key_type: None,
        id: label.as_bytes().to_vec(),
        label: label.into(),
        persistent: true,
    }
}
pub fn start(
    session: &AdvancedSession,
    route: &str,
    label: &str,
    invalid: bool,
) -> std::result::Result<OperationTicket, Failure> {
    if super::generation_family_spec::supported(route) {
        return super::generation_family_spec::start(session, route, label, invalid);
    }
    let mut spec = key(label);
    // AES has no HMAC key representation. This is a local type mismatch,
    // leaving every native template and object untouched.
    if invalid {
        spec.hmac_key_type = Some(HmacKeyType::Generic);
    }
    Ok(match route {
        "typed_generate_aes_key" => session.generate_aes_key(spec),
        "typed_generate_symmetric_key" => session.generate_symmetric_key(spec),
        "typed_generate_aes_key_encryption_key" => {
            session.generate_aes_key_encryption_key(AesKeyEncryptionSpec {
                native_protection: spec.protection_request,
                history_observation: history(),
                key: spec,
                usage: KeyTransportUsage::WrapAndUnwrap,
            })
        }
        "typed_generate_transport_symmetric_key" => {
            session.generate_transport_symmetric_key(SymmetricIntroductionSpec {
                native_protection: spec.protection_request,
                history_observation: history(),
                key: spec,
            })
        }
        _ => return Err(Failure::Input("generation_route")),
    }?)
}
pub fn fields(label: &str) -> Vec<Field> {
    let mut fields = vec![
        Field {
            attribute: StandardAttribute::CLASS,
            value: Value::Unsigned(fe11_sys::CKO_SECRET_KEY as u64),
        },
        Field {
            attribute: StandardAttribute::KEY_TYPE,
            value: Value::Unsigned(fe11_sys::CKK_AES as u64),
        },
        Field {
            attribute: StandardAttribute::VALUE_LEN,
            value: Value::Unsigned(16),
        },
        Field {
            attribute: StandardAttribute::ID,
            value: Value::Bytes(label.as_bytes().to_vec()),
        },
        Field {
            attribute: StandardAttribute::LABEL,
            value: Value::Bytes(label.as_bytes().to_vec()),
        },
    ];
    for (attribute, value) in [
        (StandardAttribute::TOKEN, true),
        (StandardAttribute::PRIVATE, false),
        (StandardAttribute::ENCRYPT, true),
        (StandardAttribute::DECRYPT, true),
        (StandardAttribute::WRAP, true),
        (StandardAttribute::UNWRAP, true),
        (StandardAttribute::SENSITIVE, true),
        (StandardAttribute::EXTRACTABLE, false),
    ] {
        fields.push(Field {
            attribute,
            value: Value::Boolean(value),
        });
    }
    fields
}
pub fn observation(value: GeneratedObjects, route: &str) -> std::result::Result<(), Failure> {
    if super::generation_family_spec::supported(route) {
        return super::generation_family_spec::observation(value, route);
    }
    let correct = matches!(
        (route, value),
        (
            "typed_generate_aes_key" | "typed_generate_symmetric_key",
            GeneratedObjects::SymmetricKey(_)
        ) | (
            "typed_generate_aes_key_encryption_key",
            GeneratedObjects::AesKeyEncryptionKey(_)
        ) | (
            "typed_generate_transport_symmetric_key",
            GeneratedObjects::IntroducedSymmetricKey(_)
        )
    );
    if correct {
        Ok(())
    } else {
        Err(Failure::Oracle("generated_descriptive_kind"))
    }
}

/// Number of native objects created by this exact entry point.
pub fn count(route: &str) -> usize {
    if super::generation_family_spec::supported(route) {
        super::generation_family_spec::count(route)
    } else {
        1
    }
}
pub fn invalid_reason(route: &str) -> Option<RejectionReason> {
    if super::generation_family_spec::supported(route) {
        super::generation_family_spec::invalid_reason(route)
    } else {
        Some(RejectionReason::SymmetricParameters(
            SymmetricParametersRejection::HmacKeyTypeOnAead,
        ))
    }
}
