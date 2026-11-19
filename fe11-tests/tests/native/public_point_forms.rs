// SPDX-License-Identifier: Apache-2.0
//! Exact public point representations, selection and destruction on real objects.
use super::super::{
    arguments::hex,
    configuration::{select_token, Budgets, Configuration},
    module_controls, object_fixture,
    outcome::{self, Failure},
    report::{Observation, Phase, Producer, Report},
};
use fe11::*;
use std::{
    fs::File,
    io::{self, Read, Write},
    path::Path,
};

struct Case {
    kind: String,
    typed: bool,
    envelope: bool,
    parameters: Vec<u8>,
    point: Vec<u8>,
    spki: Vec<u8>,
    message: Vec<u8>,
    signature: Vec<u8>,
}
impl Case {
    fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let mut bytes = Vec::new();
        File::open(path)
            .map_err(|_| Failure::Input("point_fixture_open"))?
            .take(8193)
            .read_to_end(&mut bytes)
            .map_err(|_| Failure::Input("point_fixture_read"))?;
        if bytes.len() > 8192 {
            return Err(Failure::Input("point_fixture_bound"));
        }
        let text =
            std::str::from_utf8(&bytes).map_err(|_| Failure::Input("point_fixture_encoding"))?;
        let f: Vec<_> = text.split_terminator('\n').collect();
        if f.len() != 9
            || f[0] != "public-point"
            || !matches!(f[1], "p256" | "ed25519" | "ed448")
            || !matches!(
                f[2],
                "native-raw" | "native-der" | "typed-raw" | "typed-der"
            )
        {
            return Err(Failure::Input("point_fixture_fields"));
        }
        let decode = |i, n| hex(f[i], n).map_err(Failure::Input);
        let value = Self {
            kind: f[1].into(),
            typed: f[2].starts_with("typed"),
            envelope: f[2].ends_with("der"),
            parameters: decode(3, 32)?,
            point: decode(4, 65)?,
            spki: decode(5, 256)?,
            message: decode(6, 4096)?,
            signature: decode(7, 114)?,
        };
        if f[8] != "positive"
            || value.parameters.is_empty()
            || value.point.len()
                != match value.kind.as_str() {
                    "p256" => 65,
                    "ed25519" => 32,
                    _ => 57,
                }
            || value.signature.len() != if value.kind == "ed448" { 114 } else { 64 }
            || (value.kind == "p256" && (!value.envelope || value.point[0] != 4))
        {
            return Err(Failure::Input("point_fixture_dimensions"));
        }
        Ok(value)
    }
    fn profile(&self) -> VerificationProfile {
        match self.kind.as_str() {
            "p256" => VerificationProfile::Ecdsa(HashAlgorithm::Sha256),
            "ed25519" => VerificationProfile::Ed25519,
            _ => VerificationProfile::Ed448,
        }
    }
    fn encoded(&self) -> Vec<u8> {
        if self.envelope {
            // All three public points fit the canonical short DER length form.
            let mut bytes = vec![4, self.point.len() as u8];
            bytes.extend_from_slice(&self.point);
            bytes
        } else {
            self.point.clone()
        }
    }
    fn native_parameters(&self) -> NativeSignatureParameters<'_> {
        if self.kind == "p256" {
            NativeSignatureParameters::Parameterless(NativeSignatureAlgorithm::ECDSA)
        } else {
            NativeSignatureParameters::EdDsa(Some(NativeEdDsaParameters {
                prehash: false,
                context: None,
            }))
        }
    }
}
fn attr(attribute: StandardAttribute, value: AttributeInputValue<'_>) -> AttributeInput<'_> {
    AttributeInput {
        attribute: attribute.into(),
        value,
    }
}
fn read_exact(
    s: &Session,
    key: &NativeObjectRef,
    attr: StandardAttribute,
    expected: &[u8],
) -> std::result::Result<(), Failure> {
    let value =
        s.read_flat_attribute(key, attr, FlatAttributeReadPlan::Buffer { capacity: 256 })?;
    if value.calls != (AttributeReadCalls::Direct { code: 0 })
        || !matches!(value.value, FlatAttributeValue::Available(ref b) if b.as_bytes() == expected)
    {
        return Err(Failure::Oracle("public_point_native_identity"));
    }
    Ok(())
}

pub(super) fn execute<W: Write>(
    config: &Configuration,
    path: &Path,
    mut report: Report<W>,
) -> io::Result<bool> {
    let mut module = None;
    let mut session = None;
    let mut sets = Vec::new();
    let mut object = None;
    let mut destroyed = false;
    let setup = (|| -> std::result::Result<Case, Failure> {
        let case = Case::read(path)?;
        let budgets = Budgets::ordinary();
        let mut options = config.options(&budgets);
        options.crypto_options.edwards.point_encoding = if case.envelope {
            EdwardsPointEncoding::DerOctetString
        } else {
            EdwardsPointEncoding::Raw
        };
        // Parameters are the exact RFC8410 OID; no automatic representation retry.
        options.crypto_options.edwards.parameter_encoding = EdwardsParameterEncoding::Oid;
        module = Some(
            config
                .builder(&budgets)
                .crypto_options(options.crypto_options)
                .open()?,
        );
        let m = module.as_ref().ok_or(Failure::Input("point_module"))?;
        let token = select_token(m, &config.label).ok_or(Failure::Input("point_token"))?;
        session = Some(m.select(&token)?.open_session(true)?);
        Ok(case)
    })();
    let body = (|| -> std::result::Result<(), Failure> {
        let (Ok(case), Some(s)) = (&setup, &session) else {
            return Ok(());
        };
        let encoded = case.encoded();
        let id = config.label.as_bytes();
        let options = object_fixture::public_key_options(id);
        if case.typed {
            let created = s.create_verification_key(
                &case.spki,
                &[case.profile()],
                MechanismObservationPlan::NotRequested,
                options,
            )?;
            let count = created.objects.as_slice().len();
            sets.push(created.objects);
            if count != 1 || created.remainder.is_some() {
                return Err(Failure::Oracle("point_creation_outputs"));
            }
            let key = created.observation?;
            object = Some(key.management_reference().native_object());
        } else {
            let attributes = [
                attr(
                    StandardAttribute::CLASS,
                    AttributeInputValue::Unsigned(fe11_sys::CKO_PUBLIC_KEY as u64),
                ),
                attr(
                    StandardAttribute::KEY_TYPE,
                    AttributeInputValue::Unsigned(if case.kind == "p256" {
                        fe11_sys::CKK_EC
                    } else {
                        fe11_sys::CKK_EC_EDWARDS
                    } as u64),
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
                    StandardAttribute::VERIFY,
                    AttributeInputValue::Boolean(true),
                ),
                attr(StandardAttribute::ID, AttributeInputValue::Bytes(id)),
                attr(StandardAttribute::LABEL, AttributeInputValue::Bytes(id)),
                attr(
                    StandardAttribute::EC_PARAMS,
                    AttributeInputValue::Bytes(&case.parameters),
                ),
                attr(
                    StandardAttribute::EC_POINT,
                    AttributeInputValue::Bytes(&encoded),
                ),
            ];
            object = Some(s.create_native_object(
                &attributes,
                AttributeTemplateLimits {
                    maximum_depth: 0,
                    maximum_attributes: attributes.len(),
                    maximum_value_bytes: 1024,
                },
            )?);
        }
        let key = object.as_ref().ok_or(Failure::Input("point_object"))?;
        read_exact(s, key, StandardAttribute::EC_PARAMS, &case.parameters)?;
        read_exact(s, key, StandardAttribute::EC_POINT, &encoded)?;
        let selected = s.find_classical_verification_key(
            id,
            &case.spki,
            &[case.profile()],
            MechanismObservationPlan::NotRequested,
            object_fixture::public_key_options(id).admission,
        )?;
        let selected_native = selected.management_reference().native_object();
        read_exact(s, &selected_native, StandardAttribute::EC_POINT, &encoded)?;
        // Retain a native verification refusal while still checking destruction
        // and the resulting empty lookup. Neither a failure nor cleanup is hidden.
        let verification = s.verify_native(
            &selected_native,
            case.native_parameters(),
            MessageRoute::Single,
            &[&case.message],
            &case.signature,
            InputLimits {
                maximum_parts: 1,
                maximum_total_bytes: case.message.len(),
            },
            None,
        );
        if let Err(error) = &verification {
            outcome::record(&mut report, Phase::Body, &Failure::Product(error.clone()))
                .map_err(|_| Failure::Input("point_report"))?;
        }
        s.destroy_native_object(key)?;
        destroyed = true;
        match s.find_classical_verification_key(
            id,
            &case.spki,
            &[case.profile()],
            MechanismObservationPlan::NotRequested,
            object_fixture::public_key_options(id).admission,
        ) {
            Err(Error::Rejected(RejectionReason::ObjectSearch(
                ObjectSearchRejection::SelectedSearchResultAbsent,
            ))) => (),
            Err(error) => return Err(error.into()),
            Ok(_) => return Err(Failure::Oracle("destroyed_public_point_selected")),
        }
        report
            .observation(
                Phase::Body,
                "public_point_identity_and_destroyed_lookup",
                Producer::Native,
                Observation::Boolean(true),
            )
            .map_err(|_| Failure::Input("point_report"))?;
        verification.map_err(Failure::from)
    })();
    let mut cleanup = Vec::new();
    if let Some(s) = &session {
        if !destroyed {
            if let Some(key) = &object {
                if let Err(error) = s.destroy_native_object(key) {
                    cleanup.push(error.into());
                }
            } else {
                // A failed typed observation still leaves exact created owners.
                for set in &sets {
                    for key in set.as_slice() {
                        if let Err(error) = s.destroy_native_object(key) {
                            cleanup.push(error.into());
                        }
                    }
                }
            }
        }
        if let Err(error) = s.close() {
            cleanup.push(error.into());
        }
    }
    drop(object);
    drop(sets);
    drop(session);
    if let Some(m) = &module {
        if let Err(error) = m.close() {
            cleanup.push(error.into());
        }
    }
    module_controls::finish(report, setup.map(|_| ()), body, cleanup)
}
