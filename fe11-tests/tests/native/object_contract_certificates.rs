// SPDX-License-Identifier: Apache-2.0
//! Public certificate objects preserve exact encoded data and native refusals.
use super::super::{object_transition_fixture, outcome};
use super::{hex, Failure, Phase, Report};
use fe11::*;
use std::io::Write;

const LABEL: &[u8] = b"public-certificate-fixture";
// Explicit OpenPGP certificate-type extension, not a standard CKC value.
// The fixture manifest records its header provenance and packet source. It is
// submitted as a caller-supplied native integer; no provider identity is tested.
const OPENPGP_CERTIFICATE_TYPE: u64 = 0x80504750;

pub(super) struct Vector {
    kind: u64,
    value: Vec<u8>,
    subject: Vec<u8>,
    issuer: Vec<u8>,
    serial: Vec<u8>,
}

impl Vector {
    pub(super) fn read(fields: &[&str]) -> std::result::Result<Self, Failure> {
        if fields.len() != 5 {
            return Err(Failure::Input("certificate_fixture_fields"));
        }
        let kind = match fields[0] {
            "certificate-x509" => fe11_sys::CKC_X_509 as u64,
            "certificate-openpgp" => OPENPGP_CERTIFICATE_TYPE,
            "certificate-attribute" => fe11_sys::CKC_X_509_ATTR_CERT as u64,
            "certificate-wtls" => fe11_sys::CKC_WTLS as u64,
            _ => return Err(Failure::Input("certificate_fixture_type")),
        };
        let decode = |index| hex(fields[index], 16384).map_err(Failure::Input);
        let value = decode(1)?;
        if value.is_empty() {
            return Err(Failure::Input("certificate_fixture_empty"));
        }
        Ok(Self {
            kind,
            value,
            subject: decode(2)?,
            issuer: decode(3)?,
            serial: decode(4)?,
        })
    }

    fn template(&self, kind: u64) -> Vec<AttributeInput<'_>> {
        let attr = |attribute: StandardAttribute, value| AttributeInput {
            attribute: attribute.into(),
            value,
        };
        vec![
            attr(
                StandardAttribute::CLASS,
                AttributeInputValue::Unsigned(fe11_sys::CKO_CERTIFICATE as u64),
            ),
            attr(
                StandardAttribute::CERTIFICATE_TYPE,
                AttributeInputValue::Unsigned(kind),
            ),
            attr(
                StandardAttribute::TOKEN,
                AttributeInputValue::Boolean(false),
            ),
            attr(
                StandardAttribute::PRIVATE,
                AttributeInputValue::Boolean(false),
            ),
            attr(StandardAttribute::LABEL, AttributeInputValue::Bytes(LABEL)),
            attr(
                StandardAttribute::SUBJECT,
                AttributeInputValue::Bytes(&self.subject),
            ),
            attr(
                StandardAttribute::ISSUER,
                AttributeInputValue::Bytes(&self.issuer),
            ),
            attr(
                StandardAttribute::SERIAL_NUMBER,
                AttributeInputValue::Bytes(&self.serial),
            ),
            attr(
                StandardAttribute::VALUE,
                AttributeInputValue::Bytes(&self.value),
            ),
        ]
    }

    fn limits(&self) -> AttributeTemplateLimits {
        AttributeTemplateLimits {
            maximum_depth: 0,
            maximum_attributes: 9,
            maximum_value_bytes: 2 * std::mem::size_of::<fe11_sys::CK_ULONG>()
                + 2
                + LABEL.len()
                + self.subject.len()
                + self.issuer.len()
                + self.serial.len()
                + self.value.len(),
        }
    }
}

fn readback(
    session: &Session,
    object: &NativeObjectRef,
    vector: &Vector,
    kind: u64,
) -> std::result::Result<(), Failure> {
    for (attribute, expected) in [
        (StandardAttribute::CLASS, fe11_sys::CKO_CERTIFICATE as u64),
        (StandardAttribute::CERTIFICATE_TYPE, kind),
    ] {
        let result = session.read_flat_attribute(
            object,
            attribute,
            FlatAttributeReadPlan::Buffer {
                capacity: std::mem::size_of::<fe11_sys::CK_ULONG>(),
            },
        )?;
        if result.calls != (AttributeReadCalls::Direct { code: 0 })
            || result.unsigned()? != expected
        {
            return Err(Failure::Oracle("certificate_class_or_type"));
        }
    }
    for (attribute, expected) in [
        (StandardAttribute::SUBJECT, &vector.subject),
        (StandardAttribute::ISSUER, &vector.issuer),
        (StandardAttribute::SERIAL_NUMBER, &vector.serial),
        (StandardAttribute::VALUE, &vector.value),
    ] {
        let result = session.read_flat_attribute(
            object,
            attribute,
            FlatAttributeReadPlan::Buffer {
                capacity: expected.len(),
            },
        )?;
        if result.calls != (AttributeReadCalls::Direct { code: 0 }) {
            return Err(Failure::Oracle("certificate_attribute_native_code"));
        }
        match result.value {
            FlatAttributeValue::Available(bytes) if bytes.as_bytes() == expected => {}
            _ => return Err(Failure::Oracle("certificate_exact_attribute_bytes")),
        }
    }
    Ok(())
}

pub(super) fn execute<W: Write>(
    session: &Session,
    objects: &mut Vec<NativeObjectRef>,
    vector: &Vector,
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    let supported =
        vector.kind == fe11_sys::CKC_X_509 as u64 || vector.kind == OPENPGP_CERTIFICATE_TYPE;
    // The unsupported-type probes keep every byte and attribute of a successful
    // X.509 control, changing only CERTIFICATE_TYPE. This reaches type dispatch;
    // it does not claim to validate an attribute-certificate or WTLS encoding.
    let control_kind = if supported {
        vector.kind
    } else {
        fe11_sys::CKC_X_509 as u64
    };
    let object = session.create_native_object(&vector.template(control_kind), vector.limits())?;
    objects.push(object);
    readback(
        session,
        objects
            .last()
            .ok_or(Failure::Input("certificate_reference"))?,
        vector,
        control_kind,
    )?;
    if !supported {
        match session.create_native_object(&vector.template(vector.kind), vector.limits()) {
            Err(
                error @ Error::Native {
                    function: "C_CreateObject",
                    code,
                    ..
                },
            ) if code == fe11_sys::CKR_ATTRIBUTE_VALUE_INVALID as u64 => {
                outcome::record(report, Phase::Body, &Failure::Product(error))
                    .map_err(|_| Failure::Input("report_write"))?;
            }
            Err(error) => return Err(error.into()),
            Ok(object) => {
                objects.push(object);
                return Err(Failure::Oracle("unsupported_certificate_type_created"));
            }
        }
        // This namespace belongs to one isolated test process. Its count is an
        // observation, never permission to destroy objects found by a search.
        let found = object_transition_fixture::find(session, LABEL)?;
        if found.len() != 1 {
            return Err(Failure::Oracle(
                "certificate_refusal_created_namespace_entry",
            ));
        }
    }
    Ok(())
}
