// SPDX-License-Identifier: Apache-2.0
//! Read back the requested Edwards domain and RFC8032 public-key width.
use super::super::{
    outcome::Failure,
    report::{Observation, Phase, Producer, Report},
};
use fe11::*;
use std::io::Write;

pub(super) fn check<W: Write>(
    session: &Session,
    pair: &NativeKeyPair,
    parameters: &[u8],
    width: usize,
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    let mut identity_matches = true;
    for (key, name) in [
        (pair.public.native(), "generated_edwards_public_parameters"),
        (
            pair.private.native(),
            "generated_edwards_private_parameters",
        ),
    ] {
        let value = session.read_flat_attribute(
            key,
            StandardAttribute::EC_PARAMS,
            FlatAttributeReadPlan::Buffer {
                // Observe either legal parameter representation fully. The
                // requested representation remains the byte-exact oracle.
                capacity: 32,
            },
        )?;
        let AttributeReadCalls::Direct { code } = value.calls else {
            return Err(Failure::Oracle("generated_edwards_parameter_call"));
        };
        report
            .observation(
                Phase::Body,
                "generated_edwards_parameter_status",
                Producer::Native,
                Observation::Native {
                    function: "C_GetAttributeValue",
                    code,
                    may_have_effect: false,
                },
            )
            .map_err(|_| Failure::Input("report_write"))?;
        let matches = code == 0
            && matches!(value.value, FlatAttributeValue::Available(ref bytes) if bytes.as_bytes() == parameters);
        report
            .observation(
                Phase::Body,
                name,
                Producer::Native,
                Observation::Boolean(matches),
            )
            .map_err(|_| Failure::Input("report_write"))?;
        identity_matches &= matches;
    }
    // The extra two bytes allow a nonconforming DER OCTET STRING to be observed
    // as a length mismatch, rather than hidden behind BUFFER_TOO_SMALL. They do
    // not authorize stripping a prefix: PKCS#11 specifies raw RFC8032 bytes.
    let value = session.read_flat_attribute(
        pair.public.native(),
        StandardAttribute::EC_POINT,
        FlatAttributeReadPlan::Buffer {
            capacity: width + 2,
        },
    )?;
    if value.calls != (AttributeReadCalls::Direct { code: 0 }) {
        return Err(Failure::Oracle("generated_edwards_public_status"));
    }
    let FlatAttributeValue::Available(bytes) = value.value else {
        return Err(Failure::Oracle("generated_edwards_public_unavailable"));
    };
    report
        .observation(
            Phase::Body,
            "generated_edwards_public_bytes",
            Producer::Native,
            Observation::Number(bytes.as_bytes().len() as u64),
        )
        .map_err(|_| Failure::Input("report_write"))?;
    if !identity_matches || bytes.as_bytes().len() != width {
        return Err(Failure::Oracle("generated_edwards_identity"));
    }
    Ok(())
}
