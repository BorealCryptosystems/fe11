// SPDX-License-Identifier: Apache-2.0
//! Native RSA signature-size refusals with an unchanged valid witness.
use super::{outcome, Failure, Owner, Phase, Report, Vector};
use fe11::*;
use std::io::Write;

pub(super) fn check<W: Write>(
    owner: &Owner,
    key: &NativeObjectRef,
    vector: &Vector,
    route: MessageRoute,
    parts: &[&[u8]],
    limits: InputLimits,
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    let width = vector.key[0].len();
    if width != 256 || vector.expected.len() != width {
        return Err(Failure::Input("rsa_length_boundary_dimensions"));
    }
    let verify = |signature: &[u8]| {
        owner
            .verify_parameters(key, vector.signature()?, route, parts, signature, limits)
            .map_err(Failure::from)
    };
    verify(&vector.expected)?;
    let mut longer = vector.expected.clone();
    longer.push(0);
    let invalid = [&[][..], &vector.expected[..width - 1], longer.as_slice()];
    for signature in invalid {
        match verify(signature) {
            Err(Failure::Product(error @ Error::Native { function, code, .. }))
                if function
                    == if route == MessageRoute::Single {
                        "C_Verify"
                    } else {
                        "C_VerifyFinal"
                    }
                    && code == fe11_sys::CKR_SIGNATURE_LEN_RANGE as u64 =>
            {
                outcome::record(report, Phase::Body, &Failure::Product(error))
                    .map_err(|_| Failure::Input("report_write"))?;
            }
            Err(error) => return Err(error),
            Ok(()) => return Err(Failure::Oracle("rsa_wrong_signature_size_accepted")),
        }
        // Each failed verification must leave this owner reusable. Reuse the
        // same key and message; do not hide a stale native operation in a new session.
        verify(&vector.expected)?;
    }
    Ok(())
}
