// SPDX-License-Identifier: Apache-2.0
//! RFC 3394 section 4.1 through the typed size-query and output route.
use super::Failure;
use fe11::*;

pub(super) const KEK: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];
pub(super) const KEY: [u8; 16] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
];
const ENVELOPE: [u8; 24] = [
    0x1f, 0xa6, 0x8b, 0x0a, 0x81, 0x12, 0xb4, 0x47, 0xae, 0xf3, 0x4b, 0xd8, 0xfb, 0x5a, 0x7b, 0x82,
    0x9d, 0x3e, 0x86, 0x23, 0x71, 0xd2, 0xcf, 0xe5,
];

pub(super) fn check(
    module: &Module,
    session: &Session,
    kek: &WrappingKey,
    target: &ManagedObjectRef,
) -> std::result::Result<(), Failure> {
    let mut expected = module.call_counts()?;
    for capacity in [0, ENVELOPE.len() - 1, ENVELOPE.len(), ENVELOPE.len() + 1] {
        let result = session.wrap_key(
            kek,
            target,
            WrapParameters::AesKw,
            WrapLimits {
                maximum_output_bytes: capacity,
            },
        );
        // Each explicit request queries size once, then attempts the caller's
        // actual capacity. No implicit retry or larger allocation is permitted.
        *expected.entry("C_WrapKey").or_default() += 2;
        if module.call_counts()? != expected {
            return Err(Failure::Oracle("typed_wrap_query_output_count"));
        }
        match result {
            Err(Error::OutputBufferTooSmall {
                function: "C_WrapKey",
                code: 0x150,
                required,
                capacity: actual,
            }) if capacity < ENVELOPE.len() && required == ENVELOPE.len() && actual == capacity => {
                ()
            }
            Ok(value) if capacity >= ENVELOPE.len() => {
                if value.as_bytes() != ENVELOPE
                    || value.profile() != KeyWrapProfile::AesKw
                    || value.oaep_label().is_some()
                    || value.oaep_parameters().is_some()
                    || value.nonce().is_some()
                    || value.nonce_origin().is_some()
                    || value.tag().is_some()
                    || value.associated_data().is_some()
                {
                    return Err(Failure::Oracle("typed_wrap_exact_envelope_and_profile"));
                }
            }
            Err(error) => return Err(error.into()),
            Ok(_) => return Err(Failure::Oracle("typed_wrap_undersized_accepted")),
        }
    }
    Ok(())
}
