// SPDX-License-Identifier: Apache-2.0
//! Multipart EdDSA uses the original message, after a usable single-part control.
use super::{limits, Failure};
use fe11::*;

pub(super) fn check(
    owner: &Session,
    pair: &NativeKeyPair,
    sign: bool,
    signature: &[u8],
) -> std::result::Result<(), Failure> {
    let mechanism = NativeSignatureParameters::EdDsa(None);
    let parts: [&[u8]; 3] = [b"a", b"b", b"c"];
    let input = InputLimits {
        maximum_parts: 3,
        maximum_total_bytes: 3,
    };
    if sign {
        let result = owner.sign_native(
            pair.private.native(),
            mechanism,
            MessageRoute::Multipart,
            &parts,
            input,
            signature.len(),
            None,
        )?;
        if result.as_bytes() != signature {
            return Err(Failure::Oracle("edwards_multipart_signature_changed"));
        }
        owner.verify_native(
            pair.public.native(),
            NativeSignatureParameters::EdDsa(None),
            MessageRoute::Single,
            &[b"abc"],
            result.as_bytes(),
            limits(),
            None,
        )?;
    } else {
        owner.verify_native(
            pair.public.native(),
            mechanism,
            MessageRoute::Multipart,
            &parts,
            signature,
            input,
            None,
        )?;
    }
    // A module refusal remains a failed nominal multipart operation. It must
    // never be changed into a success or replaced with local prehashing.
    Ok(())
}
