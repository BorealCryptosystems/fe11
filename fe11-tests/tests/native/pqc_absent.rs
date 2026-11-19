// SPDX-License-Identifier: Apache-2.0
//! Unsupported hash-signature selectors are checked after a valid pure control.
use super::{arguments::hex, object_owner::Owner, outcome::Failure, pqc_fixture::Vector};
use fe11::*;

pub(super) enum Selector {
    ExternalSha256(Vec<u8>),
    Combined(NativePqcCombined),
}

impl Selector {
    pub(super) fn number(&self, family: NativePqcFamily) -> u64 {
        match self {
            Self::ExternalSha256(_) => match family {
                NativePqcFamily::MlDsa => fe11_sys::CKM_HASH_ML_DSA as u64,
                NativePqcFamily::SlhDsa => fe11_sys::CKM_HASH_SLH_DSA as u64,
            },
            Self::Combined(algorithm) => algorithm.mechanism_number(),
        }
    }
    pub(super) fn read(
        name: &str,
        bytes: &str,
        family: NativePqcFamily,
    ) -> std::result::Result<Self, Failure> {
        if name == "external-sha256" {
            let digest = hex(bytes, 32).map_err(Failure::Input)?;
            if digest.len() != 32 {
                return Err(Failure::Input("pqc_external_hash_length"));
            }
            return Ok(Self::ExternalSha256(digest));
        }
        let index = name
            .strip_prefix("combined-")
            .and_then(|s| s.parse::<usize>().ok())
            .filter(|n| *n < 10)
            .ok_or(Failure::Input("pqc_combined_selector"))?;
        if !bytes.is_empty() {
            return Err(Failure::Input("pqc_combined_uses_message"));
        }
        let offset = match family {
            NativePqcFamily::MlDsa => 0,
            NativePqcFamily::SlhDsa => 10,
        };
        NativePqcCombined::ALL
            .get(offset + index)
            .copied()
            .map(Self::Combined)
            .ok_or(Failure::Input("pqc_combined_catalogue"))
    }
}

pub(super) fn check(
    owner: &Owner,
    key: &NativeObjectRef,
    v: &Vector,
    selector: &Selector,
) -> std::result::Result<(), Failure> {
    let parameters = NativePqcContext {
        hedging: PqcHedging::DeterministicRequired,
        context: Some(&[]),
    };
    let (mechanism, input) = match selector {
        Selector::ExternalSha256(digest) => (
            NativeSignatureParameters::PqcPrehashed {
                family: v.parameters.family,
                hash: fe11_sys::CKM_SHA256 as u64,
                parameters,
            },
            digest.as_slice(),
        ),
        Selector::Combined(algorithm) => (
            NativeSignatureParameters::PqcHashMessage {
                algorithm: *algorithm,
                parameters: Some(parameters),
            },
            v.message.as_slice(),
        ),
    };
    let parts = [input];
    let limits = InputLimits {
        maximum_parts: 1,
        maximum_total_bytes: input.len(),
    };
    // This negative deliberately supplies a complete, correctly sized signature;
    // rejection must come from Init's unsupported mechanism, not Verify's bytes.
    let result = match (owner, v.sign) {
        (Owner::Session(s), true) => s
            .sign_native(
                key,
                mechanism,
                MessageRoute::Single,
                &parts,
                limits,
                v.parameters.signature_bytes,
                None,
            )
            .map(|_| ()),
        (Owner::Session(s), false) => s.verify_native(
            key,
            mechanism,
            MessageRoute::Single,
            &parts,
            &v.signature,
            limits,
            None,
        ),
        (Owner::Advanced(_), _) => return Err(Failure::Input("pqc_absent_session_owner")),
    };
    let expected = if v.sign { "C_SignInit" } else { "C_VerifyInit" };
    match result {
        Err(Error::Native {
            function,
            code: 0x70,
            ..
        }) if function == expected => Ok(()),
        Err(error) => Err(error.into()),
        Ok(()) => Err(Failure::Oracle("unsupported_pqc_hash_accepted")),
    }
}
