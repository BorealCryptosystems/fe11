// SPDX-License-Identifier: Apache-2.0
//! Single-part routing rejects multiple slices before any native cryptographic call.
use super::{
    object_owner::Owner, outcome::Failure, report::Report, rsa_known_fixture::Vector,
    single_key_case::SingleKeyCase,
};
use fe11::*;
use std::{io::Write, path::Path};

/// The fixture supplies a real public test key; KIND selects the public entry point.
pub struct Guard<const KIND: u8>(Vector);

fn signature() -> NativeSignatureParameters<'static> {
    NativeSignatureParameters::Parameterless(NativeSignatureAlgorithm::SHA256_RSA_PKCS)
}

fn cms() -> NativeCmsParameters<'static> {
    NativeCmsParameters {
        certificate: None,
        signing: NativeNestedMechanism::Signature(signature()),
        digest: Some(NativeNestedMechanism::Digest(NativeDigestAlgorithm::Sha256)),
        content_type: None,
        requested_attributes: None,
        required_attributes: None,
    }
}

impl<const KIND: u8> SingleKeyCase for Guard<KIND> {
    const ASSERTION: &'static str = "single_route_rejects_two_input_slices_before_native_call";
    const PRODUCER: super::report::Producer = super::report::Producer::TestOracle;
    fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let vector = Vector::read(path)?;
        if KIND > 5
            || !matches!(vector.signature()?,
            NativeSignatureParameters::Parameterless(a) if a == NativeSignatureAlgorithm::SHA256_RSA_PKCS)
        {
            return Err(Failure::Input("single_part_guard_fixture"));
        }
        Ok(Self(vector))
    }
    fn advanced(&self) -> bool {
        self.0.advanced
    }
    fn import(&self, owner: &Owner) -> std::result::Result<NativeObjectRef, Failure> {
        Ok(match KIND {
            0 | 3 => owner.import_rsa_private_usage(&self.0.key, StandardAttribute::SIGN, true)?,
            1 | 4 | 5 => owner.import_rsa_public(&self.0.key[0], &self.0.key[1])?,
            2 => owner.import_secret(
                &[0x0b; 20],
                fe11_sys::CKK_GENERIC_SECRET,
                [StandardAttribute::SIGN, StandardAttribute::VERIFY],
            )?,
            _ => return Err(Failure::Input("single_part_guard_kind")),
        })
    }
    fn check<W: Write>(
        &self,
        owner: &Owner,
        key: &NativeObjectRef,
        _report: &mut Report<W>,
    ) -> std::result::Result<(), Failure> {
        let parts: [&[u8]; 2] = [b"a", b"bc"];
        let limits = InputLimits {
            maximum_parts: 2,
            maximum_total_bytes: 3,
        };
        let (result, reason) = match KIND {
            0 => (
                match owner {
                    Owner::Session(s) => s.sign_native(
                        key,
                        signature(),
                        MessageRoute::Single,
                        &parts,
                        limits,
                        256,
                        None,
                    ),
                    Owner::Advanced(s) => s.sign_native(
                        key,
                        signature(),
                        MessageRoute::Single,
                        &parts,
                        limits,
                        256,
                        None,
                    ),
                }
                .map(|_| ()),
                RejectionReason::NativeSignature(
                    NativeSignatureRejection::SinglePartSignatureRequiresOneInput,
                ),
            ),
            1 => (
                match owner {
                    Owner::Session(s) => s.verify_signature_native(
                        key,
                        signature(),
                        MessageRoute::Single,
                        &parts,
                        &[0; 256],
                        limits,
                        None,
                    ),
                    Owner::Advanced(s) => s
                        .verify_signature_native(
                            key,
                            signature(),
                            MessageRoute::Single,
                            &parts,
                            &[0; 256],
                            limits,
                            None,
                        )
                        .map(|_| ()),
                },
                RejectionReason::NativeSignature(
                    NativeSignatureRejection::SinglePartVerificationRequiresOneInput,
                ),
            ),
            2 => (
                match owner {
                    Owner::Session(s) => s.verify_signature_native_mac(
                        key,
                        NativeMacParameters::Full(NativeMacAlgorithm::SHA256_HMAC),
                        MessageRoute::Single,
                        &parts,
                        &[0; 32],
                        limits,
                        None,
                    ),
                    Owner::Advanced(s) => s
                        .verify_signature_native_mac(
                            key,
                            NativeMacParameters::Full(NativeMacAlgorithm::SHA256_HMAC),
                            MessageRoute::Single,
                            &parts,
                            &[0; 32],
                            limits,
                            None,
                        )
                        .map(|_| ()),
                },
                RejectionReason::NativeMac(NativeMacRejection::SinglePartMacRequiresOneInput),
            ),
            3 => (
                match owner {
                    Owner::Session(s) => s.sign_native_cms(
                        key,
                        cms(),
                        MessageRoute::Single,
                        &parts,
                        limits,
                        256,
                        None,
                    ),
                    Owner::Advanced(s) => s.sign_native_cms(
                        key,
                        cms(),
                        MessageRoute::Single,
                        &parts,
                        limits,
                        256,
                        None,
                    ),
                }
                .map(|_| ()),
                RejectionReason::NativeProtocols(
                    NativeProtocolsRejection::SingleCmsCallRequiresOneInput,
                ),
            ),
            4 => (
                match owner {
                    Owner::Session(s) => s.verify_native_cms(
                        key,
                        cms(),
                        MessageRoute::Single,
                        &parts,
                        &[0; 256],
                        limits,
                    ),
                    Owner::Advanced(s) => s.verify_native_cms(
                        key,
                        cms(),
                        MessageRoute::Single,
                        &parts,
                        &[0; 256],
                        limits,
                    ),
                },
                RejectionReason::NativeProtocols(
                    NativeProtocolsRejection::SingleCmsCallRequiresOneInput,
                ),
            ),
            5 => (
                match owner {
                    Owner::Session(s) => s.verify_native_at_init(
                        key,
                        NativeVerificationParameters::Signature(signature()),
                        MessageRoute::Single,
                        &parts,
                        &[0; 256],
                        limits,
                        None,
                    ),
                    Owner::Advanced(_) => return Err(Failure::Input("single_part_guard_owner")),
                },
                RejectionReason::NativeSignature(
                    NativeSignatureRejection::SingleVerificationRequiresOneInput,
                ),
            ),
            _ => return Err(Failure::Input("single_part_guard_kind")),
        };
        match result {
            Err(Error::Rejected(actual)) if actual == reason => Ok(()),
            Err(error) => Err(error.into()),
            Ok(()) => Err(Failure::Oracle(
                "single_part_guard_accepted_multiple_slices",
            )),
        }
    }
}
