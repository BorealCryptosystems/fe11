// SPDX-License-Identifier: Apache-2.0
//! Exercise a disabled usage on the same secret key whose attributes were read.
use super::Failure;
use fe11::*;

#[derive(Clone, Copy)]
pub(crate) enum Operation {
    Encrypt,
    Decrypt,
    Sign,
    Verify,
    Wrap,
    Unwrap,
    Derive,
}

impl Operation {
    pub(super) fn parse(name: &str, generator: &str) -> std::result::Result<Self, Failure> {
        match (name, generator) {
            ("encrypt", "CKM_AES_KEY_GEN") => Ok(Self::Encrypt),
            ("decrypt", "CKM_AES_KEY_GEN") => Ok(Self::Decrypt),
            ("sign", "CKM_GENERIC_SECRET_KEY_GEN") => Ok(Self::Sign),
            ("verify", "CKM_GENERIC_SECRET_KEY_GEN") => Ok(Self::Verify),
            ("wrap", "CKM_AES_KEY_GEN") => Ok(Self::Wrap),
            ("unwrap", "CKM_AES_KEY_GEN") => Ok(Self::Unwrap),
            ("derive", "CKM_AES_KEY_GEN") => Ok(Self::Derive),
            _ => Err(Failure::Input("disabled_usage_generator")),
        }
    }

    pub(super) fn attribute(self) -> StandardAttribute {
        match self {
            Self::Encrypt => StandardAttribute::ENCRYPT,
            Self::Decrypt => StandardAttribute::DECRYPT,
            Self::Sign => StandardAttribute::SIGN,
            Self::Verify => StandardAttribute::VERIFY,
            Self::Wrap => StandardAttribute::WRAP,
            Self::Unwrap => StandardAttribute::UNWRAP,
            Self::Derive => StandardAttribute::DERIVE,
        }
    }

    pub(crate) fn observe_refusal(
        self,
        session: &Session,
        key: &NativeObjectRef,
    ) -> std::result::Result<(), Failure> {
        use super::super::{derived_value, key_wrap_fixture};
        let block = [0x42u8; 16];
        let input = [block.as_slice()];
        let limits = InputLimits {
            maximum_parts: 1,
            maximum_total_bytes: block.len(),
        };
        let route = MessageRoute::Single;
        let cipher = CipherParameters::Aes(AesCipherParameters::Ecb);
        let mac = NativeMacParameters::Full(NativeMacAlgorithm::SHA256_HMAC);
        let (function, result) = match self {
            Self::Encrypt => (
                "C_EncryptInit",
                session
                    .encrypt_cipher(
                        CipherKeyReference::Secret(key),
                        cipher,
                        route,
                        &input,
                        limits,
                    )
                    .map(|_| ()),
            ),
            Self::Decrypt => (
                "C_DecryptInit",
                session
                    .decrypt_cipher(
                        CipherKeyReference::Secret(key),
                        cipher,
                        route,
                        &input,
                        limits,
                    )
                    .map(|_| ()),
            ),
            Self::Sign => (
                "C_SignInit",
                session
                    .compute_native_mac(key, mac, route, &input, limits, 32, None)
                    .map(|_| ()),
            ),
            Self::Verify => (
                "C_VerifyInit",
                session.verify_native_mac(key, mac, route, &input, &[0; 32], limits, None),
            ),
            Self::Wrap | Self::Unwrap => {
                // A separate extractable target keeps the key permission as the only fault.
                let mut attributes = Vec::from(key_wrap_fixture::template());
                attributes.push(AttributeInput {
                    attribute: StandardAttribute::VALUE.into(),
                    value: AttributeInputValue::Bytes(&block),
                });
                let target = session.create_native_object(
                    &attributes,
                    key_wrap_fixture::limits(attributes.len(), block.len()),
                )?;
                let observation = self.transport(session, key, &target);
                session.destroy_native_object(&target)?;
                return observation;
            }
            Self::Derive => {
                let attributes = derived_value::template_attributes(block.len());
                let result = session.derive_native_key(
                    key,
                    NativeKeyDerivation::EncryptData(NativeEncryptData::AesEcb(&block)),
                    destination(&attributes),
                );
                return match result {
                    Err(error) => check_refusal("C_DeriveKey", Err(error)),
                    Ok(created) => unexpected_creation(session, created.objects),
                };
            }
        };
        check_refusal(function, result)
    }

    fn transport(
        self,
        session: &Session,
        key: &NativeObjectRef,
        target: &NativeObjectRef,
    ) -> std::result::Result<(), Failure> {
        use super::super::key_wrap_fixture;
        let wrap = || session.wrap_native_key(key, target, key_wrap_fixture::parameters(false), 24);
        if matches!(self, Self::Wrap) {
            return check_refusal("C_WrapKey", wrap().map(|_| ()));
        }
        // The same generated key has WRAP enabled. Its own 24-byte RFC 3394
        // envelope therefore corresponds to this key before exercising UNWRAP.
        let wrapped = wrap()?;
        if wrapped.as_bytes().len() != 24 {
            return Err(Failure::Oracle("generated_wrapped_key_width"));
        }
        let attributes = key_wrap_fixture::template();
        match session.unwrap_native_key(
            key,
            wrapped.as_bytes(),
            key_wrap_fixture::parameters(false),
            ManagedClass::SecretKey,
            destination(&attributes),
        ) {
            Err(error) => check_refusal("C_UnwrapKey", Err(error)),
            Ok(created) => unexpected_creation(session, created.objects),
        }
    }
}

fn destination<'a>(attributes: &'a [AttributeInput<'a>]) -> GenerationTemplate<'a> {
    GenerationTemplate {
        attributes,
        limits: super::super::key_wrap_fixture::limits(attributes.len(), 0),
        observation: None,
        destination: DestinationPlan {
            search: DestinationSearchPlan::NotRequested,
            user: DestinationUserObservation::NotRequested,
        },
    }
}

fn unexpected_creation(
    session: &Session,
    objects: CreatedObjectSet,
) -> std::result::Result<(), Failure> {
    for object in objects.as_slice() {
        session.destroy_native_object(object)?;
    }
    Err(Failure::Oracle("disabled_generated_key_usage_accepted"))
}

fn check_refusal(function: &'static str, result: fe11::Result<()>) -> std::result::Result<(), Failure> {
    match result {
        Err(Error::Native {
            function: origin,
            code,
            ..
        }) if origin == function && code == fe11_sys::CKR_KEY_FUNCTION_NOT_PERMITTED as u64 => {
            Ok(())
        }
        Err(other) => Err(other.into()),
        Ok(()) => Err(Failure::Oracle("disabled_generated_key_usage_accepted")),
    }
}
