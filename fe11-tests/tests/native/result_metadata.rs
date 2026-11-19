// SPDX-License-Identifier: Apache-2.0
//! Metadata carried by genuine cryptographic results and module-bound declarations.
use super::super::{
    gcm_fixture, object_owner::Owner, outcome::Failure, report::{Producer, Report},
    rsa_known_fixture, single_key_case::SingleKeyCase,
};
use fe11::*;
use std::{io::Write, path::Path};

pub(super) struct Gcm(gcm_fixture::Vector);

impl SingleKeyCase for Gcm {
    const ASSERTION: &'static str = "result_metadata_matches_native_operation";
    const PRODUCER: Producer = Producer::TestOracle;

    fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let v = gcm_fixture::Vector::read(path)?;
        if v.advanced || !v.valid {
            return Err(Failure::Input("expected_valid_session_gcm_vector"));
        }
        Ok(Self(v))
    }

    fn bind_module(&mut self, module: &Module) -> std::result::Result<(), Failure> {
        let number = fe11_sys::CKM_AES_GCM as u64;
        let before = module.call_counts()?;
        // SAFETY: the selected standard mechanism has the CK_GCM_PARAMS ABI
        // for classic encryption and the CK_GCM_MESSAGE_PARAMS ABI for message
        // calls. These declarations are inspected without dispatching either.
        let classic = unsafe {
            module.declare_mechanism_extension(number, (2, 40), ExtensionOperation::Encrypt, false)
        }?;
        let message = unsafe {
            module.declare_gcm_message_extension(number, MessageRoute::Single, false)
        }?;
        // SAFETY: this number is unassigned on the pinned module. No attribute
        // call is issued and no native pointer is constructed.
        let id = fe11_sys::CKA_VENDOR_DEFINED as u64 + 0x00ff_ffff;
        let attribute = unsafe { module.declare_attribute_extension(id, AttributeLayout::Bytes) }?;
        if classic.mechanism_number() != number || message.mechanism_number() != number
            || attribute.identifier() != id || attribute.layout() != AttributeLayout::Bytes
            || module.call_counts()? != before
        {
            return Err(Failure::Oracle("module_declaration_metadata"));
        }
        Ok(())
    }

    fn advanced(&self) -> bool { false }

    fn import(&self, owner: &Owner) -> std::result::Result<NativeObjectRef, Failure> {
        self.0.import(owner)
    }

    fn check<W: Write>(&self, owner: &Owner, key: &NativeObjectRef, _: &mut Report<W>)
        -> std::result::Result<(), Failure>
    {
        let Owner::Session(session) = owner else { return Err(Failure::Input("session_required")); };
        let v = &self.0;
        let parts = [v.input.as_slice()];
        let plaintext_len = if v.encrypt { v.input.len() } else { v.expected.len() };
        let limits = InputLimits { maximum_parts: 1, maximum_total_bytes: plaintext_len + v.aad.len() };
        if v.encrypt {
            let value = session.encrypt_classic_aead(key, v.parameters(), MessageRoute::Single, &parts, limits)?;
            if value.tag_bits() != v.tag_bits || value.mechanism_number() != fe11_sys::CKM_AES_GCM as u64
                || value.nonce() != v.iv || value.as_bytes() != v.expected
            {
                return Err(Failure::Oracle("classic_ciphertext_metadata"));
            }
        } else {
            let value = session.decrypt_classic_aead(key, v.parameters(), MessageRoute::Single, &parts, limits)?;
            if value.tag_bits() != v.tag_bits || value.message_init().is_some() || value.as_bytes() != v.expected {
                return Err(Failure::Oracle("classic_plaintext_metadata"));
            }
        }
        Ok(())
    }
}

pub(super) struct Signature(rsa_known_fixture::Vector);

impl SingleKeyCase for Signature {
    const ASSERTION: &'static str = "result_metadata_matches_native_operation";
    const PRODUCER: Producer = Producer::TestOracle;

    fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let v = rsa_known_fixture::Vector::read(path)?;
        if v.action != "sign" || v.advanced || v.randomized || v.negative.is_some() {
            return Err(Failure::Input("expected_deterministic_session_signature"));
        }
        Ok(Self(v))
    }

    fn advanced(&self) -> bool { false }

    fn import(&self, owner: &Owner) -> std::result::Result<NativeObjectRef, Failure> {
        self.0.import(owner)
    }

    fn check<W: Write>(&self, owner: &Owner, key: &NativeObjectRef, _: &mut Report<W>)
        -> std::result::Result<(), Failure>
    {
        let Owner::Session(session) = owner else { return Err(Failure::Input("session_required")); };
        let v = &self.0;
        let mechanism = match v.signature()? {
            NativeSignatureParameters::Parameterless(NativeSignatureAlgorithm::SHA256_RSA_PKCS) => fe11_sys::CKM_SHA256_RSA_PKCS,
            NativeSignatureParameters::Parameterless(NativeSignatureAlgorithm::SHA384_RSA_PKCS) => fe11_sys::CKM_SHA384_RSA_PKCS,
            _ => return Err(Failure::Input("expected_sha2_rsa_pkcs")),
        };
        let limits = InputLimits { maximum_parts: 1, maximum_total_bytes: v.input.len() };
        let signature = session.sign_native(key, v.signature()?, MessageRoute::Single,
            &[v.input.as_slice()], limits, v.expected.len(), None)?;
        if signature.mechanism_number() != mechanism as u64 || signature.as_bytes() != v.expected {
            return Err(Failure::Oracle("native_signature_metadata"));
        }
        Ok(())
    }
}
