// SPDX-License-Identifier: Apache-2.0
//! AES-CBC declarations retain the exact IV and published known-answer bytes.
use super::super::{
    cipher_vector, object_owner::Owner, outcome::Failure, report::Report,
    single_key_case::SingleKeyCase,
};
use fe11::*;
use std::{io::Write, path::Path};

pub(super) struct Case {
    vector: cipher_vector::Vector,
    contract: Option<MechanismExtension>,
}
impl SingleKeyCase for Case {
    const ASSERTION: &'static str = "declared_cipher_exact_answer_and_provenance";
    fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let vector = cipher_vector::read(path)?;
        if !matches!(
            vector.parameters,
            CipherParameters::Aes(AesCipherParameters::Cbc { .. })
        ) || vector.key.len() != 16
            || vector.input.len() != vector.expected.len()
            || vector.input.is_empty()
            || vector.input.len() % 16 != 0
        {
            return Err(Failure::Input("extension_cbc_fixture"));
        }
        Ok(Self {
            vector,
            contract: None,
        })
    }
    fn bind_module(&mut self, module: &Module) -> std::result::Result<(), Failure> {
        let before = module.call_counts()?;
        let operation = if self.vector.encrypt {
            ExtensionOperation::Encrypt
        } else {
            ExtensionOperation::Decrypt
        };
        // SAFETY: PKCS#11 AES-CBC takes exactly16 IV bytes with no pointers or
        // parameter outputs. The selected operation matches the request below.
        self.contract = Some(unsafe {
            module.declare_mechanism_extension(
                fe11_sys::CKM_AES_CBC as u64,
                (2, 40),
                operation,
                false,
            )
        }?);
        if module.call_counts()? != before {
            return Err(Failure::Oracle("extension_declaration_dispatched"));
        }
        Ok(())
    }
    fn advanced(&self) -> bool {
        self.vector.advanced
    }
    fn import(&self, owner: &Owner) -> std::result::Result<NativeObjectRef, Failure> {
        Ok(owner.import_secret(
            &self.vector.key,
            fe11_sys::CKK_AES,
            [StandardAttribute::ENCRYPT, StandardAttribute::DECRYPT],
        )?)
    }
    fn check<W: Write>(
        &self,
        owner: &Owner,
        key: &NativeObjectRef,
        _report: &mut Report<W>,
    ) -> std::result::Result<(), Failure> {
        let contract = self
            .contract
            .as_ref()
            .ok_or(Failure::Input("extension_cipher_contract"))?;
        let iv = match self.vector.parameters {
            CipherParameters::Aes(AesCipherParameters::Cbc { iv }) => iv,
            _ => return Err(Failure::Input("extension_cipher_iv")),
        };
        let blocks = [ExtensionBlock {
            initial: &iv,
            alignment: 1,
            direction: ExtensionDirection::Input,
        }];
        // SAFETY: the sole root is the exact IV array; it has no encoded
        // pointers, mutable fields or outputs. Fe11 owns its copy before Init.
        let request = unsafe {
            ExtensionRequest::new(
                contract,
                ExtensionParameters {
                    blocks: &blocks,
                    pointers: &[],
                    root: Some(0),
                    outputs: &[],
                },
            )
        };
        let input = if self.vector.encrypt {
            ExtensionInput::Encrypt {
                key,
                input: &self.vector.input,
                output_capacity: self.vector.expected.len(),
            }
        } else {
            ExtensionInput::Decrypt {
                key,
                input: &self.vector.input,
                output_capacity: self.vector.expected.len(),
            }
        };
        let limits = InputLimits {
            maximum_parts: 1,
            maximum_total_bytes: self.vector.input.len(),
        };
        let result = match owner {
            Owner::Session(s) => s.execute_extension(request, input, limits, None),
            Owner::Advanced(s) => s.execute_extension(request, input, limits, None),
        }?;
        if result.as_bytes() != self.vector.expected
            || result.provenance() != MechanismLayoutProvenance::CallerAssertedLayout
            || result.parameter_output(0).is_some()
        {
            return Err(Failure::Oracle("extension_cipher_result"));
        }
        Ok(())
    }
}
