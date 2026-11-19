// SPDX-License-Identifier: Apache-2.0
//! Declared RSA PKCS#1 signing and verification preserve exact public-vector bytes.
use super::super::{
    object_owner::Owner, outcome::Failure, report::Report, rsa_known_fixture::Vector,
    single_key_case::SingleKeyCase,
};
use fe11::*;
use std::{io::Write, path::Path};

pub(super) struct Case {
    vector: Vector,
    contract: Option<MechanismExtension>,
}
impl SingleKeyCase for Case {
    const ASSERTION: &'static str = "declared_signature_exact_answer_and_provenance";
    fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let vector = Vector::read(path)?;
        if !matches!(vector.signature()?, NativeSignatureParameters::Parameterless(a)
            if a == NativeSignatureAlgorithm::RSA_PKCS || a == NativeSignatureAlgorithm::SHA256_RSA_PKCS)
            || !matches!(vector.action.as_str(), "sign" | "verify")
            // The shared reader chooses a multipart route for its original
            // combined-mechanism harness. This fixture explicitly exercises
            // one-shot extension dispatch with exactly one complete part.
            || vector.lengths.as_slice() != [vector.input.len()]
            || vector.randomized
            || vector.negative.is_some()
            || vector.expected.len() != 256
        {
            return Err(Failure::Input("extension_signature_fixture"));
        }
        Ok(Self {
            vector,
            contract: None,
        })
    }
    fn bind_module(&mut self, module: &Module) -> std::result::Result<(), Failure> {
        let mechanism = match self.vector.signature()? {
            NativeSignatureParameters::Parameterless(a)
                if a == NativeSignatureAlgorithm::RSA_PKCS =>
            {
                fe11_sys::CKM_RSA_PKCS
            }
            NativeSignatureParameters::Parameterless(a)
                if a == NativeSignatureAlgorithm::SHA256_RSA_PKCS =>
            {
                fe11_sys::CKM_SHA256_RSA_PKCS
            }
            _ => return Err(Failure::Input("extension_signature_mechanism")),
        };
        let operation = if self.vector.action == "sign" {
            ExtensionOperation::Sign
        } else {
            ExtensionOperation::Verify
        };
        let before = module.call_counts()?;
        // SAFETY: both standard RSA selectors have a NULL/0 parameter ABI.
        // The declaration has no auxiliary outputs or mutable key-state claim.
        self.contract = Some(unsafe {
            module.declare_mechanism_extension(mechanism as u64, (2, 40), operation, false)
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
        Ok(if self.vector.action == "sign" {
            owner.import_rsa_private(&self.vector.key, StandardAttribute::SIGN)?
        } else {
            owner.import_rsa_public(&self.vector.key[0], &self.vector.key[1])?
        })
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
            .ok_or(Failure::Input("extension_signature_contract"))?;
        // SAFETY: the declared NULL/0 ABI has no pointer, allocation or output
        // field. Message/signature bytes are owned by the typed data route.
        let request = unsafe {
            ExtensionRequest::new(
                contract,
                ExtensionParameters {
                    blocks: &[],
                    pointers: &[],
                    root: None,
                    outputs: &[],
                },
            )
        };
        let input = if self.vector.action == "sign" {
            ExtensionInput::Sign {
                key,
                input: &self.vector.input,
                output_capacity: 256,
            }
        } else {
            ExtensionInput::Verify {
                key,
                input: &self.vector.input,
                signature: &self.vector.expected,
            }
        };
        let result = match owner {
            Owner::Session(s) => s.execute_extension(
                request,
                input,
                InputLimits {
                    maximum_parts: 1,
                    maximum_total_bytes: self.vector.input.len(),
                },
                None,
            ),
            Owner::Advanced(s) => s.execute_extension(
                request,
                input,
                InputLimits {
                    maximum_parts: 1,
                    maximum_total_bytes: self.vector.input.len(),
                },
                None,
            ),
        }?;
        let expected = if self.vector.action == "sign" {
            self.vector.expected.as_slice()
        } else {
            &[]
        };
        if result.as_bytes() != expected
            || result.provenance() != MechanismLayoutProvenance::CallerAssertedLayout
            || result.parameter_output(0).is_some()
        {
            return Err(Failure::Oracle("extension_signature_result"));
        }
        Ok(())
    }
}
