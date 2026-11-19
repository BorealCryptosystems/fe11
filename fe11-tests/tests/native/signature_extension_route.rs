// SPDX-License-Identifier: Apache-2.0
//! Correct native declarations passed to the wrong public signature route.
use super::{
    object_owner::Owner, outcome::Failure, report::Report, rsa_known_fixture::Vector,
    single_key_case::SingleKeyCase,
};
use fe11::*;
use std::{io::Write, path::Path};

pub struct Route<const STREAM: bool> {
    vector: Vector,
    contract: Option<MechanismExtension>,
}

impl<const STREAM: bool> SingleKeyCase for Route<STREAM> {
    const ASSERTION: &'static str = "signature_extension_route_rejected_before_native_init";
    const PRODUCER: super::report::Producer = super::report::Producer::TestOracle;
    fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let vector = Vector::read(path)?;
        if !matches!(vector.signature()?, NativeSignatureParameters::Parameterless(a)
            if a == NativeSignatureAlgorithm::SHA256_RSA_PKCS)
        {
            return Err(Failure::Input("extension_route_fixture"));
        }
        if vector.action != "sign" || vector.key[0].len() != 256 {
            return Err(Failure::Input("extension_route_key"));
        }
        Ok(Self {
            vector,
            contract: None,
        })
    }
    fn bind_module(&mut self, module: &Module) -> std::result::Result<(), Failure> {
        let before = module.call_counts()?;
        let (mechanism, operation) = if STREAM {
            (fe11_sys::CKM_RSA_PKCS, ExtensionOperation::Sign)
        } else {
            (
                fe11_sys::CKM_SHA256_RSA_PKCS,
                ExtensionOperation::SignMultipart,
            )
        };
        // SAFETY: Both standard mechanisms have a NULL/0 parameter ABI in
        // PKCS#11 2.40 and 3.2. The operation correctly describes their selected
        // native route, with no key mutation or auxiliary pointer outputs.
        self.contract = Some(unsafe {
            module.declare_mechanism_extension(mechanism as u64, (2, 40), operation, false)?
        });
        if module.call_counts()? != before {
            return Err(Failure::Oracle("declaration_native_dispatch"));
        }
        Ok(())
    }
    fn advanced(&self) -> bool {
        self.vector.advanced
    }
    fn import(&self, owner: &Owner) -> std::result::Result<NativeObjectRef, Failure> {
        Ok(owner.import_rsa_private_usage(&self.vector.key, StandardAttribute::SIGN, true)?)
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
            .ok_or(Failure::Input("extension_route_contract"))?;
        // SAFETY: The declaration above requires no parameters. No allocations,
        // pointers, outputs or borrowed native graph are present in this request.
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
        let limits = InputLimits {
            maximum_parts: 1,
            maximum_total_bytes: self.vector.input.len(),
        };
        let output = SignatureOutputPlan::Buffer { capacity: 256 };
        let result = match (owner, STREAM) {
            (Owner::Session(s), true) => {
                s.begin_extension_signature_stream(key, request, None, limits, output, 256)
            }
            (Owner::Advanced(s), true) => {
                s.begin_extension_signature_stream(key, request, None, limits, output, 256)
            }
            (Owner::Session(s), false) => {
                s.begin_extension_signature_single(key, request, None, limits, output, 256)
            }
            (Owner::Advanced(s), false) => {
                s.begin_extension_signature_single(key, request, None, limits, output, 256)
            }
        };
        let expected = if STREAM {
            SignatureContinuationRejection::SignatureStreamExtensionRoute
        } else {
            SignatureContinuationRejection::SingleSignatureExtensionRoute
        };
        match result {
            Err(Error::Rejected(RejectionReason::SignatureContinuation(actual)))
                if actual == expected =>
            {
                Ok(())
            }
            Err(error) => Err(error.into()),
            Ok(_) => Err(Failure::Oracle("wrong_extension_route_accepted")),
        }
    }
}
