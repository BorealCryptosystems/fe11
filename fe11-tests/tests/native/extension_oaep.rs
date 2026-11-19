// SPDX-License-Identifier: Apache-2.0
//! OAEP label relocations preserve the independently published plaintext.
use super::super::{
    oaep_fixture::Vector, object_owner::Owner, outcome::Failure, report::Report,
    single_key_case::SingleKeyCase,
};
use fe11::*;
use fe11_sys::{CK_RSA_PKCS_OAEP_PARAMS, CK_ULONG};
use std::{
    io::Write,
    mem::{align_of, offset_of, size_of},
    path::Path,
};

pub(super) struct Case<const NULL: bool> {
    vector: Vector,
    contract: Option<MechanismExtension>,
}

impl<const NULL: bool> SingleKeyCase for Case<NULL> {
    const ASSERTION: &'static str = "oaep_label_graph_exact_plaintext";

    fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let vector = Vector::read(path)?;
        if !vector.valid || vector.contract.is_some() || (NULL && !vector.label.is_empty()) {
            return Err(Failure::Input("oaep_graph_fixture"));
        }
        Ok(Self {
            vector,
            contract: None,
        })
    }
    fn bind_module(&mut self, module: &Module) -> std::result::Result<(), Failure> {
        let before = module.call_counts()?;
        // SAFETY: CK_RSA_PKCS_OAEP_PARAMS is the standard synchronous RSA
        // decryption ABI. The label is input-only; no parameter output exists.
        self.contract = Some(unsafe {
            module.declare_mechanism_extension(
                fe11_sys::CKM_RSA_PKCS_OAEP as u64,
                (2, 40),
                ExtensionOperation::Decrypt,
                false,
            )
        }?);
        if module.call_counts()? != before {
            return Err(Failure::Oracle("oaep_declaration_dispatched"));
        }
        Ok(())
    }
    fn advanced(&self) -> bool {
        self.vector.advanced
    }
    fn import(&self, owner: &Owner) -> std::result::Result<NativeObjectRef, Failure> {
        Ok(self.vector.import(owner)?)
    }
    fn check<W: Write>(
        &self,
        owner: &Owner,
        key: &NativeObjectRef,
        _report: &mut Report<W>,
    ) -> std::result::Result<(), Failure> {
        let v = &self.vector;
        let contract = self
            .contract
            .as_ref()
            .ok_or(Failure::Input("oaep_graph_contract"))?;
        // Explicitly initialized padding and native-width scalars. Prefix bytes
        // are not label bytes: the pointed-to extent ends exactly at the block end.
        let mut root = [0u8; size_of::<CK_RSA_PKCS_OAEP_PARAMS>()];
        for (offset, value) in [
            (offset_of!(CK_RSA_PKCS_OAEP_PARAMS, hashAlg), v.hash),
            (offset_of!(CK_RSA_PKCS_OAEP_PARAMS, mgf), v.mgf),
            (
                offset_of!(CK_RSA_PKCS_OAEP_PARAMS, source),
                fe11_sys::CKZ_DATA_SPECIFIED as u64,
            ),
            (
                offset_of!(CK_RSA_PKCS_OAEP_PARAMS, ulSourceDataLen),
                v.label.len() as u64,
            ),
        ] {
            let value =
                CK_ULONG::try_from(value).map_err(|_| Failure::Input("oaep_graph_ulong"))?;
            root[offset..offset + size_of::<CK_ULONG>()].copy_from_slice(&value.to_ne_bytes());
        }
        let mut storage = vec![0xa5; 8];
        storage.extend_from_slice(&v.label);
        let blocks = [
            ExtensionBlock {
                initial: &root,
                alignment: align_of::<CK_RSA_PKCS_OAEP_PARAMS>(),
                direction: ExtensionDirection::Input,
            },
            ExtensionBlock {
                initial: &storage,
                alignment: 1,
                direction: ExtensionDirection::Input,
            },
        ];
        let pointers = [ExtensionPointer {
            block: 0,
            offset: offset_of!(CK_RSA_PKCS_OAEP_PARAMS, pSourceData),
            target: if NULL {
                ExtensionPointerTarget::Null
            } else {
                ExtensionPointerTarget::Block {
                    block: 1,
                    offset: 8,
                }
            },
        }];
        // SAFETY: ABI-derived field offsets/alignment; one immutable label
        // pointer. NULL is used only with length0. A non-NULL label fits its
        // owned block exactly; an empty label points one-past-end. Ciphertext
        // and output use separate storage; no native pointer survives this call.
        let request = unsafe {
            ExtensionRequest::new(
                contract,
                ExtensionParameters {
                    blocks: &blocks,
                    pointers: &pointers,
                    root: Some(0),
                    outputs: &[],
                },
            )
        };
        let input = ExtensionInput::Decrypt {
            key,
            input: &v.ciphertext,
            output_capacity: v.key[0].len(),
        };
        let limits = InputLimits {
            maximum_parts: 1,
            maximum_total_bytes: v.ciphertext.len(),
        };
        let result = match owner {
            Owner::Session(s) => s.execute_extension(request, input, limits, None),
            Owner::Advanced(s) => s.execute_extension(request, input, limits, None),
        }?;
        if result.as_bytes() != v.plaintext
            || result.provenance() != MechanismLayoutProvenance::CallerAssertedLayout
            || result.parameter_output(0).is_some()
        {
            return Err(Failure::Oracle("oaep_graph_exact_result"));
        }
        Ok(())
    }
}
