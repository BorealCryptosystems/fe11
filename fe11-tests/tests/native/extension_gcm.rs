// SPDX-License-Identifier: Apache-2.0
//! Legal shared input blocks and exact GCM outputs through an explicit ABI graph.
use super::super::{
    gcm_fixture::Vector,
    object_owner::Owner,
    outcome::Failure,
    report::{Producer, Report},
    single_key_case::SingleKeyCase,
};
use fe11::*;
use fe11_sys::{CK_GCM_PARAMS, CK_ULONG};
use std::{
    io::Write,
    mem::{align_of, offset_of, size_of},
    path::Path,
};

pub(super) struct Case {
    vector: Vector,
    graph: String,
    contract: Option<MechanismExtension>,
}

impl SingleKeyCase for Case {
    const ASSERTION: &'static str = "gcm_owned_input_graph_exact_answer";
    const PRODUCER: Producer = Producer::TestOracle;

    fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let (vector, graph) = Vector::read_graph(path)?;
        if !vector.valid
            || vector.tag_bits != 128
            || vector.iv.len() != 12
            || vector.lengths.len() != 1
            || (graph.starts_with("empty-") && !vector.aad.is_empty())
            || (graph == "shared-alias" && vector.aad != vector.iv)
            || (graph == "shared-disjoint" && vector.aad.is_empty())
        {
            return Err(Failure::Input("gcm_graph_dimensions"));
        }
        Ok(Self {
            vector,
            graph,
            contract: None,
        })
    }

    fn bind_module(&mut self, module: &Module) -> std::result::Result<(), Failure> {
        let before = module.call_counts()?;
        // SAFETY: PKCS#11 CK_GCM_PARAMS, synchronous one-shot Encrypt/Decrypt;
        // IV and AAD are read-only and may alias. Output is separate caller-owned
        // cipher storage; this ABI has no parameter output or hidden handles.
        self.contract = Some(unsafe {
            module.declare_mechanism_extension(
                fe11_sys::CKM_AES_GCM as u64,
                (2, 40),
                if self.vector.encrypt {
                    ExtensionOperation::Encrypt
                } else {
                    ExtensionOperation::Decrypt
                },
                false,
            )
        }?);
        if module.call_counts()? != before {
            return Err(Failure::Oracle("gcm_graph_declaration_dispatched"));
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
        let vector = &self.vector;
        let contract = self
            .contract
            .as_ref()
            .ok_or(Failure::Input("gcm_graph_contract"))?;
        // Initialize every padding byte; never read padding from a Rust struct.
        let mut root = [0u8; size_of::<CK_GCM_PARAMS>()];
        for (offset, value) in [
            (offset_of!(CK_GCM_PARAMS, ulIvLen), vector.iv.len()),
            (offset_of!(CK_GCM_PARAMS, ulIvBits), vector.iv.len() * 8),
            (offset_of!(CK_GCM_PARAMS, ulAADLen), vector.aad.len()),
            (offset_of!(CK_GCM_PARAMS, ulTagBits), 128),
        ] {
            let value = CK_ULONG::try_from(value).map_err(|_| Failure::Input("gcm_graph_ulong"))?;
            root[offset..offset + size_of::<CK_ULONG>()].copy_from_slice(&value.to_ne_bytes());
        }
        let mut storage = vector.iv.clone();
        let target = match self.graph.as_str() {
            "shared-disjoint" => {
                storage.extend_from_slice(&vector.aad);
                ExtensionPointerTarget::Block {
                    block: 1,
                    offset: vector.iv.len(),
                }
            }
            "shared-alias" => ExtensionPointerTarget::Block {
                block: 1,
                offset: 0,
            },
            "empty-null" => ExtensionPointerTarget::Null,
            "empty-end" => ExtensionPointerTarget::Block {
                block: 1,
                offset: storage.len(),
            },
            _ => return Err(Failure::Input("gcm_graph_selector")),
        };
        let blocks = [
            ExtensionBlock {
                initial: &root,
                alignment: align_of::<CK_GCM_PARAMS>(),
                direction: ExtensionDirection::Input,
            },
            ExtensionBlock {
                initial: &storage,
                alignment: 1,
                direction: ExtensionDirection::Input,
            },
        ];
        let pointers = [
            ExtensionPointer {
                block: 0,
                offset: offset_of!(CK_GCM_PARAMS, pIv),
                target: ExtensionPointerTarget::Block {
                    block: 1,
                    offset: 0,
                },
            },
            ExtensionPointer {
                block: 0,
                offset: offset_of!(CK_GCM_PARAMS, pAAD),
                target,
            },
        ];
        // SAFETY: exact ABI offsets/alignment from fe11-sys; two zero pointer
        // placeholders become owned relocations. Each nonempty extent fits the
        // shared block; aliasing is input-only. The end pointer has length zero.
        // No input overlaps output, no pointer field is exported as bytes, and
        // native code cannot retain these pointers beyond sequence completion.
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
        let input = if vector.encrypt {
            ExtensionInput::Encrypt {
                key,
                input: &vector.input,
                output_capacity: vector.expected.len(),
            }
        } else {
            ExtensionInput::Decrypt {
                key,
                input: &vector.input,
                // A module may conservatively require space for the complete
                // ciphertext. The exact authenticated plaintext is checked below.
                output_capacity: vector.input.len(),
            }
        };
        let limits = InputLimits {
            maximum_parts: 1,
            maximum_total_bytes: vector.input.len(),
        };
        let result = match owner {
            Owner::Session(s) => s.execute_extension(request, input, limits, None),
            Owner::Advanced(s) => s.execute_extension(request, input, limits, None),
        }?;
        if result.as_bytes() != vector.expected
            || result.provenance() != MechanismLayoutProvenance::CallerAssertedLayout
            || result.parameter_output(0).is_some()
        {
            return Err(Failure::Oracle("gcm_graph_exact_result"));
        }
        Ok(())
    }
}
