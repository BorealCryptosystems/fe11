// SPDX-License-Identifier: Apache-2.0
//! Standard wrap, unwrap and derivation through explicit caller ABI declarations.
use super::super::{
    arguments::{hex, Arguments},
    derived_value, key_wrap_fixture, module_controls,
    object_owner::Owner,
    outcome::Failure,
    report::Report,
};
use fe11::*;
use std::{
    fs::File,
    io::{self, Read, Write},
};
#[path = "extension_derive_graph.rs"]
mod derive_graph;

fn request(contract: &MechanismExtension) -> ExtensionRequest<'_> {
    // SAFETY: AES key wrap uses NULL/0 parameters.
    // There are no nested pointers or auxiliary output regions in this graph.
    unsafe {
        ExtensionRequest::new(
            contract,
            ExtensionParameters {
                blocks: &[],
                pointers: &[],
                root: None,
                outputs: &[],
            },
        )
    }
}

fn template<'a>(attributes: &'a [AttributeInput<'a>]) -> GenerationTemplate<'a> {
    GenerationTemplate {
        attributes,
        limits: key_wrap_fixture::limits(attributes.len(), 32),
        observation: None,
        destination: DestinationPlan {
            search: DestinationSearchPlan::NotRequested,
            user: DestinationUserObservation::NotRequested,
        },
    }
}

fn derive(
    owner: &Owner,
    base: &NativeObjectRef,
    contract: &MechanismExtension,
    attributes: &[AttributeInput<'_>],
    layout: &str,
) -> Result<CreatedObjects<NativeObjectView>> {
    if layout == "derive-cbc-tail" {
        return derive_graph::derive(owner, base, contract, template(attributes));
    }
    use fe11_sys::{CK_KEY_DERIVATION_STRING_DATA, CK_ULONG};
    use std::mem::{align_of, offset_of, size_of};
    let storage = [0xaa, 0xff, 0x00, 0xfe];
    let (suffix, pointer_offset, length) = match layout {
        "derive-offset" => (&storage[..], 1, 3),
        "derive-tail" => (&storage[..], 3, 1),
        "derive-empty" => (&storage[..], 4, 0),
        _ => (&storage[1..], 0, 3),
    };
    // Initialize padding as bytes rather than reading a Rust struct's padding.
    let mut root = [0u8; size_of::<CK_KEY_DERIVATION_STRING_DATA>()];
    let offset = offset_of!(CK_KEY_DERIVATION_STRING_DATA, ulLen);
    root[offset..offset + size_of::<CK_ULONG>()]
        .copy_from_slice(&(length as CK_ULONG).to_ne_bytes());
    let blocks = [
        ExtensionBlock {
            initial: &root,
            alignment: align_of::<CK_KEY_DERIVATION_STRING_DATA>(),
            direction: ExtensionDirection::Input,
        },
        ExtensionBlock {
            initial: suffix,
            alignment: 1,
            direction: ExtensionDirection::Input,
        },
    ];
    let pointers = [ExtensionPointer {
        block: 0,
        offset: offset_of!(CK_KEY_DERIVATION_STRING_DATA, pData),
        target: ExtensionPointerTarget::Block {
            block: 1,
            offset: pointer_offset,
        },
    }];
    // SAFETY: exact string-data ABI and one relocated pointer. The declared
    // length fits the remaining extent, including the explicitly empty span at
    // one-past-end. Native rejection of empty data does not authorize a read.
    // Fe11 copies both live input blocks; neither contains auxiliary outputs
    // or hidden handles, and the pointer field itself remains immutable.
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
    let parameters = NativeKeyDerivation::Extension {
        request,
        class: ManagedClass::SecretKey,
    };
    match owner {
        Owner::Session(s) => s.derive_native_key(base, parameters, template(attributes)),
        Owner::Advanced(s) => s.derive_native_key(base, parameters, template(attributes)),
    }
}

fn attribute(
    module: &Module,
    owner: &Owner,
    key: &NativeObjectRef,
) -> std::result::Result<(), Failure> {
    let identifier = fe11_sys::CKA_VENDOR_DEFINED as u64 + 0x00ff_ffff;
    // SAFETY: this recipe's module has no definition for the selected number.
    // Its flat unsupported-attribute path does not interpret nested pointers.
    let declared =
        unsafe { module.declare_attribute_extension(identifier, AttributeLayout::Bytes) }?;
    let kind = AttributeType::from(declared);
    if declared.identifier() != identifier || kind.layout() != AttributeLayout::Bytes {
        return Err(Failure::Oracle("extension_attribute_identity_layout"));
    }
    let value = match owner {
        Owner::Session(s) => s.read_flat_attribute(
            key,
            declared,
            FlatAttributeReadPlan::Buffer { capacity: 16 },
        ),
        Owner::Advanced(s) => s.read_flat_attribute(
            key,
            declared,
            FlatAttributeReadPlan::Buffer { capacity: 16 },
        ),
    }?;
    if value.calls
        != (AttributeReadCalls::Direct {
            code: fe11_sys::CKR_ATTRIBUTE_TYPE_INVALID as u64,
        })
        || !matches!(
            value.value,
            FlatAttributeValue::Unavailable(AttributeUnavailableCause::Unsupported)
        )
    {
        return Err(Failure::Oracle("extension_attribute_native_unsupported"));
    }
    Ok(())
}

fn equal_value(
    owner: &Owner,
    object: &NativeObjectRef,
    expected: &[u8],
) -> std::result::Result<(), Failure> {
    let read = match owner {
        Owner::Session(s) => s.read_flat_attribute(
            object,
            StandardAttribute::VALUE,
            FlatAttributeReadPlan::Buffer {
                capacity: expected.len(),
            },
        ),
        Owner::Advanced(s) => s.read_flat_attribute(
            object,
            StandardAttribute::VALUE,
            FlatAttributeReadPlan::Buffer {
                capacity: expected.len(),
            },
        ),
    }?;
    if read.calls != (AttributeReadCalls::Direct { code: 0 }) {
        return Err(Failure::Oracle("extension_object_read_status"));
    }
    match read.value {
        FlatAttributeValue::Available(bytes) if bytes.as_bytes() == expected => Ok(()),
        _ => Err(Failure::Oracle("extension_object_exact_value")),
    }
}

pub fn execute<W: Write>(module: Module, args: &Arguments, report: Report<W>) -> io::Result<bool> {
    let mut owner = None;
    let mut base = None;
    let mut target = None;
    let mut created = None;
    let setup =
        (|| -> std::result::Result<(String, Vec<u8>, Vec<u8>, Option<MechanismExtension>), Failure> {
            let mut text = String::new();
            File::open(&args.vector)
                .map_err(|_| Failure::Input("extension_object_open"))?
                .take(257)
                .read_to_string(&mut text)
                .map_err(|_| Failure::Input("extension_object_read"))?;
            let fields: Vec<_> = text.split_terminator('\n').collect();
            if text.len() > 256
                || fields.len() != 4
                || !matches!(fields[0], "session" | "advanced")
                || !matches!(fields[1], "wrap" | "unwrap" | "derive" | "attribute"
                    | "derive-offset" | "derive-tail" | "derive-empty" | "derive-cbc-tail")
            {
                return Err(Failure::Input("extension_object_fields"));
            }
            let input = hex(fields[2], 32).map_err(Failure::Input)?;
            let expected = hex(fields[3], 32).map_err(Failure::Input)?;
            let (mechanism, operation) = match fields[1] {
                "wrap" => (fe11_sys::CKM_AES_KEY_WRAP, ExtensionOperation::WrapKey),
                "unwrap" => (fe11_sys::CKM_AES_KEY_WRAP, ExtensionOperation::UnwrapKey),
                "derive-cbc-tail" => (fe11_sys::CKM_AES_CBC_ENCRYPT_DATA, ExtensionOperation::DeriveKey),
                _ => (
                    fe11_sys::CKM_CONCATENATE_BASE_AND_DATA,
                    ExtensionOperation::DeriveKey,
                ),
            };
            // SAFETY: standard AES-KW NULL/0, CBC-encrypt-data or concatenation ABI,
            // one returned secret for unwrap/derive, byte output for wrap, and
            // no source-key mutation or hidden object handles.
            let contract = if fields[1] == "attribute" {
                None
            } else {
                Some(unsafe {
                    module.declare_mechanism_extension(mechanism as u64, (2, 40), operation, false)
                }?)
            };
            owner = Some(Owner::open(&module, &args.config, fields[0] == "advanced")?);
            let o = owner
                .as_ref()
                .ok_or(Failure::Input("extension_object_owner"))?;
            let key = hex("000102030405060708090a0b0c0d0e0f", 16).map_err(Failure::Input)?;
            base = Some(if fields[1].starts_with("derive") {
                // Concatenation propagates a non-extractable base policy to
                // its result. This public-value witness therefore imports an
                // explicitly extractable base, just like the typed route.
                o.import_secret_usages(
                    &input,
                    if fields[1] == "derive-cbc-tail" { fe11_sys::CKK_AES } else { fe11_sys::CKK_GENERIC_SECRET },
                    [
                        (StandardAttribute::DERIVE, true),
                        (StandardAttribute::EXTRACTABLE, true),
                    ],
                )?
            } else {
                o.import_secret(
                    &key,
                    fe11_sys::CKK_AES,
                    [StandardAttribute::WRAP, StandardAttribute::UNWRAP],
                )?
            });
            if fields[1] == "wrap" {
                target = Some(key_wrap_fixture::import_target(o, &input)?);
            }
            Ok((fields[1].into(), input, expected, contract))
        })();
    let body = (|| -> std::result::Result<(), Failure> {
        let Ok((action, input, expected, contract)) = &setup else {
            return Ok(());
        };
        let o = owner
            .as_ref()
            .ok_or(Failure::Input("extension_object_owner"))?;
        let key = base
            .as_ref()
            .ok_or(Failure::Input("extension_object_key"))?;
        if action == "attribute" {
            return attribute(&module, o, key);
        }
        let contract = contract
            .as_ref()
            .ok_or(Failure::Input("extension_object_contract"))?;
        if action == "wrap" {
            let target = target
                .as_ref()
                .ok_or(Failure::Input("extension_wrap_target"))?;
            let result = match o {
                Owner::Session(s) => {
                    s.wrap_key_extension(key, target, request(contract), expected.len())
                }
                Owner::Advanced(s) => {
                    s.wrap_key_extension(key, target, request(contract), expected.len())
                }
            }?;
            if result.as_bytes() != expected
                || result.parameter_output(0).is_some()
                || result.provenance() != MechanismLayoutProvenance::CallerAssertedLayout
            {
                return Err(Failure::Oracle("extension_wrap_known_answer"));
            }
        } else {
            // AES key unwrap obtains the length from the envelope. Its template
            // omits CKA_VALUE_LEN; concatenation explicitly requests seven bytes.
            let attributes = if action == "unwrap" {
                Vec::from(key_wrap_fixture::template())
            } else {
                Vec::from(derived_value::template_attributes(expected.len()))
            };
            if action == "unwrap" {
                let result = match o {
                    Owner::Session(s) => s.unwrap_key_extension(
                        key,
                        input,
                        request(contract),
                        ManagedClass::SecretKey,
                        template(&attributes),
                    ),
                    Owner::Advanced(s) => s.unwrap_key_extension(
                        key,
                        input,
                        request(contract),
                        ManagedClass::SecretKey,
                        template(&attributes),
                    ),
                }?;
                created = Some(result.objects);
                result.observation?;
                if result.remainder.is_some() {
                    return Err(Failure::Oracle("extension_unwrap_remainder"));
                }
            } else {
                // The concatenation oracle preserves the base for an empty
                // suffix. A module-specific refusal remains an error, not a
                // successful proof of the nominal derived value.
                let result = derive(o, key, contract, &attributes, action)?;
                created = Some(result.objects);
                result.observation?;
                if result.remainder.is_some() {
                    return Err(Failure::Oracle("extension_derive_remainder"));
                }
            }
            let objects = created
                .as_ref()
                .ok_or(Failure::Input("extension_created_owner"))?
                .as_slice();
            if objects.len() != 1 {
                return Err(Failure::Oracle("extension_created_count"));
            }
            equal_value(o, &objects[0], expected)?;
        }
        Ok(())
    })();
    let mut cleanup = Vec::new();
    if let Some(o) = &owner {
        let created_objects = created.as_ref().map_or(&[][..], CreatedObjectSet::as_slice);
        for object in created_objects
            .iter()
            .chain(target.iter())
            .chain(base.iter())
        {
            let result = match o {
                Owner::Session(s) => s.destroy_native_object(object),
                Owner::Advanced(s) => s.destroy_native_object(object),
            };
            if let Err(error) = result {
                cleanup.push(error.into());
            }
        }
        cleanup.extend(o.close(None));
    }
    drop(created);
    drop(target);
    drop(base);
    drop(owner);
    if let Err(error) = module.close() {
        cleanup.push(error.into());
    }
    module_controls::finish(report, setup.map(|_| ()), body, cleanup)
}
