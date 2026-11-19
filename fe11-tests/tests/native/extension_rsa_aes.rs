// SPDX-License-Identifier: Apache-2.0
//! A two-level standard RSA-AES unwrap graph and exact derived object value.
use super::{
    arguments::Arguments, credentials::Credentials, key_wrap_fixture, module_controls,
    object_owner::Owner, outcome::Failure, report::Report, rsa_unwrap_negative::Case,
};
use fe11::*;
use fe11_sys::{CK_RSA_AES_KEY_WRAP_PARAMS, CK_RSA_PKCS_OAEP_PARAMS, CK_ULONG};
use std::{
    io::{self, Write},
    mem::{align_of, offset_of, size_of},
};

fn unwrap(
    owner: &Owner,
    key: &NativeObjectRef,
    contract: &MechanismExtension,
    case: &Case,
    retained: &mut Option<CreatedObjectSet>,
) -> std::result::Result<(), Failure> {
    let mut root = [0u8; size_of::<CK_RSA_AES_KEY_WRAP_PARAMS>()];
    let bits = offset_of!(CK_RSA_AES_KEY_WRAP_PARAMS, ulAESKeyBits);
    root[bits..bits + size_of::<CK_ULONG>()].copy_from_slice(&(192 as CK_ULONG).to_ne_bytes());
    let mut oaep = [0u8; size_of::<CK_RSA_PKCS_OAEP_PARAMS>()];
    for (offset, value) in [
        (
            offset_of!(CK_RSA_PKCS_OAEP_PARAMS, hashAlg),
            fe11_sys::CKM_SHA256,
        ),
        (
            offset_of!(CK_RSA_PKCS_OAEP_PARAMS, mgf),
            fe11_sys::CKG_MGF1_SHA256,
        ),
        (
            offset_of!(CK_RSA_PKCS_OAEP_PARAMS, source),
            fe11_sys::CKZ_DATA_SPECIFIED,
        ),
    ] {
        oaep[offset..offset + size_of::<CK_ULONG>()].copy_from_slice(&value.to_ne_bytes());
    }
    let label_storage = [0xa5; 8];
    let blocks = [
        ExtensionBlock {
            initial: &root,
            alignment: align_of::<CK_RSA_AES_KEY_WRAP_PARAMS>(),
            direction: ExtensionDirection::Input,
        },
        ExtensionBlock {
            initial: &oaep,
            alignment: align_of::<CK_RSA_PKCS_OAEP_PARAMS>(),
            direction: ExtensionDirection::Input,
        },
        ExtensionBlock {
            initial: &label_storage,
            alignment: 1,
            direction: ExtensionDirection::Input,
        },
    ];
    let pointers = [
        ExtensionPointer {
            block: 0,
            offset: offset_of!(CK_RSA_AES_KEY_WRAP_PARAMS, pOAEPParams),
            target: ExtensionPointerTarget::Block {
                block: 1,
                offset: 0,
            },
        },
        ExtensionPointer {
            block: 1,
            offset: offset_of!(CK_RSA_PKCS_OAEP_PARAMS, pSourceData),
            target: ExtensionPointerTarget::Block {
                block: 2,
                offset: 8,
            },
        },
    ];
    // SAFETY: standard nested ABI with exact offsets and aligned initialized
    // roots. The empty label points one-past-end with length0. All parameters
    // are input-only. C_UnwrapKey returns its sole public object through the
    // usual output handle; no parameter output or retained pointer is declared.
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
    let attributes = key_wrap_fixture::template();
    let template = GenerationTemplate {
        attributes: &attributes,
        limits: key_wrap_fixture::limits(attributes.len(), 0),
        observation: None,
        destination: DestinationPlan {
            search: DestinationSearchPlan::NotRequested,
            user: DestinationUserObservation::NotRequested,
        },
    };
    let result = match owner {
        Owner::Session(s) => s.unwrap_key_extension(
            key,
            &case.envelope,
            request,
            ManagedClass::SecretKey,
            template,
        ),
        Owner::Advanced(s) => s.unwrap_key_extension(
            key,
            &case.envelope,
            request,
            ManagedClass::SecretKey,
            template,
        ),
    }?;
    *retained = Some(result.objects);
    result.observation?;
    if result.remainder.is_some() {
        return Err(Failure::Oracle("nested_unwrap_remainder"));
    }
    let objects = retained
        .as_ref()
        .ok_or(Failure::Input("nested_unwrap_owner"))?
        .as_slice();
    if objects.len() != 1 {
        return Err(Failure::Oracle("nested_unwrap_count"));
    }
    let plan = FlatAttributeReadPlan::Buffer {
        capacity: case.plain.len(),
    };
    let value = match owner {
        Owner::Session(s) => s.read_flat_attribute(&objects[0], StandardAttribute::VALUE, plan),
        Owner::Advanced(s) => s.read_flat_attribute(&objects[0], StandardAttribute::VALUE, plan),
    }?;
    if value.calls != (AttributeReadCalls::Direct { code: 0 }) {
        return Err(Failure::Oracle("nested_unwrap_read_code"));
    }
    match value.value {
        FlatAttributeValue::Available(v) if v.as_bytes() == case.plain => Ok(()),
        _ => Err(Failure::Oracle("nested_unwrap_exact_value")),
    }
}

pub fn execute<W: Write>(
    module: Module,
    args: &Arguments,
    pins: &Credentials,
    report: Report<W>,
) -> io::Result<bool> {
    let mut owner = None;
    let mut key = None;
    let mut retained = None;
    let setup = (|| -> std::result::Result<(Case, MechanismExtension), Failure> {
        let case = Case::read(&args.vector)?;
        if case.algorithm != "rsa_aes" {
            return Err(Failure::Input("nested_unwrap_algorithm"));
        }
        let before = module.call_counts()?;
        // SAFETY: standard RSA-AES key unwrap, one returned object and no
        // source-key mutation. Internal temporary key ownership belongs to the module.
        let contract = unsafe {
            module.declare_mechanism_extension(
                fe11_sys::CKM_RSA_AES_KEY_WRAP as u64,
                (2, 40),
                ExtensionOperation::UnwrapKey,
                false,
            )
        }?;
        if module.call_counts()? != before {
            return Err(Failure::Oracle("nested_declaration_dispatched"));
        }
        owner = Some(Owner::open(&module, &args.config, false)?);
        // The real module creates an internal private AES key for this mechanism.
        let Some(Owner::Session(session)) = &owner else {
            return Err(Failure::Input("nested_login_owner"));
        };
        session.login_as(LoginRole::User, SecretPin::new(pins.user.to_vec()))?;
        if args.mode.ends_with("advanced") {
            let Some(Owner::Session(session)) = owner.take() else {
                return Err(Failure::Input("nested_conversion_owner"));
            };
            owner = Some(Owner::Advanced(session.into_advanced()?));
        }
        let o = owner.as_ref().ok_or(Failure::Input("nested_owner"))?;
        key = Some(o.import_rsa_private(&case.key, StandardAttribute::UNWRAP)?);
        Ok((case, contract))
    })();
    let body = match &setup {
        Ok((case, contract)) => match (&owner, &key) {
            (Some(o), Some(k)) => unwrap(o, k, contract, case, &mut retained),
            _ => Err(Failure::Input("nested_fixture_owner")),
        },
        Err(_) => Ok(()),
    };
    let mut cleanup = Vec::new();
    if let Some(o) = &owner {
        if let Some(set) = &retained {
            for object in set.as_slice() {
                if let Err(e) = key_wrap_fixture::destroy(o, object) {
                    cleanup.push(e.into());
                }
            }
        }
        if let Some(k) = &key {
            if let Err(e) = key_wrap_fixture::destroy(o, k) {
                cleanup.push(e.into());
            }
        }
    }
    drop(retained);
    drop(key);
    if let Some(o) = &owner {
        cleanup.extend(o.close(None));
    }
    drop(owner);
    if let Err(e) = module.close() {
        cleanup.push(e.into());
    }
    module_controls::finish(report, setup.map(|_| ()), body, cleanup)
}
