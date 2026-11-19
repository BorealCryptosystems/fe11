// SPDX-License-Identifier: Apache-2.0
//! Declared RSA generation retains both capabilities and checks their native use.
use super::super::{
    arguments::Arguments, key_wrap_fixture, module_controls, object_owner::Owner, outcome::Failure,
    report::Report,
};
use fe11::*;
use std::{
    fs::File,
    io::{self, Read, Write},
};

fn template<'a>(attributes: &'a [AttributeInput<'a>]) -> GenerationTemplate<'a> {
    GenerationTemplate {
        attributes,
        limits: AttributeTemplateLimits {
            maximum_depth: 0,
            maximum_attributes: attributes.len(),
            maximum_value_bytes: 64,
        },
        observation: None,
        destination: DestinationPlan {
            search: DestinationSearchPlan::NotRequested,
            user: DestinationUserObservation::NotRequested,
        },
    }
}

pub fn execute<W: Write>(module: Module, args: &Arguments, report: Report<W>) -> io::Result<bool> {
    let mut owner = None;
    let mut retained = None;
    let setup = (|| -> std::result::Result<(), Failure> {
        let mut bytes = Vec::new();
        File::open(&args.vector)
            .map_err(|_| Failure::Input("fixture_open"))?
            .take(17)
            .read_to_end(&mut bytes)
            .map_err(|_| Failure::Input("fixture_read"))?;
        let advanced = match bytes.as_slice() {
            b"session\n" => false,
            b"advanced\n" => true,
            _ => return Err(Failure::Input("extension_pair_owner")),
        };
        owner = Some(Owner::open(&module, &args.config, advanced)?);
        Ok(())
    })();
    let body = (|| -> std::result::Result<(), Failure> {
        if setup.is_err() {
            return Ok(());
        }
        let o = owner
            .as_ref()
            .ok_or(Failure::Input("extension_pair_owner"))?;
        let attr = |attribute: StandardAttribute, value| AttributeInput {
            attribute: attribute.into(),
            value,
        };
        let public = [
            attr(
                StandardAttribute::CLASS,
                AttributeInputValue::Unsigned(fe11_sys::CKO_PUBLIC_KEY as u64),
            ),
            attr(
                StandardAttribute::KEY_TYPE,
                AttributeInputValue::Unsigned(fe11_sys::CKK_RSA as u64),
            ),
            attr(
                StandardAttribute::TOKEN,
                AttributeInputValue::Boolean(false),
            ),
            attr(
                StandardAttribute::PRIVATE,
                AttributeInputValue::Boolean(false),
            ),
            attr(
                StandardAttribute::VERIFY,
                AttributeInputValue::Boolean(true),
            ),
            attr(
                StandardAttribute::MODULUS_BITS,
                AttributeInputValue::Unsigned(2048),
            ),
            attr(
                StandardAttribute::PUBLIC_EXPONENT,
                AttributeInputValue::Bytes(&[1, 0, 1]),
            ),
        ];
        let private = [
            attr(
                StandardAttribute::CLASS,
                AttributeInputValue::Unsigned(fe11_sys::CKO_PRIVATE_KEY as u64),
            ),
            attr(
                StandardAttribute::KEY_TYPE,
                AttributeInputValue::Unsigned(fe11_sys::CKK_RSA as u64),
            ),
            attr(
                StandardAttribute::TOKEN,
                AttributeInputValue::Boolean(false),
            ),
            attr(
                StandardAttribute::PRIVATE,
                AttributeInputValue::Boolean(false),
            ),
            attr(StandardAttribute::SIGN, AttributeInputValue::Boolean(true)),
            attr(
                StandardAttribute::SENSITIVE,
                AttributeInputValue::Boolean(true),
            ),
            attr(
                StandardAttribute::EXTRACTABLE,
                AttributeInputValue::Boolean(false),
            ),
        ];
        // SAFETY: RSA PKCS key-pair generation takes NULL/0 mechanism parameters;
        // its two object outputs are owned by this dedicated pair-generation API.
        let contract = unsafe {
            module.declare_mechanism_extension(
                fe11_sys::CKM_RSA_PKCS_KEY_PAIR_GEN as u64,
                (2, 40),
                ExtensionOperation::GenerateKeyPair,
                false,
            )
        }?;
        // SAFETY: no block, pointer or auxiliary output exists in this exact ABI.
        let request = unsafe {
            ExtensionRequest::new(
                &contract,
                ExtensionParameters {
                    blocks: &[],
                    pointers: &[],
                    root: None,
                    outputs: &[],
                },
            )
        };
        let created = match o {
            Owner::Session(s) => {
                s.generate_extension_key_pair(request, template(&public), template(&private))
            }
            Owner::Advanced(s) => {
                s.generate_extension_key_pair(request, template(&public), template(&private))
            }
        }?;
        retained = Some(created.objects);
        let observed = created.observation?;
        match observed.output {
            NativeGenerationOutput::Extension(value)
                if value.provenance() == MechanismLayoutProvenance::CallerAssertedLayout
                    && value.output(0).is_none() =>
            {
                ()
            }
            _ => return Err(Failure::Oracle("extension_pair_provenance")),
        }
        if created.remainder.is_some() {
            return Err(Failure::Oracle("extension_pair_auxiliary_output"));
        }
        let objects = retained
            .as_ref()
            .ok_or(Failure::Input("extension_pair_ownership"))?
            .as_slice();
        if objects.len() != 2
            || objects[0].output_slot() != Some(0)
            || objects[1].output_slot() != Some(1)
        {
            return Err(Failure::Oracle("extension_pair_output_order"));
        }
        for (object, class) in [
            (&objects[0], fe11_sys::CKO_PUBLIC_KEY),
            (&objects[1], fe11_sys::CKO_PRIVATE_KEY),
        ] {
            for (attribute, wanted) in [
                (StandardAttribute::CLASS, class),
                (StandardAttribute::KEY_TYPE, fe11_sys::CKK_RSA),
            ] {
                let plan = FlatAttributeReadPlan::Buffer {
                    capacity: std::mem::size_of::<fe11_sys::CK_ULONG>(),
                };
                let read = match o {
                    Owner::Session(s) => s.read_flat_attribute(object, attribute, plan),
                    Owner::Advanced(s) => s.read_flat_attribute(object, attribute, plan),
                }?;
                if read.calls != (AttributeReadCalls::Direct { code: 0 })
                    || read.unsigned()? != wanted as u64
                {
                    return Err(Failure::Oracle("extension_pair_attributes"));
                }
            }
        }
        let parameters =
            NativeSignatureParameters::Parameterless(NativeSignatureAlgorithm::SHA256_RSA_PKCS);
        let limits = InputLimits {
            maximum_parts: 1,
            maximum_total_bytes: 3,
        };
        let signature = match o {
            Owner::Session(s) => s.sign_native(
                &objects[1],
                parameters,
                MessageRoute::Single,
                &[b"abc"],
                limits,
                256,
                None,
            ),
            Owner::Advanced(s) => s.sign_native(
                &objects[1],
                parameters,
                MessageRoute::Single,
                &[b"abc"],
                limits,
                256,
                None,
            ),
        }?;
        if signature.as_bytes().len() != 256 {
            return Err(Failure::Oracle("extension_pair_signature_length"));
        }
        o.verify_signature(
            &objects[0],
            NativeSignatureAlgorithm::SHA256_RSA_PKCS,
            MessageRoute::Single,
            &[b"abc"],
            signature.as_bytes(),
            limits,
        )?;
        match o.verify_signature(
            &objects[0],
            NativeSignatureAlgorithm::SHA256_RSA_PKCS,
            MessageRoute::Single,
            &[b"abd"],
            signature.as_bytes(),
            limits,
        ) {
            Err(Error::Native {
                function: "C_Verify",
                code,
                ..
            }) if code == fe11_sys::CKR_SIGNATURE_INVALID as u64 => (),
            Err(error) => return Err(error.into()),
            Ok(()) => return Err(Failure::Oracle("extension_pair_changed_message_accepted")),
        }
        o.verify_signature(
            &objects[0],
            NativeSignatureAlgorithm::SHA256_RSA_PKCS,
            MessageRoute::Single,
            &[b"abc"],
            signature.as_bytes(),
            limits,
        )?;
        Ok(())
    })();
    let mut cleanup = Vec::new();
    if let (Some(o), Some(set)) = (&owner, &retained) {
        for object in set.as_slice() {
            if let Err(error) = key_wrap_fixture::destroy(o, object) {
                cleanup.push(error.into());
            }
        }
    }
    drop(retained);
    if let Some(o) = &owner {
        cleanup.extend(o.close(None));
    }
    drop(owner);
    if let Err(error) = module.close() {
        cleanup.push(error.into());
    }
    module_controls::finish(report, setup, body, cleanup)
}
