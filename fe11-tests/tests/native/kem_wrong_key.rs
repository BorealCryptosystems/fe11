// SPDX-License-Identifier: Apache-2.0
//! Wrong key classes reach KEM only after their requested usage imports succeed.
use crate::{
    arguments::{hex, Arguments},
    module_controls,
    object_owner::Owner,
    outcome::{self, Failure},
    report::{Phase, Report},
};
use fe11::*;
use std::{
    fs::File,
    io::{self, Read, Write},
    path::Path,
};

struct Case {
    advanced: bool,
    encapsulate: bool,
    key: Vec<Vec<u8>>,
    ciphertext: Vec<u8>,
}
impl Case {
    fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let mut text = String::new();
        File::open(path)
            .map_err(|_| Failure::Input("kem_wrong_key_open"))?
            .take(8193)
            .read_to_string(&mut text)
            .map_err(|_| Failure::Input("kem_wrong_key_read"))?;
        let fields: Vec<_> = text.split_terminator('\n').collect();
        if text.len() > 8192
            || fields.len() != 11
            || !matches!(fields[0], "session" | "advanced")
            || !matches!(fields[1], "encapsulate" | "decapsulate")
        {
            return Err(Failure::Input("kem_wrong_key_fields"));
        }
        let key = fields[2..10]
            .iter()
            .map(|v| hex(v, 256).map_err(Failure::Input))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let ciphertext = hex(fields[10], 768).map_err(Failure::Input)?;
        if key[0].len() != 256 || key.iter().any(Vec::is_empty) || ciphertext.len() != 768 {
            return Err(Failure::Input("kem_wrong_key_dimensions"));
        }
        Ok(Self {
            advanced: fields[0] == "advanced",
            encapsulate: fields[1] == "encapsulate",
            key,
            ciphertext,
        })
    }
}

fn expected(error: &Error, encapsulate: bool) -> bool {
    match error {
        Error::ObjectsMayRemain(cause) => expected(cause, encapsulate),
        Error::Native { function, code, .. } => {
            *function
                == (if encapsulate {
                    "C_EncapsulateKey"
                } else {
                    "C_DecapsulateKey"
                })
                && *code
                    == (if encapsulate {
                        fe11_sys::CKR_KEY_TYPE_INCONSISTENT as u64
                    } else {
                        fe11_sys::CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT as u64
                    })
        }
        _ => false,
    }
}

pub(super) fn execute<W: Write>(
    module: Module,
    args: &Arguments,
    mut report: Report<W>,
) -> io::Result<bool> {
    let mut owner = None;
    let mut key = None;
    let mut created = None;
    let setup = (|| -> std::result::Result<Case, Failure> {
        let case = Case::read(&args.vector)?;
        owner = Some(Owner::open(&module, &args.config, case.advanced)?);
        let o = owner
            .as_ref()
            .ok_or(Failure::Input("kem_wrong_key_owner"))?;
        // The incompatible usage is a native import prerequisite. Refusal is
        // reported in Setup; it must not be counted as a KEM invocation.
        key = Some(if case.encapsulate {
            o.import_rsa_public_usage(&case.key[0], &case.key[1], StandardAttribute::ENCAPSULATE)?
        } else {
            o.import_rsa_private(&case.key, StandardAttribute::DECAPSULATE)?
        });
        Ok(case)
    })();
    let body = (|| -> std::result::Result<(), Failure> {
        let Ok(case) = &setup else {
            return Ok(());
        };
        let o = owner
            .as_ref()
            .ok_or(Failure::Input("kem_wrong_key_owner"))?;
        let key = key.as_ref().ok_or(Failure::Input("kem_wrong_key_object"))?;
        let attr = |attribute: StandardAttribute, value| AttributeInput {
            attribute: attribute.into(),
            value,
        };
        let attributes = [
            attr(
                StandardAttribute::CLASS,
                AttributeInputValue::Unsigned(fe11_sys::CKO_SECRET_KEY as u64),
            ),
            attr(
                StandardAttribute::KEY_TYPE,
                AttributeInputValue::Unsigned(fe11_sys::CKK_GENERIC_SECRET as u64),
            ),
            attr(
                StandardAttribute::VALUE_LEN,
                AttributeInputValue::Unsigned(32),
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
                StandardAttribute::SENSITIVE,
                AttributeInputValue::Boolean(false),
            ),
            attr(
                StandardAttribute::EXTRACTABLE,
                AttributeInputValue::Boolean(true),
            ),
        ];
        let template = GenerationTemplate {
            attributes: &attributes,
            limits: AttributeTemplateLimits {
                maximum_depth: 0,
                maximum_attributes: attributes.len(),
                maximum_value_bytes: 28,
            },
            observation: None,
            destination: DestinationPlan {
                search: DestinationSearchPlan::NotRequested,
                user: DestinationUserObservation::NotRequested,
            },
        };
        let result = match (o, case.encapsulate) {
            (Owner::Session(s), true) => {
                s.encapsulate_native(Some(key), NativeKemParameters::MlKem, 768, template)
            }
            (Owner::Advanced(s), true) => {
                s.encapsulate_native(Some(key), NativeKemParameters::MlKem, 768, template)
            }
            (Owner::Session(s), false) => s.decapsulate_native(
                Some(key),
                NativeKemParameters::MlKem,
                &case.ciphertext,
                template,
            ),
            (Owner::Advanced(s), false) => s.decapsulate_native(
                Some(key),
                NativeKemParameters::MlKem,
                &case.ciphertext,
                template,
            ),
        };
        match result {
            Err(error) if expected(&error, case.encapsulate) => {
                outcome::record(&mut report, Phase::Body, &Failure::Product(error))
                    .map_err(|_| Failure::Input("report_write"))
            }
            Err(error) => Err(error.into()),
            Ok(result) => {
                // Even an unexpected successful creation must stay owned for cleanup.
                created = Some(result.objects);
                Err(Failure::Oracle("kem_wrong_key_accepted"))
            }
        }
    })();
    let mut cleanup = Vec::new();
    if let (Some(o), Some(objects)) = (&owner, &created) {
        for object in objects.as_slice() {
            let result = match o {
                Owner::Session(s) => s.destroy_native_object(object),
                Owner::Advanced(s) => s.destroy_native_object(object),
            };
            if let Err(e) = result {
                cleanup.push(e.into());
            }
        }
    }
    drop(created);
    if let Some(o) = &owner {
        cleanup.extend(o.close(key.as_ref()));
    }
    drop(key);
    drop(owner);
    if let Err(e) = module.close() {
        cleanup.push(e.into());
    }
    module_controls::finish(report, setup.map(|_| ()), body, cleanup)
}
