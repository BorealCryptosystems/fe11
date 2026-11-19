// SPDX-License-Identifier: Apache-2.0
//! One changed permission or destination type after a byte-exact native control.
use super::{
    configuration::Configuration,
    derived_value,
    object_owner::Owner,
    outcome::{self, Failure},
    report::{Phase, PhaseResult, Report},
};
use fe11::*;
use std::{
    fs::File,
    io::{self, Read, Write},
    path::Path,
};

struct Case {
    route: String,
    usage: bool,
}
impl Case {
    fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let mut bytes = Vec::new();
        File::open(path)
            .map_err(|_| Failure::Input("fixture_open"))?
            .take(65)
            .read_to_end(&mut bytes)
            .map_err(|_| Failure::Input("fixture_read"))?;
        if bytes.len() > 64 {
            return Err(Failure::Input("fixture_size"));
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| Failure::Input("fixture_encoding"))?;
        let f: Vec<_> = text.split_terminator('\n').collect();
        if f.len() != 2
            || !matches!(f[0], "before" | "after" | "key")
            || !matches!(f[1], "usage" | "template")
        {
            return Err(Failure::Input("concatenation_fields"));
        }
        Ok(Self {
            route: f[0].into(),
            usage: f[1] == "usage",
        })
    }
    fn parameters<'a>(
        &self,
        auxiliary: Option<&'a NativeObjectRef>,
        data: &'a [u8],
    ) -> std::result::Result<NativeKeyDerivation<'a>, Failure> {
        Ok(match self.route.as_str() {
            "key" => NativeKeyDerivation::ConcatenateKey(
                auxiliary.ok_or(Failure::Input("concatenation_key"))?,
            ),
            "before" => NativeKeyDerivation::ConcatenateData {
                data,
                placement: DerivationDataPlacement::BeforeBase,
            },
            "after" => NativeKeyDerivation::ConcatenateData {
                data,
                placement: DerivationDataPlacement::AfterBase,
            },
            _ => return Err(Failure::Input("concatenation_route")),
        })
    }
}

pub fn execute<W: Write>(
    module: Module,
    config: &Configuration,
    path: &Path,
    mut report: Report<W>,
) -> io::Result<bool> {
    // Deliberately public, distinct bytes make the ordering oracle unambiguous.
    let base = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
    let data = [0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10];
    let mut owner = None;
    let mut keys = Vec::new();
    let mut control_objects = None;
    let mut unexpected_objects = None;
    let setup = (|| -> std::result::Result<Case, Failure> {
        let case = Case::read(path)?;
        owner = Some(Owner::open(&module, config, false)?);
        let o = owner
            .as_ref()
            .ok_or(Failure::Input("concatenation_owner"))?;
        keys.push(o.import_secret_usages(
            &base,
            fe11_sys::CKK_GENERIC_SECRET,
            [
                (StandardAttribute::DERIVE, true),
                (StandardAttribute::EXTRACTABLE, true),
            ],
        )?);
        if case.route == "key" {
            keys.push(o.import_secret_usages(
                &data,
                fe11_sys::CKK_GENERIC_SECRET,
                [
                    (StandardAttribute::DERIVE, true),
                    (StandardAttribute::EXTRACTABLE, true),
                ],
            )?);
        }
        if case.usage {
            keys.push(o.import_secret_usages(
                &base,
                fe11_sys::CKK_GENERIC_SECRET,
                [
                    (StandardAttribute::DERIVE, false),
                    (StandardAttribute::EXTRACTABLE, true),
                ],
            )?);
        }
        Ok(case)
    })();
    let body = match &setup {
        Err(_) => Ok(()),
        Ok(case) => (|| -> std::result::Result<(), Failure> {
            let Some(o @ Owner::Session(session)) = &owner else {
                return Err(Failure::Input("concatenation_owner"));
            };
            let first = keys.first().ok_or(Failure::Input("concatenation_base"))?;
            let auxiliary = if case.route == "key" {
                keys.get(1)
            } else {
                None
            };
            let expected = if case.route == "before" {
                [data, base].concat()
            } else {
                [base, data].concat()
            };
            // Validate the unchanged complete tuple first. This control belongs
            // to this negative case; it is not a replay of a separate scenario.
            derived_value::check(
                o,
                first,
                case.parameters(auxiliary, &data)?,
                &expected,
                &mut control_objects,
            )?;
            let mut attributes = derived_value::template_attributes(expected.len());
            if !case.usage {
                // Keep CLASS=SECRET_KEY; only the incompatible KEY_TYPE changes.
                // Omitting CLASS is not a valid negative for concatenation.
                if attributes[1].attribute != StandardAttribute::KEY_TYPE {
                    return Err(Failure::Input("destination_key_type"));
                }
                attributes[1].value = AttributeInputValue::Unsigned(fe11_sys::CKK_RSA as u64);
            }
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
            let key = if case.usage {
                keys.last().ok_or(Failure::Input("denied_base"))?
            } else {
                first
            };
            let expected_code = if case.usage {
                fe11_sys::CKR_KEY_FUNCTION_NOT_PERMITTED
            } else {
                fe11_sys::CKR_TEMPLATE_INCONSISTENT
            };
            match session.derive_native_key(key, case.parameters(auxiliary, &data)?, template) {
                Err(
                    error @ Error::Native {
                        function: "C_DeriveKey",
                        code,
                        ..
                    },
                ) if code == expected_code as u64 => {
                    outcome::record(&mut report, Phase::Body, &Failure::Product(error))
                        .map_err(|_| Failure::Input("report_write"))?;
                    Ok(())
                }
                Err(error) => Err(error.into()),
                Ok(result) => {
                    unexpected_objects = Some(result.objects);
                    Err(Failure::Oracle("invalid_concatenation_accepted"))
                }
            }
        })(),
    };
    let mut cleanup = Vec::new();
    if let Some(Owner::Session(session)) = &owner {
        for objects in control_objects.iter().chain(unexpected_objects.iter()) {
            for object in objects.as_slice() {
                if let Err(error) = session.destroy_native_object(object) {
                    cleanup.push(error.into());
                }
            }
        }
        for key in &keys {
            if let Err(error) = session.destroy_native_object(key) {
                cleanup.push(error.into());
            }
        }
    }
    drop(control_objects);
    drop(unexpected_objects);
    drop(keys);
    if let Some(owner) = &owner {
        cleanup.extend(owner.close(None));
    }
    drop(owner);
    if let Err(error) = module.close() {
        cleanup.push(error.into());
    }
    if let Err(error) = &setup {
        outcome::record(&mut report, Phase::Setup, error)?;
    }
    if let Err(error) = &body {
        outcome::record(&mut report, Phase::Body, error)?;
    }
    for error in &cleanup {
        outcome::record(&mut report, Phase::Cleanup, error)?;
    }
    report.finish(
        if setup.is_ok() {
            PhaseResult::Passed
        } else {
            PhaseResult::Failed
        },
        if setup.is_err() {
            PhaseResult::NotExecuted
        } else if body.is_ok() {
            PhaseResult::Passed
        } else {
            PhaseResult::Failed
        },
        if cleanup.is_empty() {
            PhaseResult::Passed
        } else {
            PhaseResult::Failed
        },
    )
}
