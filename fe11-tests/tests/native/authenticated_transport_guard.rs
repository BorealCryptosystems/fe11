// SPDX-License-Identifier: Apache-2.0
//! Transport refusals preserve real key owners and expose the expected dispatch boundary.
use super::{
    configuration::{Budgets, Configuration},
    object_owner::Owner,
    outcome::{self, Failure},
    report::{Observation, Phase, PhaseResult, Producer, Report},
    selection_symmetric,
};
use fe11::*;
use std::{
    fs::File,
    io::{self, Read, Write},
    path::Path,
};

#[path = "typed_wrap_contract.rs"]
mod typed_wrap_contract;
#[path = "transport_layout_identity.rs"]
mod transport_layout_identity;

fn retain<T>(
    value: CreatedObjects<T>,
    owners: &mut Vec<CreatedObjectSet>,
) -> std::result::Result<T, Failure> {
    let count = value.objects.as_slice().len();
    owners.push(value.objects);
    if count != 1 || value.remainder.is_some() {
        return Err(Failure::Oracle("transport_guard_creation_count"));
    }
    Ok(value.observation?)
}

fn rejected<T>(
    value: fe11::Result<T>,
    expected: KeyTransportRejection,
    native: bool,
    function: &'static str,
) -> std::result::Result<(), Failure> {
    match value {
        Err(Error::Rejected(RejectionReason::KeyTransport(reason)))
            if !native && reason == expected =>
        {
            Ok(())
        }
        Err(Error::Native {
            function: actual,
            code,
            ..
        }) if native
            && actual == function
            && code == fe11_sys::CKR_FUNCTION_NOT_SUPPORTED as u64 =>
        {
            Ok(())
        }
        Err(error) => Err(error.into()),
        Ok(_) => Err(Failure::Oracle(
            "authenticated_transport_unexpected_success",
        )),
    }
}

pub fn open<W: Write>(
    config: &Configuration,
    path: &Path,
    budgets: &Budgets,
    mut report: Report<W>,
) -> io::Result<bool> {
    let setup = (|| -> std::result::Result<_, Failure> {
        let mut action = String::new();
        File::open(path)
            .map_err(|_| Failure::Input("transport_guard_fixture_open"))?
            .take(32)
            .read_to_string(&mut action)
            .map_err(|_| Failure::Input("transport_guard_fixture_read"))?;
        // The observer resolves native entry points against the provider's
        // verified pathname. Load that pathname first so an fd path closed
        // with the first Fe11 owner cannot be mistaken for another mapping.
        let image = if transport_layout_identity::Layout::parse(&action).is_some() {
            Some(crate::foreign_info_image::Image::load(config)?)
        } else {
            None
        };
        Ok((action, image, config.open(budgets)?))
    })();
    let (action, _image, module) = match setup {
        Ok(values) => values,
        Err(error) => {
            outcome::record(&mut report, Phase::Setup, &error)?;
            return report.finish(PhaseResult::Failed, PhaseResult::NotExecuted, PhaseResult::NotExecuted);
        }
    };
    report.observation(Phase::Setup, "module_opened", Producer::Fe11Local, Observation::Boolean(true))?;
    execute(module, config, &action, report)
}

fn execute<W: Write>(
    mut module: Module,
    config: &Configuration,
    action: &str,
    mut report: Report<W>,
) -> io::Result<bool> {
    let mut owner = None;
    let mut objects = Vec::new();
    let mut kek = None;
    let mut target = None;
    let mut standard_wrap = false;
    let mut layout_check = None;
    let setup = (|| -> std::result::Result<bool, Failure> {
        if let Some(layout) = transport_layout_identity::Layout::parse(action) {
            let prior = layout.replace_module(&mut module, config)?;
            layout_check = Some((layout, prior));
        }
        let wrap = match action {
            _ if layout_check.is_some() => true,
            "wrap\n" | "native-wrap\n" | "standard-wrap\n" => true,
            "unwrap\n" | "native-unwrap\n" => false,
            _ => return Err(Failure::Input("transport_guard_fixture_action")),
        };
        standard_wrap = action == "standard-wrap\n";
        owner = Some(Owner::open(&module, config, false)?);
        let Some(Owner::Session(session)) = &owner else {
            return Err(Failure::Input("transport_guard_owner"));
        };
        let mut kek_bytes = SecretBytes::new(16)?;
        if standard_wrap {
            kek_bytes
                .as_mut_slice()
                .copy_from_slice(&typed_wrap_contract::KEK);
        }
        kek = Some(retain(
            session.import_aes_key_encryption_key(selection_symmetric::kek(), kek_bytes)?,
            &mut objects,
        )?);
        if wrap {
            let mut spec = selection_symmetric::introduced();
            spec.key.algorithm = SymmetricAlgorithm::HmacSha256 { key_length: 16 };
            spec.key.hmac_key_type = Some(HmacKeyType::Generic);
            spec.key.usages = KeyUsageRequest::omitted();
            let mut target_bytes = SecretBytes::new(16)?;
            if standard_wrap {
                target_bytes
                    .as_mut_slice()
                    .copy_from_slice(&typed_wrap_contract::KEY);
            }
            target = Some(retain(
                session.import_symmetric_key(spec, target_bytes)?,
                &mut objects,
            )?);
        }
        if layout_check.is_none() && !standard_wrap
            && action.starts_with("native-")
                != matches!(config.interface, InterfaceSelection::Standard { .. })
        {
            return Err(Failure::Input("transport_guard_interface"));
        }
        Ok(wrap)
    })();
    let body = (|| -> std::result::Result<(), Failure> {
        let (Ok(wrap), Some(Owner::Session(session)), Some(kek)) = (&setup, &owner, &kek) else {
            return Ok(());
        };
        if let Some((layout, prior)) = &layout_check {
            let [wrapping_set, target_set] = objects.as_slice() else {
                return Err(Failure::Input("layout_guard_owners"));
            };
            let ([wrapping], [target]) = (wrapping_set.as_slice(), target_set.as_slice()) else {
                return Err(Failure::Input("layout_guard_objects"));
            };
            return layout.check(&module, session, prior, wrapping, target);
        }
        let before = module.call_counts()?;
        if standard_wrap {
            let target = target.as_ref().ok_or(Failure::Input("typed_wrap_target"))?;
            let key = kek.wrapping().ok_or(Failure::Input("typed_wrap_kek"))?;
            return typed_wrap_contract::check(&module, session, &key, target.managed());
        }
        let native = matches!(config.interface, InterfaceSelection::Standard { .. });
        if *wrap {
            let target = target
                .as_ref()
                .ok_or(Failure::Input("transport_guard_target"))?;
            let key = kek
                .wrapping()
                .ok_or(Failure::Input("transport_guard_wrapping_view"))?;
            rejected(
                session.wrap_key(
                    &key,
                    target.managed(),
                    WrapParameters::AuthenticatedGcm {
                        nonce: AeadNonce::Provided([0; 12]),
                        aad: &[],
                    },
                    WrapLimits {
                        maximum_output_bytes: 64,
                    },
                ),
                KeyTransportRejection::CWrapKeyAuthenticatedUnavailableInSelectedInterface,
                native,
                "C_WrapKeyAuthenticated",
            )?;
        } else {
            let key = kek
                .unwrapping()
                .ok_or(Failure::Input("transport_guard_unwrapping_view"))?;
            rejected(
                session
                    .unwrap_symmetric_key(
                        &key,
                        UnwrapParameters::AuthenticatedGcm {
                            nonce: AeadNonce::Provided([0; 12]),
                            tag: &[0; 16],
                            aad: &[],
                        },
                        &[0; 16],
                        selection_symmetric::introduced(),
                    )
                    .map(|created| {
                        // An unexpected success is still owned and must be
                        // destroyed by the common cleanup before reporting FAIL.
                        objects.push(created.objects);
                    }),
                KeyTransportRejection::CUnwrapKeyAuthenticatedUnavailableInSelectedInterface,
                native,
                "C_UnwrapKeyAuthenticated",
            )?;
        }
        let mut expected = before;
        if native {
            let function = if *wrap {
                "C_WrapKeyAuthenticated"
            } else {
                "C_UnwrapKeyAuthenticated"
            };
            *expected.entry(function).or_default() += 1;
        }
        if module.call_counts()? != expected {
            return Err(Failure::Oracle("transport_guard_dispatched"));
        }
        Ok(())
    })();
    drop(target);
    drop(kek);
    let mut cleanup = Vec::new();
    if let Some(Owner::Session(session)) = &owner {
        for set in &objects {
            for key in set.as_slice() {
                if let Err(error) = session.destroy_native_object(key) {
                    cleanup.push(error.into());
                }
            }
        }
    }
    drop(objects);
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
    if setup.is_ok() {
        report.observation(
            Phase::Body,
            if layout_check.is_some() {
                "layout_owner_operation_and_number_checked_before_wrap"
            } else if standard_wrap {
                "typed_wrap_queries_and_exact_capacity"
            } else {
                "authenticated_slot_refusal_preserves_objects"
            },
            Producer::TestOracle,
            Observation::Boolean(body.is_ok()),
        )?;
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
