// SPDX-License-Identifier: Apache-2.0
//! Typed discovery is checked separately from the import that establishes its input.
use super::{
    arguments::hex,
    configuration::{select_token, Configuration},
    credentials::Credentials,
    object_owner::Owner,
    outcome::{self, Failure},
    report::{Observation, Phase, PhaseResult, Producer, Report},
    selection_additional, selection_symmetric,
};
use fe11::*;
use std::{
    fs::File,
    io::{self, Read, Write},
    path::Path,
};

struct Fixture {
    advanced: bool,
    route: String,
    spki: Option<Vec<u8>>,
    rsa: Option<Vec<Vec<u8>>>,
    generation_exponent: Option<Vec<u8>>,
}
fn read(path: &Path) -> std::result::Result<Fixture, Failure> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|_| Failure::Input("typed_selection_open"))?
        .take(8193)
        .read_to_end(&mut bytes)
        .map_err(|_| Failure::Input("typed_selection_read"))?;
    if bytes.len() > 8192 {
        return Err(Failure::Input("typed_selection_size"));
    }
    let text =
        std::str::from_utf8(&bytes).map_err(|_| Failure::Input("typed_selection_encoding"))?;
    let f: Vec<_> = text.split_terminator('\n').collect();
    if !matches!(f.len(), 2 | 3 | 11)
        || !matches!(f[0], "session" | "advanced")
        || !matches!(
            f[1],
            "aes"
                | "symmetric"
                | "introduced"
                | "kek"
                | "hkdf"
                | "managed-data"
                | "native-data"
                | "rsa-pair"
                | "rsa-introduced"
                | "rsa-wrap"
                | "rsa-unwrap"
                | "rsa-verify"
                | "montgomery-empty"
                | "agreement"
                | "agreement-introduced"
                | "pqc"
                | "kem"
                | "rsa-exact"
                | "rsa-oaep-exact"
                | "rsa-empty"
                | "rsa-after-destroy"
        )
    {
        return Err(Failure::Input("typed_selection_fields"));
    }
    let exact = matches!(
        f[1],
        "rsa-exact" | "rsa-oaep-exact" | "rsa-empty" | "rsa-after-destroy"
    );
    let (spki, rsa) = if exact {
        if f.len() != 11 || f[0] != "session" {
            return Err(Failure::Input("typed_selection_rsa_fields"));
        }
        let components = f[3..]
            .iter()
            .map(|field| hex(field, 512).map_err(Failure::Input))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        (
            Some(hex(f[2], 512).map_err(Failure::Input)?),
            Some(components),
        )
    } else if f[1] == "rsa-verify" {
        if f.len() != 3 {
            return Err(Failure::Input("typed_selection_spki_fields"));
        }
        (Some(hex(f[2], 512).map_err(Failure::Input)?), None)
    } else {
        if f.len() != 2 && !(matches!(f[1], "rsa-pair" | "rsa-wrap") && f.len() == 3) {
            return Err(Failure::Input("typed_selection_extra_fields"));
        }
        (None, None)
    };
    Ok(Fixture {
        advanced: f[0] == "advanced",
        route: f[1].into(),
        generation_exponent: if matches!(f[1], "rsa-pair" | "rsa-wrap") && f.len() == 3 {
            let exponent = hex(f[2], 32).map_err(Failure::Input)?;
            if exponent.is_empty() {
                return Err(Failure::Input("rsa_generation_empty_exponent"));
            }
            Some(exponent)
        } else {
            None
        },
        spki,
        rsa,
    })
}
pub(super) fn retain<T>(
    created: CreatedObjects<T>,
    objects: &mut Vec<CreatedObjectSet>,
) -> std::result::Result<(), Failure> {
    let count = created.objects.as_slice().len();
    objects.push(created.objects);
    if count != 1 || created.remainder.is_some() {
        return Err(Failure::Oracle("typed_selection_import_count"));
    }
    created.observation?;
    Ok(())
}

pub fn execute<W: Write>(
    module: Module,
    config: &Configuration,
    path: &Path,
    pins: &Credentials,
    mut report: Report<W>,
) -> io::Result<bool> {
    let mut creator = None;
    let mut subject = None;
    let mut objects = Vec::new();
    let mut native_objects = Vec::new();
    let mut expected_spki = None;
    let mut logged = false;
    let mut selected = None;
    let setup = (|| -> std::result::Result<String, Failure> {
        let fixture = read(path)?;
        let advanced = fixture.advanced;
        let route = fixture.route;
        expected_spki = fixture.spki;
        let token =
            select_token(&module, &config.label).ok_or(Failure::Input("typed_selection_token"))?;
        creator = Some(module.select(&token)?.open_session(true)?);
        let session = creator
            .as_ref()
            .ok_or(Failure::Input("typed_selection_creator"))?;
        session.login_as(LoginRole::User, SecretPin::new(pins.user.to_vec()))?;
        logged = true;
        let mut material = SecretBytes::new(16)?;
        material.as_mut_slice().fill(0);
        if let Some(components) = &fixture.rsa {
            super::selection_exact::prepare(session, &route, components, &mut native_objects)?;
        } else if let Some(spki) = super::selection_rsa::prepare(
            session,
            &route,
            &mut objects,
            expected_spki.as_deref(),
            fixture.generation_exponent.as_deref(),
        )? {
            expected_spki = Some(spki);
        } else if selection_additional::prepare(
            session,
            &route,
            &mut objects,
            &mut native_objects,
            &mut expected_spki,
        )? {
            // The exact producer has retained every created native reference.
        } else if route == "kek" {
            retain(
                session.import_aes_key_encryption_key(selection_symmetric::kek(), material)?,
                &mut objects,
            )?;
        } else {
            retain(
                session.import_symmetric_key(selection_symmetric::introduced(), material)?,
                &mut objects,
            )?;
        }
        subject = Some(Owner::open(&module, config, advanced)?);
        if let Some(Owner::Advanced(s)) = subject.as_mut() {
            s.set_pacing(OperationPacing::Eager)?;
            s.set_validation_capture(ValidationCaptureMode::Disabled)?;
        }
        Ok(route)
    })();
    let started = setup.is_ok();
    let body = match (&setup, &subject) {
        (Ok(route), Some(owner)) => (|| -> std::result::Result<(), Failure> {
            if matches!(route.as_str(), "rsa-empty" | "rsa-after-destroy") {
                return super::selection_exact::missing(
                    creator
                        .as_ref()
                        .ok_or(Failure::Input("typed_selection_creator"))?,
                    owner,
                    route,
                    &mut native_objects,
                );
            }
            let before = module.call_counts()?;
            selected = Some(selection_additional::find(
                owner,
                route,
                expected_spki.as_deref(),
            )?);
            selected
                .as_ref()
                .ok_or(Failure::Input("typed_selection_result"))?
                .check(owner, expected_spki.as_deref())?;
            let after = module.call_counts()?;
            for function in [
                "C_CreateObject",
                "C_GenerateKey",
                "C_GenerateKeyPair",
                "C_DestroyObject",
            ] {
                if after.get(function) != before.get(function) {
                    return Err(Failure::Oracle("typed_selection_created_or_destroyed"));
                }
            }
            let searches = if matches!(
                route.as_str(),
                "rsa-pair" | "rsa-unwrap" | "pqc" | "kem" | "rsa-exact" | "rsa-oaep-exact"
            ) {
                2
            } else {
                1
            };
            let batches = if route == "montgomery-empty" { 1 } else { 2 };
            for (function, count) in [
                ("C_FindObjectsInit", 1),
                ("C_FindObjects", batches),
                ("C_FindObjectsFinal", 1),
            ] {
                if after
                    .get(function)
                    .copied()
                    .unwrap_or(0)
                    .checked_sub(before.get(function).copied().unwrap_or(0))
                    != Some(count * searches)
                {
                    return Err(Failure::Oracle("typed_selection_enumeration_sequence"));
                }
            }
            Ok(())
        })(),
        _ => Ok(()),
    };
    drop(selected);
    let mut cleanup = Vec::new();
    if let Some(session) = &creator {
        for object in &native_objects {
            if let Err(error) = session.destroy_native_object(object) {
                cleanup.push(error.into());
            }
        }
        for set in &objects {
            for object in set.as_slice() {
                if let Err(error) = session.destroy_native_object(object) {
                    cleanup.push(error.into());
                }
            }
        }
    }
    objects.clear();
    native_objects.clear();
    if let Some(owner) = &subject {
        cleanup.extend(owner.close(None));
    }
    drop(subject);
    if let Some(session) = &creator {
        if logged {
            if let Err(error) = session.logout() {
                cleanup.push(error.into());
            }
        }
        if let Err(error) = session.close() {
            cleanup.push(error.into());
        }
    }
    drop(creator);
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
    if started {
        report.observation(
            Phase::Body,
            "typed_selection_exact_identity_without_creation",
            Producer::Fe11Local,
            Observation::Boolean(body.is_ok()),
        )?;
    }
    report.finish(
        if started {
            PhaseResult::Passed
        } else {
            PhaseResult::Failed
        },
        if !started {
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
