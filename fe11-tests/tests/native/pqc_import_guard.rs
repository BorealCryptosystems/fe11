// SPDX-License-Identifier: Apache-2.0
//! Representation-length errors must precede private-object creation.
use super::{
    arguments::hex,
    configuration::Configuration,
    generation_transition_spec, object_fixture,
    object_owner::Owner,
    outcome::{self, Failure},
    report::{Observation, Phase, PhaseResult, Producer, Report},
};
use fe11::*;
use std::{
    fs::File,
    io::{self, Read, Write},
    path::Path,
};

#[path = "pqc_private_forms.rs"]
mod private_forms;

enum Input {
    Malformed(Case),
    PrivateForm(private_forms::Case),
}

struct Case {
    kind: String,
    private: SecretBytes,
    public: Vec<u8>,
}

impl Case {
    fn read(path: &Path) -> std::result::Result<Input, Failure> {
        let mut bytes = Vec::new();
        File::open(path)
            .map_err(|_| Failure::Input("pqc_guard_open"))?
            .take(32769)
            .read_to_end(&mut bytes)
            .map_err(|_| Failure::Input("pqc_guard_read"))?;
        if bytes.len() > 32768 {
            return Err(Failure::Input("pqc_guard_size"));
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| Failure::Input("pqc_guard_encoding"))?;
        let fields: Vec<_> = text.split_terminator('\n').collect();
        if fields.first() == Some(&"private-form") {
            return private_forms::Case::read(&fields).map(Input::PrivateForm);
        }
        if bytes.len() > 8192 {
            return Err(Failure::Input("pqc_guard_size"));
        }
        if fields.len() != 3 || !matches!(fields[0], "public" | "seed" | "value") {
            return Err(Failure::Input("pqc_guard_fields"));
        }
        // These bytes come only from the public test-vector directory. The
        // fixture reader is not an application private-key import interface.
        let decoded = hex(fields[1], 2560).map_err(Failure::Input)?;
        let mut private = SecretBytes::new(decoded.len())?;
        private.as_mut_slice().copy_from_slice(&decoded);
        let public = hex(fields[2], 1312).map_err(Failure::Input)?;
        let expected = match fields[0] {
            "public" => (2560, 0),
            "seed" => (31, 1312),
            "value" => (2559, 1312),
            _ => return Err(Failure::Input("pqc_guard_kind")),
        };
        if (private.len(), public.len()) != expected {
            return Err(Failure::Input("pqc_guard_dimensions"));
        }
        Ok(Input::Malformed(Self {
            kind: fields[0].into(),
            private,
            public,
        }))
    }
}

fn check<W: Write>(
    module: &Module,
    session: &Session,
    case: Case,
    label: &str,
    retained: &mut Option<CreatedObjectSet>,
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    let mut admission = object_fixture::public_key_options(label.as_bytes()).admission;
    admission.observation.verify = false;
    admission.observation.sign = true;
    let spec = PqcPrivateImportSpec {
        history_observation: generation_transition_spec::history(),
        admission,
        id: label.as_bytes().to_vec(),
        label: label.into(),
        persistent: false,
        protection: CurrentKeyProtection {
            sensitive: true,
            extractable: false,
        },
        usages: KeyUsageRequest {
            sign: Some(true),
            ..KeyUsageRequest::omitted()
        },
        visibility: ObjectVisibility::Public,
    };
    let algorithm = PqcPrivateKeyAlgorithm::MlDsa(MlDsaParameterSet::MlDsa44);
    let reason = match case.kind.as_str() {
        "public" => PostQuantumKeysRejection::PqcImportPublicLength,
        "seed" => PostQuantumKeysRejection::PqcImportSeedLength,
        "value" => PostQuantumKeysRejection::PqcImportValueLength,
        _ => return Err(Failure::Input("pqc_guard_kind")),
    };
    let input = if case.kind == "seed" {
        PqcPrivateInput::Seed {
            algorithm,
            seed: case.private,
        }
    } else {
        PqcPrivateInput::Value {
            algorithm,
            value: case.private,
        }
    };
    let before = module.call_counts()?;
    let result = session.import_pqc_private_key(
        spec,
        input,
        &case.public,
        MechanismAttributes {
            request: MechanismRequest::Omitted,
            admission: MechanismObservationPlan::NotRequested,
        },
    );
    match result {
        Err(error @ Error::Rejected(RejectionReason::PostQuantumKeys(actual)))
            if actual == reason =>
        {
            outcome::record(report, Phase::Body, &Failure::Product(error))
                .map_err(|_| Failure::Input("report_write"))?;
        }
        Err(error) => return Err(error.into()),
        Ok(created) => {
            *retained = Some(created.objects);
            return Err(Failure::Oracle("malformed_pqc_import_accepted"));
        }
    }
    if module.call_counts()? != before {
        return Err(Failure::Oracle("pqc_guard_native_dispatch"));
    }
    let digest = session.digest_multipart(
        HashAlgorithm::Sha256,
        &[b"abc"],
        InputLimits {
            maximum_parts: 1,
            maximum_total_bytes: 3,
        },
    )?;
    let expected = hex(
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        32,
    )
    .map_err(Failure::Input)?;
    if digest.as_bytes() != expected {
        return Err(Failure::Oracle("pqc_guard_retained_session"));
    }
    Ok(())
}

pub fn execute<W: Write>(
    module: Module,
    config: &Configuration,
    path: &Path,
    mut report: Report<W>,
) -> io::Result<bool> {
    let mut owner = None;
    let mut retained = None;
    let mut additional = Vec::new();
    let setup = Case::read(path).and_then(|case| {
        owner = Some(Owner::open(&module, config, false)?);
        Ok(case)
    });
    let started = setup.is_ok();
    let (setup, body) = match setup {
        Err(error) => (Err(error), Ok(())),
        Ok(case) => (
            Ok(()),
            match &owner {
                Some(Owner::Session(session)) => match case {
                    Input::Malformed(case) => check(
                        &module,
                        session,
                        case,
                        &config.label,
                        &mut retained,
                        &mut report,
                    ),
                    Input::PrivateForm(case) => private_forms::check(
                        session,
                        case,
                        &config.label,
                        &mut retained,
                        &mut additional,
                    ),
                },
                _ => Err(Failure::Input("pqc_guard_owner")),
            },
        ),
    };
    let mut cleanup = Vec::new();
    if let Some(Owner::Session(session)) = &owner {
        for object in &additional {
            if let Err(error) = session.destroy_native_object(object) {
                cleanup.push(error.into());
            }
        }
    }
    drop(additional);
    if let (Some(Owner::Session(session)), Some(objects)) = (&owner, &retained) {
        for object in objects.as_slice() {
            if let Err(error) = session.destroy_native_object(object) {
                cleanup.push(error.into());
            }
        }
    }
    drop(retained);
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
    if started {
        report.observation(
            Phase::Body,
            "pqc_import_shape_and_retained_session",
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
