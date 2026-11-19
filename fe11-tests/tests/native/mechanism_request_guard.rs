// SPDX-License-Identifier: Apache-2.0
//! Exact native-array budgeting precedes creation of a valid PQC public object.
use super::{
    arguments::hex, configuration::Configuration, module_controls, object_fixture,
    object_owner::Owner, outcome::Failure, report::Report,
};
use fe11::*;
use std::{
    fs::File,
    io::{self, Read, Write},
    path::Path,
};

pub fn execute<W: Write>(
    module: Module,
    config: &Configuration,
    path: &Path,
    report: Report<W>,
) -> io::Result<bool> {
    let mut owner = None;
    let mut objects = None;
    let setup = (|| -> std::result::Result<Vec<u8>, Failure> {
        let mut input = Vec::new();
        File::open(path)
            .map_err(|_| Failure::Input("mechanism_guard_open"))?
            .take(2626)
            .read_to_end(&mut input)
            .map_err(|_| Failure::Input("mechanism_guard_read"))?;
        if input.len() != 2625 {
            return Err(Failure::Input("mechanism_guard_length"));
        }
        let text =
            std::str::from_utf8(&input).map_err(|_| Failure::Input("mechanism_guard_encoding"))?;
        let text = text
            .strip_suffix('\n')
            .ok_or(Failure::Input("mechanism_guard_fields"))?;
        let public = PqcPublicKey::from_raw(
            PqcAlgorithm::MlDsa(MlDsaParameterSet::MlDsa44),
            &hex(text, 1312).map_err(Failure::Input)?,
        )?;
        owner = Some(Owner::open(&module, config, false)?);
        Ok(public.to_spki()?)
    })();
    let body = (|| -> std::result::Result<(), Failure> {
        let Ok(spki) = &setup else { return Ok(()) };
        let Some(Owner::Session(session)) = &owner else {
            return Err(Failure::Input("mechanism_guard_owner"));
        };
        let before = module.call_counts()?;
        let result = session.import_pqc_verification_key(
            spki,
            MechanismAttributes {
                request: MechanismRequest::Explicit {
                    mechanisms: &[fe11_sys::CKM_ML_DSA as u64],
                    maximum_bytes: 7,
                },
                admission: MechanismObservationPlan::NotRequested,
            },
            object_fixture::public_key_options(config.label.as_bytes()),
        );
        match result {
            Err(Error::Rejected(RejectionReason::Mechanisms(
                MechanismsRejection::MechanismRequestBudget,
            ))) => (),
            Err(error) => return Err(error.into()),
            Ok(created) => {
                objects = Some(created.objects);
                return Err(Failure::Oracle("mechanism_guard_accepted"));
            }
        }
        if module.call_counts()? != before {
            return Err(Failure::Oracle("mechanism_guard_dispatched"));
        }
        let digest = session.digest(
            HashAlgorithm::Sha256,
            b"abc",
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
            return Err(Failure::Oracle("mechanism_guard_idle_control"));
        }
        Ok(())
    })();
    let mut cleanup = Vec::new();
    if let Some(current) = &owner {
        if let (Owner::Session(session), Some(set)) = (current, &objects) {
            for object in set.as_slice() {
                if let Err(error) = session.destroy_native_object(object) {
                    cleanup.push(error.into());
                }
            }
        }
        drop(objects);
        cleanup.extend(current.close(None));
    }
    drop(owner);
    if let Err(error) = module.close() {
        cleanup.push(error.into());
    }
    module_controls::finish(report, setup.map(|_| ()), body, cleanup)
}
