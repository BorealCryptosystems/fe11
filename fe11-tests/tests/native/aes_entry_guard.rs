// SPDX-License-Identifier: Apache-2.0
//! Reject a non-AES specification, then generate through the same public session.
use super::{
    configuration::Configuration,
    generation_transition_spec,
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

pub fn execute<W: Write>(
    module: Module,
    config: &Configuration,
    path: &Path,
    mut report: Report<W>,
) -> io::Result<bool> {
    let mut owner = None;
    let mut created = None;
    let setup = (|| -> std::result::Result<bool, Failure> {
        let mut input = Vec::new();
        File::open(path)
            .map_err(|_| Failure::Input("fixture_open"))?
            .take(10)
            .read_to_end(&mut input)
            .map_err(|_| Failure::Input("fixture_read"))?;
        let find = match input.as_slice() {
            b"find\n" => true,
            b"generate\n" => false,
            _ => return Err(Failure::Input("aes_guard_action")),
        };
        owner = Some(Owner::open(&module, config, false)?);
        Ok(find)
    })();
    let body = match &setup {
        Err(_) => Ok(()),
        Ok(find) => (|| -> std::result::Result<(), Failure> {
            let Some(Owner::Session(session)) = &owner else {
                return Err(Failure::Input("aes_guard_owner"));
            };
            let mut spec = generation_transition_spec::key(&config.label);
            spec.persistent = false;
            spec.algorithm = SymmetricAlgorithm::HmacSha256 { key_length: 32 };
            spec.hmac_key_type = Some(HmacKeyType::Generic);
            spec.usages = KeyUsageRequest {
                sign: Some(true),
                verify: Some(true),
                ..KeyUsageRequest::omitted()
            };
            spec.admission.observation.encrypt = false;
            spec.admission.observation.decrypt = false;
            spec.admission.observation.sign = true;
            spec.admission.observation.verify = true;
            let before = module.call_counts()?;
            let result = if *find {
                session.find_aes_key(spec).map(|_| ())
            } else {
                session.generate_aes_key(spec).map(|result| {
                    created = Some(result.objects);
                })
            };
            match result {
                Err(Error::Rejected(RejectionReason::KeyAdmission(
                    KeyAdmissionRejection::AesKeyRequired,
                ))) => (),
                Err(error) => return Err(error.into()),
                Ok(()) => return Err(Failure::Oracle("non_aes_spec_accepted")),
            }
            if module.call_counts()? != before {
                return Err(Failure::Oracle("aes_guard_dispatched"));
            }
            let mut valid = generation_transition_spec::key(&config.label);
            valid.persistent = false;
            let result = session.generate_aes_key(valid)?;
            created = Some(result.objects);
            result.observation?;
            let objects = created
                .as_ref()
                .ok_or(Failure::Input("aes_guard_creation"))?
                .as_slice();
            if objects.len() != 1 || result.remainder.is_some() {
                return Err(Failure::Oracle("aes_guard_creation_count"));
            }
            for (attribute, expected) in [
                (StandardAttribute::CLASS, fe11_sys::CKO_SECRET_KEY as u64),
                (StandardAttribute::KEY_TYPE, fe11_sys::CKK_AES as u64),
                (StandardAttribute::VALUE_LEN, 16),
            ] {
                let value = session.read_flat_attribute(
                    &objects[0],
                    attribute,
                    FlatAttributeReadPlan::Buffer { capacity: 8 },
                )?;
                if value.calls != (AttributeReadCalls::Direct { code: 0 })
                    || value.unsigned()? != expected
                {
                    return Err(Failure::Oracle("aes_guard_created_metadata"));
                }
            }
            Ok(())
        })(),
    };
    let mut cleanup = Vec::new();
    if let (Some(Owner::Session(session)), Some(objects)) = (&owner, &created) {
        for object in objects.as_slice() {
            if let Err(e) = session.destroy_native_object(object) {
                cleanup.push(e.into());
            }
        }
    }
    drop(created);
    if let Some(owner) = &owner {
        cleanup.extend(owner.close(None));
    }
    drop(owner);
    if let Err(e) = module.close() {
        cleanup.push(e.into());
    }
    if let Err(e) = &setup {
        outcome::record(&mut report, Phase::Setup, e)?;
    }
    if let Err(e) = &body {
        outcome::record(&mut report, Phase::Body, e)?;
    }
    for e in &cleanup {
        outcome::record(&mut report, Phase::Cleanup, e)?;
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
