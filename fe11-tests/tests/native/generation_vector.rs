// SPDX-License-Identifier: Apache-2.0
//! Native generation, retained output ownership and explicit attribute assertions.
use super::{
    configuration::{select_token, Configuration},
    credentials::Credentials,
    generation_fixture::{self, Fixture, Generator},
    generation_observation,
    outcome::{self, Failure},
    report::{Observation, Phase, PhaseResult, Producer, Report},
};
use fe11::*;
use std::{
    io::{self, Write},
    path::Path,
};

#[path = "generation_pqc_witness.rs"]
mod pqc_witness;

#[path = "generation_rsa_witness.rs"]
mod rsa_witness;

#[path = "generation_domain_witness.rs"]
mod domain_witness;

#[path = "generation_lifetime.rs"]
mod lifetime;
#[path = "generation_protection.rs"]
mod protection;
#[path = "generation_secret_witness.rs"]
mod secret_witness;

pub(super) fn generate(
    session: &Session,
    fixture: &Fixture,
    objects: &mut Option<CreatedObjectSet>,
) -> std::result::Result<(), Failure> {
    let public: Vec<_> = fixture.public.iter().map(|f| f.input()).collect();
    let private: Vec<_> = fixture.private.iter().map(|f| f.input()).collect();
    let public_request = generation_fixture::request(&public, &fixture.public);
    let (created, mechanism, count) = match fixture.generator {
        Generator::Single(generator) => (
            session
                .generate_native_key(generator, public_request)?
                .map(|_| ()),
            generator.mechanism_number(),
            1,
        ),
        Generator::Pair(generator) => (
            session
                .generate_native_key_pair(
                    generator,
                    public_request,
                    generation_fixture::request(&private, &fixture.private),
                )?
                .map(|_| ()),
            generator.mechanism_number(),
            2,
        ),
    };
    // Retain every native result before inspecting descriptive publication.
    // Neither an assertion nor an observation failure may discard cleanup rights.
    *objects = Some(created.objects);
    if created.remainder.is_some() {
        return Err(Failure::Oracle("generation_auxiliary_output"));
    }
    created.observation?;
    let objects = objects
        .as_ref()
        .ok_or(Failure::Input("generation_owners"))?
        .as_slice();
    if objects.len() != count {
        return Err(Failure::Oracle("generation_object_count"));
    }
    generation_observation::check(session, &objects[0], &fixture.public, mechanism)?;
    if count == 2 {
        generation_observation::check(session, &objects[1], &fixture.private, mechanism)?;
    }
    if let Some(operation) = fixture.disabled_use {
        operation.observe_refusal(session, &objects[0])?;
    }
    if fixture.protection_matrix {
        protection::check(
            session,
            &objects[count - 1],
            if count == 1 {
                &fixture.public
            } else {
                &fixture.private
            },
        )?;
    }
    if fixture.secret_witness {
        if count != 1 {
            return Err(Failure::Input("generation_secret_owner_count"));
        }
        secret_witness::check(session, &objects[0], mechanism)?;
    }
    if fixture.domain_witness {
        if count != 1 {
            return Err(Failure::Input("generation_domain_owner_count"));
        }
        domain_witness::check(
            session,
            &objects[0],
            &fixture.public,
            mechanism == fe11_sys::CKM_DSA_PARAMETER_GEN as u64,
        )?;
    }
    if let Some(parameters) = &fixture.pqc_witness {
        if count != 2 {
            return Err(Failure::Input("generation_witness_pair"));
        }
        pqc_witness::check(session, &objects[0], &objects[1], parameters)?;
    }
    if fixture.rsa_witness {
        if count != 2 {
            return Err(Failure::Input("generation_rsa_pair"));
        }
        rsa_witness::check(session, &objects[0], &objects[1], &fixture.public)?;
    }
    Ok(())
}

pub fn execute<W: Write>(
    module: Module,
    config: &Configuration,
    path: &Path,
    pins: &Credentials,
    mut report: Report<W>,
) -> io::Result<bool> {
    let mut session = None;
    let mut objects = None;
    let mut logged_in = false;
    let mut session_closed = false;
    let setup = (|| -> std::result::Result<Fixture, Failure> {
        let fixture = Fixture::read(path, config.label.as_bytes())?;
        let token =
            select_token(&module, &config.label).ok_or(Failure::Input("token_not_unique"))?;
        session = Some(module.select(&token)?.open_session(true)?);
        session
            .as_ref()
            .ok_or(Failure::Input("generation_session"))?
            .login_as(LoginRole::User, SecretPin::new(pins.user.to_vec()))?;
        logged_in = true;
        Ok(fixture)
    })();
    let started = setup.is_ok();
    let (setup_result, body_result) = match setup {
        Err(error) => (Err(error), Ok(())),
        Ok(fixture) => (
            Ok(()),
            match &session {
                Some(session) => generate(session, &fixture, &mut objects).and_then(|()| {
                    if fixture.lifetime {
                        lifetime::check(
                            &module,
                            config,
                            session,
                            &fixture,
                            &mut objects,
                            &mut session_closed,
                        )
                    } else {
                        Ok(())
                    }
                }),
                None => Err(Failure::Input("generation_session")),
            },
        ),
    };
    let mut cleanup = Vec::new();
    if let Some(session) = &session {
        if !session_closed {
            if let Some(objects) = &objects {
                for object in objects.as_slice() {
                    if let Err(error) = session.destroy_native_object(object) {
                        cleanup.push(error.into());
                    }
                }
            }
            if logged_in {
                if let Err(error) = session.logout() {
                    cleanup.push(error.into());
                }
            }
            if let Err(error) = session.close() {
                cleanup.push(error.into());
            }
        }
    }
    drop(objects);
    drop(session);
    if let Err(error) = module.close() {
        cleanup.push(error.into());
    }
    if let Err(error) = &setup_result {
        outcome::record(&mut report, Phase::Setup, error)?;
    }
    if let Err(error) = &body_result {
        outcome::record(&mut report, Phase::Body, error)?;
    }
    for error in &cleanup {
        outcome::record(&mut report, Phase::Cleanup, error)?;
    }
    if started {
        report.observation(
            Phase::Body,
            "generated_attributes_and_history",
            Producer::Fe11Local,
            Observation::Boolean(body_result.is_ok()),
        )?;
    }
    report.finish(
        if setup_result.is_ok() {
            PhaseResult::Passed
        } else {
            PhaseResult::Failed
        },
        if !started {
            PhaseResult::NotExecuted
        } else if body_result.is_ok() {
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
