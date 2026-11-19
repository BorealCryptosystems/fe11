// SPDX-License-Identifier: Apache-2.0
//! Direct generation transitions preserve returned references across local actions.
use super::{
    configuration::{select_token, Configuration},
    credentials::Credentials,
    direct_generation_fixture::Case,
    generation_vector,
    outcome::{self, Failure},
    report::{Observation as ReportObservation, Phase, PhaseResult, Producer, Report},
};
use fe11::*;
use std::{
    io::{self, Write},
    path::Path,
};

struct Fixture {
    session: Option<Session>,
    objects: Vec<CreatedObjectSet>,
    closed: bool,
    logged: bool,
}
impl Fixture {
    fn session(&self) -> std::result::Result<&Session, Failure> {
        self.session
            .as_ref()
            .ok_or(Failure::Input("generation_session"))
    }
    fn generate(
        &mut self,
        c: &Case,
        label: &str,
        invalid: bool,
    ) -> std::result::Result<(), Failure> {
        let mut created = None;
        let result =
            generation_vector::generate(self.session()?, &c.template(label, invalid), &mut created);
        if let Some(objects) = created {
            self.objects.push(objects);
        }
        result
    }
    fn snapshot(&self) -> Vec<(Option<usize>, ObjectCreatorProvenance, Observation<bool>)> {
        self.objects
            .iter()
            .flat_map(|set| set.as_slice())
            .map(|object| {
                (
                    object.output_slot(),
                    object.creator_provenance(),
                    object.visibility_observation(),
                )
            })
            .collect()
    }
    fn close(&mut self) -> std::result::Result<(), Failure> {
        self.session()?.close()?;
        self.closed = true;
        Ok(())
    }
    fn prepare(
        &mut self,
        module: &Module,
        config: &Configuration,
        pins: &Credentials,
        c: &Case,
    ) -> std::result::Result<(), Failure> {
        let token =
            select_token(module, &config.label).ok_or(Failure::Input("token_not_unique"))?;
        self.session = Some(module.select(&token)?.open_session(true)?);
        self.session()?
            .login_as(LoginRole::User, SecretPin::new(pins.user.to_vec()))?;
        self.logged = true;
        match c.state.as_str() {
            "CONSUMED" => self.generate(c, &config.label, false)?,
            "REFUSED_TERMINAL" => match self.generate(c, &config.label, true) {
                Err(Failure::Product(Error::Native { function, code, .. }))
                    if function == c.function()
                        && code == fe11_sys::CKR_TEMPLATE_INCOMPLETE as u64 =>
                {
                    ()
                }
                Err(error) => return Err(error),
                Ok(()) => return Err(Failure::Oracle("incomplete_generation_template_accepted")),
            },
            "RETIRED" => self.close()?,
            _ => (),
        }
        Ok(())
    }
    fn cleanup(&mut self) -> Vec<Failure> {
        let mut errors = Vec::new();
        if self.closed {
            return errors;
        }
        if let Some(session) = &self.session {
            for set in &self.objects {
                for object in set.as_slice() {
                    if let Err(error) = session.destroy_native_object(object) {
                        errors.push(error.into());
                    }
                }
            }
            if self.logged {
                if let Err(error) = session.logout() {
                    errors.push(error.into());
                }
            }
            if let Err(error) = session.close() {
                errors.push(error.into());
            } else {
                self.closed = true;
            }
        }
        errors
    }
}
fn closed<T>(result: std::result::Result<T, Failure>) -> std::result::Result<(), Failure> {
    match result {
        Err(Failure::Product(Error::Rejected(RejectionReason::SessionLifecycle(
            SessionLifecycleRejection::SessionClosed,
        )))) => Ok(()),
        Err(error) => Err(error),
        Ok(_) => Err(Failure::Oracle("closed_generation_session_accepted")),
    }
}
fn action(
    f: &mut Fixture,
    module: &Module,
    c: &Case,
    config: &Configuration,
) -> std::result::Result<(), Failure> {
    let before = f.snapshot();
    match c.action.as_str() {
        "init" => {
            let result = f.generate(c, &config.label, false);
            if f.closed {
                closed(result)?;
            } else {
                result?;
            }
        }
        "take" => {
            let calls = module.call_counts()?;
            if before.len() != c.count()
                || before
                    .iter()
                    .enumerate()
                    .any(|(index, v)| v.0 != Some(index))
            {
                return Err(Failure::Oracle("created_output_slots"));
            }
            if f.snapshot() != before || module.call_counts()? != calls {
                return Err(Failure::Oracle("created_accessor_changed_state"));
            }
        }
        "logout" => {
            let result = f.session()?.logout().map_err(Failure::from);
            if f.closed {
                // Authentication selects this exact session under token possession.
                // A closed session is absent from the eligible native entries.
                match result {
                    Err(Failure::Product(Error::Rejected(RejectionReason::Authentication(
                        AuthenticationRejection::LogoutRequiresLiveSession,
                    )))) => (),
                    Err(error) => return Err(error),
                    Ok(_) => return Err(Failure::Oracle("closed_logout_accepted")),
                }
            } else {
                result?;
                f.logged = false;
                if f.session()?.info()?.state != fe11_sys::CKS_RW_PUBLIC_SESSION as u64 {
                    return Err(Failure::Oracle("generation_logout_role"));
                }
            }
        }
        "close" => {
            let result = f.close();
            if c.state == "RETIRED" {
                closed(result)?;
            } else {
                result?;
            }
        }
        _ => return Err(Failure::Input("direct_generation_action")),
    }
    let after = f.snapshot();
    if c.action == "init" && !f.closed {
        if after.len() != before.len() + c.count() || after[..before.len()] != before {
            return Err(Failure::Oracle("generation_replaced_prior_owners"));
        }
    } else if after != before {
        return Err(Failure::Oracle("generation_owned_metadata_changed"));
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
    let mut fixture = Fixture {
        session: None,
        objects: Vec::new(),
        closed: false,
        logged: false,
    };
    let setup = Case::read(path).and_then(|case| {
        fixture.prepare(&module, config, pins, &case)?;
        Ok(case)
    });
    let started = setup.is_ok();
    let (setup_result, body) = match setup {
        Err(error) => (Err(error), Ok(())),
        Ok(case) => (Ok(()), action(&mut fixture, &module, &case, config)),
    };
    let mut cleanup = fixture.cleanup();
    drop(fixture);
    if let Err(error) = module.close() {
        cleanup.push(error.into());
    }
    if let Err(error) = &setup_result {
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
            "direct_generation_transition_and_owned_metadata",
            Producer::TestOracle,
            ReportObservation::Boolean(body.is_ok()),
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
