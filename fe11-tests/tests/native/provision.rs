// SPDX-License-Identifier: Apache-2.0
//! Provision one isolated blank token and release every owner before a case starts.
use super::configuration::{Budgets, Configuration};
use crate::credentials::Credentials;
use fe11::{LoginRole, SecretPin};

/// Setup and cleanup are returned separately, including when PIN setup failed.
pub struct ProvisionOutcome {
    pub setup: std::result::Result<(), ProvisionFailure>,
    pub cleanup: Vec<fe11::Error>,
}

pub enum ProvisionFailure {
    NativeOrLocal(fe11::Error),
    ExpectedOneBlankToken,
    InitializedTokenNotUnique,
}

impl From<fe11::Error> for ProvisionFailure {
    fn from(error: fe11::Error) -> Self {
        Self::NativeOrLocal(error)
    }
}

pub fn run(config: &Configuration, pins: &mut Credentials) -> ProvisionOutcome {
    let mut module = None;
    let mut session = None;
    let mut logged_in = false;
    let setup = (|| -> std::result::Result<(), ProvisionFailure> {
        module = Some(config.open(&Budgets::ordinary())?);
        let owner = module.as_ref().expect("owner assigned before provisioning");
        let targets = owner.administration_targets()?;
        // The supervisor supplies a new private token directory. Never select or
        // reinitialize an existing token, even if a label happens to match.
        if targets.len() != 1
            || targets[0].capabilities().flags & fe11_sys::CKF_TOKEN_INITIALIZED as u64 != 0
        {
            return Err(ProvisionFailure::ExpectedOneBlankToken);
        }
        owner.initialize_token(
            &targets[0],
            SecretPin::new(pins.officer.to_vec()),
            &config.label,
        )?;
        owner.refresh_tokens()?;
        // tokens() is the opening snapshot. A fresh administrative snapshot is
        // needed after InitToken; the next worker will discover independently.
        let targets = owner.administration_targets()?;
        let matches: Vec<_> = targets
            .iter()
            .filter(|target| {
                let token = target.capabilities();
                let end = token
                    .label
                    .iter()
                    .rposition(|byte| *byte != b' ')
                    .map_or(0, |last| last + 1);
                &token.label[..end] == config.label.as_bytes()
                    && token.flags & fe11_sys::CKF_TOKEN_INITIALIZED as u64 != 0
            })
            .collect();
        if matches.len() != 1 {
            return Err(ProvisionFailure::InitializedTokenNotUnique);
        }
        let token = owner.select(&matches[0].capabilities().identity)?;
        session = Some(token.open_session(true)?);
        let active = session.as_ref().expect("session assigned before PIN setup");
        active.login_as(
            LoginRole::SecurityOfficer,
            SecretPin::new(std::mem::take(&mut *pins.officer)),
        )?;
        logged_in = true;
        active.initialize_user_pin(SecretPin::new(std::mem::take(&mut *pins.user)))?;
        Ok(())
    })();
    let mut cleanup = Vec::new();
    if let Some(active) = session.as_ref() {
        if logged_in {
            if let Err(error) = active.logout() {
                cleanup.push(error);
            }
        }
        if let Err(error) = active.close() {
            cleanup.push(error);
        }
    }
    drop(session);
    if let Some(owner) = module.as_ref() {
        if let Err(error) = owner.close() {
            cleanup.push(error);
        }
    }
    ProvisionOutcome { setup, cleanup }
}

/// Report provisioning separately from product-case execution.
pub fn execute<W: std::io::Write>(
    config: &Configuration,
    pins: &mut Credentials,
    mut report: crate::report::Report<W>,
) -> std::io::Result<bool> {
    use crate::{
        outcome::{self, Failure},
        report::{Phase, PhaseResult},
    };
    let result = run(config, pins);
    if let Err(error) = &result.setup {
        let failure = match error {
            ProvisionFailure::NativeOrLocal(error) => Failure::Product(error.clone()),
            ProvisionFailure::ExpectedOneBlankToken => Failure::Input("expected_one_blank_token"),
            ProvisionFailure::InitializedTokenNotUnique => {
                Failure::Input("initialized_token_not_unique")
            }
        };
        outcome::record(&mut report, Phase::Setup, &failure)?;
    }
    for error in &result.cleanup {
        outcome::record(
            &mut report,
            Phase::Cleanup,
            &Failure::Product(error.clone()),
        )?;
    }
    // Provisioning is a prerequisite, never a product-case PASS.
    return report.finish_preparation(
        if result.setup.is_ok() {
            PhaseResult::Passed
        } else {
            PhaseResult::Failed
        },
        if result.cleanup.is_empty() {
            PhaseResult::Passed
        } else {
            PhaseResult::Failed
        },
    );
}
