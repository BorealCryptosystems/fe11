// SPDX-License-Identifier: Apache-2.0
//! Real recovery archives retain inputs; authentication remains an explicit act.
use super::{
    arguments::hex,
    configuration::{select_token, Configuration},
    credentials::Credentials,
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

mod guards;
mod lengths;

const LIMITS: RecordLimits = RecordLimits {
    bytes: 16384,
    messages: 1,
    fragments: 1,
};

fn require(value: bool, name: &'static str) -> std::result::Result<(), Failure> {
    if value {
        Ok(())
    } else {
        Err(Failure::Oracle(name))
    }
}

struct Case {
    state: String,
    action: String,
    ciphertext: Vec<u8>,
}
impl Case {
    fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let mut bytes = Vec::new();
        File::open(path)
            .map_err(|_| Failure::Input("recovery_fixture_open"))?
            .take(513)
            .read_to_end(&mut bytes)
            .map_err(|_| Failure::Input("recovery_fixture_read"))?;
        if bytes.len() > 512 {
            return Err(Failure::Input("recovery_fixture_size"));
        }
        let text =
            std::str::from_utf8(&bytes).map_err(|_| Failure::Input("recovery_fixture_encoding"))?;
        let f: Vec<_> = text.split_terminator('\n').collect();
        if f.len() != 3
            || !matches!(
                f[0],
                "ACTIVE" | "BYTES" | "PARSED" | "AUTHENTICATED" | "RESTORE_PREPARED" | "CONSUMED"
            )
            || !matches!(
                f[1],
                "capture"
                    | "exclude"
                    | "parse"
                    | "authenticate_accept"
                    | "authenticate_reject"
                    | "restore"
                    | "poll"
                    | "drop"
                    | "key_roles"
                    | "destination_active"
                    | "length_payload_short"
                    | "length_payload_long"
                    | "length_consumed"
                    | "length_produced"
                    | "length_capacity"
                    | "length_residual"
            )
        {
            return Err(Failure::Input("recovery_fixture_fields"));
        }
        let ciphertext = hex(f[2], 32).map_err(Failure::Input)?;
        if ciphertext.len() != 32 {
            return Err(Failure::Input("recovery_ciphertext_width"));
        }
        Ok(Self {
            state: f[0].into(),
            action: f[1].into(),
            ciphertext,
        })
    }
}

#[derive(Default)]
struct Fixture {
    admin: Option<Session>,
    old: Option<AdvancedSession>,
    new: Option<AdvancedSession>,
    created: Option<CreatedObjectSet>,
    guard_created: Option<CreatedObjectSet>,
    old_ticket: Option<OperationTicket>,
    new_ticket: Option<OperationTicket>,
    record: Option<DualRecoveryRecord>,
    bytes: Vec<u8>,
    parsed: Option<ParsedRecord>,
    authenticated: Option<CallerAssertedAuthenticatedRecord>,
    old_closed: bool,
    logged: bool,
    native_refusals: Vec<Failure>,
}
impl Fixture {
    fn admin(&self) -> std::result::Result<&Session, Failure> {
        self.admin.as_ref().ok_or(Failure::Input("recovery_admin"))
    }
    fn old(&self) -> std::result::Result<&AdvancedSession, Failure> {
        self.old
            .as_ref()
            .ok_or(Failure::Input("recovery_old_owner"))
    }
    fn spec() -> SymmetricKeySpec {
        let mut spec = selection_symmetric::key(false);
        spec.persistent = true;
        spec
    }
    fn prepare(
        &mut self,
        module: &Module,
        config: &Configuration,
        pins: &Credentials,
        case: &Case,
    ) -> std::result::Result<(), Failure> {
        let token =
            select_token(module, &config.label).ok_or(Failure::Input("token_not_unique"))?;
        let context = module.select(&token)?;
        self.admin = Some(context.open_session(true)?);
        self.admin()?
            .login_as(LoginRole::User, SecretPin::new(pins.user.to_vec()))?;
        self.logged = true;
        let mut spec = selection_symmetric::introduced();
        spec.key = Self::spec();
        let imported = self
            .admin()?
            .import_symmetric_key(spec, SecretBytes::new(16)?)?;
        self.created = Some(imported.objects);
        require(
            imported.remainder.is_none(),
            "recovery_import_extra_objects",
        )?;
        imported.observation?;
        let session = context.open_session(true)?;
        let key = session.find_aes_key(Self::spec())?;
        self.old = Some(session.into_advanced()?);
        self.old
            .as_mut()
            .ok_or(Failure::Input("recovery_old_owner"))?
            .set_pacing(OperationPacing::Cooperative)?;
        let before = module.call_counts()?;
        self.old_ticket = Some(self.old()?.decrypt_digest(
            &key,
            DualCipher::Gcm {
                nonce: AeadNonce::Provided([0; 12]),
                aad: &[],
            },
            &[&case.ciphertext],
            InputLimits {
                maximum_parts: 1,
                maximum_total_bytes: 44,
            },
        )?);
        let mut expected = before;
        *expected.entry("C_DigestInit").or_default() += 1;
        require(
            module.call_counts()? == expected,
            "recovery_only_authentication_initialized",
        )?;
        if case.action == "capture" {
            return Ok(());
        }
        self.capture(module)?;
        if case.action == "exclude" {
            return Ok(());
        }
        self.close_old()?;
        if matches!(
            case.state.as_str(),
            "PARSED" | "AUTHENTICATED" | "RESTORE_PREPARED" | "CONSUMED"
        ) {
            self.parse(module)?;
        }
        if matches!(
            case.state.as_str(),
            "AUTHENTICATED" | "RESTORE_PREPARED" | "CONSUMED"
        ) {
            self.authenticate(module, false)?;
        }
        if matches!(case.state.as_str(), "RESTORE_PREPARED" | "CONSUMED") {
            self.restore(module, config)?;
        }
        if case.state == "CONSUMED" {
            self.poll_refusal(module)?;
        }
        Ok(())
    }
    fn capture(&mut self, module: &Module) -> std::result::Result<(), Failure> {
        let expected = module.call_counts()?;
        let ticket = self
            .old_ticket
            .as_ref()
            .ok_or(Failure::Input("recovery_ticket"))?;
        self.record = Some(self.old()?.capture_dual_gcm_recovery(ticket, LIMITS)?);
        require(
            module.call_counts()? == expected,
            "recovery_capture_native_dispatch",
        )?;
        let record = self
            .record
            .as_ref()
            .ok_or(Failure::Input("recovery_record"))?;
        require(
            record.historical_validation()?.is_none(),
            "recovery_fabricated_validation",
        )?;
        self.bytes = record.as_bytes().to_vec();
        require(!self.bytes.is_empty(), "recovery_empty_record")?;
        require(
            !self.old_closed && self.old_ticket.is_some(),
            "recovery_capture_stopped_old_owner",
        )
    }
    fn close_old(&mut self) -> std::result::Result<(), Failure> {
        require(
            matches!(self.old()?.close()?, AdvancedCloseStatus::Complete),
            "recovery_old_close_pending",
        )?;
        self.old_closed = true;
        self.old_ticket.take();
        Ok(())
    }
    fn parse(&mut self, module: &Module) -> std::result::Result<(), Failure> {
        let before = module.call_counts()?;
        let parsed = ParsedRecord::parse(module, &self.bytes, LIMITS)?;
        require(
            parsed.as_bytes() == self.bytes && module.call_counts()? == before,
            "recovery_exact_parse",
        )?;
        self.parsed = Some(parsed);
        Ok(())
    }
    fn authenticate(&mut self, module: &Module, reject: bool) -> std::result::Result<(), Failure> {
        require(
            self.old_closed && self.created.is_some(),
            "recovery_unproven_old_exclusion",
        )?;
        let before = module.call_counts()?;
        let mut calls = 0;
        let parsed = self
            .parsed
            .take()
            .ok_or(Failure::Input("recovery_parsed_owner"))?;
        let result = parsed.assert_authenticated(|bytes| {
            calls += 1;
            if bytes != self.bytes || reject {
                Err(Error::InvalidCiphertext)
            } else {
                Ok(())
            }
        });
        require(
            calls == 1 && module.call_counts()? == before,
            "recovery_assertion_count_or_dispatch",
        )?;
        if reject {
            require(
                matches!(result, Err(Error::InvalidCiphertext)),
                "recovery_callback_error_changed",
            )?;
        } else {
            self.authenticated = Some(result?);
        }
        Ok(())
    }
    fn restore(
        &mut self,
        module: &Module,
        config: &Configuration,
    ) -> std::result::Result<(), Failure> {
        require(self.old_closed, "recovery_old_executor_live")?;
        let token =
            select_token(module, &config.label).ok_or(Failure::Input("token_not_unique"))?;
        let session = module.select(&token)?.open_session(true)?;
        let key = session.find_aes_key(Self::spec())?;
        self.new = Some(session.into_advanced()?);
        let new = self
            .new
            .as_mut()
            .ok_or(Failure::Input("recovery_new_owner"))?;
        new.set_pacing(OperationPacing::Cooperative)?;
        let before = module.call_counts()?;
        self.new_ticket = Some(
            new.start_dual_gcm_recovery(
                self.authenticated
                    .take()
                    .ok_or(Failure::Input("recovery_authenticated_owner"))?,
                &key,
                None,
            )?,
        );
        require(
            module.call_counts()? == before,
            "recovery_preparation_dispatched",
        )
    }
    fn poll_refusal(&mut self, module: &Module) -> std::result::Result<(), Failure> {
        let new = self
            .new
            .as_ref()
            .ok_or(Failure::Input("recovery_new_owner"))?;
        let ticket = self
            .new_ticket
            .as_mut()
            .ok_or(Failure::Input("recovery_new_ticket"))?;
        let before = module.call_counts()?;
        require(
            matches!(new.poll(ticket)?, OperationProgress::Ready),
            "recovery_authentication_poll",
        )?;
        let mut expected = before;
        *expected.entry("C_DigestInit").or_default() += 1;
        require(
            module.call_counts()? == expected,
            "recovery_authentication_poll_calls",
        )?;
        match new.poll(ticket) {
            Err(
                error @ Error::Native {
                    function: "C_DecryptInit",
                    code,
                    ..
                },
            ) if code == fe11_sys::CKR_OPERATION_ACTIVE as u64 => {
                self.native_refusals.push(error.into())
            }
            Err(e) => return Err(e.into()),
            Ok(_) => return Err(Failure::Oracle("recovery_expected_native_dual_refusal")),
        }
        *expected.entry("C_DecryptInit").or_default() += 1;
        require(
            module.call_counts()? == expected,
            "recovery_refusal_extra_native_calls",
        )
    }
    fn check(
        &mut self,
        module: &Module,
        config: &Configuration,
        case: &Case,
    ) -> std::result::Result<(), Failure> {
        match case.action.as_str() {
            action if action.starts_with("length_") => self.length_guard(module, case),
            "capture" => self.capture(module),
            "exclude" => self.close_old(),
            "parse" => self.parse(module),
            "authenticate_accept" => self.authenticate(module, false),
            "authenticate_reject" => self.authenticate(module, true),
            "restore" => self.restore(module, config),
            "key_roles" => self.guard(module, config, false),
            "destination_active" => self.guard(module, config, true),
            "poll" => self.poll_refusal(module),
            "drop" => {
                let before = module.call_counts()?;
                self.parsed.take();
                self.authenticated.take();
                self.new_ticket.take();
                self.record.take();
                require(module.call_counts()? == before, "recovery_drop_dispatched")
            }
            _ => Err(Failure::Input("recovery_action")),
        }
    }
    fn cleanup(&mut self) -> Vec<Failure> {
        let mut errors = Vec::new();
        if let Some(new) = &self.new {
            match new.close() {
                Ok(AdvancedCloseStatus::Complete) => (),
                Ok(_) => errors.push(Failure::Oracle("recovery_new_cleanup_pending")),
                Err(e) => errors.push(e.into()),
            }
        }
        if self.old.is_some() && !self.old_closed {
            if let Err(e) = self.close_old() {
                errors.push(e);
            }
        }
        self.old_ticket.take();
        self.new_ticket.take();
        self.parsed.take();
        self.authenticated.take();
        self.record.take();
        if let Some(admin) = &self.admin {
            if let Some(created) = &self.guard_created {
                for object in created.as_slice() {
                    if let Err(e) = admin.destroy_native_object(object) {
                        errors.push(e.into());
                    }
                }
            }
            if let Some(created) = &self.created {
                for object in created.as_slice() {
                    if let Err(e) = admin.destroy_native_object(object) {
                        errors.push(e.into());
                    }
                }
            }
            if self.logged {
                if let Err(e) = admin.logout() {
                    errors.push(e.into());
                }
            }
            if let Err(e) = admin.close() {
                errors.push(e.into());
            }
        }
        errors
    }
}

pub fn execute<W: Write>(
    module: Module,
    config: &Configuration,
    path: &Path,
    pins: &Credentials,
    mut report: Report<W>,
) -> io::Result<bool> {
    let mut fixture = Fixture::default();
    let setup = (|| {
        let case = Case::read(path)?;
        fixture.prepare(&module, config, pins, &case)?;
        Ok::<_, Failure>(case)
    })();
    let body = match &setup {
        Ok(case) => fixture.check(&module, config, case),
        Err(_) => Ok(()),
    };
    let mut cleanup = fixture.cleanup();
    for e in &fixture.native_refusals {
        outcome::record(&mut report, Phase::Body, e)?;
    }
    drop(fixture);
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
    if setup.is_ok() {
        report.observation(
            Phase::Body,
            "real_recovery_owner_transition",
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
