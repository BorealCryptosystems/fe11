// SPDX-License-Identifier: Apache-2.0
//! Retained whole-message cipher owners, distinct from caller-fed streams.
use super::{
    arguments::hex,
    configuration::Configuration,
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

struct Case {
    state: String,
    action: String,
    key: Vec<u8>,
    input: Vec<u8>,
    expected: Vec<u8>,
    parameters: CipherParameters<'static>,
}

impl Case {
    fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let mut bytes = Vec::new();
        File::open(path)
            .map_err(|_| Failure::Input("fixture_open"))?
            .take(4097)
            .read_to_end(&mut bytes)
            .map_err(|_| Failure::Input("fixture_read"))?;
        if bytes.len() > 4096 {
            return Err(Failure::Input("fixture_size"));
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| Failure::Input("fixture_encoding"))?;
        let fields: Vec<_> = text.split_terminator('\n').collect();
        if fields.len() != 7
            || !matches!(
                fields[0],
                "ABSENT" | "ACTIVE" | "PUBLISHED" | "OUTPUT_REQUIRED" | "OUTPUT_STORAGE_SELECTED"
            )
            || !matches!(
                fields[1],
                "start"
                    | "complete"
                    | "poll_consumed"
                    | "close"
                    | "capture"
                    | "cancel"
                    | "provide_0"
                    | "provide_15"
                    | "provide_16"
                    | "provide_17"
                    | "poll_sufficient"
            )
        {
            return Err(Failure::Input("cipher_batch_fields"));
        }
        let key = hex(fields[3], 16).map_err(Failure::Input)?;
        let input = hex(fields[4], 256).map_err(Failure::Input)?;
        let expected = hex(fields[5], 256).map_err(Failure::Input)?;
        let iv = hex(fields[6], 16).map_err(Failure::Input)?;
        if key.len() != 16
            || input.is_empty()
            || input.len() % 16 != 0
            || expected.len() != input.len()
        {
            return Err(Failure::Input("cipher_batch_dimensions"));
        }
        let parameters = CipherParameters::Aes(match fields[2] {
            "CKM_AES_ECB" if iv.is_empty() && input.len() == 16 => AesCipherParameters::Ecb,
            "CKM_AES_CBC" => AesCipherParameters::Cbc {
                iv: iv.try_into().map_err(|_| Failure::Input("iv_width"))?,
            },
            _ => return Err(Failure::Input("cipher_batch_parameters")),
        });
        Ok(Self {
            state: fields[0].into(),
            action: fields[1].into(),
            key,
            input,
            expected,
            parameters,
        })
    }
}

struct Fixture {
    owner: Owner,
    key: Option<NativeObjectRef>,
    ticket: Option<OperationTicket>,
    output: Option<Ciphertext>,
    closed: bool,
}

impl Fixture {
    fn subject(&self) -> std::result::Result<&AdvancedSession, Failure> {
        match &self.owner {
            Owner::Advanced(session) => Ok(session),
            _ => Err(Failure::Input("cipher_batch_owner")),
        }
    }
    fn start(&mut self, case: &Case, capacity: usize) -> std::result::Result<(), Failure> {
        self.ticket = Some(
            self.subject()?.start_encrypt_cipher(
                CipherKeyReference::Secret(
                    self.key
                        .as_ref()
                        .ok_or(Failure::Input("cipher_batch_key"))?,
                ),
                case.parameters,
                MessageRoute::Single,
                &[&case.input],
                InputLimits {
                    maximum_parts: 1,
                    maximum_total_bytes: case.input.len(),
                },
                CipherOutputPlan::Buffer { capacity },
            )?,
        );
        // Cooperative start must stop after Init. A retained ticket alone is
        // insufficient evidence: eager execution can already hold a result.
        let (status, progress) = self.ticket()?.cipher_progress()?;
        if status != StreamInputStatus::Closed || progress != StreamProgress::default() {
            return Err(Failure::Oracle("cipher_batch_initialized_without_input"));
        }
        Ok(())
    }
    fn ticket(&self) -> std::result::Result<&OperationTicket, Failure> {
        self.ticket
            .as_ref()
            .ok_or(Failure::Input("cipher_batch_ticket"))
    }
    fn poll(&mut self) -> std::result::Result<OperationProgress, Failure> {
        let mut ticket = self
            .ticket
            .take()
            .ok_or(Failure::Input("cipher_batch_ticket"))?;
        let result = self.subject()?.poll(&mut ticket);
        self.ticket = Some(ticket);
        Ok(result?)
    }
    fn required(result: OperationProgress) -> std::result::Result<(), Failure> {
        match result {
            OperationProgress::CipherBufferRequired(request)
                if request.function == "C_Encrypt"
                    && request.required == 16
                    && request.code == fe11_sys::CKR_BUFFER_TOO_SMALL as u64 =>
            {
                Ok(())
            }
            _ => Err(Failure::Oracle("cipher_batch_exact_buffer_request")),
        }
    }
    fn complete(&mut self, case: &Case) -> std::result::Result<(), Failure> {
        match self.poll()? {
            OperationProgress::CipherEncrypted(value) if value.as_bytes() == case.expected => {
                self.output = Some(value);
                Ok(())
            }
            _ => Err(Failure::Oracle("cipher_batch_known_answer")),
        }
    }
    fn resize(&self, capacity: usize) -> std::result::Result<(), Failure> {
        Ok(self
            .subject()?
            .resize_cipher_output(self.ticket()?, capacity)?)
    }
    fn close(&mut self) -> std::result::Result<(), Failure> {
        match self.subject()?.close()? {
            AdvancedCloseStatus::Complete => {
                self.closed = true;
                Ok(())
            }
            AdvancedCloseStatus::Pending => Err(Failure::Oracle("cipher_batch_close_pending")),
        }
    }
    fn verify(&self, case: &Case) -> std::result::Result<(), Failure> {
        if self
            .output
            .as_ref()
            .is_some_and(|value| value.as_bytes() != case.expected)
        {
            return Err(Failure::Oracle("cipher_batch_owned_output_changed"));
        }
        Ok(())
    }
    fn prepare(&mut self, case: &Case) -> std::result::Result<(), Failure> {
        if case.state == "ABSENT" {
            return Ok(());
        }
        let waiting = matches!(
            case.state.as_str(),
            "OUTPUT_REQUIRED" | "OUTPUT_STORAGE_SELECTED"
        );
        self.start(case, if waiting { 15 } else { case.expected.len() })?;
        if waiting {
            Self::required(self.poll()?)?;
            if case.state == "OUTPUT_STORAGE_SELECTED" {
                self.resize(16)?;
            }
        } else if case.state == "PUBLISHED" {
            self.complete(case)?;
        }
        Ok(())
    }
    fn action<W: Write>(
        &mut self,
        case: &Case,
        config: &Configuration,
        report: &mut Report<W>,
    ) -> std::result::Result<(), Failure> {
        match case.action.as_str() {
            "start" => self.start(case, case.expected.len())?,
            "complete" | "poll_sufficient" => self.complete(case)?,
            "poll_consumed" => match self.poll() {
                Err(Failure::Product(Error::Rejected(RejectionReason::Authentication(
                    AuthenticationRejection::ForeignOrConsumedOperationTicket,
                )))) => (),
                Err(error) => return Err(error),
                Ok(_) => return Err(Failure::Oracle("consumed_cipher_ticket_accepted")),
            },
            "close" => self.close()?,
            "capture" => {
                // Cooperative capture first observes session state, then yields.
                // Poll this control explicitly; Ready is not a captured state.
                match self.subject()?.start_state_capture(self.ticket()?, 4096)? {
                    StateCaptureProgress::Ready => (),
                    _ => return Err(Failure::Oracle("cipher_capture_initial_progress")),
                }
                native_refusal(
                    self.subject()?.poll_state_capture(self.ticket()?),
                    "C_GetOperationState",
                    false,
                    report,
                )?;
            }
            "cancel" => {
                let result = self.subject()?.cancel(CancellationFlags::ENCRYPT);
                if matches!(config.interface, InterfaceSelection::Legacy240) {
                    match result {
                        Err(Error::Rejected(RejectionReason::Cancellation(
                            CancellationRejection::CSessionCancelUnavailable,
                        ))) => (),
                        Err(error) => return Err(error.into()),
                        Ok(_) => return Err(Failure::Oracle("unavailable_cancel_accepted")),
                    }
                } else {
                    native_refusal(result, "C_SessionCancel", true, report)?;
                }
            }
            "provide_0" | "provide_15" | "provide_16" | "provide_17" => {
                let capacity = case.action[8..]
                    .parse::<usize>()
                    .map_err(|_| Failure::Input("cipher_capacity"))?;
                self.resize(capacity)?;
                if capacity < 16 {
                    Self::required(self.poll()?)?;
                    self.resize(16)?;
                }
                self.complete(case)?;
            }
            _ => return Err(Failure::Input("cipher_batch_action")),
        }
        if !self.closed && self.output.is_none() {
            self.complete(case)?;
        }
        self.verify(case)
    }
}

fn native_refusal<T, W: Write>(
    result: Result<T>,
    function: &'static str,
    no_effect: bool,
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    match result {
        Err(
            error @ Error::Native {
                function: actual,
                code,
                may_have_effect,
            },
        ) if actual == function
            && code == fe11_sys::CKR_FUNCTION_NOT_SUPPORTED as u64
            && (!no_effect || !may_have_effect) =>
        {
            outcome::record(report, Phase::Body, &Failure::Product(error))
                .map_err(|_| Failure::Input("report_write"))
        }
        Err(error) => Err(error.into()),
        Ok(_) => Err(Failure::Oracle("unsupported_native_function_accepted")),
    }
}

pub fn execute<W: Write>(
    module: Module,
    config: &Configuration,
    path: &Path,
    mut report: Report<W>,
) -> io::Result<bool> {
    let mut fixture = None;
    let setup: std::result::Result<Case, Failure> = (|| {
        let case = Case::read(path)?;
        let mut owner = Owner::open(&module, config, true)?;
        if let Owner::Advanced(session) = &mut owner {
            session.set_pacing(OperationPacing::Cooperative)?;
        }
        fixture = Some(Fixture {
            owner,
            key: None,
            ticket: None,
            output: None,
            closed: false,
        });
        let active = fixture
            .as_mut()
            .ok_or(Failure::Input("cipher_batch_fixture"))?;
        active.key = Some(active.owner.import_secret(
            &case.key,
            fe11_sys::CKK_AES,
            [StandardAttribute::ENCRYPT, StandardAttribute::DECRYPT],
        )?);
        active.prepare(&case)?;
        Ok(case)
    })();
    let started = setup.is_ok();
    let body = match (&setup, fixture.as_mut()) {
        (Ok(case), Some(fixture)) => fixture.action(case, config, &mut report),
        _ => Ok(()),
    };
    let mut cleanup = Vec::new();
    if let Some(fixture) = fixture.as_mut() {
        if !fixture.closed {
            if let Err(error) = fixture.close() {
                cleanup.push(error);
            }
        }
        if let Ok(case) = &setup {
            if let Err(error) = fixture.verify(case) {
                cleanup.push(error);
            }
        }
    }
    drop(fixture);
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
            "cipher_batch_transition_and_owned_value",
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
