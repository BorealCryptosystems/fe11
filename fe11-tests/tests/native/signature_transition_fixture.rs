// SPDX-License-Identifier: Apache-2.0
//! Signature stream ownership with explicit input closure and independent outputs.
use super::{
    configuration::{select_token, Configuration},
    credentials::Credentials,
    object_owner::Owner,
    outcome::Failure,
};
use fe11::*;

pub use super::signature_transition_case::Case;

pub struct Fixture {
    pub peer: Option<Session>,
    subject: Option<Owner>,
    key: Option<NativeObjectRef>,
    denied: Option<NativeObjectRef>,
    other: Option<NativeObjectRef>,
    pub ticket: Option<OperationTicket>,
    pub submitted: u64,
    pub pending: bool,
    pub replacement: bool,
    pub input_closed: bool,
    pub completed: bool,
    pub closed: bool,
    pub logged: bool,
    published: Vec<(ExtensionResult, Vec<u8>)>,
    external_reference: bool,
}
impl Fixture {
    pub fn empty() -> Self {
        Self {
            peer: None,
            subject: None,
            key: None,
            denied: None,
            other: None,
            ticket: None,
            submitted: 0,
            pending: false,
            replacement: false,
            input_closed: false,
            completed: false,
            closed: false,
            logged: false,
            published: Vec::new(),
            external_reference: false,
        }
    }
    pub fn subject(&self) -> std::result::Result<&AdvancedSession, Failure> {
        match &self.subject {
            Some(Owner::Advanced(s)) => Ok(s),
            _ => Err(Failure::Input("signature_subject")),
        }
    }
    pub fn begin(
        &self,
        case: &Case,
        denied: bool,
        capacity: usize,
    ) -> std::result::Result<OperationTicket, Failure> {
        let key = if denied { &self.denied } else { &self.key };
        let key = key.as_ref().ok_or(Failure::Input("signature_key"))?;
        Ok(case.begin(self.subject()?, key, capacity)?)
    }
    pub fn begin_other(&self, case: &Case) -> std::result::Result<OperationTicket, Failure> {
        let other = self.other.as_ref().ok_or(Failure::Input("rsa_other_key"))?;
        Ok(case.begin(self.subject()?, other, case.width)?)
    }
    pub fn start(&mut self, ticket: OperationTicket) {
        self.ticket = Some(ticket);
        self.submitted = 0;
        self.pending = false;
        self.replacement = false;
        self.input_closed = false;
        self.completed = false;
    }
    pub fn update(&mut self, case: &Case) -> std::result::Result<OperationProgress, Failure> {
        let bytes = case.input.as_slice();
        let mut ticket = self
            .ticket
            .take()
            .ok_or(Failure::Input("signature_ticket"))?;
        let result = self.subject()?.signature_update(
            &mut ticket,
            bytes,
            InputLimits {
                maximum_parts: 8,
                maximum_total_bytes: 4096,
            },
        );
        self.ticket = Some(ticket);
        let result = result?;
        self.submitted += 1;
        Ok(result)
    }
    pub fn poll(&mut self) -> std::result::Result<OperationProgress, Failure> {
        let mut ticket = self
            .ticket
            .take()
            .ok_or(Failure::Input("signature_ticket"))?;
        let result = self.subject()?.poll(&mut ticket);
        self.ticket = Some(ticket);
        Ok(result?)
    }
    pub fn resize(&self, case: &Case) -> std::result::Result<(), Failure> {
        self.resize_to(case.width)
    }
    pub fn resize_to(&self, capacity: usize) -> std::result::Result<(), Failure> {
        Ok(self.subject()?.provide_signature_output_capacity(
            self.ticket
                .as_ref()
                .ok_or(Failure::Input("signature_ticket"))?,
            capacity,
        )?)
    }
    pub fn finish_step(&mut self, case: &Case) -> std::result::Result<OperationProgress, Failure> {
        let mut ticket = self
            .ticket
            .take()
            .ok_or(Failure::Input("signature_ticket"))?;
        let result = if case.single() {
            self.subject()?.finish_signature_single(
                &mut ticket,
                &case.input,
                if case.sign {
                    None
                } else {
                    Some(case.expected(1)?)
                },
                InputLimits {
                    maximum_parts: 8,
                    maximum_total_bytes: 4096,
                },
            )
        } else {
            self.subject()?.finish_signature_stream(
                &mut ticket,
                if case.sign {
                    None
                } else {
                    Some(case.expected(self.submitted)?)
                },
            )
        };
        self.ticket = Some(ticket);
        let result = result?;
        if case.single() {
            self.submitted += 1;
        }
        self.input_closed = true;
        Ok(result)
    }
    pub fn publish(
        &mut self,
        value: OperationProgress,
        case: &Case,
    ) -> std::result::Result<(), Failure> {
        let value = match value {
            OperationProgress::NativeSignature(v) if case.sign => v,
            OperationProgress::NativeVerification(v) if !case.sign => v,
            _ => return Err(Failure::Oracle("signature_terminal_result")),
        };
        let expected = if case.external_signature_reference() {
            // Randomized ECDSA has no fixed signature bytes. This copy checks
            // ownership only; the runner must independently verify every output
            // before it can publish a case PASS.
            if value.as_bytes().len() != case.width {
                return Err(Failure::Oracle("ecdsa_signature_width"));
            }
            value.as_bytes()
        } else if case.sign {
            case.expected(self.submitted)?
        } else {
            &[]
        };
        if value.as_bytes() != expected {
            return Err(Failure::Oracle("signature_complete_known_answer"));
        }
        let expected = expected.to_vec();
        self.published.push((value, expected));
        self.completed = true;
        self.pending = false;
        self.replacement = false;
        Ok(())
    }
    pub fn ready(value: OperationProgress) -> std::result::Result<(), Failure> {
        if matches!(value, OperationProgress::Ready) {
            Ok(())
        } else {
            Err(Failure::Oracle("signature_open_input_boundary"))
        }
    }
    pub fn required(value: OperationProgress, case: &Case) -> std::result::Result<(), Failure> {
        Self::required_with(value, case.width - 1, case)
    }
    pub fn required_with(
        value: OperationProgress,
        previous: usize,
        case: &Case,
    ) -> std::result::Result<(), Failure> {
        match value {
            OperationProgress::SignatureBufferRequired(r)
                if r.required == case.width
                    && r.previous_capacity == previous
                    && r.code == fe11_sys::CKR_BUFFER_TOO_SMALL as u64
                    && r.function
                        == if case.single() {
                            "C_Sign"
                        } else {
                            "C_SignFinal"
                        } =>
            {
                Ok(())
            }
            _ => Err(Failure::Oracle("signature_exact_retained_buffer_request")),
        }
    }
    pub fn progress(&self, case: &Case) -> std::result::Result<(), Failure> {
        let (status, p) = self
            .ticket
            .as_ref()
            .ok_or(Failure::Input("signature_ticket"))?
            .signature_progress()?;
        // A retained single call has issued one submission but has not yet
        // established acceptance of any bytes. Multipart Update successes have.
        let bytes = if case.single() && self.pending {
            0
        } else {
            u128::from(self.submitted) * case.input.len() as u128
        };
        let expected_status = if self.input_closed {
            StreamInputStatus::Closed
        } else {
            StreamInputStatus::Open
        };
        if status != expected_status
            || p.submissions != self.submitted
            || p.input_bytes != bytes
            || p.output_bytes != 0
            || p.delivered_bytes != 0
        {
            return Err(Failure::Oracle("signature_exact_stream_progress"));
        }
        Ok(())
    }
    pub fn verify_owned(&self) -> std::result::Result<(), Failure> {
        if self.published.iter().any(|(v, e)| v.as_bytes() != e) {
            return Err(Failure::Oracle("signature_published_output_changed"));
        }
        Ok(())
    }
    pub fn write_reference_output(&self) -> std::result::Result<(), Failure> {
        if !self.external_reference {
            return Ok(());
        }
        use std::{fs::OpenOptions, io::Write};
        if self.published.len() > 2 {
            return Err(Failure::Oracle("unexpected_signature_publication_count"));
        }
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open("public-transition-signatures.bin")
            .map_err(|_| Failure::Input("signature_reference_create"))?;
        for (signature, _) in &self.published {
            file.write_all(signature.as_bytes())
                .map_err(|_| Failure::Input("signature_reference_write"))?;
        }
        file.flush()
            .map_err(|_| Failure::Input("signature_reference_flush"))
    }
    pub fn complete(&mut self, case: &Case) -> std::result::Result<(), Failure> {
        if self.ticket.is_none() || self.closed || self.completed {
            return self.verify_owned();
        }
        self.progress(case)?;
        let value = if self.pending {
            if !self.replacement {
                self.resize(case)?;
            }
            self.poll()?
        } else {
            if self.submitted == 0 && !case.single() {
                Self::ready(self.update(case)?)?;
            }
            self.progress(case)?;
            self.finish_step(case)?
        };
        self.publish(value, case)?;
        self.verify_owned()
    }
    pub fn prepare(
        &mut self,
        module: &Module,
        config: &Configuration,
        pins: &Credentials,
        case: &Case,
    ) -> std::result::Result<(), Failure> {
        self.external_reference = case.external_signature_reference();
        let token =
            select_token(module, &config.label).ok_or(Failure::Input("token_not_unique"))?;
        self.peer = Some(module.select(&token)?.open_session(true)?);
        self.peer
            .as_ref()
            .ok_or(Failure::Input("signature_peer"))?
            .login_as(LoginRole::User, SecretPin::new(pins.user.to_vec()))?;
        self.logged = true;
        self.subject = Some(Owner::open(module, config, true)?);
        let owner = self
            .subject
            .as_ref()
            .ok_or(Failure::Input("signature_owner"))?;
        self.key = Some(case.import(owner, true)?);
        self.denied = Some(case.import(owner, false)?);
        self.other = case.import_other(owner)?;
        if case.state == "REFUSED_TERMINAL" {
            return match self.begin(case, true, case.width) {
                Err(Failure::Product(Error::Native { function, code, .. }))
                    if code == fe11_sys::CKR_KEY_FUNCTION_NOT_PERMITTED as u64
                        && function
                            == if case.sign {
                                "C_SignInit"
                            } else {
                                "C_VerifyInit"
                            } =>
                {
                    Ok(())
                }
                Err(error) => Err(error),
                Ok(_) => Err(Failure::Oracle("denied_signature_usage_accepted")),
            };
        }
        if case.state == "IDLE" {
            return Ok(());
        }
        let waiting = matches!(
            case.state.as_str(),
            "OUTPUT_REQUIRED" | "OUTPUT_STORAGE_SELECTED"
        );
        self.start(self.begin(
            case,
            false,
            if waiting { case.width - 1 } else { case.width },
        )?);
        if waiting {
            if !case.single() {
                Self::ready(self.update(case)?)?;
            }
            Self::required(self.finish_step(case)?, case)?;
            self.pending = true;
            if case.state == "OUTPUT_STORAGE_SELECTED" {
                self.resize(case)?;
                self.replacement = true;
            }
        } else if matches!(case.state.as_str(), "MULTIPART_ACTIVE" | "CONSUMED") {
            if !case.single() {
                Self::ready(self.update(case)?)?;
            }
            if case.state == "CONSUMED" {
                let value = self.finish_step(case)?;
                self.publish(value, case)?;
            }
        }
        if case.state == "TICKET_DROPPED" {
            drop(self.ticket.take());
        }
        if case.state == "RETIRED" {
            self.close()?;
        }
        Ok(())
    }
    pub fn close(&mut self) -> std::result::Result<(), Failure> {
        match self.subject()?.close()? {
            AdvancedCloseStatus::Complete => {
                self.closed = true;
                Ok(())
            }
            AdvancedCloseStatus::Pending => Err(Failure::Oracle("signature_close_pending")),
        }
    }
    pub fn cleanup(&mut self) -> Vec<Failure> {
        let mut errors = Vec::new();
        // All fixture keys are session objects. Close destroys them without a stale
        // object lookup after Logout, a refused Init or a dropped observer.
        if self.subject.is_some() && !self.closed {
            if let Err(e) = self.close() {
                errors.push(e);
            }
        }
        if let Some(peer) = &self.peer {
            if self.logged {
                if let Err(e) = peer.logout() {
                    errors.push(e.into());
                }
            }
            if let Err(e) = peer.close() {
                errors.push(e.into());
            }
        }
        errors
    }
}
