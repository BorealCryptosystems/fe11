// SPDX-License-Identifier: Apache-2.0
//! Real SHA-256 extension output negotiation, without synthetic native returns.
use super::{
    arguments::hex,
    configuration::{select_token, Configuration},
    credentials::Credentials,
    outcome::Failure,
};
use fe11::*;
use std::{fs::File, io::Read, path::Path};

pub struct Case {
    pub state: String,
    pub action: String,
    pub expected: Vec<u8>,
}
impl Case {
    pub fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let mut bytes = Vec::new();
        File::open(path)
            .map_err(|_| Failure::Input("fixture_open"))?
            .take(513)
            .read_to_end(&mut bytes)
            .map_err(|_| Failure::Input("fixture_read"))?;
        if bytes.len() > 512 {
            return Err(Failure::Input("fixture_size"));
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| Failure::Input("fixture_encoding"))?;
        let fields: Vec<_> = text.split_terminator('\n').collect();
        if fields.len() != 3
            || !matches!(
                fields[0],
                "OUTPUT_REQUIRED"
                    | "OUTPUT_STORAGE_SELECTED"
                    | "FACADE_RETAINED"
                    | "OUTPUT_EXACT"
                    | "ZERO_OUTPUT"
                    | "ZERO_COOPERATIVE"
            )
            || !matches!(
                fields[1],
                "init"
                    | "exact"
                    | "requirement"
                    | "update"
                    | "final"
                    | "take"
                    | "poll"
                    | "output_capacity"
                    | "capture"
                    | "cancel"
                    | "login"
                    | "logout"
                    | "close"
                    | "drop_ticket"
            )
        {
            return Err(Failure::Input("digest_capacity_fields"));
        }
        if (fields[0] == "OUTPUT_EXACT") != (fields[1] == "exact") {
            return Err(Failure::Input("digest_exact_capacity_action"));
        }
        if fields[0].starts_with("ZERO_") && fields[1] != "requirement" {
            return Err(Failure::Input("digest_zero_capacity_action"));
        }
        let expected = hex(fields[2], 32).map_err(Failure::Input)?;
        if expected.len() != 32 {
            return Err(Failure::Input("digest_expected_width"));
        }
        Ok(Self {
            state: fields[0].into(),
            action: fields[1].into(),
            expected,
        })
    }
}
pub fn too_small<T>(result: Result<T>) -> std::result::Result<(), Failure> {
    too_small_at(result, 31)
}
fn too_small_at<T>(
    result: Result<T>,
    expected_capacity: usize,
) -> std::result::Result<(), Failure> {
    match result {
        Err(Error::OutputBufferTooSmall {
            function: "C_DigestFinal",
            code,
            required: 32,
            capacity,
        }) if code == fe11_sys::CKR_BUFFER_TOO_SMALL as u64 && capacity == expected_capacity => {
            Ok(())
        }
        Err(error) => Err(error.into()),
        Ok(_) => Err(Failure::Oracle("digest_capacity_refusal_missing")),
    }
}
pub struct Fixture {
    pub peer: Option<Session>,
    ordinary: Option<Session>,
    pub subject: Option<AdvancedSession>,
    pub ticket: Option<OperationTicket>,
    pub output: Option<ExtensionResult>,
    pub replacement: bool,
    pub logged: bool,
    pub closed: bool,
    pub appended: bool,
}
impl Fixture {
    pub fn empty() -> Self {
        Self {
            peer: None,
            ordinary: None,
            subject: None,
            ticket: None,
            output: None,
            replacement: false,
            logged: false,
            closed: false,
            appended: false,
        }
    }
    pub fn subject(&self) -> std::result::Result<&AdvancedSession, Failure> {
        self.subject
            .as_ref()
            .ok_or(Failure::Input("digest_subject"))
    }
    pub fn prepare(
        &mut self,
        module: &Module,
        config: &Configuration,
        pins: &Credentials,
        case: &Case,
    ) -> std::result::Result<(), Failure> {
        let token =
            select_token(module, &config.label).ok_or(Failure::Input("token_not_unique"))?;
        self.peer = Some(module.select(&token)?.open_session(true)?);
        self.peer
            .as_ref()
            .ok_or(Failure::Input("digest_peer"))?
            .login_as(LoginRole::User, SecretPin::new(pins.user.to_vec()))?;
        self.logged = true;
        self.ordinary = Some(module.select(&token)?.open_session(true)?);
        // SAFETY: PKCS#11 SHA-256 has no mechanism parameter, key input,
        // auxiliary output or mutation. The real module uses the selected ABI;
        // this declaration covers exactly DigestInit/Update/Final.
        let contract = unsafe {
            module.declare_mechanism_extension(
                fe11_sys::CKM_SHA256 as u64,
                (2, 40),
                ExtensionOperation::DigestMultipart,
                false,
            )?
        };
        // SAFETY: NULL/0 exactly represents the parameterless SHA-256 mechanism.
        // There are no blocks, pointers, writable extents or hidden addresses.
        let request = unsafe {
            ExtensionRequest::new(
                &contract,
                ExtensionParameters {
                    blocks: &[],
                    pointers: &[],
                    root: None,
                    outputs: &[],
                },
            )
        };
        let session = self
            .ordinary
            .take()
            .ok_or(Failure::Input("digest_session"))?;
        self.subject = Some(session.into_advanced()?);
        if case.state == "ZERO_COOPERATIVE" {
            self.subject
                .as_mut()
                .ok_or(Failure::Input("digest_subject"))?
                .set_pacing(OperationPacing::Cooperative)?;
        }
        if case.state == "FACADE_RETAINED" {
            let session = self.subject()?;
            too_small(session.execute_extension(
                request,
                ExtensionInput::DigestMultipart {
                    parts: &[b"abc"],
                    output_capacity: 31,
                },
                InputLimits {
                    maximum_parts: 1,
                    maximum_total_bytes: 3,
                },
                None,
            ))?;
        }
        if case.state != "FACADE_RETAINED" {
            let capacity = match case.state.as_str() {
                "OUTPUT_EXACT" => 32,
                "ZERO_OUTPUT" | "ZERO_COOPERATIVE" => 0,
                _ => 31,
            };
            let mut ticket = self
                .subject()?
                .begin_extension_digest_stream(request, capacity)?;
            let parts: &[&[u8]] = if case.state.starts_with("ZERO_") {
                &[b"a", b"b", b"c"]
            } else {
                &[b"abc"]
            };
            let updated = (|| -> std::result::Result<(), Failure> {
                for part in parts {
                    self.subject()?.digest_update(
                        &mut ticket,
                        part,
                        InputLimits {
                            maximum_parts: parts.len(),
                            maximum_total_bytes: 3,
                        },
                    )?;
                }
                Ok(())
            })();
            self.ticket = Some(ticket);
            updated?;
            if case.state == "OUTPUT_EXACT" {
                return Ok(());
            }
            too_small_at(self.final_result()?, capacity)?;
            if case.state == "OUTPUT_STORAGE_SELECTED" {
                self.resize()?;
                self.replacement = true;
            }
        }
        Ok(())
    }
    pub fn final_result(&mut self) -> std::result::Result<Result<OperationProgress>, Failure> {
        let mut ticket = self.ticket.take().ok_or(Failure::Input("digest_ticket"))?;
        let result = self.subject()?.finish_extension_digest_stream(&mut ticket);
        self.ticket = Some(ticket);
        Ok(result)
    }
    pub fn poll_result(&mut self) -> std::result::Result<Result<OperationProgress>, Failure> {
        let mut ticket = self.ticket.take().ok_or(Failure::Input("digest_ticket"))?;
        let result = self.subject()?.poll(&mut ticket);
        self.ticket = Some(ticket);
        Ok(result)
    }
    pub fn resize(&self) -> std::result::Result<(), Failure> {
        Ok(self.subject()?.provide_extension_digest_output_capacity(
            self.ticket
                .as_ref()
                .ok_or(Failure::Input("digest_ticket"))?,
            32,
        )?)
    }
    pub fn accept(
        &mut self,
        progress: OperationProgress,
        case: &Case,
    ) -> std::result::Result<(), Failure> {
        match progress {
            OperationProgress::ExtensionDigest(output) => {
                self.output = Some(output);
                self.verify(case)
            }
            _ => Err(Failure::Oracle("extension_digest_result")),
        }
    }
    pub fn verify(&self, case: &Case) -> std::result::Result<(), Failure> {
        if self.output.as_ref().map(|v| v.as_bytes()) != Some(case.expected.as_slice()) {
            return Err(Failure::Oracle("extension_digest_known_answer"));
        }
        Ok(())
    }
    pub fn close(&mut self) -> std::result::Result<(), Failure> {
        match self.subject()?.close()? {
            AdvancedCloseStatus::Complete => {
                self.closed = true;
                Ok(())
            }
            AdvancedCloseStatus::Pending => Err(Failure::Oracle("digest_close_pending")),
        }
    }
    pub fn cleanup(&mut self) -> Vec<Failure> {
        let mut errors = Vec::new();
        if self.subject.is_some() && !self.closed {
            if let Err(error) = self.close() {
                errors.push(error);
            }
        }
        if let Some(session) = &self.ordinary {
            if let Err(error) = session.close() {
                errors.push(error.into());
            }
        }
        if let Some(peer) = &self.peer {
            if self.logged {
                if let Err(error) = peer.logout() {
                    errors.push(error.into());
                }
            }
            if let Err(error) = peer.close() {
                errors.push(error.into());
            }
        }
        errors
    }
}
