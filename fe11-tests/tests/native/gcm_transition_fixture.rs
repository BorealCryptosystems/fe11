// SPDX-License-Identifier: Apache-2.0
//! GCM stream fixtures distinguish a retained Update from a retained Final.
use super::{
    arguments::hex,
    configuration::{select_token, Configuration},
    credentials::Credentials,
    object_owner::Owner,
    outcome::Failure,
};
use fe11::*;
use std::{fs::File, io::Read, path::Path};

pub struct Case {
    pub state: String,
    pub action: String,
    pub encrypt: bool,
    key: Vec<u8>,
    iv: Vec<u8>,
    pub input: Vec<u8>,
    pub expected: Vec<u8>,
}
impl Case {
    pub fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let mut bytes = Vec::new();
        File::open(path)
            .map_err(|_| Failure::Input("fixture_open"))?
            .take(1025)
            .read_to_end(&mut bytes)
            .map_err(|_| Failure::Input("fixture_read"))?;
        if bytes.len() > 1024 {
            return Err(Failure::Input("fixture_size"));
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| Failure::Input("fixture_encoding"))?;
        let f: Vec<_> = text.split_terminator('\n').collect();
        if f.len() != 7
            || !matches!(
                f[0],
                "IDLE"
                    | "INITIALIZED"
                    | "MULTIPART_ACTIVE"
                    | "OUTPUT_REQUIRED"
                    | "OUTPUT_STORAGE_SELECTED"
                    | "CONSUMED"
                    | "RETIRED"
                    | "REFUSED_TERMINAL"
                    | "TICKET_DROPPED"
            )
            || !matches!(
                f[1],
                "init"
                    | "update"
                    | "final"
                    | "provide_capacity"
                    | "poll"
                    | "take"
                    | "logout"
                    | "close"
                    | "capture"
                    | "cancel"
                    | "drop_ticket"
            )
            || !matches!(f[2], "encrypt" | "decrypt")
        {
            return Err(Failure::Input("gcm_transition_fields"));
        }
        let case = Self {
            state: f[0].into(),
            action: f[1].into(),
            encrypt: f[2] == "encrypt",
            key: hex(f[3], 16).map_err(Failure::Input)?,
            iv: hex(f[4], 12).map_err(Failure::Input)?,
            input: hex(f[5], 32).map_err(Failure::Input)?,
            expected: hex(f[6], 16).map_err(Failure::Input)?,
        };
        if case.key.len() != 16
            || case.iv.len() != 12
            || case.expected.len() != 16
            || case.input.len() != if case.encrypt { 0 } else { 32 }
        {
            return Err(Failure::Input("gcm_transition_dimensions"));
        }
        Ok(case)
    }
    pub fn required(&self) -> usize {
        if self.encrypt {
            16
        } else {
            32
        }
    }
    pub fn parameters(&self) -> ClassicAeadParameters<'_> {
        ClassicAeadParameters::Gcm {
            iv: &self.iv,
            aad: &[],
            tag_bits: 128,
        }
    }
}

enum Published {
    Encrypted(ClassicAeadCiphertext),
    Decrypted(AeadPlaintext),
}
impl Published {
    fn bytes(&self) -> &[u8] {
        match self {
            Self::Encrypted(v) => v.as_bytes(),
            Self::Decrypted(v) => v.as_bytes(),
        }
    }
}

pub struct Fixture {
    pub peer: Option<Session>,
    subject: Option<Owner>,
    key: Option<NativeObjectRef>,
    denied: Option<NativeObjectRef>,
    pub ticket: Option<OperationTicket>,
    pub submitted: u64,
    pub pending: bool,
    pub replacement: bool,
    pub input_closed: bool,
    pub completed: bool,
    pub closed: bool,
    pub logged: bool,
    pub output_taken: bool,
    published: Vec<(Published, Vec<u8>)>,
    chunks: Vec<CipherStreamChunk>,
}
impl Fixture {
    pub fn empty() -> Self {
        Self {
            peer: None,
            subject: None,
            key: None,
            denied: None,
            ticket: None,
            submitted: 0,
            pending: false,
            replacement: false,
            input_closed: false,
            completed: false,
            closed: false,
            logged: false,
            output_taken: false,
            published: Vec::new(),
            chunks: Vec::new(),
        }
    }
    pub fn subject(&self) -> std::result::Result<&AdvancedSession, Failure> {
        match &self.subject {
            Some(Owner::Advanced(s)) => Ok(s),
            _ => Err(Failure::Input("gcm_subject")),
        }
    }
    pub fn begin(
        &self,
        case: &Case,
        denied: bool,
        capacity: usize,
    ) -> std::result::Result<OperationTicket, Failure> {
        let key = if denied { &self.denied } else { &self.key };
        let key = key.as_ref().ok_or(Failure::Input("gcm_key"))?;
        let output = CipherOutputPlan::Buffer { capacity };
        Ok(if case.encrypt {
            self.subject()?.begin_encrypt_classic_aead_stream(
                key,
                case.parameters(),
                None,
                output,
            )?
        } else {
            self.subject()?.begin_decrypt_classic_aead_stream(
                key,
                case.parameters(),
                None,
                output,
            )?
        })
    }
    pub fn start(&mut self, ticket: OperationTicket) {
        self.ticket = Some(ticket);
        self.submitted = 0;
        self.pending = false;
        self.replacement = false;
        self.input_closed = false;
        self.completed = false;
        self.output_taken = false;
    }
    pub fn update(&mut self, case: &Case) -> std::result::Result<OperationProgress, Failure> {
        // The complete authenticated envelope is submitted once. A second
        // nominal Update is empty, preserving that exact message and its tag.
        let bytes = if self.submitted == 0 {
            case.input.as_slice()
        } else {
            &[]
        };
        let mut ticket = self.ticket.take().ok_or(Failure::Input("gcm_ticket"))?;
        let result = self.subject()?.cipher_update(
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
        let mut ticket = self.ticket.take().ok_or(Failure::Input("gcm_ticket"))?;
        let result = self.subject()?.poll(&mut ticket);
        self.ticket = Some(ticket);
        Ok(result?)
    }
    pub fn resize(&self, case: &Case) -> std::result::Result<(), Failure> {
        Ok(self.subject()?.resize_cipher_output(
            self.ticket.as_ref().ok_or(Failure::Input("gcm_ticket"))?,
            case.required(),
        )?)
    }
    pub fn finish_step(&mut self) -> std::result::Result<OperationProgress, Failure> {
        let mut ticket = self.ticket.take().ok_or(Failure::Input("gcm_ticket"))?;
        let result = self.subject()?.finish_cipher_stream(&mut ticket);
        self.ticket = Some(ticket);
        let result = result?;
        self.input_closed = true;
        Ok(result)
    }
    pub fn publish(
        &mut self,
        value: OperationProgress,
        case: &Case,
    ) -> std::result::Result<(), Failure> {
        let value = match value {
            OperationProgress::ClassicAeadEncrypted(v) if case.encrypt => Published::Encrypted(v),
            OperationProgress::ClassicAeadDecrypted(v) if !case.encrypt => Published::Decrypted(v),
            _ => return Err(Failure::Oracle("gcm_authenticated_terminal_result")),
        };
        if value.bytes() != case.expected {
            return Err(Failure::Oracle("gcm_complete_known_answer"));
        }
        self.published.push((value, case.expected.clone()));
        self.completed = true;
        self.pending = false;
        self.replacement = false;
        Ok(())
    }
    pub fn ready(value: OperationProgress) -> std::result::Result<(), Failure> {
        if matches!(value, OperationProgress::Ready) {
            Ok(())
        } else {
            Err(Failure::Oracle("gcm_open_input_boundary"))
        }
    }
    pub fn required(value: OperationProgress, case: &Case) -> std::result::Result<(), Failure> {
        match value {
            OperationProgress::CipherBufferRequired(request)
                if request.required == case.required()
                    && request.code == fe11_sys::CKR_BUFFER_TOO_SMALL as u64
                    && request.function
                        == if case.encrypt {
                            "C_EncryptFinal"
                        } else {
                            "C_DecryptUpdate"
                        } =>
            {
                Ok(())
            }
            _ => Err(Failure::Oracle("gcm_exact_retained_buffer_request")),
        }
    }
    pub fn progress(&self, case: &Case) -> std::result::Result<(), Failure> {
        let (status, p) = self
            .ticket
            .as_ref()
            .ok_or(Failure::Input("gcm_ticket"))?
            .cipher_progress()?;
        let bytes = if !case.encrypt && self.submitted > 0 && !self.pending {
            32
        } else {
            0
        };
        let expected_status = if self.input_closed {
            StreamInputStatus::Closed
        } else {
            StreamInputStatus::Open
        };
        // All encryption input is empty. Decryption Update buffers ciphertext;
        // no unauthenticated plaintext may escape through stream output.
        if status != expected_status
            || p.submissions != self.submitted
            || p.input_bytes != bytes
            || p.output_bytes != 0
            || p.delivered_bytes != 0
        {
            return Err(Failure::Oracle("gcm_exact_stream_progress"));
        }
        Ok(())
    }
    pub fn take(&mut self) -> std::result::Result<(), Failure> {
        let chunk = self
            .subject()?
            .take_cipher_stream_output(self.ticket.as_ref().ok_or(Failure::Input("gcm_ticket"))?)?;
        if chunk.is_unauthenticated_plaintext() || !chunk.as_bytes().is_empty() {
            return Err(Failure::Oracle("gcm_empty_ciphertext_chunk"));
        }
        self.chunks.push(chunk);
        self.output_taken = true;
        Ok(())
    }
    pub fn verify_owned(&self) -> std::result::Result<(), Failure> {
        if self.published.iter().any(|(v, e)| v.bytes() != e)
            || self.chunks.iter().any(|v| !v.as_bytes().is_empty())
        {
            return Err(Failure::Oracle("gcm_published_output_changed"));
        }
        Ok(())
    }
    pub fn complete(&mut self, case: &Case) -> std::result::Result<(), Failure> {
        if self.ticket.is_none() || self.closed || self.completed {
            return self.verify_owned();
        }
        self.progress(case)?;
        if self.pending {
            if !self.replacement {
                self.resize(case)?;
            }
            let value = self.poll()?;
            self.pending = false;
            self.replacement = false;
            if self.input_closed {
                self.publish(value, case)?;
                return self.verify_owned();
            }
            Self::ready(value)?;
        }
        if self.submitted == 0 {
            Self::ready(self.update(case)?)?;
        }
        self.progress(case)?;
        let result = self.finish_step()?;
        if self.output_taken {
            // Transferring even an empty chunk transfers the output allocation.
            // Negotiate a fresh tag buffer explicitly; do not hide a retry.
            Self::required(result, case)?;
            self.resize(case)?;
            let resumed = self.poll()?;
            self.publish(resumed, case)?;
        } else {
            self.publish(result, case)?;
        }
        self.verify_owned()
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
            .ok_or(Failure::Input("gcm_peer"))?
            .login_as(LoginRole::User, SecretPin::new(pins.user.to_vec()))?;
        self.logged = true;
        self.subject = Some(Owner::open(module, config, true)?);
        let owner = self.subject.as_ref().ok_or(Failure::Input("gcm_owner"))?;
        self.key = Some(owner.import_secret(
            &case.key,
            fe11_sys::CKK_AES,
            [StandardAttribute::ENCRYPT, StandardAttribute::DECRYPT],
        )?);
        self.denied = Some(owner.import_secret_usages(
            &case.key,
            fe11_sys::CKK_AES,
            [
                (StandardAttribute::ENCRYPT, false),
                (StandardAttribute::DECRYPT, false),
            ],
        )?);
        if case.state == "REFUSED_TERMINAL" {
            return match self.begin(case, true, 32) {
                Err(Failure::Product(Error::Native { function, code, .. }))
                    if code == fe11_sys::CKR_KEY_FUNCTION_NOT_PERMITTED as u64
                        && function
                            == if case.encrypt {
                                "C_EncryptInit"
                            } else {
                                "C_DecryptInit"
                            } =>
                {
                    Ok(())
                }
                Err(error) => Err(error),
                Ok(_) => Err(Failure::Oracle("denied_gcm_usage_accepted")),
            };
        }
        if case.state == "IDLE" {
            return Ok(());
        }
        let waiting = matches!(
            case.state.as_str(),
            "OUTPUT_REQUIRED" | "OUTPUT_STORAGE_SELECTED"
        );
        self.start(self.begin(case, false, if waiting { case.required() - 1 } else { 32 })?);
        if waiting {
            let value = self.update(case)?;
            if case.encrypt {
                Self::ready(value)?;
                Self::required(self.finish_step()?, case)?;
            } else {
                Self::required(value, case)?;
            }
            self.pending = true;
            if case.state == "OUTPUT_STORAGE_SELECTED" {
                self.resize(case)?;
                self.replacement = true;
            }
        } else if matches!(case.state.as_str(), "MULTIPART_ACTIVE" | "CONSUMED") {
            Self::ready(self.update(case)?)?;
            if case.state == "CONSUMED" {
                let value = self.finish_step()?;
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
            AdvancedCloseStatus::Pending => Err(Failure::Oracle("gcm_close_pending")),
        }
    }
    pub fn cleanup(&mut self) -> Vec<Failure> {
        let mut errors = Vec::new();
        // Both keys are session objects. Close destroys them without a stale
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
