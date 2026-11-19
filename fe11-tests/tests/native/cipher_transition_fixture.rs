// SPDX-License-Identifier: Apache-2.0
//! Real AES stream owners at explicit public continuation boundaries.
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
    pub key: Vec<u8>,
    pub input: Vec<u8>,
    pub expected: Vec<u8>,
    iv: Option<[u8; 16]>,
    initial_capacity: Option<usize>,
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
        if !matches!(f.len(), 6 | 8)
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
            return Err(Failure::Input("cipher_transition_fields"));
        }
        let key = hex(f[3], 16).map_err(Failure::Input)?;
        let width = if f.len() == 8 { 32 } else { 16 };
        let input = hex(f[4], width).map_err(Failure::Input)?;
        let expected = hex(f[5], width).map_err(Failure::Input)?;
        if key.len() != 16 || input.len() != width || expected.len() != width {
            return Err(Failure::Input("cipher_transition_dimensions"));
        }
        let (iv, initial_capacity) = if f.len() == 8 {
            let iv = hex(f[6], 16).map_err(Failure::Input)?;
            let capacity = f[7]
                .parse::<usize>()
                .map_err(|_| Failure::Input("cipher_initial_capacity"))?;
            let valid = match capacity {
                0 | 31 => f[..2] == ["OUTPUT_REQUIRED", "provide_capacity"],
                32 => f[..2] == ["MULTIPART_ACTIVE", "final"],
                _ => false,
            };
            if !valid {
                return Err(Failure::Input("cipher_cbc_capacity_case"));
            }
            (
                Some(
                    iv.try_into()
                        .map_err(|_| Failure::Input("cipher_iv_width"))?,
                ),
                Some(capacity),
            )
        } else {
            (None, None)
        };
        Ok(Self {
            state: f[0].into(),
            action: f[1].into(),
            encrypt: f[2] == "encrypt",
            key,
            input,
            expected,
            iv,
            initial_capacity,
        })
    }
}

enum Published {
    Encrypted(Ciphertext),
    Decrypted(UnauthenticatedCipherPlaintext),
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
    pub subject: Option<Owner>,
    pub key: Option<NativeObjectRef>,
    pub denied: Option<NativeObjectRef>,
    pub ticket: Option<OperationTicket>,
    pub transferred: Vec<u8>,
    published: Vec<(Published, Vec<u8>)>,
    chunks: Vec<(CipherStreamChunk, Vec<u8>)>,
    pub blocks: usize,
    pub pending_input: bool,
    pub replacement: bool,
    pub logged: bool,
    pub closed: bool,
    pub completed: bool,
    pub input_closed: bool,
    submission_bytes: usize,
}
impl Fixture {
    pub fn empty() -> Self {
        Self {
            peer: None,
            subject: None,
            key: None,
            denied: None,
            ticket: None,
            transferred: Vec::new(),
            published: Vec::new(),
            chunks: Vec::new(),
            blocks: 0,
            pending_input: false,
            replacement: false,
            logged: false,
            closed: false,
            completed: false,
            input_closed: false,
            submission_bytes: 16,
        }
    }
    pub fn subject(&self) -> std::result::Result<&AdvancedSession, Failure> {
        match self.subject.as_ref() {
            Some(Owner::Advanced(s)) => Ok(s),
            _ => Err(Failure::Input("cipher_subject")),
        }
    }
    pub fn begin(
        &self,
        case: &Case,
        denied: bool,
        capacity: usize,
    ) -> std::result::Result<OperationTicket, Failure> {
        let key = if denied { &self.denied } else { &self.key };
        let key = key.as_ref().ok_or(Failure::Input("cipher_key"))?;
        let parameters = CipherParameters::Aes(match case.iv {
            Some(iv) => AesCipherParameters::Cbc { iv },
            None => AesCipherParameters::Ecb,
        });
        let output = CipherOutputPlan::Buffer { capacity };
        Ok(if case.encrypt {
            self.subject()?.begin_encrypt_stream(
                CipherKeyReference::Secret(key),
                parameters,
                output,
            )?
        } else {
            self.subject()?.begin_decrypt_stream(
                CipherKeyReference::Secret(key),
                parameters,
                output,
            )?
        })
    }
    pub fn update(&mut self, case: &Case) -> std::result::Result<OperationProgress, Failure> {
        let mut ticket = self.ticket.take().ok_or(Failure::Input("cipher_ticket"))?;
        let result = self.subject()?.cipher_update(
            &mut ticket,
            &case.input,
            InputLimits {
                maximum_parts: 8,
                maximum_total_bytes: 4096,
            },
        );
        self.ticket = Some(ticket);
        Ok(result?)
    }
    pub fn poll(&mut self) -> std::result::Result<OperationProgress, Failure> {
        let mut ticket = self.ticket.take().ok_or(Failure::Input("cipher_ticket"))?;
        let result = self.subject()?.poll(&mut ticket);
        self.ticket = Some(ticket);
        Ok(result?)
    }
    pub fn resize(&self) -> std::result::Result<(), Failure> {
        Ok(self.subject()?.resize_cipher_output(
            self.ticket
                .as_ref()
                .ok_or(Failure::Input("cipher_ticket"))?,
            self.submission_bytes,
        )?)
    }
    pub fn finish(&mut self, case: &Case) -> std::result::Result<(), Failure> {
        let result = self.finish_step()?;
        self.publish_final(result, case)
    }
    pub fn finish_step(&mut self) -> std::result::Result<OperationProgress, Failure> {
        let mut ticket = self.ticket.take().ok_or(Failure::Input("cipher_ticket"))?;
        let result = self.subject()?.finish_cipher_stream(&mut ticket);
        self.ticket = Some(ticket);
        let result = result?;
        self.input_closed = true;
        Ok(result)
    }
    pub fn publish_final(
        &mut self,
        result: OperationProgress,
        case: &Case,
    ) -> std::result::Result<(), Failure> {
        let output = match result {
            OperationProgress::CipherEncrypted(value) if case.encrypt => {
                Published::Encrypted(value)
            }
            OperationProgress::CipherDecrypted(value) if !case.encrypt => {
                Published::Decrypted(value)
            }
            _ => return Err(Failure::Oracle("cipher_terminal_result")),
        };
        let mut all = self.transferred.clone();
        all.extend_from_slice(output.bytes());
        if all != case.expected.repeat(self.blocks) {
            return Err(Failure::Oracle("cipher_complete_known_answer"));
        }
        let expected = case.expected.repeat(self.blocks)[self.transferred.len()..].to_vec();
        self.published.push((output, expected));
        self.completed = true;
        Ok(())
    }
    pub fn buffer_required(
        progress: OperationProgress,
        case: &Case,
    ) -> std::result::Result<(), Failure> {
        match progress {
            OperationProgress::CipherBufferRequired(request)
                if request.required == case.input.len()
                    && request.code == fe11_sys::CKR_BUFFER_TOO_SMALL as u64
                    && request.function
                        == if case.encrypt {
                            "C_EncryptUpdate"
                        } else {
                            "C_DecryptUpdate"
                        } =>
            {
                Ok(())
            }
            _ => Err(Failure::Oracle("cipher_exact_buffer_request")),
        }
    }
    pub fn ready(progress: OperationProgress) -> std::result::Result<(), Failure> {
        if matches!(progress, OperationProgress::Ready) {
            Ok(())
        } else {
            Err(Failure::Oracle("cipher_input_boundary"))
        }
    }
    pub fn retain_chunk(&mut self, chunk: CipherStreamChunk, expected: Vec<u8>) {
        self.transferred.extend_from_slice(chunk.as_bytes());
        self.chunks.push((chunk, expected));
    }
    pub fn verify_owned(&self) -> std::result::Result<(), Failure> {
        if self
            .published
            .iter()
            .any(|(value, expected)| value.bytes() != expected)
            || self
                .chunks
                .iter()
                .any(|(value, expected)| value.as_bytes() != expected)
        {
            return Err(Failure::Oracle("published_cipher_output_changed"));
        }
        Ok(())
    }
    pub fn progress(&self) -> std::result::Result<(), Failure> {
        let ticket = self
            .ticket
            .as_ref()
            .ok_or(Failure::Input("cipher_ticket"))?;
        let (status, progress) = ticket.cipher_progress()?;
        let accepted = self.blocks - usize::from(self.pending_input);
        let expected_status = if self.input_closed {
            StreamInputStatus::Closed
        } else {
            StreamInputStatus::Open
        };
        if status != expected_status
            || progress.submissions != self.blocks as u64
            || progress.input_bytes != (accepted * self.submission_bytes) as u128
            || progress.output_bytes != (accepted * self.submission_bytes) as u128
            || progress.delivered_bytes != self.transferred.len() as u128
        {
            return Err(Failure::Oracle("cipher_exact_stream_progress"));
        }
        Ok(())
    }
    pub fn prepare(
        &mut self,
        module: &Module,
        config: &Configuration,
        pins: &Credentials,
        case: &Case,
    ) -> std::result::Result<(), Failure> {
        self.submission_bytes = case.input.len();
        let token =
            select_token(module, &config.label).ok_or(Failure::Input("token_not_unique"))?;
        self.peer = Some(module.select(&token)?.open_session(true)?);
        self.peer
            .as_ref()
            .ok_or(Failure::Input("cipher_peer"))?
            .login_as(LoginRole::User, SecretPin::new(pins.user.to_vec()))?;
        self.logged = true;
        self.subject = Some(Owner::open(module, config, true)?);
        let owner = self
            .subject
            .as_ref()
            .ok_or(Failure::Input("cipher_owner"))?;
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
            return match self.begin(case, true, 16) {
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
                Ok(_) => Err(Failure::Oracle("denied_cipher_usage_accepted")),
            };
        }
        if case.state == "IDLE" {
            return Ok(());
        }
        let waiting = matches!(
            case.state.as_str(),
            "OUTPUT_REQUIRED" | "OUTPUT_STORAGE_SELECTED"
        );
        // The nominal second Update retains the first block: its whole-operation
        // buffer needs two blocks. Capacity-negotiation cases deliberately use zero.
        let capacity = if let Some(capacity) = case.initial_capacity {
            capacity
        } else if waiting {
            0
        } else if case.state == "MULTIPART_ACTIVE" && case.action == "update" {
            32
        } else {
            16
        };
        self.ticket = Some(self.begin(case, false, capacity)?);
        if waiting {
            Self::buffer_required(self.update(case)?, case)?;
            self.blocks = 1;
            self.pending_input = true;
            if case.state == "OUTPUT_STORAGE_SELECTED" {
                self.resize()?;
                self.replacement = true;
            }
        } else if matches!(case.state.as_str(), "MULTIPART_ACTIVE" | "CONSUMED") {
            Self::ready(self.update(case)?)?;
            self.blocks = 1;
            if case.state == "CONSUMED" {
                self.finish(case)?;
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
            AdvancedCloseStatus::Pending => Err(Failure::Oracle("cipher_close_pending")),
        }
    }
    pub fn cleanup(&mut self) -> Vec<Failure> {
        let mut failures = Vec::new();
        // These are session objects. Proven close destroys both without using
        // stale references after Logout or resurrecting a dropped ticket.
        if self.subject.is_some() && !self.closed {
            if let Err(error) = self.close() {
                failures.push(error);
            }
        }
        if let Some(peer) = &self.peer {
            if self.logged {
                if let Err(error) = peer.logout() {
                    failures.push(error.into());
                }
            }
            if let Err(error) = peer.close() {
                failures.push(error.into());
            }
        }
        failures
    }
}
