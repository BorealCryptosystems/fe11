// SPDX-License-Identifier: Apache-2.0
//! Caller-fed standard AEAD messages, with explicit message and parent endings.
//! Native ownership suffices; key suitability is decided by the module without
//! a descriptive attribute read. Managed views borrow the same native owner.
//!
//! An ordinary message refusal is returned unchanged and leaves the initialized
//! parent available for an explicit next message or parent finish. The refused
//! entry keeps its index and diagnostic, but its current output is erased.
//! Earlier captures retain their independent opaque copies. After parent
//! completion each result's `rejection` accessor distinguishes those entries;
//! `get` never returns their bytes. Pending or context-wide failures retain their
//! existing cleanup requirements and cannot be treated as ordinary refusals.
use super::{initialization, submission, CipherKind, MessageKey, MessageRoute, Selection};
use crate::advanced::{
    AdvancedSession, OperationPacing, OperationProgress, OperationTicket, ValidationCaptureMode,
};
use crate::{
    AeadNonce, CcmNonce, Error, InputLimits, NativeObjectRef, Result, Session, StreamAeadNonce,
};

/// Native mechanism for a message process. Key suitability is decided by the module.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageAeadMechanism {
    /// CKM_AES_GCM.
    Gcm,
    /// CKM_AES_CCM.
    Ccm,
    /// CKM_CHACHA20_POLY1305.
    ChaCha20Poly1305,
    /// CKM_SALSA20_POLY1305.
    Salsa20Poly1305,
}
impl MessageAeadMechanism {
    fn kind(self) -> CipherKind {
        match self {
            Self::Gcm => CipherKind::Gcm,
            Self::Ccm => CipherKind::Ccm,
            Self::ChaCha20Poly1305 => CipherKind::ChaChaPoly1305,
            Self::Salsa20Poly1305 => CipherKind::SalsaPoly1305,
        }
    }
}

/// Safe native parameter representation for one message. No future fragments
/// are borrowed or copied by these parameters.
#[derive(Clone, Debug)]
pub enum MessageAeadParameters {
    /// GCM IV, generation fields and tag-bit length.
    Gcm(AeadNonce),
    /// CCM includes its native declared data length, independent of storage.
    Ccm {
        /// Nonce and native generation fields.
        nonce: CcmNonce,
        /// Native MAC length in bytes.
        mac_length: u64,
        /// Value passed as ulDataLen; it does not preallocate that many bytes.
        data_length: usize,
    },
    /// ChaCha20-Poly1305 or Salsa20-Poly1305 nonce and ABI length encoding.
    Stream(StreamAeadNonce),
}
impl MessageAeadParameters {
    fn selection(&self) -> (Selection, usize) {
        match self {
            Self::Gcm(nonce) => (Selection::Gcm(nonce.clone()), 0),
            Self::Ccm {
                nonce,
                mac_length,
                data_length,
            } => (
                Selection::Ccm {
                    nonce: nonce.clone(),
                    mac_length: *mac_length,
                },
                *data_length,
            ),
            Self::Stream(nonce) => (Selection::Stream(*nonce), 0),
        }
    }
}

/// Explicit Init layout. Shared GCM/CCM parameters retain stable nonce/tag
/// addresses throughout the parent process, even when it contains no messages.
#[derive(Clone, Copy)]
pub enum MessageAeadInit<'a> {
    /// Pass a NULL parameter pointer and zero parameter length to Init.
    WithoutParameters,
    /// Pass an owned GCM/CCM descriptor to Init. Future messages must fit its
    /// fixed fields; no input data is implied by this initial parameter seed.
    WithParameters {
        /// Initial scalar fields and nonce contents.
        parameters: &'a MessageAeadParameters,
        /// Optional decryption tag contents for Init; not inherited by messages.
        expected_tag: Option<&'a [u8]>,
    },
}

/// One message's fixed inputs and initial output storage, before Single or Begin.
#[derive(Clone, Copy)]
pub struct MessageAeadInput<'a> {
    /// Mechanism-specific selection, matching the parent mechanism.
    pub parameters: &'a MessageAeadParameters,
    /// Associated data supplied once, to Single or Begin.
    pub aad: &'a [u8],
    /// Decryption tag. Required for Single; optional for Begin when it will be
    /// supplied with the final fragment. Absent for encryption.
    pub expected_tag: Option<&'a [u8]>,
    /// Initial non-NULL output capacity, including zero. Insufficient storage
    /// yields CipherBufferRequired; it never changes the chosen input boundary.
    pub output_capacity: usize,
}

fn start(
    session: &Session,
    key: &NativeObjectRef,
    mechanism: MessageAeadMechanism,
    route: MessageRoute,
    init: MessageAeadInit<'_>,
    decrypt: bool,
    capture: bool,
) -> Result<OperationTicket> {
    let selection = match init {
        MessageAeadInit::WithoutParameters => None,
        MessageAeadInit::WithParameters {
            parameters,
            expected_tag,
        } => {
            let (origin, length) = parameters.selection();
            Some((origin, length, expected_tag))
        }
    };
    let initial =
        selection.as_ref().map(
            |(origin, length, expected_tag)| initialization::Parameters {
                origin,
                declared_length: *length,
                expected_tag: *expected_tag,
            },
        );
    initialization::start(
        session,
        MessageKey::Native(key),
        mechanism.kind(),
        decrypt,
        route,
        initial,
        capture,
    )
}

fn submit_message(
    session: &Session,
    ticket: &mut OperationTicket,
    input: MessageAeadInput<'_>,
    single: Option<&[u8]>,
    limits: InputLimits,
    pacing: OperationPacing,
    diagnostics: &mut Option<crate::advanced::progress::FailureDiagnostics>,
    poll_diagnostics: &mut crate::advanced::PollDiagnostics,
) -> Result<OperationProgress> {
    let (origin, declared_length) = input.parameters.selection();
    let message = submission::Message {
        origin: &origin,
        aad: input.aad,
        expected_tag: input.expected_tag,
        declared_length,
        output_capacity: input.output_capacity,
    };
    let request = match single {
        Some(bytes) => submission::Submission::Single { message, bytes },
        None => submission::Submission::Begin(message),
    };
    submission::submit(
        session,
        ticket,
        request,
        limits,
        pacing,
        diagnostics,
        poll_diagnostics,
    )
}

impl AdvancedSession {
    /// Install an empty encryption process. Poll the returned ticket to issue
    /// Init; no native call occurs before the caller receives that ticket.
    pub fn begin_aead_encrypt_message_stream(
        &self,
        key: &NativeObjectRef,
        mechanism: MessageAeadMechanism,
        route: MessageRoute,
        init: MessageAeadInit<'_>,
    ) -> Result<OperationTicket> {
        start(
            &self.session,
            key,
            mechanism,
            route,
            init,
            false,
            self.validation_capture == ValidationCaptureMode::Capture,
        )
    }
    /// Install an empty decryption process. Plaintext remains owned until all
    /// submitted messages and explicit parent Final succeed. Poll first for Init.
    pub fn begin_aead_decrypt_message_stream(
        &self,
        key: &NativeObjectRef,
        mechanism: MessageAeadMechanism,
        route: MessageRoute,
        init: MessageAeadInit<'_>,
    ) -> Result<OperationTicket> {
        start(
            &self.session,
            key,
            mechanism,
            route,
            init,
            true,
            self.validation_capture == ValidationCaptureMode::Capture,
        )
    }
    /// Submit one complete message to a Single-route process. An empty slice is
    /// an actual empty message, distinct from an idle parent with no message.
    pub fn submit_aead_message(
        &self,
        ticket: &mut OperationTicket,
        input: MessageAeadInput<'_>,
        bytes: &[u8],
        limits: InputLimits,
    ) -> Result<OperationProgress> {
        let mut diagnostics = None;
        let mut poll_diagnostics = crate::advanced::PollDiagnostics::default();
        submit_message(
            &self.session,
            ticket,
            input,
            Some(bytes),
            limits,
            self.pacing,
            &mut diagnostics,
            &mut poll_diagnostics,
        )
    }
    /// Start one multipart message, supplying its AAD but no data fragment.
    pub fn begin_aead_message(
        &self,
        ticket: &mut OperationTicket,
        input: MessageAeadInput<'_>,
        limits: InputLimits,
    ) -> Result<OperationProgress> {
        let mut diagnostics = None;
        let mut poll_diagnostics = crate::advanced::PollDiagnostics::default();
        submit_message(
            &self.session,
            ticket,
            input,
            None,
            limits,
            self.pacing,
            &mut diagnostics,
            &mut poll_diagnostics,
        )
    }
    /// Submit exactly one nonfinal fragment. Poll Pending before supplying more
    /// input; no rechunking, prehashing or automatic finalization is performed.
    pub fn update_aead_message(
        &self,
        ticket: &mut OperationTicket,
        bytes: &[u8],
        limits: InputLimits,
    ) -> Result<OperationProgress> {
        let mut diagnostics = None;
        let mut poll_diagnostics = crate::advanced::PollDiagnostics::default();
        submission::submit(
            &self.session,
            ticket,
            submission::Submission::Update(bytes),
            limits,
            self.pacing,
            &mut diagnostics,
            &mut poll_diagnostics,
        )
    }
    /// Submit the last fragment. Decryption may supply its tag here, or reuse
    /// the tag supplied at Begin. Encryption requires expected_tag to be None.
    /// This finishes the message, leaving its parent open for another message.
    pub fn finish_aead_message(
        &self,
        ticket: &mut OperationTicket,
        bytes: &[u8],
        expected_tag: Option<&[u8]>,
        limits: InputLimits,
    ) -> Result<OperationProgress> {
        let mut diagnostics = None;
        let mut poll_diagnostics = crate::advanced::PollDiagnostics::default();
        submission::submit(
            &self.session,
            ticket,
            submission::Submission::Last {
                bytes,
                expected_tag,
            },
            limits,
            self.pacing,
            &mut diagnostics,
            &mut poll_diagnostics,
        )
    }
    /// Explicit parent Final, including for a process with zero messages.
    /// Completed results use the existing GCM/CCM/stream-AEAD result variants.
    pub fn finish_aead_messages(&self, ticket: &mut OperationTicket) -> Result<OperationProgress> {
        let mut poll_diagnostics = crate::advanced::PollDiagnostics::default();
        submission::finish(&self.session, ticket, self.pacing, &mut poll_diagnostics)
    }
    /// Replace output after CipherBufferRequired. Capacity is for the retained
    /// call, in addition to previously produced bytes. This does not invoke C.
    pub fn prepare_aead_message_output(
        &self,
        ticket: &OperationTicket,
        capacity: usize,
    ) -> Result<()> {
        crate::advanced::output_preparation::replace(
            &self.session,
            ticket,
            capacity,
            crate::advanced::output_preparation::Family::Aead,
        )
    }
}

impl Session {
    /// Advance this session's AEAD message process to its next input or output
    /// boundary. Call this after beginning a process and after preparing output
    /// capacity for a retained call. It does not resubmit input or replay Init.
    /// Plaintext remains private until the existing parent completion checks.
    pub fn poll_aead(&self, ticket: &mut OperationTicket) -> Result<OperationProgress> {
        if !std::sync::Arc::ptr_eq(&ticket.owner, &self.inner)
            || ticket.uid != self.uid
            || ticket.id == 0
        {
            return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::ForeignOrConsumedAeadTicket,
            )));
        }
        let mut released = crate::advanced::poll::ReleasedInputs::default();
        let access = self.advanced_access()?;
        {
            let held = access.operations.get(self.uid)?;
            let operation = held.lock().map_err(|_| Error::Poisoned)?;
            if operation.id != ticket.id
                || !matches!(
                    &operation.body,
                    crate::advanced::OperationBody::AeadMessages(_)
                )
            {
                return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                    crate::OperationOwnershipRejection::AeadMessageTicketRequired,
                )));
            }
        }
        crate::advanced::poll::poll_with_access(
            self,
            ticket,
            &access,
            OperationPacing::Eager,
            &mut released,
        )
    }

    /// Install the same empty stream as AdvancedSession, without validation capture.
    /// Poll the returned ticket before submitting its first message.
    pub fn begin_aead_encrypt_message_stream(
        &self,
        key: &NativeObjectRef,
        mechanism: MessageAeadMechanism,
        route: MessageRoute,
        init: MessageAeadInit<'_>,
    ) -> Result<OperationTicket> {
        start(self, key, mechanism, route, init, false, false)
    }
    /// Decryption counterpart; all plaintext remains private until parent Final.
    pub fn begin_aead_decrypt_message_stream(
        &self,
        key: &NativeObjectRef,
        mechanism: MessageAeadMechanism,
        route: MessageRoute,
        init: MessageAeadInit<'_>,
    ) -> Result<OperationTicket> {
        start(self, key, mechanism, route, init, true, false)
    }
    /// See AdvancedSession::submit_aead_message; uses eager native pacing.
    pub fn submit_aead_message(
        &self,
        ticket: &mut OperationTicket,
        input: MessageAeadInput<'_>,
        bytes: &[u8],
        limits: InputLimits,
    ) -> Result<OperationProgress> {
        let mut diagnostics = None;
        let mut poll_diagnostics = crate::advanced::PollDiagnostics::default();
        submit_message(
            self,
            ticket,
            input,
            Some(bytes),
            limits,
            OperationPacing::Eager,
            &mut diagnostics,
            &mut poll_diagnostics,
        )
    }
    /// See AdvancedSession::begin_aead_message; no data fragment is implied.
    pub fn begin_aead_message(
        &self,
        ticket: &mut OperationTicket,
        input: MessageAeadInput<'_>,
        limits: InputLimits,
    ) -> Result<OperationProgress> {
        let mut diagnostics = None;
        let mut poll_diagnostics = crate::advanced::PollDiagnostics::default();
        submit_message(
            self,
            ticket,
            input,
            None,
            limits,
            OperationPacing::Eager,
            &mut diagnostics,
            &mut poll_diagnostics,
        )
    }
    /// See AdvancedSession::update_aead_message.
    pub fn update_aead_message(
        &self,
        ticket: &mut OperationTicket,
        bytes: &[u8],
        limits: InputLimits,
    ) -> Result<OperationProgress> {
        let mut diagnostics = None;
        let mut poll_diagnostics = crate::advanced::PollDiagnostics::default();
        submission::submit(
            self,
            ticket,
            submission::Submission::Update(bytes),
            limits,
            OperationPacing::Eager,
            &mut diagnostics,
            &mut poll_diagnostics,
        )
    }
    /// See AdvancedSession::finish_aead_message; the tag may arrive here.
    pub fn finish_aead_message(
        &self,
        ticket: &mut OperationTicket,
        bytes: &[u8],
        expected_tag: Option<&[u8]>,
        limits: InputLimits,
    ) -> Result<OperationProgress> {
        let mut diagnostics = None;
        let mut poll_diagnostics = crate::advanced::PollDiagnostics::default();
        submission::submit(
            self,
            ticket,
            submission::Submission::Last {
                bytes,
                expected_tag,
            },
            limits,
            OperationPacing::Eager,
            &mut diagnostics,
            &mut poll_diagnostics,
        )
    }
    /// See AdvancedSession::finish_aead_messages; explicitly ends the parent.
    pub fn finish_aead_messages(&self, ticket: &mut OperationTicket) -> Result<OperationProgress> {
        let mut poll_diagnostics = crate::advanced::PollDiagnostics::default();
        submission::finish(self, ticket, OperationPacing::Eager, &mut poll_diagnostics)
    }
    /// Attach replacement capacity without issuing the retained native call.
    pub fn prepare_aead_message_output(
        &self,
        ticket: &OperationTicket,
        capacity: usize,
    ) -> Result<()> {
        crate::advanced::output_preparation::replace(
            self,
            ticket,
            capacity,
            crate::advanced::output_preparation::Family::Aead,
        )
    }
}

impl OperationTicket {
    /// Read established caller-fed AEAD progress without a native call.
    /// Queued input is not consumed input. Output counts do not authenticate
    /// plaintext; no output is delivered before the successful parent result.
    pub fn aead_message_progress(
        &self,
    ) -> Result<(crate::StreamInputStatus, crate::StreamProgress)> {
        if self.id == 0 {
            return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::ConsumedAeadMessageTicket,
            )));
        }
        let state = self.owner.read()?;
        let held = state.operations.get(self.uid)?;
        let operation = held.lock().map_err(|_| Error::Poisoned)?;
        if operation.id != self.id {
            return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::StaleAeadMessageTicket,
            )));
        }
        let crate::advanced::OperationBody::AeadMessages(body) = &operation.body else {
            return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::AeadMessageTicketRequired,
            )));
        };
        let input =
            body.input
                .as_ref()
                .ok_or(Error::Rejected(crate::RejectionReason::AeadMessages(
                    crate::AeadMessagesRejection::CallerFedAeadStreamRequired,
                )))?;
        Ok((input.state.status, input.state.progress))
    }
}
