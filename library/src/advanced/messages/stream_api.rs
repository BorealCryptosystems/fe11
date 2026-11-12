// SPDX-License-Identifier: Apache-2.0
//! Explicit message input on the same native process and operation ticket.
//!
//! A returned operational refusal ends its message without issuing parent Final.
//! The caller can submit another message or explicitly finish the process. Refused
//! signing rows expose their error instead of bytes. Verification with such rows
//! returns MessageVerificationDetails, separate from the existing binary verdict.
//! Pending or uncertain native ownership still requires explicit recovery/cleanup.
use super::{
    input::{self, Submission},
    KeyLease, MessageRoute, ReleasedInputs,
};
use crate::advanced::{AdvancedSession, OperationPacing, OperationProgress, OperationTicket};
use crate::{Error, InputLimits, Result, Session, SymmetricKey};

impl AdvancedSession {
    /// Initialize native HMAC message signing without preloading messages.
    /// The route is fixed for this process. Submit a single message, or Begin,
    /// Update and Last for each multipart message, then explicitly finish the
    /// parent. Polling an idle stream never submits Final.
    pub fn begin_mac_sign_message_stream(
        &self,
        key: &SymmetricKey,
        route: MessageRoute,
    ) -> Result<OperationTicket> {
        self.begin_mac_message_stream(key, route, false)
    }

    /// Initialize native HMAC message verification. Each terminal submission
    /// supplies its expected signature. Any invalid native verdict remains in
    /// the final result even if subsequent messages verify successfully.
    pub fn begin_mac_verify_message_stream(
        &self,
        key: &SymmetricKey,
        route: MessageRoute,
    ) -> Result<OperationTicket> {
        self.begin_mac_message_stream(key, route, true)
    }

    fn begin_mac_message_stream(
        &self,
        key: &SymmetricKey,
        route: MessageRoute,
        verify: bool,
    ) -> Result<OperationTicket> {
        // Declared before preparation/session guards so returned native buffers
        // are erased and their budget credit released only after possession.
        let mut retired_owner = None;
        let mut released = ReleasedInputs::default();
        let size = key.algorithm.mac_length().ok_or(Error::Rejected(
            crate::RejectionReason::SignatureMessages(
                crate::SignatureMessagesRejection::MessageHmacKeyRequired,
            ),
        ))?;
        let expected: Option<&[&[u8]]> = if verify { Some(&[]) } else { None };
        let (mut prepared, cancel, validation, access, mut readers) = self.prepare_signatures(
            &key.managed,
            key.algorithm.mechanism(),
            size,
            &[],
            expected,
            route,
            None,
        )?;
        let lease = KeyLease::new(&self.session, key, &mut readers)?;
        prepared.input = crate::advanced::input::InputState::open();
        let result = self.install_signatures(
            &access.lease_admission()?,
            prepared.bind(lease),
            cancel,
            validation,
            &mut released,
            &mut retired_owner,
        );
        drop(access);
        result
    }

    /// Initialize combined native RSA-PSS message signing under the caller's
    /// exact hash, MGF and salt selection. No software prehash or fallback.
    pub fn begin_pss_sign_message_stream(
        &self,
        key: &crate::SigningKey,
        parameters: crate::RsaPssParameters,
        route: MessageRoute,
    ) -> Result<OperationTicket> {
        self.begin_pss_message_stream(
            key.management_reference(),
            key.message_pss_bits(parameters)?,
            parameters,
            route,
            false,
        )
    }

    /// Initialize combined native RSA-PSS message verification. The module
    /// decides signature validity; Fe11 preserves an invalid cumulative verdict.
    pub fn begin_pss_verify_message_stream(
        &self,
        key: &crate::VerificationKey,
        parameters: crate::RsaPssParameters,
        route: MessageRoute,
    ) -> Result<OperationTicket> {
        self.begin_pss_message_stream(
            key.management_reference(),
            key.message_pss_bits(parameters)?,
            parameters,
            route,
            true,
        )
    }

    fn begin_pss_message_stream(
        &self,
        key: &crate::ManagedObjectRef,
        bits: usize,
        parameters: crate::RsaPssParameters,
        route: MessageRoute,
        verify: bool,
    ) -> Result<OperationTicket> {
        // Declared before preparation/session guards so returned native buffers
        // are erased and their budget credit released only after possession.
        let mut retired_owner = None;
        let mut released = ReleasedInputs::default();
        let expected: Option<&[&[u8]]> = if verify { Some(&[]) } else { None };
        let (mut prepared, cancel, validation, access, mut readers) = self.prepare_signatures(
            key,
            parameters.mechanism(crate::HashExecution::Pkcs11Combined)?,
            bits / 8 + usize::from(bits % 8 != 0),
            &[],
            expected,
            route,
            Some(parameters.checked()?),
        )?;
        let lease = KeyLease::for_rsa_messages(&self.session, key, bits, !verify, &mut readers)?;
        prepared.input = crate::advanced::input::InputState::open();
        let result = self.install_signatures(
            &access.lease_admission()?,
            prepared.bind(lease),
            cancel,
            validation,
            &mut released,
            &mut retired_owner,
        );
        drop(access);
        result
    }

    /// Submit one complete message to a Single-route process. `expected` is
    /// required for Verify and absent for Sign. Limits apply to this submission,
    /// including expected signature bytes, not to previously consumed input.
    /// A capacity refusal retains this submission: resize and poll, do not resend.
    pub fn submit_signature_message(
        &self,
        ticket: &mut OperationTicket,
        bytes: &[u8],
        expected: Option<&[u8]>,
        limits: InputLimits,
    ) -> Result<OperationProgress> {
        let mut diagnostics = None;
        let mut poll_diagnostics = crate::advanced::PollDiagnostics::default();
        input::submit(
            &self.session,
            ticket,
            Submission::Single { bytes, expected },
            limits,
            self.pacing,
            &mut diagnostics,
            &mut poll_diagnostics,
        )
    }

    /// Begin one multipart message. The parent must be ready for a new message;
    /// this call accepts no data and does not infer an empty terminal fragment.
    pub fn begin_signature_message(
        &self,
        ticket: &mut OperationTicket,
    ) -> Result<OperationProgress> {
        let mut diagnostics = None;
        let mut poll_diagnostics = crate::advanced::PollDiagnostics::default();
        input::submit(
            &self.session,
            ticket,
            Submission::Begin,
            session_limits(&self.session),
            self.pacing,
            &mut diagnostics,
            &mut poll_diagnostics,
        )
    }

    /// Submit one intermediate fragment. Native Pending or uncertain completion
    /// keeps its owned bytes; poll that ticket before supplying another fragment.
    pub fn update_signature_message(
        &self,
        ticket: &mut OperationTicket,
        bytes: &[u8],
        limits: InputLimits,
    ) -> Result<OperationProgress> {
        let mut diagnostics = None;
        let mut poll_diagnostics = crate::advanced::PollDiagnostics::default();
        input::submit(
            &self.session,
            ticket,
            Submission::Update(bytes),
            limits,
            self.pacing,
            &mut diagnostics,
            &mut poll_diagnostics,
        )
    }

    /// Submit the final fragment of the current multipart message, possibly
    /// empty. `expected` is required only for Verify. This closes the message,
    /// leaving the parent open for another Begin or explicit parent Final.
    pub fn finish_signature_message(
        &self,
        ticket: &mut OperationTicket,
        bytes: &[u8],
        expected: Option<&[u8]>,
        limits: InputLimits,
    ) -> Result<OperationProgress> {
        let mut diagnostics = None;
        let mut poll_diagnostics = crate::advanced::PollDiagnostics::default();
        input::submit(
            &self.session,
            ticket,
            Submission::Last { bytes, expected },
            limits,
            self.pacing,
            &mut diagnostics,
            &mut poll_diagnostics,
        )
    }

    /// Finish an initialized parent after zero or more completed messages.
    /// Refuses while a multipart message or observation is unfinished. Results
    /// and the cumulative Verify verdict are published only after parent Final.
    pub fn finish_signature_messages(
        &self,
        ticket: &mut OperationTicket,
    ) -> Result<OperationProgress> {
        let mut poll_diagnostics = crate::advanced::PollDiagnostics::default();
        input::finish(&self.session, ticket, self.pacing, &mut poll_diagnostics)
    }
}

fn session_limits(session: &Session) -> InputLimits {
    InputLimits {
        maximum_parts: session.inner.crypto_options.limits.maximum_parts,
        maximum_total_bytes: session.inner.crypto_options.limits.maximum_total_bytes,
    }
}

impl Session {
    /// Continue a Single-route message signature ticket, including a restored
    /// ticket. See `AdvancedSession::submit_signature_message` for ownership,
    /// expected-signature and retry rules. Uses eager local scheduling.
    pub fn submit_signature_message(
        &self,
        ticket: &mut OperationTicket,
        bytes: &[u8],
        expected: Option<&[u8]>,
        limits: InputLimits,
    ) -> Result<OperationProgress> {
        let mut diagnostics = None;
        let mut poll_diagnostics = crate::advanced::PollDiagnostics::default();
        input::submit(
            self,
            ticket,
            Submission::Single { bytes, expected },
            limits,
            OperationPacing::Eager,
            &mut diagnostics,
            &mut poll_diagnostics,
        )
    }
    /// Begin the next multipart message; see `AdvancedSession::begin_signature_message`.
    pub fn begin_signature_message(
        &self,
        ticket: &mut OperationTicket,
    ) -> Result<OperationProgress> {
        let mut diagnostics = None;
        let mut poll_diagnostics = crate::advanced::PollDiagnostics::default();
        input::submit(
            self,
            ticket,
            Submission::Begin,
            session_limits(self),
            OperationPacing::Eager,
            &mut diagnostics,
            &mut poll_diagnostics,
        )
    }
    /// Submit an intermediate fragment; see `AdvancedSession::update_signature_message`.
    pub fn update_signature_message(
        &self,
        ticket: &mut OperationTicket,
        bytes: &[u8],
        limits: InputLimits,
    ) -> Result<OperationProgress> {
        let mut diagnostics = None;
        let mut poll_diagnostics = crate::advanced::PollDiagnostics::default();
        input::submit(
            self,
            ticket,
            Submission::Update(bytes),
            limits,
            OperationPacing::Eager,
            &mut diagnostics,
            &mut poll_diagnostics,
        )
    }
    /// Submit the current message's last fragment; see `AdvancedSession::finish_signature_message`.
    pub fn finish_signature_message(
        &self,
        ticket: &mut OperationTicket,
        bytes: &[u8],
        expected: Option<&[u8]>,
        limits: InputLimits,
    ) -> Result<OperationProgress> {
        let mut diagnostics = None;
        let mut poll_diagnostics = crate::advanced::PollDiagnostics::default();
        input::submit(
            self,
            ticket,
            Submission::Last { bytes, expected },
            limits,
            OperationPacing::Eager,
            &mut diagnostics,
            &mut poll_diagnostics,
        )
    }
    /// Explicit parent Final; see `AdvancedSession::finish_signature_messages`.
    pub fn finish_signature_messages(
        &self,
        ticket: &mut OperationTicket,
    ) -> Result<OperationProgress> {
        let mut poll_diagnostics = crate::advanced::PollDiagnostics::default();
        input::finish(self, ticket, OperationPacing::Eager, &mut poll_diagnostics)
    }
}
