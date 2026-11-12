// SPDX-License-Identifier: Apache-2.0
//! Public generic message transitions backed by the common operation registry.
//!
//! An ordinary message error is returned without issuing parent Final. Once
//! native memory return is established, the caller may submit another message
//! or explicitly finish the parent. The final results retain each operational
//! refusal separately from a verification verdict and expose none of that row's
//! output bytes. Pending calls and uncertain native ownership retain their
//! operands and require the existing explicit recovery or cleanup paths.
use super::{
    input::{self, Submission},
    start, DataKind,
};
use crate::advanced::{OperationPacing, OperationProgress, OperationTicket, ValidationCaptureMode};
use crate::{
    AdvancedSession, ExtensionRequest, InputLimits, MessageRoute, NativeMessageAction,
    NativeMessageParameters, NativeMessagePart, NativeObjectRef, Result, Session,
};

fn begin(
    session: &Session,
    key: &NativeObjectRef,
    parameters: NativeMessageParameters<'_>,
    route: MessageRoute,
    verify: bool,
    future_parameter_writes: bool,
    capture_validation: bool,
    retirement: &mut crate::advanced::PollDiagnostics,
) -> Result<OperationTicket> {
    let kind = crate::mechanism_extension::message::operation_kind(
        !verify,
        route == MessageRoute::Multipart,
    );
    crate::native_message::with_parameters(session, parameters, kind, |request, keys| {
        start::start_retained(
            session,
            key,
            request,
            keys,
            route,
            verify,
            future_parameter_writes,
            capture_validation,
            false,
            None,
            retirement,
        )
        .map(|(ticket, _, _)| ticket)
    })
}

impl AdvancedSession {
    /// Retrieve once a generic message continuation retained after a synchronous
    /// facade or Init refusal. No native call is made. The ticket permits explicit
    /// capacity selection, polling or cleanup; unusable keys are not re-admitted.
    pub fn take_native_message_ticket(&self) -> Result<OperationTicket> {
        super::batch::take_ticket(&self.session)
    }

    /// Initialize generic message signing without preloading future input.
    /// `future_parameter_writes` reserves exclusive key access when later call
    /// declarations may modify it. It does not itself revoke the key or impose
    /// a cryptographic policy. Actual submitted effects determine revocation.
    /// Single/Multipart remains fixed; parent Final is always explicit.
    pub fn begin_native_sign_message_stream(
        &self,
        key: &NativeObjectRef,
        parameters: NativeMessageParameters<'_>,
        route: MessageRoute,
        future_parameter_writes: bool,
    ) -> Result<OperationTicket> {
        let mut retirement = crate::advanced::PollDiagnostics::default();
        begin(
            &self.session,
            key,
            parameters,
            route,
            false,
            future_parameter_writes,
            self.validation_capture == ValidationCaptureMode::Capture,
            &mut retirement,
        )
    }
    /// Initialize generic message verification without preloading future input.
    /// `future_parameter_writes` reserves exclusive key access when later call
    /// declarations may modify it. It does not itself revoke the key or impose
    /// a cryptographic policy. Actual submitted effects determine revocation.
    /// Single/Multipart remains fixed; parent Final is always explicit.
    pub fn begin_native_verify_message_stream(
        &self,
        key: &NativeObjectRef,
        parameters: NativeMessageParameters<'_>,
        route: MessageRoute,
        future_parameter_writes: bool,
    ) -> Result<OperationTicket> {
        let mut retirement = crate::advanced::PollDiagnostics::default();
        begin(
            &self.session,
            key,
            parameters,
            route,
            true,
            future_parameter_writes,
            self.validation_capture == ValidationCaptureMode::Capture,
            &mut retirement,
        )
    }
    /// Submit one Single-route message with its exact per-call ABI graph.
    /// Action must match the initialized direction. A capacity refusal retains
    /// the same input; supply capacity explicitly and poll, never resubmit data.
    pub fn submit_native_message(
        &self,
        ticket: &mut OperationTicket,
        part: NativeMessagePart<'_>,
        action: NativeMessageAction<'_>,
        limits: InputLimits,
    ) -> Result<OperationProgress> {
        let mut diagnostics = None;
        let mut poll_diagnostics = crate::advanced::PollDiagnostics::default();
        input::submit(
            &self.session,
            ticket,
            Submission::Data {
                kind: DataKind::Single,
                part,
                action: Some(action.into()),
            },
            limits,
            self.pacing,
            &mut diagnostics,
            &mut poll_diagnostics,
        )
    }

    /// Begin one multipart message; an omitted parameter graph remains NULL/0.
    /// This does not finish a prior message or choose a different native route.
    pub fn begin_native_message(
        &self,
        ticket: &mut OperationTicket,
        parameters: Option<ExtensionRequest<'_>>,
        limits: InputLimits,
    ) -> Result<OperationProgress> {
        let mut diagnostics = None;
        let mut poll_diagnostics = crate::advanced::PollDiagnostics::default();
        input::submit(
            &self.session,
            ticket,
            Submission::Begin(parameters),
            limits,
            self.pacing,
            &mut diagnostics,
            &mut poll_diagnostics,
        )
    }

    /// Submit one intermediate Next. Empty data is an explicit native call,
    /// never a message terminator. Input is released after established return.
    pub fn update_native_message(
        &self,
        ticket: &mut OperationTicket,
        part: NativeMessagePart<'_>,
        limits: InputLimits,
    ) -> Result<OperationProgress> {
        let mut diagnostics = None;
        let mut poll_diagnostics = crate::advanced::PollDiagnostics::default();
        input::submit(
            &self.session,
            ticket,
            Submission::Data {
                kind: DataKind::Update,
                part,
                action: None,
            },
            limits,
            self.pacing,
            &mut diagnostics,
            &mut poll_diagnostics,
        )
    }

    /// Submit the terminal Next with its output capacity or expected signature.
    /// Native invalid verification is retained in the eventual message results.
    /// Another message can follow; this does not perform the parent's Final.
    pub fn finish_native_message(
        &self,
        ticket: &mut OperationTicket,
        part: NativeMessagePart<'_>,
        action: NativeMessageAction<'_>,
        limits: InputLimits,
    ) -> Result<OperationProgress> {
        let mut diagnostics = None;
        let mut poll_diagnostics = crate::advanced::PollDiagnostics::default();
        input::submit(
            &self.session,
            ticket,
            Submission::Data {
                kind: DataKind::Last,
                part,
                action: Some(action.into()),
            },
            limits,
            self.pacing,
            &mut diagnostics,
            &mut poll_diagnostics,
        )
    }

    /// Explicitly finish the initialized parent, including an empty process.
    /// Publishes NativeMessages only after native Final and requested observations.
    /// Polling alone never converts a ready input boundary into Final.
    pub fn finish_native_messages(
        &self,
        ticket: &mut OperationTicket,
    ) -> Result<OperationProgress> {
        let mut poll_diagnostics = crate::advanced::PollDiagnostics::default();
        input::finish(&self.session, ticket, self.pacing, &mut poll_diagnostics)
    }
}

impl Session {
    /// Retrieve once a generic message continuation retained after a synchronous
    /// facade or Init refusal. No native call is made. The ticket permits explicit
    /// capacity selection, polling or cleanup; unusable keys are not re-admitted.
    pub fn take_native_message_ticket(&self) -> Result<OperationTicket> {
        super::batch::take_ticket(self)
    }

    /// Advance this session's generic message ticket after explicitly supplying
    /// output capacity, or continue parent Final. A ready stream stays ready.
    /// AdvancedSession callers may use the common `AdvancedSession::poll`.
    pub fn poll_native_messages(&self, ticket: &mut OperationTicket) -> Result<OperationProgress> {
        let mut poll_diagnostics = crate::advanced::PollDiagnostics::default();
        input::poll(self, ticket, OperationPacing::Eager, &mut poll_diagnostics)
    }

    /// Initialize generic message signing without preloading future input.
    /// `future_parameter_writes` reserves exclusive key access when later call
    /// declarations may modify it. It does not itself revoke the key or impose
    /// a cryptographic policy. Actual submitted effects determine revocation.
    /// Single/Multipart remains fixed; parent Final is always explicit.
    pub fn begin_native_sign_message_stream(
        &self,
        key: &NativeObjectRef,
        parameters: NativeMessageParameters<'_>,
        route: MessageRoute,
        future_parameter_writes: bool,
    ) -> Result<OperationTicket> {
        let mut retirement = crate::advanced::PollDiagnostics::default();
        begin(
            self,
            key,
            parameters,
            route,
            false,
            future_parameter_writes,
            false,
            &mut retirement,
        )
    }
    /// Initialize generic message verification without preloading future input.
    /// `future_parameter_writes` reserves exclusive key access when later call
    /// declarations may modify it. It does not itself revoke the key or impose
    /// a cryptographic policy. Actual submitted effects determine revocation.
    /// Single/Multipart remains fixed; parent Final is always explicit.
    pub fn begin_native_verify_message_stream(
        &self,
        key: &NativeObjectRef,
        parameters: NativeMessageParameters<'_>,
        route: MessageRoute,
        future_parameter_writes: bool,
    ) -> Result<OperationTicket> {
        let mut retirement = crate::advanced::PollDiagnostics::default();
        begin(
            self,
            key,
            parameters,
            route,
            true,
            future_parameter_writes,
            false,
            &mut retirement,
        )
    }
    /// Submit one Single-route message with its exact per-call ABI graph.
    /// Action must match the initialized direction. A capacity refusal retains
    /// the same input; supply capacity explicitly and poll, never resubmit data.
    pub fn submit_native_message(
        &self,
        ticket: &mut OperationTicket,
        part: NativeMessagePart<'_>,
        action: NativeMessageAction<'_>,
        limits: InputLimits,
    ) -> Result<OperationProgress> {
        let mut diagnostics = None;
        let mut poll_diagnostics = crate::advanced::PollDiagnostics::default();
        input::submit(
            self,
            ticket,
            Submission::Data {
                kind: DataKind::Single,
                part,
                action: Some(action.into()),
            },
            limits,
            OperationPacing::Eager,
            &mut diagnostics,
            &mut poll_diagnostics,
        )
    }

    /// Begin one multipart message; an omitted parameter graph remains NULL/0.
    /// This does not finish a prior message or choose a different native route.
    pub fn begin_native_message(
        &self,
        ticket: &mut OperationTicket,
        parameters: Option<ExtensionRequest<'_>>,
        limits: InputLimits,
    ) -> Result<OperationProgress> {
        let mut diagnostics = None;
        let mut poll_diagnostics = crate::advanced::PollDiagnostics::default();
        input::submit(
            self,
            ticket,
            Submission::Begin(parameters),
            limits,
            OperationPacing::Eager,
            &mut diagnostics,
            &mut poll_diagnostics,
        )
    }

    /// Submit one intermediate Next. Empty data is an explicit native call,
    /// never a message terminator. Input is released after established return.
    pub fn update_native_message(
        &self,
        ticket: &mut OperationTicket,
        part: NativeMessagePart<'_>,
        limits: InputLimits,
    ) -> Result<OperationProgress> {
        let mut diagnostics = None;
        let mut poll_diagnostics = crate::advanced::PollDiagnostics::default();
        input::submit(
            self,
            ticket,
            Submission::Data {
                kind: DataKind::Update,
                part,
                action: None,
            },
            limits,
            OperationPacing::Eager,
            &mut diagnostics,
            &mut poll_diagnostics,
        )
    }

    /// Submit the terminal Next with its output capacity or expected signature.
    /// Native invalid verification is retained in the eventual message results.
    /// Another message can follow; this does not perform the parent's Final.
    pub fn finish_native_message(
        &self,
        ticket: &mut OperationTicket,
        part: NativeMessagePart<'_>,
        action: NativeMessageAction<'_>,
        limits: InputLimits,
    ) -> Result<OperationProgress> {
        let mut diagnostics = None;
        let mut poll_diagnostics = crate::advanced::PollDiagnostics::default();
        input::submit(
            self,
            ticket,
            Submission::Data {
                kind: DataKind::Last,
                part,
                action: Some(action.into()),
            },
            limits,
            OperationPacing::Eager,
            &mut diagnostics,
            &mut poll_diagnostics,
        )
    }

    /// Explicitly finish the initialized parent, including an empty process.
    /// Publishes NativeMessages only after native Final and requested observations.
    /// Polling alone never converts a ready input boundary into Final.
    pub fn finish_native_messages(
        &self,
        ticket: &mut OperationTicket,
    ) -> Result<OperationProgress> {
        let mut poll_diagnostics = crate::advanced::PollDiagnostics::default();
        input::finish(self, ticket, OperationPacing::Eager, &mut poll_diagnostics)
    }
}
