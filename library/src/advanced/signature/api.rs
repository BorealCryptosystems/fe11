// SPDX-License-Identifier: Apache-2.0
//! Caller input admission outside guards, followed by one ticket transition.
use super::{preparation as signature_preparation, Kind, SignatureOutputPlan, Stage};
use crate::advanced::{
    poll, progress, Operation, OperationBody, OperationPacing, OperationProgress, OperationTicket,
};
use crate::native::derivation::{InputBytes, InputBytesStorage};
use crate::symmetric::memory::ControlledReservation;
use crate::{
    AdvancedSession, Error, ExtensionOperation, ExtensionRequest, InputLimits, MessageRoute,
    NativeObjectRef, NativeSignatureParameters, Result, Session,
};
use std::sync::Arc;

#[derive(Clone, Copy)]
pub(super) enum Change<'a> {
    Update(&'a [u8]),
    Finish(Option<&'a [u8]>),
    Single {
        data: &'a [u8],
        signature: Option<&'a [u8]>,
    },
}

/// Admit both operands together: verification must not wait for the signature
/// while holding the only credits that could have funded it.
struct PreparedInput {
    data: Option<InputBytes>,
    signature: Option<InputBytes>,
}

pub(super) fn park_synchronous(
    session: &Session,
    ticket: &mut OperationTicket,
    held: &Arc<crate::advanced::ledger::OperationCell>,
) -> Result<()> {
    if !Arc::ptr_eq(&ticket.owner, &session.inner) || ticket.uid != session.uid || ticket.id == 0 {
        return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
            crate::OperationOwnershipRejection::ForeignOrConsumedSignatureTicket,
        )));
    }
    let mut operation = held.lock().map_err(|_| Error::Poisoned)?;
    if operation.id != ticket.id {
        return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
            crate::OperationOwnershipRejection::StaleSignatureTicket,
        )));
    }
    let OperationBody::Signature(body) = &mut operation.body else {
        return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
            crate::OperationOwnershipRejection::SignatureTicketRequired,
        )));
    };
    if body.observer != super::Observer::Ticket {
        return Err(Error::Rejected(
            crate::RejectionReason::SignatureContinuation(
                crate::SignatureContinuationRejection::SignatureContinuationTicketUnavailable,
            ),
        ));
    }
    body.observer = super::Observer::Session;
    ticket.id = 0;
    Ok(())
}

impl Session {
    /// Advance retained signature work. This never closes an open input stream;
    /// after supplying replacement capacity it retries only the retained call.
    pub fn poll_signature(&self, ticket: &mut OperationTicket) -> Result<OperationProgress> {
        let mut diagnostics = poll::PollDiagnostics::default();
        poll::poll_operation_with_diagnostics(
            self,
            ticket,
            crate::session::CleanupAdmission::Ordinary,
            OperationPacing::Eager,
            &mut diagnostics,
        )
    }

    /// Initialize a typed native MAC stream using C_SignInit. MAC parameters
    /// retain their exact standard representation; no software hashing is added.
    pub fn begin_native_mac_stream(
        &self,
        key: &NativeObjectRef,
        parameters: crate::NativeMacParameters<'_>,
        output: SignatureOutputPlan,
        maximum_output: usize,
    ) -> Result<OperationTicket> {
        let mut retirement = crate::advanced::PollDiagnostics::default();
        crate::native_mac::with_parameters(
            self,
            parameters,
            ExtensionOperation::SignMultipart,
            |request| {
                signature_preparation::start(
                    self,
                    key,
                    request.into(),
                    Kind::Sign,
                    MessageRoute::Multipart,
                    None,
                    None,
                    initial_limits(self),
                    output,
                    maximum_output,
                    false,
                    &mut 1,
                    &mut retirement,
                )
            },
        )
    }

    /// Initialize a typed native MAC verification stream with C_VerifyInit.
    /// Submit the expected MAC explicitly with finish_signature_stream.
    pub fn begin_native_mac_verify_stream(
        &self,
        key: &NativeObjectRef,
        parameters: crate::NativeMacParameters<'_>,
    ) -> Result<OperationTicket> {
        let mut retirement = crate::advanced::PollDiagnostics::default();
        crate::native_mac::with_parameters(
            self,
            parameters,
            ExtensionOperation::VerifyMultipart,
            |request| {
                signature_preparation::start(
                    self,
                    key,
                    request.into(),
                    Kind::Verify,
                    MessageRoute::Multipart,
                    None,
                    None,
                    initial_limits(self),
                    SignatureOutputPlan::Buffer { capacity: 0 },
                    0,
                    false,
                    &mut 1,
                    &mut retirement,
                )
            },
        )
    }
    /// Initialize C_VerifySignatureInit with the expected MAC. The
    /// standard parameters and expected bytes are owned before dispatch.
    /// Feed exact fragments with signature_update, then explicitly call
    /// finish_signature_stream(ticket, None). The signature stays retained
    /// through native uncertainty; no C_VerifyInit fallback is attempted.
    /// Context authentication remains possible after this Init boundary.
    pub fn begin_native_mac_verify_signature_stream(
        &self,
        key: &NativeObjectRef,
        parameters: crate::NativeMacParameters<'_>,
        signature: &[u8],
    ) -> Result<OperationTicket> {
        let mut retirement = crate::advanced::PollDiagnostics::default();
        crate::native_mac::with_parameters(
            self,
            parameters,
            ExtensionOperation::VerifySignatureMultipart,
            |request| {
                signature_preparation::start(
                    self,
                    key,
                    request.into(),
                    Kind::VerifySignature,
                    MessageRoute::Multipart,
                    None,
                    Some(signature),
                    initial_limits(self),
                    SignatureOutputPlan::Buffer { capacity: 0 },
                    0,
                    false,
                    &mut 1,
                    &mut retirement,
                )
            },
        )
    }

    /// Retrieve once the continuation left by a synchronous signature error.
    /// The native error is unchanged. This transfers only its ticket; it does
    /// not retry, cancel, or issue another Init. Explicit stream ceilings remain
    /// in force. Complete-input facades retain the ABI and memory budget limits.
    pub fn take_signature_ticket(&self) -> Result<OperationTicket> {
        let access = self.advanced_access()?;
        let held = access.operations.get(self.uid)?;
        let mut operation = held.lock().map_err(|_| Error::Poisoned)?;
        let OperationBody::Signature(body) = &mut operation.body else {
            return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::SignatureTicketRequired,
            )));
        };
        // Retrieval also permits explicit cancellation of an owner whose
        // key is no longer usable. Crypto transitions still check that key.
        if body.observer != super::Observer::Session {
            return Err(Error::Rejected(
                crate::RejectionReason::SignatureContinuation(
                    crate::SignatureContinuationRejection::SignatureContinuationTicketUnavailable,
                ),
            ));
        }
        body.observer = super::Observer::Ticket;
        Ok(OperationTicket {
            owner: self.inner.clone(),
            uid: self.uid,
            id: operation.id,
            validation_report: None,
            state_provenance: None,
        })
    }

    /// Start classic C_SignInit without copying future message input. Returns
    /// after Init so explicit context authentication may precede the first Update.
    pub fn begin_native_sign_stream(
        &self,
        key: &NativeObjectRef,
        parameters: NativeSignatureParameters<'_>,
        output: SignatureOutputPlan,
        maximum_output: usize,
    ) -> Result<OperationTicket> {
        let mut retirement = crate::advanced::PollDiagnostics::default();
        crate::native_signature::with_parameters(
            self,
            parameters,
            ExtensionOperation::SignMultipart,
            |request| {
                signature_preparation::start(
                    self,
                    key,
                    request.into(),
                    Kind::Sign,
                    MessageRoute::Multipart,
                    None,
                    None,
                    initial_limits(self),
                    output,
                    maximum_output,
                    false,
                    &mut 1,
                    &mut retirement,
                )
            },
        )
    }
    /// Start C_VerifyInit; supply the signature only when explicitly closing input.
    pub fn begin_native_verify_stream(
        &self,
        key: &NativeObjectRef,
        parameters: NativeSignatureParameters<'_>,
    ) -> Result<OperationTicket> {
        let mut retirement = crate::advanced::PollDiagnostics::default();
        crate::native_signature::with_parameters(
            self,
            parameters,
            ExtensionOperation::VerifyMultipart,
            |request| {
                signature_preparation::start(
                    self,
                    key,
                    request.into(),
                    Kind::Verify,
                    MessageRoute::Multipart,
                    None,
                    None,
                    initial_limits(self),
                    SignatureOutputPlan::Buffer { capacity: 0 },
                    0,
                    false,
                    &mut 1,
                    &mut retirement,
                )
            },
        )
    }
    /// Initialize C_VerifySignatureInit with the expected signature. The
    /// standard parameters and expected bytes are owned before dispatch.
    /// Feed exact fragments with signature_update, then explicitly call
    /// finish_signature_stream(ticket, None). The signature stays retained
    /// through native uncertainty; no C_VerifyInit fallback is attempted.
    /// Context authentication remains possible after this Init boundary.
    pub fn begin_native_verify_signature_stream(
        &self,
        key: &NativeObjectRef,
        parameters: NativeSignatureParameters<'_>,
        signature: &[u8],
    ) -> Result<OperationTicket> {
        let mut retirement = crate::advanced::PollDiagnostics::default();
        crate::native_signature::with_parameters(
            self,
            parameters,
            ExtensionOperation::VerifySignatureMultipart,
            |request| {
                signature_preparation::start(
                    self,
                    key,
                    request.into(),
                    Kind::VerifySignature,
                    MessageRoute::Multipart,
                    None,
                    Some(signature),
                    initial_limits(self),
                    SignatureOutputPlan::Buffer { capacity: 0 },
                    0,
                    false,
                    &mut 1,
                    &mut retirement,
                )
            },
        )
    }
    /// Start an asserted classic signature stream. VerifySignature requires its
    /// signature at Init; ordinary Verify accepts it at finish. No route fallback.
    pub fn begin_extension_signature_stream(
        &self,
        key: &NativeObjectRef,
        request: ExtensionRequest<'_>,
        signature: Option<&[u8]>,
        limits: InputLimits,
        output: SignatureOutputPlan,
        maximum_output: usize,
    ) -> Result<OperationTicket> {
        let mut retirement = crate::advanced::PollDiagnostics::default();
        let kind = match request.contract.operation() {
            ExtensionOperation::SignMultipart => Kind::Sign,
            ExtensionOperation::VerifyMultipart => Kind::Verify,
            ExtensionOperation::VerifySignatureMultipart => Kind::VerifySignature,
            _ => {
                return Err(Error::Rejected(
                    crate::RejectionReason::SignatureContinuation(
                        crate::SignatureContinuationRejection::SignatureStreamExtensionRoute,
                    ),
                ))
            }
        };
        signature_preparation::start(
            self,
            key,
            request.into(),
            kind,
            MessageRoute::Multipart,
            None,
            signature,
            limits,
            output,
            maximum_output,
            false,
            &mut 1,
            &mut retirement,
        )
    }
    /// Submit one exact Update, including an empty fragment. Consumed bytes are
    /// released after its established native return; polling cannot close input.
    pub fn signature_update(
        &self,
        ticket: &mut OperationTicket,
        bytes: &[u8],
        limits: InputLimits,
    ) -> Result<OperationProgress> {
        let mut diagnostics = None;
        let mut poll_diagnostics = crate::advanced::PollDiagnostics::default();
        change(
            self,
            ticket,
            Change::Update(bytes),
            limits,
            OperationPacing::Eager,
            &mut diagnostics,
            &mut poll_diagnostics,
        )
    }
    /// Close input and invoke Final. Supply a signature for ordinary Verify if
    /// it was not supplied at begin; Sign and VerifySignature use None.
    pub fn finish_signature_stream(
        &self,
        ticket: &mut OperationTicket,
        signature: Option<&[u8]>,
    ) -> Result<OperationProgress> {
        let mut diagnostics = None;
        let mut poll_diagnostics = crate::advanced::PollDiagnostics::default();
        change(
            self,
            ticket,
            Change::Finish(signature),
            initial_limits(self),
            OperationPacing::Eager,
            &mut diagnostics,
            &mut poll_diagnostics,
        )
    }
    /// Replace storage after a native size query or BUFFER_TOO_SMALL, including
    /// a retained message-signature call. This makes no native call; poll
    /// explicitly to retry that invocation without resubmitting its input.
    pub fn provide_signature_output_capacity(
        &self,
        ticket: &OperationTicket,
        capacity: usize,
    ) -> Result<()> {
        crate::advanced::output_preparation::replace(
            self,
            ticket,
            capacity,
            crate::advanced::output_preparation::Family::Signature,
        )
    }
}

impl OperationTicket {
    /// Observe established progress and explicit input closure without a native call.
    pub fn signature_progress(&self) -> Result<(crate::StreamInputStatus, crate::StreamProgress)> {
        if self.id == 0 {
            return Err(Error::Rejected(
                crate::RejectionReason::SignatureContinuation(
                    crate::SignatureContinuationRejection::ConsumedSignatureTicket,
                ),
            ));
        }
        let state = self.owner.read()?;
        let held = state.operations.get(self.uid)?;
        let operation = held.lock().map_err(|_| Error::Poisoned)?;
        if operation.id != self.id {
            return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::StaleSignatureTicket,
            )));
        }
        let OperationBody::Signature(body) = &operation.body else {
            return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::SignatureTicketRequired,
            )));
        };
        Ok((body.input.status, body.input.progress))
    }
}

impl AdvancedSession {
    /// Initialize a typed MAC and stop at Init, before any caller input.
    pub fn begin_native_mac_stream(
        &self,
        key: &NativeObjectRef,
        parameters: crate::NativeMacParameters<'_>,
        output: SignatureOutputPlan,
        maximum_output: usize,
    ) -> Result<OperationTicket> {
        let mut retirement = crate::advanced::PollDiagnostics::default();
        crate::native_mac::with_parameters(
            &self.session,
            parameters,
            ExtensionOperation::SignMultipart,
            |request| {
                signature_preparation::start(
                    &self.session,
                    key,
                    request.into(),
                    Kind::Sign,
                    MessageRoute::Multipart,
                    None,
                    None,
                    initial_limits(&self.session),
                    output,
                    maximum_output,
                    self.validation_capture == crate::advanced::ValidationCaptureMode::Capture,
                    &mut 1,
                    &mut retirement,
                )
            },
        )
    }
    /// Initialize typed native MAC verification; input closure stays explicit.
    pub fn begin_native_mac_verify_stream(
        &self,
        key: &NativeObjectRef,
        parameters: crate::NativeMacParameters<'_>,
    ) -> Result<OperationTicket> {
        let mut retirement = crate::advanced::PollDiagnostics::default();
        crate::native_mac::with_parameters(
            &self.session,
            parameters,
            ExtensionOperation::VerifyMultipart,
            |request| {
                signature_preparation::start(
                    &self.session,
                    key,
                    request.into(),
                    Kind::Verify,
                    MessageRoute::Multipart,
                    None,
                    None,
                    initial_limits(&self.session),
                    SignatureOutputPlan::Buffer { capacity: 0 },
                    0,
                    self.validation_capture == crate::advanced::ValidationCaptureMode::Capture,
                    &mut 1,
                    &mut retirement,
                )
            },
        )
    }
    /// Same signature-at-Init stream as Session, with this facade
    /// retaining its validation-capture setting and later call pacing.
    /// Finish with finish_signature_stream(ticket, None).
    pub fn begin_native_mac_verify_signature_stream(
        &self,
        key: &NativeObjectRef,
        parameters: crate::NativeMacParameters<'_>,
        signature: &[u8],
    ) -> Result<OperationTicket> {
        let mut retirement = crate::advanced::PollDiagnostics::default();
        crate::native_mac::with_parameters(
            &self.session,
            parameters,
            ExtensionOperation::VerifySignatureMultipart,
            |request| {
                signature_preparation::start(
                    &self.session,
                    key,
                    request.into(),
                    Kind::VerifySignature,
                    MessageRoute::Multipart,
                    None,
                    Some(signature),
                    initial_limits(&self.session),
                    SignatureOutputPlan::Buffer { capacity: 0 },
                    0,
                    self.validation_capture == crate::advanced::ValidationCaptureMode::Capture,
                    &mut 1,
                    &mut retirement,
                )
            },
        )
    }
    /// Advance the common owner using this facade's configured pacing.
    pub fn poll_signature(&self, ticket: &mut OperationTicket) -> Result<OperationProgress> {
        let mut diagnostics = poll::PollDiagnostics::default();
        poll::poll_operation_with_diagnostics(
            &self.session,
            ticket,
            crate::session::CleanupAdmission::Ordinary,
            self.pacing,
            &mut diagnostics,
        )
    }
    /// Retrieve the single ticket left by a synchronous signature error.
    pub fn take_signature_ticket(&self) -> Result<OperationTicket> {
        self.session.take_signature_ticket()
    }

    /// Same synchronous retained owner as Session; does not activate native asynchronous mode.
    pub fn begin_native_sign_stream(
        &self,
        key: &NativeObjectRef,
        parameters: NativeSignatureParameters<'_>,
        output: SignatureOutputPlan,
        maximum_output: usize,
    ) -> Result<OperationTicket> {
        let mut retirement = crate::advanced::PollDiagnostics::default();
        crate::native_signature::with_parameters(
            &self.session,
            parameters,
            ExtensionOperation::SignMultipart,
            |request| {
                signature_preparation::start(
                    &self.session,
                    key,
                    request.into(),
                    Kind::Sign,
                    MessageRoute::Multipart,
                    None,
                    None,
                    initial_limits(&self.session),
                    output,
                    maximum_output,
                    self.validation_capture == crate::advanced::ValidationCaptureMode::Capture,
                    &mut 1,
                    &mut retirement,
                )
            },
        )
    }
    /// Same explicit VerifyInit boundary as Session.
    pub fn begin_native_verify_stream(
        &self,
        key: &NativeObjectRef,
        parameters: NativeSignatureParameters<'_>,
    ) -> Result<OperationTicket> {
        let mut retirement = crate::advanced::PollDiagnostics::default();
        crate::native_signature::with_parameters(
            &self.session,
            parameters,
            ExtensionOperation::VerifyMultipart,
            |request| {
                signature_preparation::start(
                    &self.session,
                    key,
                    request.into(),
                    Kind::Verify,
                    MessageRoute::Multipart,
                    None,
                    None,
                    initial_limits(&self.session),
                    SignatureOutputPlan::Buffer { capacity: 0 },
                    0,
                    self.validation_capture == crate::advanced::ValidationCaptureMode::Capture,
                    &mut 1,
                    &mut retirement,
                )
            },
        )
    }
    /// Same signature-at-Init stream as Session, with this facade
    /// retaining its validation-capture setting and later call pacing.
    /// Finish with finish_signature_stream(ticket, None).
    pub fn begin_native_verify_signature_stream(
        &self,
        key: &NativeObjectRef,
        parameters: NativeSignatureParameters<'_>,
        signature: &[u8],
    ) -> Result<OperationTicket> {
        let mut retirement = crate::advanced::PollDiagnostics::default();
        crate::native_signature::with_parameters(
            &self.session,
            parameters,
            ExtensionOperation::VerifySignatureMultipart,
            |request| {
                signature_preparation::start(
                    &self.session,
                    key,
                    request.into(),
                    Kind::VerifySignature,
                    MessageRoute::Multipart,
                    None,
                    Some(signature),
                    initial_limits(&self.session),
                    SignatureOutputPlan::Buffer { capacity: 0 },
                    0,
                    self.validation_capture == crate::advanced::ValidationCaptureMode::Capture,
                    &mut 1,
                    &mut retirement,
                )
            },
        )
    }
    /// Same asserted multipart ABI and owned graph as Session.
    pub fn begin_extension_signature_stream(
        &self,
        key: &NativeObjectRef,
        request: ExtensionRequest<'_>,
        signature: Option<&[u8]>,
        limits: InputLimits,
        output: SignatureOutputPlan,
        maximum_output: usize,
    ) -> Result<OperationTicket> {
        let mut retirement = crate::advanced::PollDiagnostics::default();
        let kind = match request.contract.operation() {
            ExtensionOperation::SignMultipart => Kind::Sign,
            ExtensionOperation::VerifyMultipart => Kind::Verify,
            ExtensionOperation::VerifySignatureMultipart => Kind::VerifySignature,
            _ => {
                return Err(Error::Rejected(
                    crate::RejectionReason::SignatureContinuation(
                        crate::SignatureContinuationRejection::SignatureStreamExtensionRoute,
                    ),
                ))
            }
        };
        signature_preparation::start(
            &self.session,
            key,
            request.into(),
            kind,
            MessageRoute::Multipart,
            None,
            signature,
            limits,
            output,
            maximum_output,
            self.validation_capture == crate::advanced::ValidationCaptureMode::Capture,
            &mut 1,
            &mut retirement,
        )
    }
    /// Submit one exact native Update through the common owner.
    pub fn signature_update(
        &self,
        ticket: &mut OperationTicket,
        bytes: &[u8],
        limits: InputLimits,
    ) -> Result<OperationProgress> {
        let mut diagnostics = None;
        let mut poll_diagnostics = crate::advanced::PollDiagnostics::default();
        change(
            &self.session,
            ticket,
            Change::Update(bytes),
            limits,
            self.pacing,
            &mut diagnostics,
            &mut poll_diagnostics,
        )
    }
    /// Explicitly close input, independently of polling and fragment emptiness.
    pub fn finish_signature_stream(
        &self,
        ticket: &mut OperationTicket,
        signature: Option<&[u8]>,
    ) -> Result<OperationProgress> {
        let mut diagnostics = None;
        let mut poll_diagnostics = crate::advanced::PollDiagnostics::default();
        change(
            &self.session,
            ticket,
            Change::Finish(signature),
            initial_limits(&self.session),
            self.pacing,
            &mut diagnostics,
            &mut poll_diagnostics,
        )
    }
    /// Supply storage without retrying the native terminal call implicitly.
    pub fn provide_signature_output_capacity(
        &self,
        ticket: &OperationTicket,
        capacity: usize,
    ) -> Result<()> {
        self.session
            .provide_signature_output_capacity(ticket, capacity)
    }
}

mod preparation;
pub(super) use preparation::change;
pub(super) use preparation::change_with_budget;

pub(super) use preparation::initial_limits;

