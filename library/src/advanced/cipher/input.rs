// SPDX-License-Identifier: Apache-2.0
//! Explicit input submissions for the existing cipher owner.
use super::{api, CipherKeyReference, CipherOutputPlan, Direction, Stage};
use crate::advanced::{
    continuation::InputLayout, input::InputState, poll, preparation, progress, AdvancedSession,
    MessageRoute, Operation, OperationBody, OperationPacing, OperationProgress, OperationTicket,
    StreamInputStatus, StreamProgress, ValidationCaptureMode,
};
use crate::symmetric::memory::{Buffer, ControlledReservation, Credit, UnboundBuffer};
use crate::{bounds, CipherParameters, Error, InputLimits, Result, Session};
use std::sync::Arc;

/// Bytes transferred before the final cipher result. Decryption chunks are
/// explicitly unauthenticated. AEAD plaintext cannot be transferred here.
pub struct CipherStreamChunk {
    bytes: Buffer,
    decrypting: bool,
}
impl CipherStreamChunk {
    /// Borrow the transferred bytes; copies made by the caller are not erased here.
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }
    /// True identifies unauthenticated plaintext, not a successful AEAD result.
    pub fn is_unauthenticated_plaintext(&self) -> bool {
        self.decrypting
    }
}

struct InputBuffers {
    inputs: crate::advanced::fragment_queue::FragmentQueue,
    expected: super::shadow::Shadow,
    retirement: super::retirement::Pool,
    layout: InputLayout,
    metadata: Credit,
}
impl InputBuffers {
    fn prepare(
        budget: &Arc<crate::symmetric::memory::Budget>,
        bytes: &[u8],
        mut before: impl FnMut() -> Result<()>,
    ) -> Result<Self> {
        let admission = crate::admission_wait::current();
        let mut required = bytes
            .len()
            .checked_mul(2)
            .and_then(|n| n.checked_add(std::mem::size_of::<Buffer>()))
            .and_then(|n| n.checked_add(std::mem::size_of::<usize>()))
            .and_then(|n| n.checked_add(super::retirement::Storage::required_bytes(1, true).ok()?))
            .ok_or(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::CipherInputStorageAccounting,
            )))?;
        loop {
            let mut prepaid = match budget
                .reserve_controlled_retaining::<std::convert::Infallible>(
                    required,
                    crate::session::lifecycle_diagnostics::Store::allocation_bytes(),
                    &admission,
                    || {
                        before()?;
                        Ok(None)
                    },
                    || Ok(None),
                )? {
                ControlledReservation::Acquired(credit) => credit,
                ControlledReservation::Redirect(never) => match never {},
            };
            let input = UnboundBuffer::allocate(bytes.len())?;
            let expected = UnboundBuffer::allocate(bytes.len())?;
            let retirement = super::retirement::Storage::allocate(1, true)?;
            let mut inputs = Vec::<Buffer>::new();
            inputs.try_reserve_exact(1).map_err(|_| {
                Error::Rejected(crate::RejectionReason::CipherContinuation(
                    crate::CipherContinuationRejection::CipherInputMetadataAllocation,
                ))
            })?;
            let mut lengths = Vec::<usize>::new();
            lengths.try_reserve_exact(1).map_err(|_| {
                Error::Rejected(crate::RejectionReason::CipherContinuation(
                    crate::CipherContinuationRejection::CipherInputLayoutAllocation,
                ))
            })?;
            let actual = input
                .allocated()
                .checked_add(expected.allocated())
                .and_then(|n| n.checked_add(retirement.allocated_bytes().ok()?))
                .and_then(|n| {
                    n.checked_add(
                        inputs
                            .capacity()
                            .checked_mul(std::mem::size_of::<Buffer>())?,
                    )
                })
                .and_then(|n| {
                    n.checked_add(
                        lengths
                            .capacity()
                            .checked_mul(std::mem::size_of::<usize>())?,
                    )
                })
                .ok_or(Error::Rejected(crate::RejectionReason::CipherContinuation(
                    crate::CipherContinuationRejection::CipherInputStorageAccounting,
                )))?;
            if actual > required {
                drop(input);
                drop(expected);
                drop(retirement);
                drop(inputs);
                drop(lengths);
                drop(prepaid);
                required = actual;
                continue;
            }
            prepaid.release(required - actual);
            let mut input = input.bind(&mut prepaid)?;
            let mut expected = expected.bind(&mut prepaid)?;
            input.as_mut().copy_from_slice(bytes);
            expected.as_mut().copy_from_slice(bytes);
            inputs.push(input);
            lengths.push(bytes.len());
            let layout = InputLayout::from_owned_lengths(&mut prepaid, lengths)?;
            return Ok(Self {
                inputs: inputs.into(),
                expected: expected.into(),
                retirement: retirement.bind(&mut prepaid)?,
                layout,
                metadata: prepaid,
            });
        }
    }
}

fn check_owner(operation: &Operation, session: &Session, id: u64, ready: bool) -> Result<()> {
    if operation.id != id {
        return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
            crate::OperationOwnershipRejection::StaleCipherTicket,
        )));
    }
    operation.check_control_access(&session.entry)?;
    if operation.cancellation.is_withdrawn()
        || operation.cancel.is_submitted()
        || operation.state_io().is_some()
        || operation.transfer.is_some()
        || operation.joined.is_some()
        || operation.continuation_status.is_frozen()
        || operation.validation_pending()
    {
        return Err(Error::Busy(crate::BusyReason::CipherContinuation(
            crate::CipherContinuationBusy::CipherControlInProgress,
        )));
    }
    let OperationBody::Cipher(body) = &operation.body else {
        return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
            crate::OperationOwnershipRejection::CipherTicketRequired,
        )));
    };
    body.check_key(&session.entry)?;
    if !body.input.incremental
        || !body.input.is_open()
        || body.pending()
        || matches!(body.stage, Stage::Init(_) | Stage::Done | Stage::Failed)
        || ready
            && (!matches!(
                body.stage,
                Stage::Final | Stage::Query(super::OutputStep::Final)
            ) || !body.frame.inputs.is_empty())
    {
        return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
            crate::CipherContinuationRejection::CipherIsNotReadyForAnotherInput,
        )));
    }
    Ok(())
}

fn ticket_owner(session: &Session, ticket: &OperationTicket) -> Result<()> {
    if !Arc::ptr_eq(&session.inner, &ticket.owner) || ticket.uid != session.uid || ticket.id == 0 {
        return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
            crate::OperationOwnershipRejection::ForeignOrConsumedCipherTicket,
        )));
    }
    Ok(())
}

fn submit(
    session: &Session,
    ticket: &mut OperationTicket,
    bytes: &[u8],
    limits: InputLimits,
    pacing: OperationPacing,
    diagnostics: &mut Option<progress::FailureDiagnostics>,
    poll_diagnostics: &mut poll::PollDiagnostics,
) -> Result<OperationProgress> {
    ticket_owner(session, ticket)?;
    limits.validate(session.inner.crypto_options.limits, &[bytes])?;
    bounds::ck_length(bytes.len())?;
    // The public invocation retains preparation and polling diagnostics through
    // result projection. Neither owner is dropped while session access is held.
    let mut waiter: Option<progress::Waiter<'_>> = None;
    let mut candidate: Option<InputBuffers> = None;
    loop {
        // Partial moves and displaced metadata also unwind after access guards.
        let prepared: InputBuffers;
        let displaced_credit: Credit;
        let displaced: InputBuffers;
        let access = session.advanced_access()?;
        let held = access.operations.get(ticket.uid)?;
        let mut operation = held.lock().map_err(|_| Error::Poisoned)?;
        check_owner(&operation, session, ticket.id, true)?;
        if diagnostics.is_none() {
            drop(operation);
            drop(held);
            drop(access);
            *diagnostics = Some(progress::FailureDiagnostics::prepare(session, ticket.id)?);
            continue;
        }
        if let Some(waiting) = waiter.as_mut() {
            let unchanged = !waiting.changed() && candidate.is_some();
            waiting.succeed()?;
            if !unchanged {
                drop(operation);
                drop(held);
                drop(access);
                drop(candidate.take());
                drop(waiter.take());
                continue;
            }
            access
                .operations
                .claim_progress(&session.entry, operation.id)?;
            let OperationBody::Cipher(body) = &mut operation.body else {
                unreachable!()
            };
            body.input.submission(bytes.len(), false)?;
            prepared = candidate.take().expect("prepared cipher input");
            let old_capacity = body
                .frame
                .inputs
                .capacity()
                .checked_mul(std::mem::size_of::<Buffer>())
                .ok_or(Error::Rejected(crate::RejectionReason::CipherContinuation(
                    crate::CipherContinuationRejection::CipherInputMetadataAccounting,
                )))?;
            displaced_credit = body.frame._credit.split(old_capacity)?;
            body.frame._credit.merge(prepared.metadata)?;
            displaced = InputBuffers {
                inputs: std::mem::replace(&mut body.frame.inputs, prepared.inputs),
                expected: std::mem::replace(&mut body.frame.expected, prepared.expected),
                retirement: std::mem::replace(&mut body.frame.retirement, prepared.retirement),
                layout: std::mem::replace(&mut body.frame.layout, prepared.layout),
                metadata: displaced_credit,
            };
            let update = super::OutputStep::Update {
                index: 0,
                offset: 0,
            };
            body.stage = if matches!(body.stage, Stage::Query(_)) {
                Stage::Query(update)
            } else {
                update.stage()
            };
            drop(operation);
            drop(held);
            drop(access);
            drop(displaced);
            drop(waiter.take());
            return poll::poll_operation_with_diagnostics(
                session,
                ticket,
                crate::session::CleanupAdmission::Ordinary,
                pacing,
                poll_diagnostics,
            );
        }

        waiter = Some(progress::Waiter::new(
            session,
            operation.id,
            progress::Effect::PreserveOwner,
        )?);
        drop(operation);
        drop(held);
        drop(access);
        let waiting = waiter.as_mut().expect("registered cipher input waiter");
        let diagnostics = diagnostics
            .as_mut()
            .expect("cipher input diagnostics prepared");
        match InputBuffers::prepare(diagnostics.budget(), bytes, || {
            preparation::context(session)?;
            if waiting.changed() {
                return Err(Error::Busy(crate::BusyReason::CipherContinuation(
                    crate::CipherContinuationBusy::CipherControlChanged,
                )));
            }
            Ok(())
        }) {
            Ok(input) => candidate = Some(input),
            Err(_) if waiting.changed() => {
                waiting.succeed()?;
            }
            Err(error) => return Err(waiting.fail_prepared(error, diagnostics)),
        }
    }
}

fn finish(
    session: &Session,
    ticket: &mut OperationTicket,
    pacing: OperationPacing,
    retired_owner: &mut Option<std::sync::Arc<crate::advanced::ledger::OperationCell>>,
) -> Result<OperationProgress> {
    ticket_owner(session, ticket)?;
    let mut released = crate::advanced::poll::ReleasedInputs::default();
    let access = session.advanced_access()?;
    {
        let held = access.operations.get(ticket.uid)?;
        let mut operation = held.lock().map_err(|_| Error::Poisoned)?;
        check_owner(&operation, session, ticket.id, false)?;
        access
            .operations
            .claim_progress(&session.entry, operation.id)?;
        let OperationBody::Cipher(body) = &mut operation.body else {
            unreachable!()
        };
        body.input.close();
    }
    let result = poll::poll_with_access(session, ticket, &access, pacing, &mut released);
    *retired_owner = released.take_owner();
    result
}

fn take_output(session: &Session, ticket: &OperationTicket) -> Result<CipherStreamChunk> {
    ticket_owner(session, ticket)?;
    // Empty replacement requires no byte allocation; prepare it before guards.
    let mut credit = session.inner.symmetric_budget.reserve(0)?;
    let replacement = UnboundBuffer::allocate(0)?.bind(&mut credit)?;
    let access = session.advanced_access()?;
    let held = access.operations.get(ticket.uid)?;
    let mut operation = held.lock().map_err(|_| Error::Poisoned)?;
    check_owner(&operation, session, ticket.id, true)?;
    access
        .operations
        .claim_progress(&session.entry, operation.id)?;
    let OperationBody::Cipher(body) = &mut operation.body else {
        unreachable!()
    };
    let decrypting = body.frame.direction.decrypts();
    if decrypting && super::parameters::is_aead(body.frame.parameters.kind() as u64) {
        return Err(Error::Busy(crate::BusyReason::CipherContinuation(
            crate::CipherContinuationBusy::AeadPlaintextAwaitsSuccessfulFinal,
        )));
    }
    let next = body.input.delivered(body.used)?;
    let output = body.frame.output.as_mut().ok_or(Error::Rejected(
        crate::RejectionReason::CipherContinuation(
            crate::CipherContinuationRejection::CipherOutputAlreadyTransferred,
        ),
    ))?;
    output.set_length(body.used)?;
    let bytes = std::mem::replace(output, replacement);
    body.input = next;
    body.used = 0;
    Ok(CipherStreamChunk { bytes, decrypting })
}

fn begin(
    session: &Session,
    key: CipherKeyReference<'_>,
    parameters: CipherParameters,
    direction: Direction,
    output: CipherOutputPlan,
    capture: bool,
    retirement: &mut crate::advanced::PollDiagnostics,
) -> Result<OperationTicket> {
    let limits = InputLimits {
        maximum_parts: session.inner.crypto_options.limits.maximum_parts,
        maximum_total_bytes: session.inner.crypto_options.limits.maximum_total_bytes,
    };
    api::start_common_with_input(
        session,
        api::CipherKey::Native(key),
        parameters,
        direction,
        MessageRoute::Multipart,
        &[],
        limits,
        output,
        capture,
        &mut 1,
        InputState::open(),
        None,
        retirement,
    )
}

impl Session {
    /// Initialize native multipart encryption without predicting future input.
    /// MechanismBound starts with zero capacity because no input size is known;
    /// Buffer or LengthOnly makes the initial storage choice explicit.
    pub fn begin_encrypt_stream(
        &self,
        key: CipherKeyReference<'_>,
        parameters: CipherParameters,
        output: CipherOutputPlan,
    ) -> Result<OperationTicket> {
        let mut retirement = crate::advanced::PollDiagnostics::default();
        begin(
            self,
            key,
            parameters,
            Direction::Encrypt,
            output,
            false,
            &mut retirement,
        )
    }
    /// Initialize native multipart decryption. Ordinary cipher chunks are
    /// unauthenticated; only an AEAD owner's successful Final authenticates data.
    pub fn begin_decrypt_stream(
        &self,
        key: CipherKeyReference<'_>,
        parameters: CipherParameters,
        output: CipherOutputPlan,
    ) -> Result<OperationTicket> {
        let mut retirement = crate::advanced::PollDiagnostics::default();
        begin(
            self,
            key,
            parameters,
            Direction::Decrypt,
            output,
            false,
            &mut retirement,
        )
    }
    /// Submit one exact Update, including an empty fragment. A capacity result
    /// retains these bytes; resize and poll that ticket instead of resubmitting.
    pub fn cipher_update(
        &self,
        ticket: &mut OperationTicket,
        bytes: &[u8],
        limits: InputLimits,
    ) -> Result<OperationProgress> {
        let mut diagnostics = None;
        let mut poll_diagnostics = poll::PollDiagnostics::default();
        submit(
            self,
            ticket,
            bytes,
            limits,
            OperationPacing::Eager,
            &mut diagnostics,
            &mut poll_diagnostics,
        )
    }
    /// Explicitly close input and invoke Final once capacity is available.
    pub fn finish_cipher_stream(&self, ticket: &mut OperationTicket) -> Result<OperationProgress> {
        let mut retired_owner = None;
        finish(self, ticket, OperationPacing::Eager, &mut retired_owner)
    }
    /// Transfer established intermediate output exactly once. The final result
    /// subsequently contains only the tail not already transferred by this call.
    pub fn take_cipher_stream_output(&self, ticket: &OperationTicket) -> Result<CipherStreamChunk> {
        take_output(self, ticket)
    }
}

impl AdvancedSession {
    /// Initialize the same caller-driven encryption owner as Session.
    pub fn begin_encrypt_stream(
        &self,
        key: CipherKeyReference<'_>,
        parameters: CipherParameters,
        output: CipherOutputPlan,
    ) -> Result<OperationTicket> {
        let mut retirement = crate::advanced::PollDiagnostics::default();
        begin(
            &self.session,
            key,
            parameters,
            Direction::Encrypt,
            output,
            self.validation_capture == ValidationCaptureMode::Capture,
            &mut retirement,
        )
    }
    /// Initialize the same caller-driven decryption owner as Session.
    pub fn begin_decrypt_stream(
        &self,
        key: CipherKeyReference<'_>,
        parameters: CipherParameters,
        output: CipherOutputPlan,
    ) -> Result<OperationTicket> {
        let mut retirement = crate::advanced::PollDiagnostics::default();
        begin(
            &self.session,
            key,
            parameters,
            Direction::Decrypt,
            output,
            self.validation_capture == ValidationCaptureMode::Capture,
            &mut retirement,
        )
    }
    /// Submit one exact fragment using the selected native-dispatch pacing.
    pub fn cipher_update(
        &self,
        ticket: &mut OperationTicket,
        bytes: &[u8],
        limits: InputLimits,
    ) -> Result<OperationProgress> {
        let mut diagnostics = None;
        let mut poll_diagnostics = poll::PollDiagnostics::default();
        submit(
            &self.session,
            ticket,
            bytes,
            limits,
            self.pacing,
            &mut diagnostics,
            &mut poll_diagnostics,
        )
    }
    /// Close input with the selected pacing, including any validation read.
    /// Ordinary polling never closes an open stream.
    pub fn finish_cipher_stream(&self, ticket: &mut OperationTicket) -> Result<OperationProgress> {
        let mut retired_owner = None;
        finish(&self.session, ticket, self.pacing, &mut retired_owner)
    }
    /// Transfer established bytes, preserving authentication and delivery rules.
    pub fn take_cipher_stream_output(&self, ticket: &OperationTicket) -> Result<CipherStreamChunk> {
        take_output(&self.session, ticket)
    }
}

impl OperationTicket {
    /// Read stream closure and established counters without a native call.
    pub fn cipher_progress(&self) -> Result<(StreamInputStatus, StreamProgress)> {
        if self.id == 0 {
            return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::ConsumedCipherTicket,
            )));
        }
        let state = self.owner.read()?;
        let held = state.operations.get(self.uid)?;
        let operation = held.lock().map_err(|_| Error::Poisoned)?;
        if operation.id != self.id {
            return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::StaleCipherTicket,
            )));
        }
        let OperationBody::Cipher(body) = &operation.body else {
            return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::CipherTicketRequired,
            )));
        };
        Ok((body.input.status, body.input.progress))
    }
}
