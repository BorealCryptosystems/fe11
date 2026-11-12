// SPDX-License-Identifier: Apache-2.0
//! Both facades retain the same recovery owner and explicit buffer negotiation.
use super::{
    checkpoint, drive, poll, preparation, validation, AdvancedSession, AdvancedSessionMode,
    KeyLease, Kind, Operation, OperationBody, OperationPacing, OperationProgress, OperationTicket,
    RecoverMechanism, RecoverOutputPlan,
};
use crate::{Error, Result, Session};
use std::sync::Arc;

fn synchronous(session: &Session) -> Result<()> {
    if session.entry.mode != AdvancedSessionMode::Synchronous {
        return Err(Error::Rejected(
            crate::RejectionReason::AsynchronousExecution(
                crate::AsynchronousExecutionRejection::SignatureRecoveryAsynchronousModeUnavailable,
            ),
        ));
    }
    Ok(())
}
fn start(
    session: &Session,
    key: &crate::NativeObjectRef,
    kind: Kind,
    mechanism: RecoverMechanism,
    input: &[u8],
    limits: crate::InputLimits,
    output: RecoverOutputPlan,
    maximum_output: usize,
    capture_validation: bool,
    remaining: &mut usize,
    retired_owner: &mut Option<Arc<crate::advanced::ledger::OperationCell>>,
) -> Result<OperationTicket> {
    synchronous(session)?;
    limits.validate(session.inner.crypto_options.limits, &[input])?;
    let check_functions = |state: &crate::module::State| -> Result<()> {
        let available = match kind {
            Kind::Sign => {
                state.native.table.C_SignRecoverInit.is_some()
                    && state.native.table.C_SignRecover.is_some()
            }
            Kind::Verify => {
                state.native.table.C_VerifyRecoverInit.is_some()
                    && state.native.table.C_VerifyRecover.is_some()
            }
        };
        if !available {
            return Err(Error::Rejected(crate::RejectionReason::OperationRecovery(
                crate::OperationRecoveryRejection::RecoveryFunctionsUnavailable,
            )));
        }
        Ok(())
    };
    let progress = session.advanced_preflight(&check_functions)?;
    let shape =
        checkpoint::SnapshotShape::for_request(mechanism, input.len(), output, maximum_output)?;
    let validation_bytes = if capture_validation {
        validation::Capture::allocation_bytes(1)?
    } else {
        0
    };
    let mut bytes = shape
        .allocation_bytes()?
        .checked_add(preparation::Shell::allocation_bytes())
        .and_then(|n| n.checked_add(validation_bytes))
        .ok_or(Error::Rejected(crate::RejectionReason::OperationRecovery(
            crate::OperationRecoveryRejection::RecoveryOperationStorageSize,
        )))?;
    let key_readers = crate::advanced::keys::KeyReaders::prepare(session, [Some(key)])?;
    let ((prepared, cancel, validation), access, mut prepared_readers) =
        key_readers.prepare_with(session, &progress, || loop {
            let mut prepaid = preparation::reserve_new_with_progress(session, bytes, &progress)?;
            let storage = shape.allocate()?;
            let validation = capture_validation
                .then(|| validation::CaptureStorage::allocate(1))
                .transpose()?;
            let validation_actual = validation
                .as_ref()
                .map(validation::CaptureStorage::allocated_bytes)
                .transpose()?
                .unwrap_or(0);
            let actual = storage
                .allocated_bytes()?
                .checked_add(validation_actual)
                .and_then(|n| n.checked_add(preparation::Shell::allocation_bytes()))
                .ok_or(Error::Rejected(crate::RejectionReason::OperationRecovery(
                    crate::OperationRecoveryRejection::RecoveryOperationStorageSize,
                )))?;
            if actual > bytes {
                drop(validation);
                drop(storage);
                drop(prepaid);
                bytes = actual;
                continue;
            }
            prepaid.release(bytes - actual);
            let prepared = storage.bind(&mut prepaid)?.fill_request(input)?;
            let validation = validation
                .map(|storage| storage.bind(&mut prepaid))
                .transpose()?;
            let cancel = preparation::Shell::from_prepaid(&mut prepaid)?;
            return Ok((prepared, cancel, validation));
        })?;
    check_functions(&access)?;
    let lease = KeyLease::for_recovery(session, key, mechanism.native()?, &mut prepared_readers)?;
    let body = prepared.bind(lease, kind, output);
    let (token, cancel) = cancel.bind(&access.lease_admission()?)?;
    let (id, operation) = access.operations.install(
        &session.entry,
        Operation::new(OperationBody::Recover(body), token, cancel).with_validation(validation),
    )?;
    let ticket = OperationTicket {
        owner: session.inner.clone(),
        uid: session.uid,
        id,
        validation_report: None,
        state_provenance: None,
    };
    // Caller declares this anchor before all access. Terminal Init can remove
    // the registry entry while the public return still owns its diagnostic.
    *retired_owner = Some(operation.clone());
    let mut operation = operation.lock().map_err(|_| Error::Poisoned)?;
    if let Err(error) = drive(&access, &session.entry, &mut operation, false, remaining) {
        let (error, _) = operation.retire_terminal_error(&access, &session.entry, error);
        return Err(error);
    }
    Ok(ticket)
}
fn resize(session: &Session, ticket: &OperationTicket, capacity: usize) -> Result<()> {
    synchronous(session)?;
    crate::advanced::output_preparation::replace(
        session,
        ticket,
        capacity,
        crate::advanced::output_preparation::Family::Recovery,
    )
}
impl Session {
    /// Initialize C_SignRecover with an admitted key and exact mechanism.
    /// Returns after Init so contextual authentication can precede key use.
    /// No hashing, capability probe, size query or retry is implicit.
    pub fn begin_sign_recover(
        &self,
        key: &crate::NativeObjectRef,
        mechanism: RecoverMechanism,
        data: &[u8],
        limits: crate::InputLimits,
        output: RecoverOutputPlan,
        maximum_output: usize,
    ) -> Result<OperationTicket> {
        let mut retired_owner = None;
        start(
            self,
            key,
            Kind::Sign,
            mechanism,
            data,
            limits,
            output,
            maximum_output,
            false,
            &mut 1,
            &mut retired_owner,
        )
    }
    /// Initialize C_VerifyRecover. Recovered bytes are published only on CKR_OK.
    /// Native signature errors are returned unchanged and terminate this owner.
    pub fn begin_verify_recover(
        &self,
        key: &crate::NativeObjectRef,
        mechanism: RecoverMechanism,
        signature: &[u8],
        limits: crate::InputLimits,
        output: RecoverOutputPlan,
        maximum_output: usize,
    ) -> Result<OperationTicket> {
        let mut retired_owner = None;
        start(
            self,
            key,
            Kind::Verify,
            mechanism,
            signature,
            limits,
            output,
            maximum_output,
            false,
            &mut 1,
            &mut retired_owner,
        )
    }
    /// Provide storage after an explicit native size result. Performs no native
    /// call; allocation failure preserves the request for cancellation or retry.
    /// In-memory snapshots retain maximum_output. Imported records use the
    /// destination module's configured maximum_total_bytes as their ceiling.
    pub fn resize_recovery_output(&self, ticket: &OperationTicket, capacity: usize) -> Result<()> {
        resize(self, ticket, capacity)
    }
    /// Advance the retained recovery operation, or report its buffer request.
    /// Checking the ticket family happens before any native call or publication.
    pub fn poll_recovery(&self, ticket: &mut OperationTicket) -> Result<OperationProgress> {
        synchronous(self)?;
        if !Arc::ptr_eq(&ticket.owner, &self.inner) || ticket.uid != self.uid || ticket.id == 0 {
            return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::ForeignOrConsumedRecoveryTicket,
            )));
        }
        let mut released = crate::advanced::poll::ReleasedInputs::default();
        let access = self.advanced_access()?;
        if self.entry.advanced_progress.retired(ticket.id)? {
            ticket.id = 0;
            return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::ForeignOrConsumedRecoveryTicket,
            )));
        }
        {
            let held = access.operations.get(self.uid)?;
            let operation = held.lock().map_err(|_| Error::Poisoned)?;
            if operation.id != ticket.id || !matches!(&operation.body, OperationBody::Recover(_)) {
                return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                    crate::OperationOwnershipRejection::RecoveryTicketRequired,
                )));
            }
        }
        poll::poll_with_access(self, ticket, &access, OperationPacing::Eager, &mut released)
    }
}
impl AdvancedSession {
    /// Start signature recovery using the configured pacing and observation policy.
    /// Cooperative pacing stops after Init, permitting contextual authentication.
    /// native asynchronous mode remains outside this interface's current execution scope.
    pub fn sign_recover(
        &self,
        key: &crate::NativeObjectRef,
        mechanism: RecoverMechanism,
        data: &[u8],
        limits: crate::InputLimits,
        output: RecoverOutputPlan,
        maximum_output: usize,
    ) -> Result<OperationTicket> {
        let mut retired_owner = None;
        start(
            &self.session,
            key,
            Kind::Sign,
            mechanism,
            data,
            limits,
            output,
            maximum_output,
            self.validation_capture == crate::advanced::ValidationCaptureMode::Capture,
            &mut self.pacing.budget(),
            &mut retired_owner,
        )
    }
    /// Start native verification with recovery; no plaintext on signature error.
    pub fn verify_recover(
        &self,
        key: &crate::NativeObjectRef,
        mechanism: RecoverMechanism,
        signature: &[u8],
        limits: crate::InputLimits,
        output: RecoverOutputPlan,
        maximum_output: usize,
    ) -> Result<OperationTicket> {
        let mut retired_owner = None;
        start(
            &self.session,
            key,
            Kind::Verify,
            mechanism,
            signature,
            limits,
            output,
            maximum_output,
            self.validation_capture == crate::advanced::ValidationCaptureMode::Capture,
            &mut self.pacing.budget(),
            &mut retired_owner,
        )
    }
    /// Select storage after RecoveryBufferRequired, without dispatching a call.
    pub fn resize_recovery_output(&self, ticket: &OperationTicket, capacity: usize) -> Result<()> {
        resize(&self.session, ticket, capacity)
    }
}
